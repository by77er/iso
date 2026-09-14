"""Harbor environments on iso.

A Harbor task is a Dockerfile (or a prebuilt image) plus commands to run in
it. Here each trial gets a Firecracker microVM instead of a container: the
task's image becomes an iso template (`POST /templates/build`, which pulls
the image on every host and bakes it with the guest agent as init), a VM is
cloned from it, and Harbor's `exec`, uploads and downloads go through the
host's guest agent over vsock. Outbound traffic goes through iso's egress
proxy, so a task's network policy maps onto iso rules: no network is
`deny`, public is `allow https://*/**`, an allowlist is one `allow` per
host. Credentials are never in the VM; the proxy injects them.

Select it with `--env harbor_iso:IsoEnvironment`. Configuration comes from
`--ek key=value` kwargs or the environment:

    ISO_SERVER            https://<fleet or host>:7080   (kwarg `server`)
    ISO_CREDS             directory with ca.crt, <client>.crt, <client>.key
    ISO_CLIENT            client name in ISO_CREDS (default operator)
    ISO_HARBOR_REGISTRY   registry prefix images built from a Dockerfile are
                          pushed to, e.g. ghcr.io/acme/harbor-envs; the iso
                          hosts must be able to pull from it (kwarg `registry`)

Templates are shared by every trial of the same task: their name is derived
from the task's environment definition, and a build happens once per fleet.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import logging
import os
import shlex
import subprocess
import tarfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

import httpx
from harbor.environments.base import BaseEnvironment, ExecResult
from harbor.environments.capabilities import (
    EnvironmentCapabilities,
    EnvironmentResourceCapabilities,
)
from harbor.environments.definition import (
    effective_exec_cwd,
    parse_dockerfile_workdir,
    require_agent_environment_definition,
)
from harbor.models.task.config import EnvironmentConfig, NetworkMode, NetworkPolicy
from harbor.models.trial.paths import TrialPaths

# What `exec` may capture per stream; Harbor reads test output through it.
_MAX_OUTPUT = 64 << 20
# What a tar-based directory download may return, base64 on stdout.
_MAX_DOWNLOAD = 512 << 20


def rules_for(policy: NetworkPolicy) -> tuple[str, list[str]]:
    """The iso egress mode and rules for a Harbor network policy."""
    if policy.network_mode == NetworkMode.NO_NETWORK:
        return "deny", []
    if policy.network_mode == NetworkMode.PUBLIC:
        return "proxy", ["allow https://*/**", "allow wss://*/**"]
    rules: list[str] = []
    for host in policy.allowed_hosts:
        host = host.strip().lower()
        if not host:
            continue
        if any(c.isdigit() for c in host.split(".")[-1]) or ":" in host or "/" in host:
            raise ValueError(
                f"iso allowlists take hostnames (exact or leading-wildcard), not {host!r}"
            )
        rules.append(f"allow https://{host}/**")
        rules.append(f"allow wss://{host}/**")
    return "proxy", rules


def template_name(environment_id: str, prefix: str = "hb-") -> str:
    """An LVM- and URL-safe template name from Harbor's environment identity."""
    digest = hashlib.sha256(environment_id.encode()).hexdigest()[:20]
    return f"{prefix}{digest}"


class IsoEnvironment(BaseEnvironment):
    """One Firecracker microVM per trial, on an iso host or fleet."""

    def __init__(
        self,
        environment_dir: Path,
        environment_name: str,
        session_id: str,
        trial_paths: TrialPaths,
        task_env_config: EnvironmentConfig,
        logger: logging.Logger | None = None,
        *args: Any,
        server: str | None = None,
        creds: str | None = None,
        client: str | None = None,
        registry: str | None = None,
        template_prefix: str = "hb-",
        build_timeout_sec: float = 1800.0,
        boot_timeout_sec: float = 180.0,
        vcpus: int | None = None,
        mem_mib: int | None = None,
        rootfs_size: str = "16G",
        principal: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            environment_dir,
            environment_name,
            session_id,
            trial_paths,
            task_env_config,
            logger,
            *args,
            **kwargs,
        )
        self._server = (server or os.environ.get("ISO_SERVER") or "").rstrip("/")
        self._creds = Path(creds or os.environ.get("ISO_CREDS") or "")
        self._client_name = client or os.environ.get("ISO_CLIENT") or "operator"
        self._registry = (registry or os.environ.get("ISO_HARBOR_REGISTRY") or "").rstrip("/") or None
        self._template_prefix = template_prefix
        self._build_timeout = build_timeout_sec
        self._boot_timeout = boot_timeout_sec
        self._vcpus = vcpus
        self._mem_mib = mem_mib
        self._rootfs_size = rootfs_size
        self._principal = principal
        self._vm_id: str | None = None
        self._image_ref: str | None = None
        self._http_client: httpx.AsyncClient | None = None
        self._upload_n = 0
        dockerfile = self.environment_dir / "Dockerfile"
        self._workdir = parse_dockerfile_workdir(dockerfile) if dockerfile.exists() else None

    # ------------------------------------------------------------ identity

    @staticmethod
    def type() -> str:
        return "iso"

    @property
    def capabilities(self) -> EnvironmentCapabilities:
        return EnvironmentCapabilities(
            disable_internet=True,
            network_allowlist=True,
            network_allowlist_hostnames=True,
            network_allowlist_wildcard_hostnames=True,
            dynamic_network_policy=True,
        )

    @classmethod
    def resource_capabilities(cls) -> EnvironmentResourceCapabilities | None:
        return EnvironmentResourceCapabilities(cpu_limit=True, memory_limit=True)

    def _validate_definition(self) -> None:
        require_agent_environment_definition(
            self.environment_dir,
            docker_image=self.task_env_config.docker_image,
        )

    @classmethod
    def preflight(cls) -> None:
        missing = [k for k in ("ISO_SERVER", "ISO_CREDS") if not os.environ.get(k)]
        if missing:
            raise SystemExit(
                "iso needs ISO_SERVER (the fleet or host API) and ISO_CREDS (a directory with "
                "ca.crt, <client>.crt, <client>.key), or --ek server=… --ek creds=…; "
                f"missing: {', '.join(missing)}"
            )

    @property
    def template(self) -> str:
        return template_name(self.environment_id, self._template_prefix)

    # ---------------------------------------------------------------- http

    def _http(self) -> httpx.AsyncClient:
        if self._http_client is None:
            if not self._server:
                raise RuntimeError("iso: no server configured (ISO_SERVER or --ek server=…)")
            verify: Any = True
            cert: Any = None
            if self._creds and (self._creds / "ca.crt").exists():
                verify = str(self._creds / "ca.crt")
                cert = (
                    str(self._creds / f"{self._client_name}.crt"),
                    str(self._creds / f"{self._client_name}.key"),
                )
            self._http_client = httpx.AsyncClient(
                base_url=self._server,
                verify=verify,
                cert=cert,
                timeout=httpx.Timeout(600.0, connect=10.0),
            )
        return self._http_client

    async def _call(self, method: str, path: str, **kw: Any) -> httpx.Response:
        resp = await self._http().request(method, path, **kw)
        if resp.status_code >= 400:
            detail = resp.text[:500]
            raise RuntimeError(f"iso {method} {path}: http {resp.status_code}: {detail}")
        return resp

    # --------------------------------------------------------------- image

    async def _resolve_image(self, force_build: bool) -> str:
        """The image reference the hosts will pull: the task's prebuilt image,
        or one built from its Dockerfile and pushed where the hosts can see it."""
        if self._image_ref and not force_build:
            return self._image_ref
        dockerfile = self.environment_dir / "Dockerfile"
        if self.task_env_config.docker_image and not dockerfile.exists():
            self._image_ref = self.task_env_config.docker_image
            return self._image_ref
        if not self._registry:
            raise RuntimeError(
                "iso: this task builds from a Dockerfile, so the image must be pushed "
                "somewhere the iso hosts can pull from; set ISO_HARBOR_REGISTRY (or "
                "--ek registry=…) to a registry prefix such as ghcr.io/acme/harbor-envs"
            )
        tag = f"{self._registry}/{self.template}:{hashlib.sha256(self.environment_id.encode()).hexdigest()[:12]}"
        await asyncio.to_thread(self._docker_build_and_push, tag, force_build)
        self._image_ref = tag
        return tag

    def _docker_build_and_push(self, tag: str, force_build: bool) -> None:
        build = ["docker", "build", "-t", tag, "--platform", "linux/amd64"]
        if force_build:
            build.append("--no-cache")
        build.append(str(self.environment_dir))
        self.logger.info("iso: building %s", tag)
        subprocess.run(build, check=True)
        self.logger.info("iso: pushing %s", tag)
        subprocess.run(["docker", "push", tag], check=True)

    # ------------------------------------------------------------ template

    async def _hosts_with_template(self) -> tuple[int, int]:
        """(healthy hosts with the template, healthy hosts). A single host
        without a fleet answers /templates instead of /hosts."""
        resp = await self._http().get("/hosts")
        if resp.status_code == 200:
            hosts = [h for h in resp.json() if h.get("healthy")]
            have = [h for h in hosts if self.template in (h.get("templates") or [])]
            return len(have), len(hosts)
        resp = await self._call("GET", "/templates")
        names = {t.get("name") for t in resp.json()}
        return (1 if self.template in names else 0), 1

    async def _ensure_template(self, image: str, force_build: bool) -> None:
        have, hosts = await self._hosts_with_template()
        if hosts == 0:
            raise RuntimeError("iso: no healthy host")
        if have == hosts and not force_build:
            return
        body = {
            "name": self.template,
            "image": image,
            "vcpus": self._effective_cpus or self._vcpus or 2,
            "mem_mib": self._effective_memory_mb or self._mem_mib or 2048,
            "size": self._rootfs_size,
            "force": force_build,
        }
        self.logger.info("iso: building template %s from %s", self.template, image)
        await self._call("POST", "/templates/build", json=body)
        deadline = time.monotonic() + self._build_timeout
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            resp = await self._http().get(f"/templates/builds/{self.template}")
            if resp.status_code == 404:
                continue
            status = resp.json()
            state = status.get("state")
            if state == "ready":
                return
            if state == "failed":
                detail = status.get("error") or status.get("log_tail") or ""
                for host, s in (status.get("hosts") or {}).items():
                    if s.get("state") == "failed":
                        detail = f"{host}: {s.get('error')}\n{s.get('log_tail', '')[-2000:]}"
                        break
                raise RuntimeError(f"iso: building template {self.template} failed: {detail}")
        raise TimeoutError(f"iso: template {self.template} was not ready in {self._build_timeout}s")

    # ----------------------------------------------------------- lifecycle

    async def start(self, force_build: bool) -> None:
        image = await self._resolve_image(force_build)
        await self._ensure_template(image, force_build)
        egress, rules = rules_for(self.network_policy)
        body: dict[str, Any] = {
            "template": self.template,
            "egress": egress,
            "rules": rules,
            "labels": {"name": self.session_id, "harbor": self.environment_name},
        }
        if self._principal:
            body["principal"] = self._principal
        if self._effective_cpus or self._vcpus:
            body["vcpus"] = self._effective_cpus or self._vcpus
        if self._effective_memory_mb or self._mem_mib:
            body["mem_mib"] = self._effective_memory_mb or self._mem_mib
        resp = await self._call("POST", "/vms", json=body)
        self._vm_id = resp.json()["id"]
        self.logger.info("iso: vm %s from %s", self._vm_id, self.template)
        deadline = time.monotonic() + self._boot_timeout
        while True:
            r = await self._http().get(f"/vms/{self._vm_id}/agent")
            if r.status_code == 200:
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"iso: the guest agent of {self._vm_id} never answered")
            await asyncio.sleep(1)
        await self.ensure_dirs(self._mount_targets(writable_only=True))
        await self._upload_environment_dir_after_start()

    async def stop(self, delete: bool) -> None:
        if self._vm_id:
            try:
                await self._call("DELETE", f"/vms/{self._vm_id}")
            except Exception as e:  # noqa: BLE001
                self.logger.error("iso: deleting vm %s: %s", self._vm_id, e)
            finally:
                self._vm_id = None
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def _apply_network_policy(self, network_policy: NetworkPolicy) -> None:
        egress, rules = rules_for(network_policy)
        await self._call("PATCH", f"/vms/{self._require_vm()}/policy", json={"egress": egress, "rules": rules})

    def _require_vm(self) -> str:
        if not self._vm_id:
            raise RuntimeError("iso: the environment is not started")
        return self._vm_id

    # ---------------------------------------------------------------- exec

    async def exec(
        self,
        command: str,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_sec: int | None = None,
        user: str | int | None = None,
    ) -> ExecResult:
        user = self._resolve_user(user)
        env = self._merge_env(env)
        body: dict[str, Any] = {
            "cmd": "sh",
            "args": ["-c", command],
            "env": env or {},
            "max_output_bytes": _MAX_OUTPUT,
        }
        cwd = effective_exec_cwd(cwd, self.task_env_config.workdir, self._workdir)
        if cwd:
            body["cwd"] = cwd
        if timeout_sec is not None:
            body["timeout_ms"] = int(timeout_sec) * 1000
        if user is not None:
            body["user"] = str(user)
        r = (await self._call("POST", f"/vms/{self._require_vm()}/exec", json=body)).json()
        code = r.get("exit_code")
        if code is None:
            code = 128 + int(r.get("signal") or 9)
        return ExecResult(stdout=r.get("stdout"), stderr=r.get("stderr"), return_code=code)

    # --------------------------------------------------------------- files

    async def upload_file(self, source_path: Path | str, target_path: str) -> None:
        src = Path(source_path)
        mode = src.stat().st_mode & 0o777
        await self._call(
            "PUT",
            f"/vms/{self._require_vm()}/files",
            params={"path": target_path},
            json={"content_b64": base64.b64encode(src.read_bytes()).decode(), "mode": mode, "mkdir": True},
        )

    async def upload_dir(self, source_dir: Path | str, target_dir: str) -> None:
        src = Path(source_dir)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(src, arcname=".")
        self._upload_n += 1
        remote = f"/tmp/.iso-upload-{self._upload_n}.tar.gz"
        await self._call(
            "PUT",
            f"/vms/{self._require_vm()}/files",
            params={"path": remote},
            json={"content_b64": base64.b64encode(buf.getvalue()).decode(), "mode": 0o600, "mkdir": True},
        )
        q = shlex.quote
        r = await self.exec(f"mkdir -p {q(target_dir)} && tar -xzf {q(remote)} -C {q(target_dir)}; rc=$?; rm -f {q(remote)}; exit $rc", user="root")
        if r.return_code != 0:
            # No tar in the image: one file at a time.
            self.logger.debug("iso: tar upload failed (%s); uploading file by file", r.stderr)
            for f in src.rglob("*"):
                if f.is_file():
                    await self.upload_file(f, str(PurePosixPath(target_dir) / f.relative_to(src).as_posix()))

    async def download_file(self, source_path: str, target_path: Path | str) -> None:
        r = await self._call("GET", f"/vms/{self._require_vm()}/files", params={"path": source_path})
        body = r.json()
        dst = Path(target_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(base64.b64decode(body["content_b64"]))

    async def download_dir(self, source_dir: str, target_dir: Path | str) -> None:
        dst = Path(target_dir)
        dst.mkdir(parents=True, exist_ok=True)
        q = shlex.quote
        r = await self._exec_raw(f"tar -C {q(source_dir)} -czf - . | base64", _MAX_DOWNLOAD)
        if r.get("exit_code") == 0 and r.get("stdout") and not r.get("truncated"):
            data = base64.b64decode("".join(r["stdout"].split()))
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                tar.extractall(dst, filter="data")
            return
        # No tar or base64 in the image: walk it.
        await self._download_tree(source_dir, dst)

    async def _download_tree(self, source_dir: str, dst: Path) -> None:
        r = await self._call("GET", f"/vms/{self._require_vm()}/dir", params={"path": source_dir})
        for e in r.json().get("entries", []):
            name = e["name"]
            remote = str(PurePosixPath(source_dir) / name)
            if e.get("kind") == "dir":
                await self._download_tree(remote, dst / name)
            elif e.get("kind") == "file":
                await self.download_file(remote, dst / name)

    async def _exec_raw(self, command: str, max_output: int) -> dict[str, Any]:
        body = {"cmd": "sh", "args": ["-c", command], "max_output_bytes": max_output, "user": "root"}
        return (await self._call("POST", f"/vms/{self._require_vm()}/exec", json=body)).json()
