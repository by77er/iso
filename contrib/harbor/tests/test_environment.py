"""The adapter against Harbor's real base class and a fake iso API."""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

import httpx
import pytest
from harbor.models.task.config import EnvironmentConfig, NetworkMode, NetworkPolicy
from harbor.models.trial.paths import TrialPaths

from harbor_iso import IsoEnvironment
from harbor_iso.environment import rules_for, template_name


class FakeIso:
    """Enough of the fleet API to start, use and stop an environment."""

    def __init__(self) -> None:
        self.templates: set[str] = set()
        self.builds: dict[str, dict] = {}
        self.vms: dict[str, dict] = {}
        self.files: dict[str, bytes] = {}
        self.execs: list[dict] = []
        self.deleted: list[str] = []
        self.polls = 0

    def handle(self, req: httpx.Request) -> httpx.Response:
        p, m = req.url.path, req.method
        body = json.loads(req.content) if req.content else {}
        if p == "/hosts":
            return httpx.Response(200, json=[{"name": "a", "healthy": True, "templates": sorted(self.templates)}])
        if p == "/templates/build":
            self.builds[body["name"]] = body
            return httpx.Response(202, json={"name": body["name"], "hosts": {"a": {"state": "building", "http": 202}}})
        if p.startswith("/templates/builds/"):
            name = p.rsplit("/", 1)[1]
            self.polls += 1
            if self.polls >= 2:
                self.templates.add(name)
                return httpx.Response(200, json={"name": name, "state": "ready", "hosts": {"a": {"state": "ready"}}})
            return httpx.Response(200, json={"name": name, "state": "building", "hosts": {"a": {"state": "building"}}})
        if p == "/vms" and m == "POST":
            self.vms["vm-1"] = body
            return httpx.Response(200, json={"id": "vm-1", "host": "a"})
        if p == "/vms/vm-1/agent":
            return httpx.Response(200, json={"agent": "iso-guest-agent"})
        if p == "/vms/vm-1/exec":
            self.execs.append(body)
            cmd = body["args"][1]
            if cmd.startswith("tar -C"):
                # download_dir: tar of the files we hold under that dir
                return httpx.Response(200, json={"exit_code": 1, "stdout": "", "stderr": "no tar", "truncated": False})
            if cmd.startswith("mkdir -p") and "tar -xzf" in cmd:
                return httpx.Response(200, json={"exit_code": 1, "stdout": "", "stderr": "tar: not found", "truncated": False})
            return httpx.Response(200, json={"exit_code": 0, "stdout": f"ran:{cmd}", "stderr": "", "truncated": False})
        if p == "/vms/vm-1/files" and m == "PUT":
            self.files[req.url.params["path"]] = base64.b64decode(body["content_b64"])
            return httpx.Response(200, json={"bytes": 1})
        if p == "/vms/vm-1/files" and m == "GET":
            data = self.files.get(req.url.params["path"])
            if data is None:
                return httpx.Response(404, json={"error": "no such file"})
            return httpx.Response(200, json={"content_b64": base64.b64encode(data).decode(), "size": len(data), "truncated": False})
        if p == "/vms/vm-1/dir":
            prefix = req.url.params["path"].rstrip("/") + "/"
            names = sorted({f[len(prefix):].split("/", 1)[0] for f in self.files if f.startswith(prefix)})
            entries = [{"name": n, "kind": "dir" if any(f.startswith(prefix + n + "/") for f in self.files) else "file", "size": 0, "mode": 0o644} for n in names]
            return httpx.Response(200, json={"entries": entries})
        if p == "/vms/vm-1/policy" and m == "PATCH":
            self.vms["vm-1"]["policy"] = body
            return httpx.Response(204)
        if p == "/vms/vm-1" and m == "DELETE":
            self.deleted.append("vm-1")
            return httpx.Response(204)
        return httpx.Response(404, json={"error": f"unhandled {m} {p}"})


def make_env(tmp_path: Path, fake: FakeIso, **kw) -> IsoEnvironment:
    env_dir = tmp_path / "environment"
    env_dir.mkdir(parents=True)
    (env_dir / "Dockerfile").write_text("FROM python:3.12-slim\nWORKDIR /app\n")
    trial = tmp_path / "trial"
    trial.mkdir()
    env = IsoEnvironment(
        environment_dir=env_dir,
        environment_name="demo",
        session_id="demo__abc__env",
        trial_paths=TrialPaths(trial_dir=trial),
        task_env_config=EnvironmentConfig(),
        logger=logging.getLogger("test"),
        server="https://fleet.test:7080",
        registry="registry.test/harbor",
        **kw,
    )
    # Talk to the fake instead of the network; never actually run docker.
    env._http_client = httpx.AsyncClient(base_url="https://fleet.test:7080", transport=httpx.MockTransport(fake.handle))
    env._docker_build_and_push = lambda tag, force: None  # type: ignore[method-assign]
    return env


def test_policy_mapping_and_names():
    assert rules_for(NetworkPolicy(network_mode=NetworkMode.NO_NETWORK)) == ("deny", [])
    assert rules_for(NetworkPolicy(network_mode=NetworkMode.PUBLIC)) == ("proxy", ["allow https://*/**", "allow wss://*/**"])
    egress, rules = rules_for(NetworkPolicy(network_mode=NetworkMode.ALLOWLIST, allowed_hosts=["api.github.com", "*.pypi.org"]))
    assert egress == "proxy"
    assert "allow https://*.pypi.org/**" in rules and "allow wss://api.github.com/**" in rules
    with pytest.raises(ValueError):
        rules_for(NetworkPolicy(network_mode=NetworkMode.ALLOWLIST, allowed_hosts=["10.0.0.1"]))
    name = template_name("whatever")
    assert name.startswith("hb-") and len(name) == 23 and name == template_name("whatever")


async def test_start_builds_the_template_once_and_creates_a_vm(tmp_path, monkeypatch):
    monkeypatch.setattr("harbor_iso.environment.asyncio.sleep", _no_sleep)
    fake = FakeIso()
    env = make_env(tmp_path, fake)
    await env.start(force_build=False)
    assert env.template in fake.builds, "the template was built from the pushed image"
    assert fake.builds[env.template]["image"].startswith("registry.test/harbor/hb-")
    vm = fake.vms["vm-1"]
    assert vm["template"] == env.template
    assert (vm["egress"], vm["rules"]) == ("proxy", ["allow https://*/**", "allow wss://*/**"]), "public network as an open proxy policy"
    assert vm["labels"]["name"] == "demo__abc__env"

    # A second environment for the same task finds the template and builds nothing.
    fake.builds.clear()
    env2 = make_env(tmp_path / "second", fake)
    await env2.start(force_build=False)
    assert not fake.builds


async def test_exec_files_and_stop(tmp_path, monkeypatch):
    monkeypatch.setattr("harbor_iso.environment.asyncio.sleep", _no_sleep)
    fake = FakeIso()
    env = make_env(tmp_path, fake)
    await env.start(force_build=False)
    fake.execs.clear()

    r = await env.exec("echo hi", cwd="/work", env={"K": "v"}, timeout_sec=7, user="root")
    assert (r.return_code, r.stdout) == (0, "ran:echo hi")
    sent = fake.execs[-1]
    assert (sent["cmd"], sent["args"], sent["cwd"], sent["env"]["K"], sent["timeout_ms"], sent["user"]) == ("sh", ["-c", "echo hi"], "/work", "v", 7000, "root")

    # The Dockerfile's WORKDIR is the default cwd.
    await env.exec("pwd")
    assert fake.execs[-1]["cwd"] == "/app"

    src = tmp_path / "in.txt"
    src.write_bytes(b"payload")
    await env.upload_file(src, "/data/in.txt")
    assert fake.files["/data/in.txt"] == b"payload"
    out = tmp_path / "out.txt"
    await env.download_file("/data/in.txt", out)
    assert out.read_bytes() == b"payload"

    # Directory upload falls back to one file at a time when the image has no tar.
    d = tmp_path / "dir"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / "sub" / "b.txt").write_text("B")
    await env.upload_dir(d, "/tests")
    assert fake.files["/tests/a.txt"] == b"A" and fake.files["/tests/sub/b.txt"] == b"B"
    # And a directory download walks the tree when tar is not there either.
    got = tmp_path / "got"
    await env.download_dir("/tests", got)
    assert (got / "a.txt").read_text() == "A" and (got / "sub" / "b.txt").read_text() == "B"

    await env.set_network_policy(NetworkPolicy(network_mode=NetworkMode.NO_NETWORK))
    assert fake.vms["vm-1"]["policy"] == {"egress": "deny", "rules": []}

    await env.stop(delete=True)
    assert fake.deleted == ["vm-1"]


async def _no_sleep(_):
    return None
