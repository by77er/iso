# iso base rootfs userspace: a lean image that boots to sshd with a key-only
# `coder` user (uid 1000, passwordless sudo) and a minimal toolbelt — enough to
# log in and exercise networking. Extend `environment.systemPackages` for richer
# templates.
{ config
, lib
, pkgs
, ...
}:
let
  # SSH public keys from keys/authorized_keys (ignore comments/blanks).
  authorizedKeys = lib.pipe ../keys/authorized_keys [
    builtins.readFile
    (lib.splitString "\n")
    (map lib.trim)
    (lib.filter (l: l != "" && !lib.hasPrefix "#" l))
  ];

  # pi reads `AGENTS.md` from its config dir (~/.pi/agent) as global, always-on
  # system-prompt context. Bake a note there so the agent knows the egress proxy
  # injects credentials for it — same idea as the ANTHROPIC_API_KEY placeholder.
  piAgentNotes = pkgs.writeText "pi-global-agents.md" ''
    # Global agent notes

    ## Outbound network & credentials

    Outbound HTTPS is routed through iso's egress proxy, which injects
    credentials in flight. For GitHub (github.com, api.github.com) you do NOT
    need to log in, set a token, or run `gh auth login`: `gh`, `git` over
    HTTPS, and direct API calls are authenticated for you automatically. Just
    make the request.
  '';
in
{
  users.users.coder = {
    isNormalUser = true;
    uid = 1000;
    description = "iso workspace user";
    extraGroups = [ "wheel" ];
    shell = pkgs.bashInteractive;
    hashedPassword = ""; # key/console access only
    openssh.authorizedKeys.keys = authorizedKeys;
  };

  security.sudo.enable = true;
  security.sudo.wheelNeedsPassword = false;

  # Trust the iso egress-proxy CA, if its cert was staged next to the flake
  # before baking (cp state/ca/ca.crt image/ca.crt). Lets MITM'd TLS validate
  # inside the guest. NODE_EXTRA_CA_CERTS points node/pi at the system bundle.
  security.pki.certificateFiles =
    lib.optionals (builtins.pathExists ../ca.crt) [ ../ca.crt ];
  environment.variables.NODE_EXTRA_CA_CERTS = "/etc/ssl/certs/ca-bundle.crt";

  # pi / the Anthropic SDK refuse to start without an API key in the env, and
  # they send it as the `x-api-key` header. The egress proxy OVERRIDES that
  # header with the real key (from the host secret store), so this is a
  # non-secret placeholder — the real key never lives in the guest.
  environment.variables.ANTHROPIC_API_KEY = "iso-proxy-injects-the-real-key";

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };

  # Lean toolbelt: shell, core utils, net tools (enough to log in and test
  # connectivity). Add languages/build tools per template as needed.
  environment.systemPackages = with pkgs; [
    bashInteractive
    coreutils
    findutils
    gnugrep
    gnused
    gawk
    iproute2
    iputils
    curl
    openssh
    cacert
    jq
    vim
    less
    procps
    # dev toolbelt for the monorepo tooling
    git
    gh
    direnv
    # `devtool` launcher: find the repo root and exec its ./devtool (mirrors the
    # host's /usr/local/bin/devtool). The toolchain itself is managed by ./devtool.
    (writeShellScriptBin "devtool" ''
      set -euo pipefail
      root="$(pwd)"
      while [ -n "$root" ] && [ "$root" != "/" ] && [ ! -e "$root/.git" ]; do
        root="$(dirname "$root")"
      done
      if [ -z "$root" ] || [ "$root" = "/" ] || [ ! -x "$root/devtool" ]; then
        echo "devtool: must be run inside a repo" >&2
        exit 1
      fi
      cd "$root"
      exec ./devtool "$@"
    '')
  ];

  # Seed pi's global system-prompt context (`piAgentNotes`) into the coder
  # home before the snapshot, so every warm-resumed clone carries it. Owned by
  # coder so pi can keep writing its other config (settings.json, auth.json).
  systemd.tmpfiles.rules = [
    "d /home/coder/.pi 0755 coder users -"
    "d /home/coder/.pi/agent 0755 coder users -"
    "C /home/coder/.pi/agent/AGENTS.md 0644 coder users - ${piAgentNotes}"
  ];

  environment.variables.EDITOR = "vim";
  time.timeZone = "UTC";
  i18n.defaultLocale = "en_US.UTF-8";
}
