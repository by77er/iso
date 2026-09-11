# iso base rootfs userspace: a lean image for running agents. It boots to
# sshd with a key-only `coder` user (uid 1000, passwordless sudo), the iso
# guest agent on vsock (see guest-agent.nix), and a minimal toolbelt. Nothing in
# it is specific to one coding agent: the host drives the guest through the
# admin API's exec and file endpoints, and whatever tooling a workload needs is
# added per template through `environment.systemPackages`.
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

  # Facts an agent working inside the VM should know: the egress proxy injects
  # credentials, and the metadata service says who the VM is. Installed at
  # /etc/iso/AGENTS.md; point your agent's global-instructions file at it.
  agentNotes = pkgs.writeText "iso-agents.md" ''
    # Notes for agents running in this VM

    ## Outbound network & credentials

    Outbound HTTPS is routed through iso's egress proxy, which injects
    credentials in flight. For GitHub (github.com, api.github.com) you do NOT
    need to log in, set a token, or run `gh auth login`: `gh`, `git` over
    HTTPS, and direct API calls are authenticated for you automatically. Just
    make the request.

    ## Your VM identity & service endpoints

    You run inside an iso microVM. To learn who you are and how you're reached
    from outside, query the metadata service:

        curl -s http://metadata.iso.internal/ | jq

    It returns your `name`, the `host` you're reachable at (the iso server's
    address), and `endpoints` — one entry per forwarded port, each with
    `vm_port`, `host_port`, and a ready-to-use `endpoint` (`host:host_port`).

    If a user asks for the URL/endpoint of a service you're running, look up its
    `vm_port` in `endpoints` and give them that entry's `endpoint`. Only ports
    listed there are reachable from outside the VM; a service on an unlisted
    port has no external forward.
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

  # SDKs refuse to start without an API key in the environment and send it as
  # the `x-api-key` header. The egress proxy OVERRIDES that header with the real
  # key (from the host secret store), so this is a non-secret placeholder — the
  # real key never lives in the guest.
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
    file
    # dev toolbelt, including what agents' search tools shell out to
    git
    gh
    direnv
    ripgrep
    fd
  ];

  environment.etc."iso/AGENTS.md".source = agentNotes;

  environment.variables.EDITOR = "vim";
  time.timeZone = "UTC";
  i18n.defaultLocale = "en_US.UTF-8";
}
