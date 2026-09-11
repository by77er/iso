# The iso guest agent: a small service on vsock port 5000 that the host's
# admin API drives to run programs and move files inside the VM. Built from
# this repository's `iso-guest-agent` crate with the compiler nixpkgs ships;
# that crate and `iso-guest-proto` stay on stable Rust for this reason.
{ config
, lib
, pkgs
, ...
}:
let
  # Only the workspace manifests and crate sources go into the store, so a
  # stray target/ or state/ on the build host never changes the hash.
  src = lib.cleanSourceWith {
    src = ../..;
    filter = path: type:
      let rel = lib.removePrefix (toString ../.. + "/") (toString path);
      in rel == "Cargo.toml" || rel == "Cargo.lock" || rel == "crates" || lib.hasPrefix "crates/" rel;
  };
  iso-guest-agent = pkgs.rustPlatform.buildRustPackage {
    pname = "iso-guest-agent";
    version = "0.1.0";
    inherit src;
    cargoLock.lockFile = ../../Cargo.lock;
    cargoBuildFlags = [ "-p" "iso-guest-agent" ];
    cargoTestFlags = [ "-p" "iso-guest-agent" ];
    doCheck = false;
  };
in
{
  environment.systemPackages = [ iso-guest-agent ];

  systemd.services.iso-guest-agent = {
    description = "iso guest agent (host exec and file access over vsock)";
    wantedBy = [ "multi-user.target" ];
    # vsock needs no network; start as early as the user database allows.
    after = [ "systemd-user-sessions.service" ];
    serviceConfig = {
      ExecStart = "${iso-guest-agent}/bin/iso-guest-agent --port 5000";
      # Runs as the workspace user, so everything it does is done with that
      # user's permissions (passwordless sudo is available inside commands).
      User = "coder";
      Group = "users";
      WorkingDirectory = "/home/coder";
      Restart = "always";
      RestartSec = 1;
    };
  };
}
