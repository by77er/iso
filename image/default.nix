# The guest image, as a plain function so the repository's flake can build it:
# a stripped Firecracker kernel and a NixOS rootfs with the guest agent.
#
# Two nixpkgs: userspace comes from a release; the kernel from the revision
# whose kconfig generation still accepts modules/kernel.nix (newer ones reject
# the "unused option" requests it makes). The built kernel is handed to the
# current-nixpkgs rootfs through boot.kernelPackages.
#
# This lives at image/default.nix rather than in a flake of its own because
# modules/guest-agent.nix builds the agent from ../crates, and a flake rooted
# at image/ could not reach outside itself.
{ nixpkgs, nixpkgs-kernel }:
let
  system = "x86_64-linux";

  # crates.io refuses downloads whose User-Agent starts with "curl/", which is
  # what nixpkgs' fetchurl sends, so the crate tarballs importCargoLock fetches
  # for the guest agent need another one. Fixed-output derivations are keyed
  # on their content hash, so this rebuilds nothing that is already cached.
  fetchurlAgent = final: prev: {
    fetchurl = args: prev.fetchurl (args // {
      curlOptsList = (args.curlOptsList or [ ]) ++ [ "--user-agent" "iso guest image build (nixpkgs fetchurl)" ];
    });
  };

  pkgs = import nixpkgs { inherit system; overlays = [ fetchurlAgent ]; };
  pkgsKernel = import nixpkgs-kernel { inherit system; };

  kernelSystem = nixpkgs-kernel.lib.nixosSystem {
    inherit system;
    modules = [
      ./modules/firecracker.nix
      ./modules/base.nix
      ./modules/kernel.nix
    ];
  };

  firecrackerKernel = pkgsKernel.runCommand "firecracker-vmlinux"
    {
      nativeBuildInputs = with pkgsKernel; [ binutils gzip xz bzip2 lz4 lzop zstd ];
    } ''
    mkdir -p $out
    install -m755 ${./extract-vmlinux} ./extract-vmlinux
    ./extract-vmlinux ${kernelSystem.config.system.build.kernel}/bzImage > $out/vmlinux
    test -s $out/vmlinux
  '';

  # The agent as one static binary (musl), for rootfs flavors that are not
  # NixOS: the Debian image copies it in and runs it from a unit of its own.
  guestAgentStatic = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
    pname = "iso-guest-agent-static";
    version = "0.1.0";
    src = guestAgentSrc;
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [ "-p" "iso-guest-agent" ];
    doCheck = false;
  };

  # Only the workspace manifests and crate sources: a stray target/ or state/
  # on the build host never changes the hash.
  guestAgentSrc = pkgs.lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let rel = pkgs.lib.removePrefix (toString ../. + "/") (toString path);
      in rel == "Cargo.toml" || rel == "Cargo.lock" || rel == "crates" || pkgs.lib.hasPrefix "crates/" rel;
  };

  nixos = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      ./modules/firecracker.nix
      ./modules/base.nix
      ./modules/guest-agent.nix
      {
        boot.kernelPackages = kernelSystem.config.boot.kernelPackages;
        nixpkgs.overlays = [ fetchurlAgent ];
      }
    ];
  };
in
{
  inherit system;
  nixosConfiguration = nixos;
  packages = {
    default = nixos.config.system.build.toplevel;
    toplevel = nixos.config.system.build.toplevel;
    kernel = firecrackerKernel;
    nixos-install-tools = pkgs.nixos-install-tools;
    iso-guest-agent = nixos.config.iso.guestAgent.package;
    iso-guest-agent-static = guestAgentStatic;
  };
}
