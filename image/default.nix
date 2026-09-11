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
  pkgs = import nixpkgs { inherit system; };
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

  nixos = nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      ./modules/firecracker.nix
      ./modules/base.nix
      ./modules/guest-agent.nix
      { boot.kernelPackages = kernelSystem.config.boot.kernelPackages; }
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
  };
}
