{
  description = "iso — NixOS Firecracker microVM base image (kernel + rootfs)";

  inputs = {
    # Userspace / rootfs: current.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    # Kernel only: pinned to a revision whose kconfig generation is compatible
    # with our custom firecracker kernel config (newer nixpkgs breaks it). The
    # built kernel is handed to the current-nixpkgs rootfs via boot.kernelPackages.
    nixpkgs-kernel.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs =
    { self, nixpkgs, nixpkgs-kernel }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgsKernel = import nixpkgs-kernel { inherit system; };

      # Kernel built with the PINNED nixpkgs (full NixOS config + our custom
      # kernel.nix patches). We only consume `system.build.kernel`.
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

      # Rootfs + userspace from CURRENT nixpkgs, booting the pinned kernel
      # (so its modules + version match) without re-running the kconfig.
      nixos = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./modules/firecracker.nix
          ./modules/base.nix
          { boot.kernelPackages = kernelSystem.config.boot.kernelPackages; }
        ];
      };
    in
    {
      nixosConfigurations.base = nixos;

      packages.${system} = {
        default = nixos.config.system.build.toplevel;
        toplevel = nixos.config.system.build.toplevel;
        kernel = firecrackerKernel;
        nixos-install-tools = pkgs.nixos-install-tools;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ nixos-install-tools e2fsprogs util-linux ];
      };
    };
}
