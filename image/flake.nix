{
  description = "iso — NixOS Firecracker microVM base image (kernel + rootfs)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      nixos = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./modules/firecracker.nix
          ./modules/base.nix
        ];
      };

      # Firecracker (x86_64) boots an uncompressed ELF vmlinux, not a bzImage;
      # extract it with the upstream kernel helper.
      firecrackerKernel = pkgs.runCommand "firecracker-vmlinux"
        {
          nativeBuildInputs = with pkgs; [ binutils gzip xz bzip2 lz4 lzop zstd ];
        } ''
        mkdir -p $out
        install -m755 ${./extract-vmlinux} ./extract-vmlinux
        ./extract-vmlinux ${nixos.config.system.build.kernel}/bzImage > $out/vmlinux
        test -s $out/vmlinux
      '';
    in
    {
      nixosConfigurations.base = nixos;

      packages.${system} = {
        default = nixos.config.system.build.toplevel;
        # NixOS system to nixos-install into the rootfs LV.
        toplevel = nixos.config.system.build.toplevel;
        # Uncompressed ELF vmlinux at ${kernel}/vmlinux.
        kernel = firecrackerKernel;
        # Pinned so `isoctl` can realize nixos-install itself.
        nixos-install-tools = pkgs.nixos-install-tools;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [ nixos-install-tools e2fsprogs util-linux ];
      };
    };
}
