{
  description = "iso: Firecracker microVM sandboxes for agents (dev shell and guest image)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    # The guest image (see image/default.nix): userspace from a release, the
    # kernel from a revision whose kconfig generation accepts our config.
    nixpkgs-image.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-kernel.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, nixpkgs-image, nixpkgs-kernel }:
    let
      image = import ./image { nixpkgs = nixpkgs-image; inherit nixpkgs-kernel; };
      dev = flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        # Latest nightly Rust toolchain.
        rustToolchain = pkgs.rust-bin.selectLatestNightlyWith (toolchain:
          toolchain.default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          });

        # Latest available Firecracker + jailer (official release binaries).
        # nixpkgs lags behind upstream, so we pull the release artifacts
        # directly to guarantee the newest version.
        firecrackerVersion = "1.16.0";
        firecrackerArch =
          if system == "x86_64-linux" then "x86_64"
          else if system == "aarch64-linux" then "aarch64"
          else throw "Firecracker is not supported on ${system}";
        firecrackerSrc = pkgs.fetchurl {
          url = "https://github.com/firecracker-microvm/firecracker/releases/download/v${firecrackerVersion}/firecracker-v${firecrackerVersion}-${firecrackerArch}.tgz";
          sha256 =
            if firecrackerArch == "x86_64"
            then "1mlj5qhimmm9x8kjw60rqccjcg9q1c527ikqaw45iqfla9ly415x"
            else "1mzgd2vanwknlf380xm1myb709n0mcd8agakqa5lnzf3vcy7272k";
        };
        firecracker = pkgs.stdenv.mkDerivation {
          pname = "firecracker";
          version = firecrackerVersion;
          src = firecrackerSrc;
          sourceRoot = "release-v${firecrackerVersion}-${firecrackerArch}";
          nativeBuildInputs = [ pkgs.autoPatchelfHook ];
          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin
            for tool in firecracker jailer cpu-template-helper rebase-snap \
                        seccompiler-bin snapshot-editor; do
              install -m755 "$tool-v${firecrackerVersion}-${firecrackerArch}" \
                "$out/bin/$tool"
            done
            runHook postInstall
          '';
          meta = with pkgs.lib; {
            description = "Secure and fast microVMs for serverless computing (official release binaries)";
            homepage = "https://firecracker-microvm.github.io/";
            license = licenses.asl20;
            platforms = [ "x86_64-linux" "aarch64-linux" ];
            mainProgram = "firecracker";
          };
        };
      in
      {
        packages.firecracker = firecracker;

        devShells.default = pkgs.mkShell {
          packages = [
            rustToolchain
            pkgs.pkg-config
            pkgs.openssl
            pkgs.cargo-nextest
            pkgs.cargo-watch
            pkgs.e2fsprogs
            pkgs.util-linux
            firecracker
          ];

          env = {
            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
          };

          shellHook = ''
            echo "iso dev shell — $(rustc --version)"
            echo "firecracker $(firecracker --version | head -1 | awk '{print $NF}'), jailer $(jailer --version | head -1 | awk '{print $NF}')"
          '';
        };
      });
    in
    nixpkgs.lib.recursiveUpdate dev {
      # `nix build .#kernel`, `.#toplevel`, `.#nixos-install-tools`, `.#iso-guest-agent`;
      # `isoctl bake` consumes the first three.
      packages.${image.system} = image.packages;
      nixosConfigurations.base = image.nixosConfiguration;
    };
}
