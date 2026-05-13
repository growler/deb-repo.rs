{
    inputs = {
        nixpkgs.url = "nixpkgs";
        flake-parts.url = "github:hercules-ci/flake-parts";
        rust-overlay = {
          url = "github:oxalica/rust-overlay";
          inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    outputs = inputs@{ flake-parts, ... }:
      flake-parts.lib.mkFlake { inherit inputs; } rec {
        systems = [ "x86_64-linux" "aarch64-linux" ];
        flake = {
            overlays.default = final: _pre: {
                rdebootstrap = final.callPackage ./package.nix { };
            };
        };
        perSystem = { system, ... }: let
            pkgs = import inputs.nixpkgs {
                inherit system;
                overlays = [
                    (import inputs.rust-overlay)
                    flake.overlays.default
                ];
            };
            buildInputs = (with pkgs; [
                curl.dev
                openssl.dev
                gpgme.dev
                bzip2.dev
                xz.dev
                libunistring.dev
                clang
            ]);
            nativeBuildInputs = with pkgs; [
                pkg-config
            ];
            shellBuildInputs = with pkgs; [
                cargo-deb
                cargo-show-asm
                cargo-expand
                cargo-bloat
                cargo-fuzz
                cargo-outdated
                cargo-machete
                cargo-sort
                cargo-cache
                cargo-bloat
                cargo-depgraph
                cargo-benchcmp
                cargo-audit
                cargo-edit

                debian-devscripts
                dpkg
            ];
            rust-debian-stable = [ (pkgs.rust-bin.stable."1.89.0".default.override {
              extensions = [ "rust-analyzer" "rustfmt" "clippy" "rust-src" ];
            })];
            rust-stable = [ (pkgs.rust-bin.stable.latest.default.override {
              extensions = [ "rust-analyzer" "rustfmt" "clippy" "rust-src" ];
            })];
            rust-nightly = [ (pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default.override {
              extensions = [ "rust-analyzer" "rustfmt" "clippy" "rust-src" ];
            }))];
            shell = toolchain: params: {
                inherit buildInputs;
                nativeBuildInputs = nativeBuildInputs ++ shellBuildInputs ++ [ toolchain ];
                shellHook = ''
                export RUST_BACKTRACE=1
                '';
            } // params;
        in {
            packages.default = pkgs.rdebootstrap;
            devShells.debian-stable = pkgs.mkShell (shell rust-debian-stable { name = "deb-repo-stable"; });
            devShells.stable = pkgs.mkShell (shell rust-stable { name = "deb-repo-stable"; });
            devShells.nightly = pkgs.mkShell (shell rust-nightly { name = "deb-repo-nightly"; });
            devShells.default = pkgs.mkShell (shell rust-debian-stable { name = "deb-repo-stable"; });
        };
      };
}
