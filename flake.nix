{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        flake-utils.url = "github:numtide/flake-utils";
        rust-overlay = {
          url = "github:oxalica/rust-overlay";
          inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    outputs = {self, nixpkgs, rust-overlay, flake-utils}: flake-utils.lib.eachDefaultSystem (system: let
        cargo-debstatus-source = {
          lib,
          fetchFromGitHub,
          rustPlatform,
        }:
        rustPlatform.buildRustPackage rec {
          pname = "cargo-debstatus";
          version = "0.6.5";

          src = fetchFromGitHub {
            owner = "kpcyrd";
            repo = "cargo-debstatus";
            rev = "v${version}";
            hash = "sha256-Z14rvF0jZ+MYIxFoc0nwYgRzPJVCwzFwdjzw6kJ6PP4=";
          };

          cargoHash = "sha256-3NUqZrDfCxCfNSc3FxWsc5Gd5um26cu/2EmFDRzkZuQ=";

          doCheck = false;

          meta = with lib; {
            description = "cargo-tree for debian packaging.";
            mainProgram = "cargo-debstatus";
            homepage = "https://github.com/kpcyrd/cargo-debstatus";
            license = with licenses; [
              mit
              asl20
              gpl3Plus
            ];
          };
        };
        pkgs = import nixpkgs {
            inherit system;
            overlays = [ 
                (import rust-overlay) 
                (final: prev: {
                    cargo-debstatus = final.callPackage cargo-debstatus-source {};
                })
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
            cargo-debstatus
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

            sequoia-sq
            sequoia-sqv

            pkg-config 
        ];
        rust-debian-stable = [ (pkgs.rust-bin.stable."1.85.1".default.override {
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
            nativeBuildInputs = nativeBuildInputs ++ [ toolchain ] ++ (with pkgs; [
            ]);
            shellHook = ''
            export RUST_BACKTRACE=1
            export RUSTFLAGS="-C link-args=-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2";
            '';
        } // params;
    in rec {
        inherit self pkgs;
        devShells.debian-stable = pkgs.mkShell (shell rust-debian-stable { name = "deb-repo-stable"; });
        devShells.stable = pkgs.mkShell (shell rust-stable { name = "deb-repo-stable"; });
        devShells.nightly = pkgs.mkShell (shell rust-nightly { name = "deb-repo-nightly"; });
        devShell = devShells.debian-stable;
    });
}
