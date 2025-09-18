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
        cargo-afl-source = {
          lib,
          fetchFromGitHub,
          aflplusplus,
          rustPlatform,
        }:
        rustPlatform.buildRustPackage {
          pname = "cargo-afl";
          version = "0.16.0-rc.0";

          src = fetchFromGitHub {
            owner = "rust-fuzz";
            repo = "afl.rs";
            rev = "ea1ca87123a42538db5550adc402c3a84536fb47";
            fetchSubmodules = false;
            hash = "sha256-AHzAvjA63nRuZ2vd3fRmwhrzCZlky5bWMgVImsw/DUw=";
          };

          buildInputs = [
            aflplusplus
          ];

          cargoHash = "sha256-W+Y/KZjuQZfXTbCx1mSJ0hZXoJYzDxAbyH1GwsdaDMA=";

          doCheck = false;

          meta = with lib; {
            description = "Command line helpers for fuzzing with AFL++";
            mainProgram = "cargo-afl";
            homepage = "https://github.com/rust-fuzz/cargo-afl";
            license = with licenses; [
              mit
              asl20
            ];
          };
        };
        pkgs = import nixpkgs {
            inherit system;
            overlays = [ 
                (import rust-overlay) 
                (final: prev: {
                    cargo-afl = final.callPackage cargo-afl-source {};
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
            # aflplusplus
            # cargo-afl
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

            sequoia-sq
            sequoia-sqv

            pkg-config 
            valgrind
            gdb
        ];
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
            # export PKG_CONFIG_ALL_STATIC=1
            export RUSTFLAGS="-C link-args=-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2";
            # export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib";
            '';
        } // params;
    in rec {
        inherit self pkgs;
        devShells.stable = pkgs.mkShell (shell rust-stable { name = "deb-repo-stable"; });
        devShells.nightly = pkgs.mkShell (shell rust-nightly { name = "deb-repo-nightly"; });
        devShell = devShells.nightly;
    });
}
