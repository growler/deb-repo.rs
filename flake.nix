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
        pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
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
        devShell = devShells.stable;
    });
}
