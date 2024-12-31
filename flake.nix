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
            gpgme.dev
            openssl.dev
            bzip2.dev
            xz.dev
        ]);
        nativeBuildInputs = with pkgs; [ 
            cargo-show-asm
            cargo-expand
            cargo-bloat
            cargo-fuzz

            pkg-config 
            gpgme
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
            '';
        } // params;
    in rec {
        inherit self pkgs;
        devShells.stable = pkgs.mkShell (shell rust-stable { name = "deb-repo-stable"; });
        devShells.nightly = pkgs.mkShell (shell rust-nightly { name = "deb-repo-nightly"; });
        devShell = devShells.stable;
    });
}
