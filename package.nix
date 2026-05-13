{
  lib,
  rustPlatform,
  pkg-config,
  clang,
  gpgme,
  openssl,
  curl,
  bzip2,
  xz,
  libunistring,
}:
let
  cargoToml = lib.importTOML ./rdebootstrap/Cargo.toml;
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  version = cargoToml.package.version;

  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      name: _type:
      let
        baseName = baseNameOf (toString name);
      in
      !(baseName == "target" || baseName == "result" || baseName == ".git");
  };

  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [
    pkg-config
    clang
  ];

  buildInputs = [
    gpgme.dev
    openssl.dev
    curl.dev
    bzip2.dev
    xz.dev
    libunistring.dev
  ];

  cargoBuildFlags = [ "--package" "rdebootstrap" ];
  cargoTestFlags = [ "--package" "rdebootstrap" ];

  postBuild = ''
    cargo run --release --package xtask --bin build-man
  '';

  postInstall = ''
    install -Dm644 target/man/rdebootstrap.1 $out/share/man/man1/rdebootstrap.1
  '';

  meta = {
    description = cargoToml.package.description;
    license = lib.licenses.mit;
    mainProgram = "rdebootstrap";
    platforms = lib.platforms.linux;
  };
}
