{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  dbus,
}:

rustPlatform.buildRustPackage {
  pname = "factorseal";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../crates
      ../src
    ];
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "secretspec-ipc-0.19.1" = "sha256-uMemqk3LJo8InszQcjoFY7o3WyySd1feQZKf7Afg97E=";
    };
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dbus ];

  cargoBuildFlags = [
    "--no-default-features"
    "--features=vault,cli,hardware"
    "--bin=factorseal"
  ];

  doCheck = false;
  strictDeps = true;

  installPhase = ''
    runHook preInstall

    install -Dm0755 target/${stdenv.hostPlatform.rust.rustcTarget}/release/factorseal \
      "$out/bin/factorseal"
    install -Dm0755 ${../packaging/linux/factorseal-start} \
      "$out/bin/factorseal-start"
    substitute ${../packaging/linux/factorseal.service.in} \
      factorseal.service --replace-fail "@INSTALL_DIR@" "$out/bin"
    install -Dm0644 factorseal.service \
      "$out/share/systemd/user/factorseal.service"
    patchShebangs "$out/bin/factorseal-start"

    runHook postInstall
  '';

  meta = {
    description = "Hardware-bound Factorseal vault with a keyring interface";
    homepage = "https://github.com/domenkozar/factorseal";
    license = lib.licenses.asl20;
    mainProgram = "factorseal";
    platforms = lib.platforms.linux;
  };
}
