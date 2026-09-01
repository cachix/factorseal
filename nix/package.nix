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
      "secretspec-ipc-0.19.1" = "sha256-QZ0RyffatI1ulF+jzZEHlUsjQeDoiIRV6nX4x3OkpIo=";
    };
  };

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ dbus ];

  cargoBuildFlags = [
    "--no-default-features"
    "--features=vault,cli,hardware,secretspec-provider"
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
    substitute ${../packaging/linux/factorseal-portal.service.in} \
      factorseal-portal.service --replace-fail "@INSTALL_DIR@" "$out/bin"
    install -Dm0644 factorseal-portal.service \
      "$out/share/systemd/user/factorseal-portal.service"
    substitute ${../packaging/linux/org.freedesktop.impl.portal.desktop.factorseal.service.in} \
      org.freedesktop.impl.portal.desktop.factorseal.service \
      --replace-fail "@INSTALL_DIR@" "$out/bin"
    install -Dm0644 org.freedesktop.impl.portal.desktop.factorseal.service \
      "$out/share/dbus-1/services/org.freedesktop.impl.portal.desktop.factorseal.service"
    install -Dm0644 ${../packaging/linux/factorseal.portal} \
      "$out/share/xdg-desktop-portal/portals/factorseal.portal"
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
