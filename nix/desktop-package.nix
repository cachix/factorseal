{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  wrapGAppsHook4,
  dbus,
  gtk4,
  libxkbcommon,
  qt6,
  vulkan-loader,
}:

rustPlatform.buildRustPackage {
  pname = "factorseal-desktop";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../assets
      ../crates
      ../factorseal-desktop
      ../src
    ];
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "secretspec-ipc-0.19.1" = "sha256-QZ0RyffatI1ulF+jzZEHlUsjQeDoiIRV6nX4x3OkpIo=";
    };
  };

  nativeBuildInputs = [
    pkg-config
    qt6.wrapQtAppsHook
    wrapGAppsHook4
  ];
  buildInputs = [
    dbus
    gtk4
    libxkbcommon
    qt6.qtbase
    vulkan-loader
  ];

  cargoBuildFlags = [
    "--package=factorseal-desktop"
  ];

  doCheck = false;
  strictDeps = true;

  installPhase = ''
    runHook preInstall

    install -Dm0755 \
      target/${stdenv.hostPlatform.rust.rustcTarget}/release/factorseal-desktop \
      "$out/bin/factorseal-desktop"
    install -Dm0644 ${../assets/logo/factorseal-logo-fused.svg} \
      "$out/share/icons/hicolor/scalable/apps/dev.factorseal.Desktop.svg"
    mkdir -p "$out/share/applications"
    substitute ${../packaging/linux/dev.factorseal.Desktop.desktop.in} \
      "$out/share/applications/dev.factorseal.Desktop.desktop" \
      --replace-fail "@DESKTOP_EXECUTABLE@" "$out/bin/factorseal-desktop"
    mkdir -p "$out/share/dbus-1/services"
    substitute ${../packaging/linux/org.freedesktop.secrets.service.in} \
      "$out/share/dbus-1/services/org.freedesktop.secrets.service" \
      --replace-fail "@DESKTOP_EXECUTABLE@" "$out/bin/factorseal-desktop"

    runHook postInstall
  '';

  meta = {
    description = "Graphical host for the Factorseal hardware-backed vault";
    homepage = "https://github.com/domenkozar/factorseal";
    license = lib.licenses.asl20;
    mainProgram = "factorseal-desktop";
    platforms = lib.platforms.linux;
  };
}
