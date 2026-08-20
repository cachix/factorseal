{
  lib,
  rustPlatform,
  stdenv,
  pkg-config,
  dbus,
  pcsclite,
  tpm2-tss,
}:

rustPlatform.buildRustPackage {
  pname = "factorseal";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.lock
      ../Cargo.toml
      ../nix/patches/hardware-enclave-tpm-auth-sessions.patch
      ../src
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # hardware-enclave 0.2.10 invokes authorized TPM commands without a
  # session, which current tss-esapi rejects before reaching the TPM. Keep
  # this downstream patch isolated so it can be dropped with an upstream
  # release containing the equivalent fix.
  postPatch = ''
    patch -d "$cargoDepsCopy/hardware-enclave-0.2.10" -p1 \
      < ${./patches/hardware-enclave-tpm-auth-sessions.patch}
  '';

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    dbus
    pcsclite
    tpm2-tss
  ];

  cargoBuildFlags = [
    "--no-default-features"
    "--features=agent,cli,hardware"
    "--bin=factorseal"
  ];

  doCheck = false;
  strictDeps = true;

  installPhase = ''
    runHook preInstall

    install -Dm0755 target/${stdenv.hostPlatform.rust.rustcTarget}/release/factorseal \
      "$out/bin/factorseal"
    install -Dm0755 ${../packaging/linux/factorseal-agent-start} \
      "$out/bin/factorseal-agent-start"
    substitute ${../packaging/linux/factorseal-agent.service.in} \
      factorseal-agent.service --replace-fail "@INSTALL_DIR@" "$out/bin"
    install -Dm0644 factorseal-agent.service \
      "$out/share/systemd/user/factorseal-agent.service"
    patchShebangs "$out/bin/factorseal-agent-start"

    runHook postInstall
  '';

  meta = {
    description = "Hardware-bound per-user Factorseal secret agent";
    homepage = "https://github.com/factorseal/factorseal";
    license = lib.licenses.asl20;
    mainProgram = "factorseal";
    platforms = lib.platforms.linux;
  };
}
