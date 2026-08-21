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
      ../crates
      ../nix/patches/hardware-enclave-tpm-auth-sessions.patch
      ../src
    ];
  };

  cargoLock = {
    lockFile = ../Cargo.lock;
    # `[patch.crates-io]` in Cargo.toml points hardware-enclave at our branch
    # behind godaddy/hardware-enclave#208. Cargo.lock pins the commit this hash
    # covers, so both move together.
    outputHashes = {
      "hardware-enclave-0.2.10" = "sha256-8bvhRDkrDB9xICySrCbbWqMB2WDqN/tDqgtKYJ0soTQ=";
    };
  };

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
    homepage = "https://github.com/factorseal/factorseal";
    license = lib.licenses.asl20;
    mainProgram = "factorseal";
    platforms = lib.platforms.linux;
  };
}
