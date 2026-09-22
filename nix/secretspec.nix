{
  lib,
  rustPlatform,
  fetchurl,
}:

let
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  rev = manifest.dependencies.secretspec-ipc.rev;
in
rustPlatform.buildRustPackage {
  pname = "secretspec";
  version = "0.20.0-dev-${builtins.substring 0 7 rev}";

  # Keep the installed client on the exact revision used by Factorseal's
  # Secret Provider Protocol dependency. nixpkgs 0.18 predates external
  # provider discovery and cannot exercise this integration.
  src = fetchurl {
    url = "https://github.com/cachix/secretspec/archive/${rev}.tar.gz";
    hash = "sha256-ikktTnmYEjoHsKnPR7eqv1oGL1o+JpAWaaxEMGlc9FM=";
  };

  cargoHash = "sha256-pQb5Wtfe9k6r5Ii3F+8SGzOuPIRBevNypoJPKL4mnTg=";

  cargoBuildFlags = [
    "-p"
    "secretspec"
    "--no-default-features"
    "--features=cli"
    "--bin=secretspec"
  ];

  doCheck = false;
  strictDeps = true;

  meta = {
    description = "SecretSpec client pinned for Factorseal provider conformance";
    homepage = "https://secretspec.dev";
    license = lib.licenses.asl20;
    mainProgram = "secretspec";
  };
}
