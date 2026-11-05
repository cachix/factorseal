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
  version = "0.21.1";

  # Keep the installed client on the exact revision used by Factorseal's
  # Secret Provider Protocol dependency. nixpkgs 0.18 predates external
  # provider discovery and cannot exercise this integration.
  src = fetchurl {
    url = "https://github.com/cachix/secretspec/archive/${rev}.tar.gz";
    hash = "sha256-lohAGcwL3DdKy7bkCx0guyjDW59Ses2aKup+zI5UXUo=";
  };

  cargoHash = "sha256-48k3UKeT8qjRRLrf5yqmxULIynD6FgXiW063VEoTqmU=";

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
