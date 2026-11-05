{
  lib,
  rustPlatform,
  fetchFromGitHub,
}:

let
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  version = manifest.dependencies.secretspec-ipc.version;
in
rustPlatform.buildRustPackage {
  pname = "secretspec";
  inherit version;

  # Keep the installed client on the release matching Factorseal's
  # crates.io Secret Provider Protocol dependency. nixpkgs 0.18 predates external
  # provider discovery and cannot exercise this integration.
  src = fetchFromGitHub {
    owner = "cachix";
    repo = "secretspec";
    tag = "v${version}";
    hash = "sha256-8OC1WS8VWTSwUJlT/qWx9CCPmO90G2OWJxEKZGUgXqM=";
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
