{
  lib,
  rustPlatform,
  fetchurl,
}:

rustPlatform.buildRustPackage {
  pname = "secretspec";
  version = "0.20.0-dev-c780280";

  # Keep the installed client on the exact revision used by Factorseal's
  # Secret Provider Protocol dependency. nixpkgs 0.18 predates external
  # provider discovery and cannot exercise this integration.
  src = fetchurl {
    url = "https://github.com/cachix/secretspec/archive/c7802807e776a70419f98826cfb06e82171b81e7.tar.gz";
    hash = "sha256-clT8QT1ncCgmDOtI10rnmAAxFymSIFySJsRXMfzWl8I=";
  };

  cargoHash = "sha256-H9atiLKLAQ0co8mpkNFzh8j8fIZFu1bwSnE1wfgG8Cg=";

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
