{
  lib,
  rustPlatform,
  fetchurl,
}:

rustPlatform.buildRustPackage {
  pname = "secretspec";
  version = "0.20.0-dev-8adfdb4";

  # Keep the installed client on the exact revision used by Factorseal's
  # Secret Provider Protocol dependency. nixpkgs 0.18 predates external
  # provider discovery and cannot exercise this integration.
  src = fetchurl {
    url = "https://github.com/cachix/secretspec/archive/8adfdb4815889d4739af4f92cebf1537e5d30ef8.tar.gz";
    hash = "sha256-qYNhXkCfl40sh6riZ9eQgeFTp+6XAQYpIGcNAKpJC1A=";
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
