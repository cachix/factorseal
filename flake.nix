{
  description = "Factorseal packages and native integration checks";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      linuxSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forLinuxSystems = nixpkgs.lib.genAttrs linuxSystems;
    in
    {
      packages = forLinuxSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.callPackage ./nix/package.nix { };
          factorseal = self.packages.${system}.default;
        }
      );

      nixosModules = {
        default = import ./nix/modules/factorseal.nix;
        factorseal = self.nixosModules.default;
      };

      checks.x86_64-linux =
        let
          pkgs = import nixpkgs { system = "x86_64-linux"; };
          package = pkgs.callPackage ./nix/package.nix { };
        in
        {
          inherit package;
          nixos-module = import ./nix/tests/factorseal.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
        };
    };
}
