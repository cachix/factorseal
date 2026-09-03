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
          factorseal-desktop = pkgs.callPackage ./nix/desktop-package.nix { };
        }
      );

      # This is intentionally an app rather than a flake check: it uses the
      # host's real TPM and asks the operator to trigger a session-lock event.
      # `nix run` builds the same patched Linux package that release artifacts
      # use, then runs the opt-in physical acceptance suite against it.
      apps = forLinuxSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          acceptance = pkgs.writeShellApplication {
            name = "factorseal-acceptance-linux";
            runtimeInputs = [
              pkgs.coreutils
              pkgs.gawk
              pkgs.gnugrep
              pkgs.systemd
            ];
            text = ''
              exec ${pkgs.dash}/bin/dash ${./acceptance/linux.sh} \\
                --factorseal ${self.packages.${system}.factorseal}/bin/factorseal \\
                "$@"
            '';
          };
        in
        {
          acceptance-linux = {
            type = "app";
            program = "${acceptance}/bin/factorseal-acceptance-linux";
            meta.description = "Run Factorseal's opt-in Linux hardware acceptance suite";
          };
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
          nixos-module-desktop = import ./nix/tests/factorseal-desktop-eval.nix {
            inherit pkgs;
            module = self.nixosModules.default;
          };
        };
    };
}
