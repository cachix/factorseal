{ pkgs, module }:

let
  package = pkgs.callPackage ../package.nix { };
  desktopPackage = pkgs.callPackage ../desktop-package.nix { };
  system = import (pkgs.path + "/nixos/lib/eval-config.nix") {
    inherit (pkgs.stdenv.hostPlatform) system;
    modules = [
      module
      {
        security.polkit.enable = true;
        security.tpm2.enable = true;
        services.factorseal = {
          enable = true;
          mode = "desktop";
          inherit package desktopPackage;
          users = [ ];
          idleSeconds = 45;
          maximumSeconds = 900;
        };
        system.stateVersion = "26.05";
      }
    ];
  };
  evaluated = system.config;
  autostart = evaluated.environment.etc."xdg/autostart/dev.factorseal.Desktop.desktop".text;
in
assert !(builtins.hasAttr "factorseal" evaluated.systemd.user.services);
assert builtins.elem package evaluated.environment.systemPackages;
assert builtins.elem desktopPackage evaluated.environment.systemPackages;
assert builtins.elem desktopPackage evaluated.services.dbus.packages;
assert
  evaluated.environment.variables.FACTORSEAL_DESKTOP_EXECUTABLE
  == "${desktopPackage}/bin/factorseal-desktop";
assert evaluated.environment.variables.FACTORSEAL_CLI_EXECUTABLE == "${package}/bin/factorseal";
assert evaluated.environment.variables.FACTORSEAL_IDLE_SECONDS == "45";
assert evaluated.environment.variables.FACTORSEAL_MAXIMUM_SECONDS == "900";
assert pkgs.lib.hasInfix "factorseal-desktop --background --idle-seconds=45 --maximum-seconds=900" autostart;
pkgs.runCommand "factorseal-desktop-module-evaluation" { } ''
  touch "$out"
''
