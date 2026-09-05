{ pkgs, module }:

let
  package = pkgs.writeShellScriptBin "factorseal" "exit 0";
  # Exercise activation without a graphical session or a full GPUI build.
  desktopPackage = pkgs.runCommand "factorseal-desktop-probe" { } ''
    mkdir -p "$out/bin" "$out/share/applications" "$out/share/dbus-1/services"
    cat > "$out/bin/factorseal-desktop" <<'EOF'
    #!${pkgs.runtimeShell}
    printf '%s\n' "$FACTORSEAL_CLI_EXECUTABLE" "$FACTORSEAL_IDLE_SECONDS" "$FACTORSEAL_MAXIMUM_SECONDS" "$@"
    EOF
    chmod +x "$out/bin/factorseal-desktop"
    substitute ${../../packaging/linux/dev.factorseal.Desktop.desktop.in} \
      "$out/share/applications/dev.factorseal.Desktop.desktop" \
      --replace-fail "@DESKTOP_EXECUTABLE@" "$out/bin/factorseal-desktop"
    substitute ${../../packaging/linux/org.freedesktop.secrets.service.in} \
      "$out/share/dbus-1/services/org.freedesktop.secrets.service" \
      --replace-fail "@DESKTOP_EXECUTABLE@" "$out/bin/factorseal-desktop"
  '';
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
  configuredDesktop = pkgs.lib.findFirst (
    package: package.name == "factorseal-desktop-configured"
  ) (throw "configured desktop missing from D-Bus packages") evaluated.services.dbus.packages;
  autostart = evaluated.environment.etc."xdg/autostart/dev.factorseal.Desktop.desktop".text;
in
assert !(builtins.hasAttr "factorseal" evaluated.systemd.user.services);
assert builtins.elem package evaluated.environment.systemPackages;
assert builtins.elem configuredDesktop evaluated.environment.systemPackages;
assert
  evaluated.environment.variables.FACTORSEAL_DESKTOP_EXECUTABLE
  == "${configuredDesktop}/bin/factorseal-desktop";
assert evaluated.environment.variables.FACTORSEAL_CLI_EXECUTABLE == "${package}/bin/factorseal";
assert evaluated.environment.variables.FACTORSEAL_IDLE_SECONDS == "45";
assert evaluated.environment.variables.FACTORSEAL_MAXIMUM_SECONDS == "900";
assert pkgs.lib.hasInfix "factorseal-desktop --background" autostart;
pkgs.runCommand "factorseal-desktop-module-evaluation" { } ''
  executable=${configuredDesktop}/bin/factorseal-desktop
  # Start the actual D-Bus Exec command with no session environment.
  activation=$(sed -n 's/^Exec=//p' ${configuredDesktop}/share/dbus-1/services/org.freedesktop.secrets.service)
  test "$activation" = "$executable --keyring-activation"
  env -i $activation > actual
  printf '%s\n' '${package}/bin/factorseal' 45 900 --keyring-activation > expected
  diff -u expected actual
  grep -Fx "Exec=$executable" ${configuredDesktop}/share/applications/dev.factorseal.Desktop.desktop
  touch "$out"
''
