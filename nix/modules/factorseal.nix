{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.factorseal;
  tpmGroup = config.security.tpm2.tssGroup;
in
{
  options.services.factorseal = {
    enable = lib.mkEnableOption "the per-user Factorseal vault";

    mode = lib.mkOption {
      type = lib.types.enum [
        "agent"
        "desktop"
      ];
      default = "agent";
      description = ''
        Process that hosts the vault. The agent mode installs the headless
        systemd user service; desktop mode starts the graphical application
        from the user's graphical session. The two modes are mutually
        exclusive because they own the same vault, endpoint, and D-Bus names.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "Factorseal package providing the vault and interactive starter.";
    };

    desktopPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../desktop-package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./nix/desktop-package.nix { }";
      description = "Factorseal Desktop package providing the graphical vault host.";
    };

    desktop.autostart = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Start Factorseal Desktop in the tray with each graphical session.";
    };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Existing local users allowed to access the TPM resource-manager device.
        The systemd user unit is installed globally, but only listed users are
        added to the TPM access group by this module.
      '';
    };

    idleSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 300;
      description = "Idle seconds before the vault seals and discards unwrapped keys.";
    };

    maximumSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 28800;
      description = "Absolute maximum lifetime of one unsealed vault session.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.idleSeconds <= cfg.maximumSeconds;
        message = "services.factorseal.idleSeconds must not exceed maximumSeconds";
      }
      {
        assertion = config.security.tpm2.enable;
        message = "services.factorseal requires security.tpm2.enable";
      }
      {
        assertion = config.security.polkit.enable;
        message = "services.factorseal requires security.polkit.enable for logind delay inhibitors";
      }
      {
        assertion = tpmGroup != null || cfg.users == [ ];
        message = "services.factorseal.users requires security.tpm2.tssGroup to name a group";
      }
      {
        assertion = !config.services.gnome.gnome-keyring.enable;
        message = ''
          services.factorseal provides org.freedesktop.secrets in both agent
          and desktop modes; disable services.gnome.gnome-keyring (use
          lib.mkForce false when a desktop module enables it) so only one
          Secret Service provider runs
        '';
      }
    ];

    security.tpm2.enable = lib.mkDefault true;
    security.polkit.enable = lib.mkDefault true;
    environment.systemPackages = [ cfg.package ]
      ++ lib.optional (cfg.mode == "desktop") cfg.desktopPackage;
    services.dbus.packages = lib.optional (cfg.mode == "desktop") cfg.desktopPackage;

    environment.variables = lib.mkIf (cfg.mode == "desktop") {
      FACTORSEAL_DESKTOP_EXECUTABLE = "${cfg.desktopPackage}/bin/factorseal-desktop";
      FACTORSEAL_CLI_EXECUTABLE = "${cfg.package}/bin/factorseal";
      FACTORSEAL_IDLE_SECONDS = toString cfg.idleSeconds;
      FACTORSEAL_MAXIMUM_SECONDS = toString cfg.maximumSeconds;
    };

    users.groups = lib.mkIf (tpmGroup != null) {
      "${tpmGroup}".members = cfg.users;
    };

    systemd.user.services.factorseal = lib.mkIf (cfg.mode == "agent") {
      description = "Factorseal per-user vault service";
      documentation = [ "https://github.com/domenkozar/factorseal" ];
      wantedBy = [ "default.target" ];
      wants = [ "dbus.socket" ];
      after = [ "dbus.socket" ];

      # A user manager does not necessarily inherit the graphical session's
      # environment. The broker needs this address to publish the standard
      # org.freedesktop.secrets service on the per-user bus.
      environment.DBUS_SESSION_BUS_ADDRESS = "unix:path=%t/bus";

      # Before initialization the agent remains active and logs an actionable
      # message. Once initialized, systemd's password agent passes the factor
      # to Factorseal over a pipe; it is never staged in the runtime directory.
      serviceConfig = {
        Type = "simple";
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/factorseal"
          "--askpass=${pkgs.systemd}/bin/systemd-ask-password"
          "agent"
          "--idle-seconds=${toString cfg.idleSeconds}"
          "--maximum-seconds=${toString cfg.maximumSeconds}"
        ];
        Restart = "no";
        UMask = "0077";
        LimitCORE = 0;
        NoNewPrivileges = true;
        # Do not add options which create a filesystem mount namespace here.
        # Linux authenticates clients by reading /proc/<SO_PEERCRED pid>/exe;
        # user-service mount namespaces make that ptrace-gated link unreadable.
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };

    environment.etc."xdg/autostart/dev.factorseal.Desktop.desktop" =
      lib.mkIf (cfg.mode == "desktop" && cfg.desktop.autostart)
        {
          text = ''
            [Desktop Entry]
            Type=Application
            Name=Factorseal Desktop
            Comment=Unlock and manage the Factorseal hardware-backed vault
            Exec=${cfg.desktopPackage}/bin/factorseal-desktop --background --idle-seconds=${toString cfg.idleSeconds} --maximum-seconds=${toString cfg.maximumSeconds}
            TryExec=${cfg.desktopPackage}/bin/factorseal-desktop
            Icon=dev.factorseal.Desktop
            Terminal=false
            Categories=Utility;Security;
            X-GNOME-Autostart-enabled=true
          '';
        };
  };
}
