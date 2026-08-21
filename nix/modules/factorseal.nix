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

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ../package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./nix/package.nix { }";
      description = "Factorseal package providing the vault and interactive starter.";
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
    ];

    security.tpm2.enable = lib.mkDefault true;
    security.polkit.enable = lib.mkDefault true;
    environment.systemPackages = [ cfg.package ];

    users.groups = lib.mkIf (tpmGroup != null) {
      "${tpmGroup}".members = cfg.users;
    };

    systemd.user.services.factorseal = {
      description = "Factorseal per-user vault service";
      documentation = [ "https://github.com/factorseal/factorseal" ];
      # A user manager does not necessarily inherit the graphical session's
      # environment. The broker needs this address to publish the standard
      # org.freedesktop.secrets service on the per-user bus.
      environment.DBUS_SESSION_BUS_ADDRESS = "unix:path=%t/bus";

      # Deliberately no wantedBy: Linux requires an interactive password for
      # every unseal session. factorseal-start performs that handoff.
      serviceConfig = {
        Type = "simple";
        ExecStart = lib.concatStringsSep " " [
          "${cfg.package}/bin/factorseal"
          "--password-file=%t/factorseal/session-password"
          "unseal"
          "--idle-seconds=${toString cfg.idleSeconds}"
          "--maximum-seconds=${toString cfg.maximumSeconds}"
        ];
        Restart = "no";
        UMask = "0077";
        NoNewPrivileges = true;
        # Do not add options which create a filesystem mount namespace here.
        # Linux authenticates clients by reading /proc/<SO_PEERCRED pid>/exe;
        # user-service mount namespaces make that ptrace-gated link unreadable.
        RuntimeDirectory = "factorseal";
        RuntimeDirectoryMode = "0700";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      };
    };
  };
}
