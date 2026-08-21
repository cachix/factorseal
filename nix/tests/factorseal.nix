{ pkgs, module }:

let
  package = pkgs.callPackage ../package.nix { };
  # `locked` runs an hour-long lease so nothing but the Lock signal can seal
  # it, and logs alice in on tty1 so there is a real logind session to lock.
  node =
    { idleSeconds, autologin }:
    { lib, pkgs, ... }:
    {
      imports = [ module ];

      virtualisation.tpm.enable = true;

      users.users = {
        alice = {
          isNormalUser = true;
          uid = 1000;
          linger = true;
        };
      };

      services.getty.autologinUser = lib.mkIf autologin "alice";

      services.factorseal = {
        enable = true;
        inherit package;
        users = [ "alice" ];
        inherit idleSeconds;
        maximumSeconds = idleSeconds * 12;
      };

      environment.systemPackages = [ pkgs.jq ];
      system.stateVersion = "26.05";
    };
in
pkgs.testers.runNixOSTest {
  name = "factorseal";

  nodes = {
    machine = node {
      idleSeconds = 5;
      autologin = false;
    };
    locked = node {
      idleSeconds = 3600;
      autologin = true;
    };
  };

  testScript = ''
    alice_prefix = "runuser -u alice -- env HOME=/home/alice XDG_RUNTIME_DIR=/run/user/1000"
    root = "/home/alice/.local/share/factorseal"
    runtime = "/run/user/1000/factorseal"
    password_file = f"{runtime}/session-password"
    socket = f"{root}/factorseal.sock"

    def as_user(node, command):
        return node.succeed(f"{alice_prefix} {command}")

    def write_password_on(node):
        node.succeed(
            f"install -d -m 0700 -o alice -g users {runtime} && "
            f"printf '%s\\n' factorseal-nixos-test > {password_file} && "
            f"chown alice:users {password_file} && chmod 0600 {password_file}"
        )

    def initialize_on(node):
        write_password_on(node)
        as_user(
            node,
            f"${package}/bin/factorseal --root={root} "
            f"--password-file={password_file} init",
        )
        node.succeed(f"rm -f {password_file}")

    def as_alice(command):
        return as_user(machine, command)

    def write_password():
        write_password_on(machine)

    def start_vault():
        write_password()
        as_alice("systemctl --user start factorseal.service")
        machine.wait_until_succeeds(f"test -S {socket}")
        machine.succeed(f"rm -f {password_file}")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")

    with subtest("module installs a static, password-gated user service"):
        machine.succeed("test -e /dev/tpm0")
        machine.succeed("test -e /dev/tpmrm0")
        machine.wait_for_unit("polkit.service")
        machine.succeed("id -nG alice | grep -w tss")
        machine.fail(
            f"{alice_prefix} systemctl --user cat factorseal.service "
            "| grep -q '^WantedBy='"
        )
        as_alice("systemctl --user cat factorseal.service | grep -- '--idle-seconds=5'")
        machine.succeed("test -x ${package}/bin/factorseal-start")
        machine.succeed("test -x ${package}/bin/factorseal")

    with subtest("service fails closed without a runtime password"):
        as_alice("systemctl --user start factorseal.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-failed factorseal.service"
        )
        machine.fail(f"test -S {socket}")
        as_alice("systemctl --user reset-failed factorseal.service")

    with subtest("initialize a real device through the virtual TPM"):
        initialize_on(machine)
        as_alice(f"${package}/bin/factorseal --root={root} status | jq -e '.state == \"sealed\"'")
        as_alice(
            f"${package}/bin/factorseal --root={root} status "
            "| jq -e '.hardware_backend == \"tpm\"'"
        )
        machine.succeed(f"test $(stat -c %a {root}) = 700")

    with subtest("start the native socket"):
        start_vault()
        machine.succeed("systemd-inhibit --list | grep -F Factorseal")
        machine.succeed(f"test $(stat -c %a {socket}) = 600")
        machine.succeed(f"test $(stat -c %a {root}) = 700")

    with subtest("idle expiry seals the vault and removes the socket"):
        # The 5 s idle lease above is what ends this; wait for the outcome
        # rather than for a fixed duration.
        machine.wait_until_fails(f"test -e {socket}")
        machine.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )

    with subtest("a stopped service cannot be restarted without a new handoff"):
        as_alice("systemctl --user start factorseal.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-failed factorseal.service"
        )
        machine.fail(f"test -S {socket}")

    with subtest("a logind session-lock event seals the vault"):
        locked.start()
        locked.wait_for_unit("multi-user.target")
        locked.wait_for_unit("user@1000.service")
        initialize_on(locked)

        # The unit lives in the user manager, which sits outside every logind
        # session, so it cannot infer which session to watch. `factorseal-start`
        # hands it the caller's session id; do exactly that here. Without it the
        # agent runs with no session-lock monitoring and this subtest would pass
        # on the lease instead.
        locked.wait_until_succeeds(
            "test -n \"$(loginctl show-user alice --property=Sessions --value)\""
        )
        session = locked.succeed(
            "loginctl show-user alice --property=Sessions --value | awk '{ print $1 }'"
        ).strip()

        write_password_on(locked)
        as_user(locked, f"systemctl --user set-environment FACTORSEAL_SESSION_ID={session}")
        as_user(locked, "systemctl --user start factorseal.service")
        locked.wait_until_succeeds(f"test -S {socket}")
        locked.succeed(f"rm -f {password_file}")

        # This node's lease is an hour, so expiry cannot be what ends it below.
        locked.succeed(f"loginctl lock-session {session}")
        locked.wait_until_fails(f"test -e {socket}")
        locked.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )
  '';
}
