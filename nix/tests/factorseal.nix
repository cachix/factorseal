{ pkgs, module }:

let
  package = pkgs.callPackage ../package.nix { };
in
pkgs.testers.runNixOSTest {
  name = "factorseal";

  nodes.machine = { pkgs, ... }: {
    imports = [ module ];

    virtualisation.tpm.enable = true;

    users.users = {
      alice = {
        isNormalUser = true;
        uid = 1000;
        linger = true;
      };
    };

    services.factorseal = {
      enable = true;
      inherit package;
      users = [ "alice" ];
      idleSeconds = 5;
      maximumSeconds = 60;
    };

    environment.systemPackages = [ pkgs.jq ];
    system.stateVersion = "26.05";
  };

  testScript = ''
    alice_prefix = "runuser -u alice -- env HOME=/home/alice XDG_RUNTIME_DIR=/run/user/1000"
    root = "/home/alice/.local/share/factorseal"
    runtime = "/run/user/1000/factorseal"
    password_file = f"{runtime}/session-password"
    socket = f"{root}/factorseal.sock"

    def as_alice(command):
        return machine.succeed(f"{alice_prefix} {command}")

    def write_password():
        machine.succeed(
            f"install -d -m 0700 -o alice -g users {runtime} && "
            f"printf '%s\\n' factorseal-nixos-test > {password_file} && "
            f"chown alice:users {password_file} && chmod 0600 {password_file}"
        )

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
        write_password()
        as_alice(
            f"${package}/bin/factorseal --root={root} "
            f"--password-file={password_file} init"
        )
        machine.succeed(f"rm -f {password_file}")
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
        as_alice("systemctl --user reset-failed factorseal.service")
        start_vault()
        machine.succeed("loginctl lock-sessions")
        machine.wait_until_fails(f"test -e {socket}")
        machine.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )
  '';
}
