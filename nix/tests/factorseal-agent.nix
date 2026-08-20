{ pkgs, module }:

let
  package = pkgs.callPackage ../package.nix { };
in
pkgs.testers.runNixOSTest {
  name = "factorseal-agent";

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
    root = "/home/alice/.local/share/factorseal/agent"
    runtime = "/run/user/1000/factorseal"
    password_file = f"{runtime}/session-password"
    socket = f"{root}/agent.sock"

    def as_alice(command):
        return machine.succeed(f"{alice_prefix} {command}")

    def write_password():
        machine.succeed(
            f"install -d -m 0700 -o alice -g users {runtime} && "
            f"printf '%s\\n' factorseal-nixos-test > {password_file} && "
            f"chown alice:users {password_file} && chmod 0600 {password_file}"
        )

    def start_agent():
        write_password()
        as_alice("systemctl --user start factorseal-agent.service")
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
            f"{alice_prefix} systemctl --user cat factorseal-agent.service "
            "| grep -q '^WantedBy='"
        )
        as_alice("systemctl --user cat factorseal-agent.service | grep -- '--idle-seconds=5'")
        machine.succeed("test -x ${package}/bin/factorseal-agent-start")
        machine.succeed("test -x ${package}/bin/factorseal")

    with subtest("service fails closed without a runtime password"):
        machine.succeed("install -d -m 0700 -o alice -g users /home/alice/.local/share/factorseal")
        as_alice("systemctl --user start factorseal-agent.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-failed factorseal-agent.service"
        )
        machine.fail(f"test -S {socket}")
        as_alice("systemctl --user reset-failed factorseal-agent.service")

    with subtest("initialize a real device through the virtual TPM"):
        write_password()
        as_alice(
            f"${package}/bin/factorseal --root={root} "
            f"--password-file={password_file} init"
        )
        machine.succeed(f"rm -f {password_file}")
        as_alice(f"${package}/bin/factorseal --root={root} status | jq -e '.state == \"locked\"'")
        machine.succeed(f"test $(stat -c %a {root}) = 700")

    with subtest("start the native socket"):
        start_agent()
        machine.succeed("systemd-inhibit --list | grep -F Factorseal")
        machine.succeed(f"test $(stat -c %a {socket}) = 600")
        machine.succeed(f"test $(stat -c %a {root}) = 700")

    with subtest("idle expiry locks the store and removes the socket"):
        # The 5 s idle lease above is what ends this; wait for the outcome
        # rather than for a fixed duration.
        machine.wait_until_fails(f"test -e {socket}")
        machine.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal-agent.service"
        )

    with subtest("a stopped service cannot be restarted without a new handoff"):
        as_alice("systemctl --user start factorseal-agent.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-failed factorseal-agent.service"
        )
        machine.fail(f"test -S {socket}")

    with subtest("a logind session-lock event locks the agent"):
        as_alice("systemctl --user reset-failed factorseal-agent.service")
        start_agent()
        machine.succeed("loginctl lock-sessions")
        machine.wait_until_fails(f"test -e {socket}")
        machine.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal-agent.service"
        )
  '';
}
