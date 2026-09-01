{ pkgs, module }:

let
  package = pkgs.callPackage ../package.nix { };
  secretspec = pkgs.callPackage ../secretspec.nix { };
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

      environment.systemPackages = [
        pkgs.jq
        pkgs.util-linux
      ];
      # The VM exercises the Factorseal module, not NixOS installation or
      # recovery tooling. Keep both profiles out so an unrelated installer-tool
      # regression cannot prevent this service test from booting.
      environment.defaultPackages = lib.mkForce [ ];
      system.disableInstallerTools = true;
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
    import json
    import shlex

    alice_prefix = "runuser -u alice -- env HOME=/home/alice XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"
    root = "/home/alice/.local/share/factorseal"
    socket = f"{root}/factorseal.sock"

    def as_user(node, command):
        return node.succeed(f"{alice_prefix} sh -c {shlex.quote(command)}")

    def with_password(node, command, confirm=False):
        answers = "factorseal-nixos-test\n" * (2 if confirm else 1)
        return as_user(
            node,
            f"printf %s {shlex.quote(answers)} | "
            f"script -qec {shlex.quote(command)} /dev/null",
        )

    def write_user_file(node, path, contents):
        parent = path.rsplit("/", 1)[0]
        as_user(
            node,
            f"install -d -m 700 {shlex.quote(parent)}; "
            f"printf %s {shlex.quote(contents)} > {shlex.quote(path)}; "
            f"chmod 600 {shlex.quote(path)}",
        )

    def secretspec_command(project, arguments, environment=""):
        manifest = f"/home/alice/projects/{project}/secretspec.toml"
        prefix = f"{environment} " if environment else ""
        return (
            f"{prefix}${secretspec}/bin/secretspec "
            f"--file {shlex.quote(manifest)} --reason nixos-provider-conformance "
            f"{arguments}"
        )

    def start_transient(node, unit, command):
        stdout = f"/tmp/{unit}.stdout"
        stderr = f"/tmp/{unit}.stderr"
        as_user(
            node,
            f"systemd-run --user --quiet --unit={shlex.quote(unit)} "
            f"--property=Type=exec --property=StandardOutput=file:{stdout} "
            f"--property=StandardError=file:{stderr} "
            f"sh -c {shlex.quote(command)}",
        )

    def wait_transient(node, unit, expected_status=0):
        node.wait_until_succeeds(
            f"{alice_prefix} systemctl --user show {shlex.quote(unit)} "
            "--property=ActiveState --value | grep -Eq '^(inactive|failed)$'"
        )
        status = int(
            as_user(
                node,
                f"systemctl --user show {shlex.quote(unit)} "
                "--property=ExecMainStatus --value",
            ).strip()
        )
        assert status == expected_status, (
            f"{unit} exited {status}; stdout:\n"
            f"{node.succeed(f'cat /tmp/{unit}.stdout')}\nstderr:\n"
            f"{node.succeed(f'cat /tmp/{unit}.stderr')}"
        )

    def pending_permission_id(node, project):
        command = (
            f"${package}/bin/factorseal --root={root} permissions list --json "
            f"| jq -er '.[] | select(.state.status == \"pending\" and "
            f".application.project == {json.dumps(project)}) | .id'"
        )
        node.wait_until_succeeds(
            f"{alice_prefix} sh -c {shlex.quote(command)}",
            timeout=30,
        )
        return as_user(node, command).strip()

    def approve_permission(node, permission_id):
        password_file = "/home/alice/.factorseal-nixos-test-password"
        write_user_file(node, password_file, "factorseal-nixos-test\n")
        command = (
            f"${package}/bin/factorseal --root={root} "
            f"--password-file={password_file} permissions approve "
            f"{shlex.quote(permission_id)}"
        )
        as_user(
            node,
            f"printf '\\n' | script -qec {shlex.quote(command)} /dev/null",
        )

    def run_with_approvals(
        node,
        unit,
        project,
        command,
        approval_count=1,
        expected_status=0,
    ):
        start_transient(node, unit, command)
        for _ in range(approval_count):
            approve_permission(node, pending_permission_id(node, project))
        wait_transient(node, unit, expected_status=expected_status)

    def initialize_on(node):
        with_password(
            node,
            f"${package}/bin/factorseal --root={root} init --unlock password",
            confirm=True,
        )

    def as_alice(command):
        return as_user(machine, command)

    def start_vault():
        with_password(
            machine,
            "systemctl --user start --no-block factorseal.service; "
            "while [ -z \"$(systemd-tty-ask-password-agent --list)\" ]; do sleep 0.05; done; "
            "systemd-tty-ask-password-agent --query",
        )
        machine.wait_until_succeeds(f"test -S {socket}")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("user@1000.service")

    with subtest("module installs an enabled, password-gated user service"):
        machine.succeed("systemd-detect-virt --quiet")
        machine.succeed("test -e /dev/tpm0")
        machine.succeed("test -e /dev/tpmrm0")
        machine.wait_for_unit("polkit.service")
        machine.succeed("id -nG alice | grep -w tss")
        as_alice("systemctl --user is-enabled factorseal.service | grep -x enabled")
        as_alice(
            "systemctl --user cat factorseal.service "
            "| grep -q '^WantedBy=default.target'"
        )
        as_alice(
            "systemctl --user cat factorseal.service "
            "| grep -q '^Wants=dbus.socket'"
        )
        as_alice(
            "systemctl --user cat factorseal.service "
            "| grep -q '^After=dbus.socket'"
        )
        as_alice("systemctl --user cat factorseal.service | grep -- '--idle-seconds=5'")
        machine.succeed("test -x ${package}/bin/factorseal-start")
        machine.succeed("test -x ${package}/bin/factorseal")

    with subtest("service startup explains how to initialize a missing vault"):
        machine.wait_until_succeeds(
            "journalctl _SYSTEMD_USER_UNIT=factorseal.service --no-pager "
            "| grep -F 'run `factorseal init` to create it; waiting for initialization'",
            timeout=30,
        )
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )
        machine.fail(f"test -S {socket}")

    with subtest("initialize a real device through the virtual TPM"):
        initialize_on(machine)
        as_alice(f"${package}/bin/factorseal --root={root} status | jq -e '.state == \"sealed\"'")
        as_alice(
            f"${package}/bin/factorseal --root={root} status "
            "| jq -e '.hardware_backend == \"tpm\"'"
        )
        machine.succeed(f"test $(stat -c %a {root}) = 700")

    with subtest("service stays sealed while its password request is unanswered"):
        as_alice("systemctl --user start --no-block factorseal.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )
        machine.fail(f"test -S {socket}")
        as_alice("systemctl --user stop factorseal.service")

    with subtest("start the native socket"):
        start_vault()
        machine.succeed("systemd-inhibit --list | grep -F Factorseal")
        machine.succeed(f"test $(stat -c %a {socket}) = 600")
        machine.succeed(f"test $(stat -c %a {root}) = 700")
        as_alice(
            "busctl --user introspect org.freedesktop.secrets "
            "/org/freedesktop/secrets org.freedesktop.Secret.Service "
            "| grep -w OpenSession"
        )

    with subtest("idle expiry seals the vault and removes the socket"):
        # The 5 s idle lease above is what ends this; wait for the outcome
        # rather than for a fixed duration.
        machine.wait_until_fails(f"test -e {socket}")
        machine.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )

    with subtest("a stopped service requires a fresh password request"):
        as_alice("systemctl --user start --no-block factorseal.service")
        machine.wait_until_succeeds(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )
        machine.fail(f"test -S {socket}")
        as_alice("systemctl --user stop factorseal.service")

    with subtest("a logind session-lock event seals the vault"):
        locked.start()
        locked.wait_for_unit("multi-user.target")
        locked.wait_for_unit("user@1000.service")
        initialize_on(locked)
        claim = "/home/alice/.config/secretspec/providers.d/factorseal.secretspec.json"
        locked.succeed(f"test $(stat -c %a {claim}) = 600")
        locked.succeed(
            f"jq -e 'keys == [\"executable\"] and "
            f".executable == \"${package}/bin/factorseal\"' {claim}"
        )

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

        with_password(
            locked,
            f"XDG_SESSION_ID={session} ${package}/bin/factorseal-start",
        )
        locked.wait_until_succeeds(f"test -S {socket}")

        with subtest("installed SecretSpec discovers Factorseal after init"):
            manifest = (
                '[project]\n'
                'name = "alpha"\n'
                'revision = "1.0"\n'
                '\n'
                '[profiles.default]\n'
                'TOKEN = { description = "Factorseal provider conformance token", required = true }\n'
            )
            write_user_file(
                locked,
                "/home/alice/projects/alpha/secretspec.toml",
                manifest,
            )
            write_user_file(
                locked,
                "/home/alice/projects/beta/secretspec.toml",
                manifest.replace('name = "alpha"', 'name = "beta"'),
            )

            run_with_approvals(
                locked,
                "secretspec-alpha-set",
                "alpha",
                secretspec_command(
                    "alpha",
                    "set TOKEN alpha-secret --provider factorseal://default",
                ),
            )
            run_with_approvals(
                locked,
                "secretspec-alpha-get",
                "alpha",
                secretspec_command("alpha", "get TOKEN --provider factorseal://default"),
            )
            assert locked.succeed(
                "cat /tmp/secretspec-alpha-get.stdout"
            ).strip() == "alpha-secret"

        with subtest("provider grants and values are isolated by project"):
            run_with_approvals(
                locked,
                "secretspec-beta-get",
                "beta",
                secretspec_command(
                    "beta", "get TOKEN --provider factorseal://default"
                ),
                expected_status=1,
            )
            locked.succeed(
                "grep -Eqi 'not found|missing|required' "
                "/tmp/secretspec-beta-get.stderr"
            )

        with subtest("installed provider supports deletion"):
            run_with_approvals(
                locked,
                "secretspec-alpha-delete",
                "alpha",
                secretspec_command(
                    "alpha", "delete TOKEN --provider factorseal://default"
                ),
            )
            locked.fail(
                f"{alice_prefix} sh -c "
                + shlex.quote(
                    secretspec_command(
                        "alpha", "get TOKEN --provider factorseal://default"
                    )
                )
            )

        with subtest("SecretSpec cache writes expire inside Factorseal"):
            expiry_manifest = (
                '[project]\n'
                'name = "expiry"\n'
                'revision = "1.0"\n'
                '\n'
                '[providers]\n'
                'factorseal = "factorseal://default"\n'
                'source = { uri = "env://", cache = { provider = "factorseal", max_age = "5s" } }\n'
                '\n'
                '[profiles.default]\n'
                'CACHE_TOKEN = { description = "Expiring cache token", required = true }\n'
            )
            write_user_file(
                locked,
                "/home/alice/projects/expiry/secretspec.toml",
                expiry_manifest,
            )
            run_with_approvals(
                locked,
                "secretspec-expiry-first",
                "expiry",
                secretspec_command(
                    "expiry", "get CACHE_TOKEN --provider source", "CACHE_TOKEN=one"
                ),
                approval_count=2,
            )
            assert locked.succeed(
                "cat /tmp/secretspec-expiry-first.stdout"
            ).strip() == "one"
            assert as_user(
                locked,
                secretspec_command(
                    "expiry", "get CACHE_TOKEN --provider source", "CACHE_TOKEN=two"
                ),
            ).strip() == "one"
            locked.succeed("sleep 7")
            assert as_user(
                locked,
                secretspec_command(
                    "expiry", "get CACHE_TOKEN --provider source", "CACHE_TOKEN=two"
                ),
            ).strip() == "two"

        # This node's lease is an hour, so expiry cannot be what ends it below.
        locked.succeed(f"loginctl lock-session {session}")
        locked.wait_until_fails(f"test -e {socket}")
        locked.wait_until_fails(
            f"{alice_prefix} systemctl --user is-active factorseal.service"
        )

        with subtest("a sealed vault is an explicit SecretSpec interaction"):
            command = secretspec_command(
                "alpha", "get TOKEN --provider factorseal://default"
            )
            locked.fail(f"{alice_prefix} sh -c {shlex.quote(command)}")
            output = locked.succeed(
                f"{alice_prefix} sh -c "
                + shlex.quote(f"{command} 2>&1 || true")
            )
            assert "interaction" in output.lower(), output
  '';
}
