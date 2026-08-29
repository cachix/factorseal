use super::cli::{Cli, Command, PermissionCommand};
use super::commands::{
    ApprovalDecision, ParsedGrantDuration, parse_grant_duration, read_approval_decision,
    read_bounded, read_grant_duration, read_keyring_value, read_password_for_groups,
    read_unlock_group_choice, require_prompt_terminal, wait_for_initialization,
};
use super::factor::read_factor;
use super::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use factorseal::{UnlockFactorKind, UnlockGroup};

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn live_endpoint_uses_the_factorseal_basename() {
    assert_eq!(DEFAULT_UNIX_SOCKET, "factorseal.sock");
}

/// One test writing a helper script while another forks makes the child
/// inherit the open write handle, and the exec of that script then fails
/// with ETXTBSY. Serializing helper use removes the overlap.
#[cfg(unix)]
static HELPER_EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
fn askpass_helper(directory: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join("askpass");
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[cfg(unix)]
fn lock_helper_exec() -> std::sync::MutexGuard<'static, ()> {
    HELPER_EXEC
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(unix)]
#[test]
fn askpass_output_is_the_factor_without_its_line_ending() {
    let _serialized = lock_helper_exec();
    let directory = tempfile::tempdir().unwrap();
    let helper = askpass_helper(directory.path(), "printf 'correct horse\\n'");

    let source = FactorSource {
        password_file: None,
        askpass: Some(&helper),
    };
    assert_eq!(
        read_factor(source, false).unwrap().as_slice(),
        b"correct horse"
    );
}

#[cfg(unix)]
#[test]
fn askpass_receives_the_prompt_and_rejects_a_mismatched_confirmation() {
    let _serialized = lock_helper_exec();
    let directory = tempfile::tempdir().unwrap();
    // Echo the prompt back, so the two confirmation prompts disagree.
    let helper = askpass_helper(directory.path(), "printf '%s' \"$1\"");

    let source = FactorSource {
        password_file: None,
        askpass: Some(&helper),
    };
    assert!(read_factor(source, true).is_err());
    assert_eq!(
        read_factor(source, false).unwrap().as_slice(),
        b"Factorseal password:"
    );
}

#[cfg(unix)]
#[test]
fn a_cancelled_askpass_helper_does_not_yield_a_factor() {
    let _serialized = lock_helper_exec();
    let directory = tempfile::tempdir().unwrap();
    let helper = askpass_helper(directory.path(), "exit 1");

    let source = FactorSource {
        password_file: None,
        askpass: Some(&helper),
    };
    assert!(matches!(
        read_factor(source, false),
        Err(CliError::Askpass(_))
    ));
}

#[cfg(unix)]
#[test]
fn an_empty_factor_is_rejected() {
    let _serialized = lock_helper_exec();
    let directory = tempfile::tempdir().unwrap();
    let helper = askpass_helper(directory.path(), "printf ''");

    let source = FactorSource {
        password_file: None,
        askpass: Some(&helper),
    };
    assert!(read_factor(source, false).is_err());
}

#[cfg(unix)]
#[test]
fn oversized_askpass_output_is_rejected_instead_of_truncated() {
    let _serialized = lock_helper_exec();
    let directory = tempfile::tempdir().unwrap();
    let helper = askpass_helper(directory.path(), "head -c 65537 /dev/zero");
    let source = FactorSource {
        password_file: None,
        askpass: Some(&helper),
    };

    assert!(matches!(
        read_factor(source, false),
        Err(CliError::Askpass(message)) if message.contains("64 KiB")
    ));
}

#[test]
fn an_explicit_file_takes_precedence_over_the_helper() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("factor");
    fs::write(&file, "from the file\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let source = FactorSource {
        password_file: Some(&file),
        askpass: Some(Path::new("/nonexistent/askpass")),
    };
    assert_eq!(
        read_factor(source, false).unwrap().as_slice(),
        b"from the file"
    );
}

#[test]
fn askpass_is_configurable_through_the_environment() {
    let cli = Cli::try_parse_from(["factorseal", "--askpass", "/usr/bin/true", "agent"]).unwrap();
    assert_eq!(cli.askpass.unwrap(), PathBuf::from("/usr/bin/true"));
}

#[test]
fn agent_policy_and_root_are_explicitly_configurable() {
    let cli = Cli::try_parse_from([
        "factorseal",
        "--root",
        "/tmp/factorseal-test",
        "agent",
        "--idle-seconds",
        "10",
        "--maximum-seconds",
        "20",
    ])
    .unwrap();
    assert_eq!(cli.root.unwrap(), PathBuf::from("/tmp/factorseal-test"));
    let Command::Agent {
        idle_seconds,
        maximum_seconds,
        ..
    } = cli.command
    else {
        panic!("expected agent command");
    };
    assert_eq!(idle_seconds, 10);
    assert_eq!(maximum_seconds, 20);
}

#[test]
fn agent_waits_for_initialization_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("missing-vault");
    let metadata = root.join("factorseal.json");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        fs::create_dir(&root).unwrap();
        fs::write(metadata, b"{}").unwrap();
    });

    wait_for_initialization(
        &directory.path().join("missing-vault"),
        Duration::from_millis(1),
    );
    writer.join().unwrap();
}

#[test]
fn unlock_cli_uses_and_inside_groups_and_or_between_repetitions() {
    let default = Cli::try_parse_from(["factorseal", "init"]).unwrap();
    assert!(matches!(
        default.command,
        Command::Init { unlock } if unlock.len() == 1 && unlock[0].to_string() == "password"
    ));

    let cli = Cli::try_parse_from([
        "factorseal",
        "init",
        "--unlock",
        "password,biometric",
        "--unlock",
        "biometric",
    ])
    .unwrap();
    let Command::Init { unlock } = cli.command else {
        panic!("expected init command");
    };
    assert_eq!(unlock.len(), 2);
    assert!(unlock[0].requires(UnlockFactorKind::Password));
    assert!(unlock[0].requires(UnlockFactorKind::Biometric));
    assert_eq!(unlock[1].to_string(), "biometric");

    let cli = Cli::try_parse_from(["factorseal", "agent", "--unlock", "biometric"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Agent { unlock: Some(group), .. } if group.to_string() == "biometric"
    ));
}

#[test]
fn biometric_only_groups_do_not_read_a_password_source() {
    let group = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
    let factor = FactorSource {
        password_file: Some(Path::new("/does/not/exist")),
        askpass: None,
    };
    assert!(
        read_password_for_groups(&[group], factor, false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn keyring_commands_accept_item_field_and_service_override() {
    let cli = Cli::try_parse_from([
        "factorseal",
        "--socket",
        "/tmp/factorseal.sock",
        "set",
        "github",
        "--field",
        "token",
        "--value-file",
        "/tmp/value",
    ])
    .unwrap();
    assert_eq!(cli.socket.unwrap(), PathBuf::from("/tmp/factorseal.sock"));
    let Command::Set {
        item,
        field,
        value_file,
    } = cli.command
    else {
        panic!("expected set command");
    };
    assert_eq!(item, "github");
    assert_eq!(field.as_deref(), Some("token"));
    assert_eq!(value_file.unwrap(), PathBuf::from("/tmp/value"));

    let cli = Cli::try_parse_from(["factorseal", "get", "github", "--field", "token"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Get { item, field }
            if item == "github" && field.as_deref() == Some("token")
    ));
}

#[test]
fn seal_is_a_first_class_cli_command_and_permission() {
    let cli = Cli::try_parse_from(["factorseal", "seal"]).unwrap();
    assert!(matches!(cli.command, Command::Seal));
    assert!(KEYRING_PERMISSIONS.contains(&GrantPermission::Seal));
}

#[test]
fn keyring_value_files_preserve_exact_binary_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("value");
    fs::write(&path, b"secret\0with\nbytes").unwrap();

    assert_eq!(
        read_keyring_value(Some(&path)).unwrap().as_slice(),
        b"secret\0with\nbytes"
    );
}

#[test]
fn bounded_reads_retain_one_byte_to_detect_overflow() {
    let bytes = vec![7; 5];
    let read = read_bounded(bytes.as_slice(), 4).unwrap();

    assert_eq!(read.as_slice(), &[7; 5]);
}

#[test]
fn permissions_use_explicit_subcommands() {
    let cli = Cli::try_parse_from(["factorseal", "permissions", "watch", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Permissions {
            action: PermissionCommand::Watch {
                prompt: false,
                json: true
            }
        }
    ));

    let cli = Cli::try_parse_from(["factorseal", "permissions", "approve", "prm_demo"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Permissions {
            action: PermissionCommand::Approve { id },
        } if id == "prm_demo"
    ));

    let cli = Cli::try_parse_from(["factorseal", "permissions", "deny", "prm_demo"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Permissions {
            action: PermissionCommand::Deny { id },
        } if id == "prm_demo"
    ));

    let cli = Cli::try_parse_from(["factorseal", "permissions", "revoke", "prm_demo"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Permissions {
            action: PermissionCommand::Revoke { id },
        } if id == "prm_demo"
    ));
    assert!(Cli::try_parse_from(["factorseal", "permissions", "--prompt"]).is_err());
    assert!(
        Cli::try_parse_from([
            "factorseal",
            "permissions",
            "approve",
            "prm_demo",
            "--unlock",
            "biometric",
        ])
        .is_err()
    );
}

#[test]
fn approval_prompt_requires_a_terminal_and_explicit_decision() {
    assert!(require_prompt_terminal(true, true).is_ok());
    assert!(require_prompt_terminal(false, true).is_err());
    assert!(require_prompt_terminal(true, false).is_err());

    for (answer, expected) in [
        ("approve\n", ApprovalDecision::Approve),
        ("d\n", ApprovalDecision::Deny),
        ("ignore\n", ApprovalDecision::Ignore),
    ] {
        let mut input = std::io::Cursor::new(answer.as_bytes());
        let mut output = Vec::new();
        assert_eq!(
            read_approval_decision(&mut input, &mut output).unwrap(),
            expected
        );
    }

    let mut closed = std::io::Cursor::new(Vec::<u8>::new());
    assert!(read_approval_decision(&mut closed, &mut Vec::new()).is_err());

    let groups = [
        UnlockGroup::new([UnlockFactorKind::Password]).unwrap(),
        UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap(),
    ];
    let mut choice = std::io::Cursor::new(b"invalid\n2\n");
    let selected = read_unlock_group_choice(&groups, &mut choice, &mut Vec::new()).unwrap();
    assert_eq!(selected, groups[1]);
}

#[test]
fn approval_grant_duration_uses_app_default_and_accepts_overrides() {
    assert_eq!(
        parse_grant_duration("30m"),
        Some(ParsedGrantDuration::Seconds(30 * 60))
    );
    assert_eq!(
        parse_grant_duration("1d"),
        Some(ParsedGrantDuration::Seconds(24 * 60 * 60))
    );
    assert_eq!(
        parse_grant_duration("forever"),
        Some(ParsedGrantDuration::Forever)
    );
    assert_eq!(parse_grant_duration("0h"), None);
    assert_eq!(parse_grant_duration("later"), None);

    let mut accept_default = std::io::Cursor::new(b"\n");
    assert_eq!(
        read_grant_duration(&mut accept_default, &mut Vec::new(), Some(8 * 60 * 60)).unwrap(),
        Some(8 * 60 * 60)
    );

    let mut retry_then_forever = std::io::Cursor::new(b"later\nforever\n");
    let mut output = Vec::new();
    assert_eq!(
        read_grant_duration(&mut retry_then_forever, &mut output, None).unwrap(),
        None
    );
    assert!(String::from_utf8(output).unwrap().contains("30m"));

    let mut closed = std::io::Cursor::new(Vec::<u8>::new());
    assert!(read_grant_duration(&mut closed, &mut Vec::new(), None).is_err());
}
