use super::cli::{Cli, Command, PermissionCommand};
#[cfg(feature = "secretspec-provider")]
use super::commands::write_secretspec_claim;
use super::commands::{
    ApprovalDecision, ParsedGrantDuration, parse_grant_duration, read_approval_decision,
    read_bounded, read_grant_duration, read_init_unlock_groups, read_password_for_groups,
    read_project_value, read_unlock_group_choice, require_prompt_terminal, resolve_unlock_group,
    wait_for_initialization, write_metadata,
};
use super::factor::read_factor;
use super::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use factorseal::{
    MAX_LIST_PAGE_SIZE, SecretSpecAddress, SecretSpecCoordinates, UnlockFactorKind, UnlockGroup,
    VaultAction, VaultClient, VaultRequest, VaultResponse, VaultResponseBody, VaultResult,
};

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

#[cfg(feature = "secretspec-provider")]
#[test]
fn secretspec_claim_contains_only_the_canonical_executable() {
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap().canonicalize().unwrap();

    write_secretspec_claim(directory.path(), &executable).unwrap();

    let claim = fs::read_to_string(directory.path().join("factorseal.secretspec.json")).unwrap();
    let claim: serde_json::Value = serde_json::from_str(&claim).unwrap();
    assert_eq!(claim, serde_json::json!({ "executable": executable }));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(directory.path().join("factorseal.secretspec.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn unlock_cli_uses_and_inside_groups_and_or_between_repetitions() {
    let default = Cli::try_parse_from(["factorseal", "init"]).unwrap();
    assert!(matches!(
        default.command,
        Command::Init { unlock, fips: false } if unlock.is_empty()
    ));

    let fips = Cli::try_parse_from(["factorseal", "init", "--fips"]).unwrap();
    assert!(matches!(fips.command, Command::Init { fips: true, .. }));

    let cli = Cli::try_parse_from([
        "factorseal",
        "init",
        "--unlock",
        "password,biometric",
        "--unlock",
        "biometric",
    ])
    .unwrap();
    let Command::Init {
        unlock,
        fips: false,
    } = cli.command
    else {
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
fn init_prompt_explains_and_maps_unlock_choices() {
    let cases = [
        ("\n", vec!["password"]),
        ("2\n", vec!["biometric"]),
        ("3\n", vec!["password,biometric"]),
        ("4\n", vec!["password", "biometric"]),
    ];

    for (answer, expected) in cases {
        let mut input = std::io::Cursor::new(answer);
        let mut output = Vec::new();
        let groups = read_init_unlock_groups(&mut input, &mut output).unwrap();
        assert_eq!(
            groups.iter().map(ToString::to_string).collect::<Vec<_>>(),
            expected
        );
        let prompt = String::from_utf8(output).unwrap();
        assert!(prompt.contains("protected by this device's hardware"));
        assert!(prompt.contains("Password or biometric approval"));
        assert!(prompt.contains("password preferred by default"));
    }
}

#[test]
fn init_prompt_retries_an_invalid_choice() {
    let mut input = std::io::Cursor::new("nope\n3\n");
    let mut output = Vec::new();
    let groups = read_init_unlock_groups(&mut input, &mut output).unwrap();
    assert_eq!(groups[0].to_string(), "password,biometric");
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("Enter a number from 1 to 4.")
    );
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
fn agent_uses_the_preferred_group_unless_unlock_is_explicit() {
    let password = UnlockGroup::new([UnlockFactorKind::Password]).unwrap();
    let biometric = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
    let groups = [password.clone(), biometric.clone()];

    assert_eq!(
        resolve_unlock_group(&groups, &password, None).unwrap(),
        password
    );
    assert_eq!(
        resolve_unlock_group(&groups, &password, Some(&biometric)).unwrap(),
        biometric
    );
    let both = UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Biometric]).unwrap();
    assert!(resolve_unlock_group(&groups, &password, Some(&both)).is_err());
}

#[test]
fn project_commands_accept_project_item_field_and_service_override() {
    let cli = Cli::try_parse_from([
        "factorseal",
        "--socket",
        "/tmp/factorseal.sock",
        "set",
        "--project",
        "demo",
        "github",
        "--field",
        "token",
        "--value-file",
        "/tmp/value",
    ])
    .unwrap();
    assert_eq!(cli.socket.unwrap(), PathBuf::from("/tmp/factorseal.sock"));
    let Command::Set {
        project,
        profile,
        item,
        field,
        value_file,
    } = cli.command
    else {
        panic!("expected set command");
    };
    assert_eq!(item, "github");
    assert_eq!(project, "demo");
    assert_eq!(profile, "default");
    assert_eq!(field.as_deref(), Some("token"));
    assert_eq!(value_file.unwrap(), PathBuf::from("/tmp/value"));

    let cli = Cli::try_parse_from([
        "factorseal",
        "get",
        "--project",
        "demo",
        "github",
        "--field",
        "token",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Command::Get { project, profile, item, field }
            if project == "demo" && profile == "default" && item == "github" && field.as_deref() == Some("token")
    ));
}

#[test]
fn metadata_list_commands_are_explicit_and_project_aware() {
    let projects = Cli::try_parse_from(["factorseal", "projects", "--json"]).unwrap();
    assert!(matches!(projects.command, Command::Projects { json: true }));

    let list = Cli::try_parse_from(["factorseal", "list", "--project", "demo", "--json"]).unwrap();
    assert!(matches!(
        list.command,
        Command::List { project, json: true } if project == "demo"
    ));
}

struct ListingClient;

impl VaultClient for ListingClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        let body = match &request.action {
            VaultAction::ListProjects { cursor, limit } => {
                assert_eq!(*limit, MAX_LIST_PAGE_SIZE);
                if cursor.is_none() {
                    VaultResponseBody::Projects {
                        projects: vec!["alpha".to_owned()],
                        next_cursor: Some("alpha".to_owned()),
                    }
                } else {
                    assert_eq!(cursor.as_deref(), Some("alpha"));
                    VaultResponseBody::Projects {
                        projects: vec!["zeta".to_owned()],
                        next_cursor: None,
                    }
                }
            }
            VaultAction::ListProjectAddresses {
                project,
                cursor,
                limit,
            } => {
                assert_eq!(project, "alpha");
                assert_eq!(*limit, MAX_LIST_PAGE_SIZE);
                if cursor.is_none() {
                    VaultResponseBody::ProjectAddresses {
                        addresses: vec![
                            SecretSpecAddress::convention("alpha", "default", "TOKEN").unwrap(),
                        ],
                        next_cursor: Some("A".repeat(43)),
                    }
                } else {
                    assert_eq!(cursor.as_deref(), Some("A".repeat(43).as_str()));
                    VaultResponseBody::ProjectAddresses {
                        addresses: vec![
                            SecretSpecAddress::native(SecretSpecCoordinates {
                                item: "database".to_owned(),
                                field: Some("password".to_owned()),
                                vault: Some("production".to_owned()),
                                section: None,
                                version: None,
                            })
                            .unwrap(),
                        ],
                        next_cursor: None,
                    }
                }
            }
            _ => panic!("listing client received an unexpected request"),
        };
        Ok(VaultResponse::success(request.request_id(), body))
    }
}

#[test]
fn metadata_commands_consume_every_page_and_emit_unambiguous_json() {
    let client = ListingClient;
    let projects = super::commands::fetch_projects(&client).unwrap();
    assert_eq!(projects, ["alpha", "zeta"]);
    let addresses = super::commands::fetch_project_addresses(&client, "alpha").unwrap();
    assert_eq!(addresses.len(), 2);

    let mut human = Vec::new();
    write_metadata(&mut human, &projects, false).unwrap();
    assert_eq!(human, b"\"alpha\"\n\"zeta\"\n");

    let mut json = Vec::new();
    write_metadata(&mut json, &addresses, true).unwrap();
    let decoded: Vec<SecretSpecAddress> = serde_json::from_slice(&json).unwrap();
    assert_eq!(decoded, addresses);
}

#[test]
fn seal_is_a_first_class_cli_command_and_permission() {
    let cli = Cli::try_parse_from(["factorseal", "seal"]).unwrap();
    assert!(matches!(cli.command, Command::Seal));
    assert!(PROJECT_PERMISSIONS.contains(&GrantPermission::List));
    assert!(!PROJECT_PERMISSIONS.contains(&GrantPermission::Seal));
}

#[test]
fn hardware_self_test_is_a_first_class_cli_command() {
    let cli = Cli::try_parse_from(["factorseal", "hardware-self-test", "--biometric"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::HardwareSelfTest { biometric: true }
    ));
}

#[test]
fn project_value_files_preserve_exact_binary_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("value");
    fs::write(&path, b"secret\0with\nbytes").unwrap();

    assert_eq!(
        read_project_value(Some(&path)).unwrap().as_slice(),
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
