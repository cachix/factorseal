#![cfg(all(feature = "cli", feature = "password"))]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn factorseal() -> Command {
    Command::new(env!("CARGO_BIN_EXE_factorseal"))
}

fn command(vault: &Path, password_file: &Path) -> Command {
    let mut command = factorseal();
    command.args([
        "--vault",
        vault.to_str().unwrap(),
        "--password-file",
        password_file.to_str().unwrap(),
    ]);
    command
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn keyring_cli_round_trip_and_password_change() {
    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join("vault");
    let password = directory.path().join("password");
    let new_password = directory.path().join("new-password");
    fs::write(&password, b"correct horse battery staple\n").unwrap();
    fs::write(&new_password, b"a different strong password\n").unwrap();

    let init = command(&vault, &password)
        .args(["init", "--password"])
        .output()
        .unwrap();
    assert_success(&init);

    let mut child = command(&vault, &password)
        .args(["set", "example", "DATABASE_URL"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"postgres://localhost\0binary")
        .unwrap();
    assert_success(&child.wait_with_output().unwrap());

    let value = command(&vault, &password)
        .args(["get", "example", "DATABASE_URL"])
        .output()
        .unwrap();
    assert_success(&value);
    assert_eq!(value.stdout, b"postgres://localhost\0binary");

    let status = command(&vault, &password).arg("status").output().unwrap();
    assert_success(&status);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["state"], "locked");
    assert_eq!(status["unlock_method"], "password");
    assert_eq!(status["factors"], serde_json::json!(["password"]));

    let changed = command(&vault, &password)
        .args([
            "change-password",
            "--new-password-file",
            new_password.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(&changed);

    let old_password = command(&vault, &password)
        .args(["get", "example", "DATABASE_URL"])
        .output()
        .unwrap();
    assert!(!old_password.status.success());

    let value = command(&vault, &new_password)
        .args(["get", "example", "DATABASE_URL"])
        .output()
        .unwrap();
    assert_success(&value);
    assert_eq!(value.stdout, b"postgres://localhost\0binary");

    let deleted = command(&vault, &new_password)
        .args(["delete", "example", "DATABASE_URL"])
        .output()
        .unwrap();
    assert_success(&deleted);
    let missing = command(&vault, &new_password)
        .args(["get", "example", "DATABASE_URL"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
}

#[cfg(unix)]
#[test]
fn vault_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let vault = directory.path().join("vault");
    let password = directory.path().join("password");
    fs::write(&password, b"test password").unwrap();
    assert_success(
        &command(&vault, &password)
            .args(["init", "--password"])
            .output()
            .unwrap(),
    );

    let mode = vault.metadata().unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0);
}
