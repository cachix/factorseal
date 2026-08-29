//! Consistency checks between the launcher configuration and the packagers.
//!
//! These cannot prove a prompt appears; that needs a native host with someone
//! to answer it. They cover the failure that does not need a GUI to happen:
//! a launcher pointing at an askpass helper the packager never installs, or
//! installs somewhere else. That breaks vault start at login and is invisible
//! until a real machine runs it.

use std::path::{Path, PathBuf};

fn packaging(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("packaging")
        .join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{} is missing or unreadable: {error}", path.display());
    })
}

fn packaging_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("packaging")
        .join(relative)
}

/// Read the `<string>` element that follows the `--askpass` element.
fn plist_askpass_argument(plist: &str) -> String {
    const MARKER: &str = "<string>--askpass</string>";
    let rest = plist
        .split_once(MARKER)
        .unwrap_or_else(|| panic!("no `{MARKER}` in the LaunchAgent"))
        .1;
    let value = rest
        .split_once("<string>")
        .expect("--askpass has no following argument element")
        .1;
    value
        .split_once("</string>")
        .expect("unterminated argument element")
        .0
        .to_owned()
}

/// Read the quoted argument that follows `--askpass` in the task template.
fn task_askpass_argument(task: &str) -> String {
    let rest = task
        .split_once("--askpass \"")
        .expect("no `--askpass` in the scheduled task")
        .1;
    rest.split_once('"')
        .expect("unterminated askpass argument")
        .0
        .to_owned()
}

/// Read the value assigned to `key=` on the unit's first matching line.
fn unit_setting(unit: &str, key: &str) -> String {
    unit.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no `{key}=` in the systemd unit"))
        .to_owned()
}

#[test]
fn the_linux_unit_and_packager_agree_on_the_install_directory() {
    let unit = packaging("linux/factorseal.service.in");
    let builder = packaging("build-unix.sh");

    // systemd needs an absolute ExecStart, so the unit cannot find the binary
    // beside itself the way the macOS and Windows launchers do. The packager
    // is what resolves it, and a hardcoded path there means a tarball
    // unpacked anywhere else fails with status=203/EXEC on every start.
    let exec_start = unit_setting(&unit, "ExecStart");
    assert!(
        exec_start.starts_with("@INSTALL_DIR@/factorseal "),
        "the unit does not resolve Factorseal from the install directory: {exec_start}"
    );
    assert!(
        builder.contains("s|@INSTALL_DIR@|$linux_install_dir|g"),
        "build-unix.sh does not substitute the install directory into the unit"
    );

    // ...and the packager must install the binary in the directory it
    // substituted, plus the starter that prompts for the factor.
    let install_dir = builder
        .lines()
        .find_map(|line| line.trim().strip_prefix("linux_install_dir="))
        .expect("build-unix.sh does not define linux_install_dir")
        .to_owned();
    assert!(
        install_dir.ends_with("/bin"),
        "the unit's install directory is not a bin directory: {install_dir}"
    );
    for name in ["factorseal", "factorseal-start"] {
        assert!(
            builder.contains(&format!("\"$stage/$archive/bin/{name}\"")),
            "build-unix.sh does not install {name} into bin/"
        );
    }
    assert!(
        packaging_path("linux/factorseal-start").is_file(),
        "the Linux session-unlock helper source is missing"
    );
}

#[test]
fn the_linux_unit_uses_askpass_without_a_password_file() {
    let unit = packaging("linux/factorseal.service.in");
    let starter = packaging("linux/factorseal-start");

    let exec_start = unit_setting(&unit, "ExecStart");
    assert!(
        exec_start.contains("--askpass=systemd-ask-password"),
        "the unit does not obtain its factor from systemd askpass: {exec_start}"
    );
    assert!(
        !exec_start.contains("--password-file") && !starter.contains("password_file"),
        "the Linux service still stages its factor in a file"
    );
    assert!(
        unit.contains("WantedBy=default.target"),
        "the Linux service is not enabled for user-session startup"
    );
    assert!(
        unit.contains("Wants=dbus.socket") && unit.contains("After=dbus.socket"),
        "the Linux service does not start the user D-Bus before publishing Secret Service"
    );
    assert!(
        starter.contains("systemctl --user start --no-block factorseal.service")
            && starter.contains("systemd-tty-ask-password-agent --query"),
        "the starter does not answer the service's password request"
    );
}

#[test]
fn the_linux_starter_hands_an_overridden_socket_to_the_unit() {
    let starter = packaging("linux/factorseal-start");

    // The unit inherits nothing from the invoking shell, so a socket override
    // the starter waits on has to reach the user manager too. Otherwise the
    // vault serves its default path while the starter reports failure.
    assert!(
        starter.contains("systemctl --user set-environment \"FACTORSEAL_SOCKET="),
        "the starter does not pass its socket override to the unit"
    );
    assert!(
        starter.contains("systemctl --user unset-environment FACTORSEAL_SOCKET"),
        "the starter leaves its socket override in the user manager"
    );
    let set = starter.find("set-environment").unwrap();
    let start = starter
        .find("systemctl --user start")
        .expect("the starter never starts the unit");
    assert!(
        set < start,
        "the socket override is exported after the start"
    );
}

#[test]
fn the_linux_starter_hands_its_logind_session_to_the_unit() {
    let starter = packaging("linux/factorseal-start");

    assert!(
        starter.contains("session_id=${XDG_SESSION_ID:?XDG_SESSION_ID is required}"),
        "the starter does not identify its logind session"
    );
    assert!(
        starter.contains("set-environment \"FACTORSEAL_SESSION_ID=$session_id\""),
        "the starter does not pass its logind session to the user service"
    );
    assert!(
        starter.contains("unset-environment FACTORSEAL_SESSION_ID"),
        "the starter leaves its logind session in the user manager"
    );
    let set = starter
        .find("set-environment \"FACTORSEAL_SESSION_ID")
        .unwrap();
    let start = starter
        .find("systemctl --user start")
        .expect("the starter never starts the unit");
    assert!(set < start, "the session ID is exported after the start");
}

#[test]
fn the_macos_launcher_and_packager_agree_on_the_askpass_helper() {
    let plist = packaging("macos/dev.factorseal.plist");
    let builder = packaging("build-unix.sh");

    // The helper must sit in the same installed directory as the binary the
    // LaunchAgent starts, so one relocation cannot move only one of them.
    let helper = plist_askpass_argument(&plist);
    let factorseal = "/Applications/Factorseal.app/Contents/MacOS/factorseal";
    assert!(
        plist.contains(factorseal),
        "the LaunchAgent no longer starts the expected binary"
    );
    assert_eq!(
        Path::new(&helper).parent(),
        Path::new(factorseal).parent(),
        "the askpass helper is not installed beside the Factorseal binary"
    );

    // ...and the packager must actually put it there.
    let name = Path::new(&helper).file_name().unwrap().to_str().unwrap();
    assert!(
        builder.contains(&format!("cp packaging/macos/{name} \"$app/MacOS/\"")),
        "build-unix.sh does not install {name} into the app bundle"
    );
    assert!(
        builder.contains(&format!("\"$app/MacOS/{name}\"")),
        "build-unix.sh does not make {name} executable"
    );
    assert!(
        packaging_path(&format!("macos/{name}")).is_file(),
        "the macOS askpass helper source is missing"
    );
}

#[test]
fn the_windows_launcher_and_packager_agree_on_the_askpass_helper() {
    let task = packaging("windows/factorseal-task.xml.in");
    let builder = packaging("build-windows.ps1");

    let helper = task_askpass_argument(&task);
    assert!(
        helper.starts_with("@INSTALL_DIR@"),
        "the askpass helper is not resolved from the install directory: {helper}"
    );
    assert!(
        task.contains("<Command>@INSTALL_DIR@\\factorseal.exe</Command>"),
        "the logon task no longer starts the expected executable"
    );

    let name = helper.rsplit('\\').next().unwrap();
    assert!(
        builder.contains(&format!("packaging/windows/{name}")),
        "build-windows.ps1 does not ship {name}"
    );
    assert!(
        packaging_path(&format!("windows/{name}")).is_file(),
        "the Windows askpass helper source is missing"
    );
}

#[test]
fn the_windows_wrapper_invokes_its_own_powershell_companion() {
    let wrapper = packaging("windows/factorseal-askpass.cmd");
    let helper = packaging("windows/factorseal-askpass.ps1");
    let builder = packaging("build-windows.ps1");

    // %~dp0 keeps the wrapper and the script together wherever the ZIP is
    // unpacked, rather than depending on the working directory.
    assert!(
        wrapper.contains("%~dp0factorseal-askpass.ps1"),
        "the wrapper does not resolve its companion relative to itself"
    );
    assert!(
        wrapper.contains("%*"),
        "the wrapper does not forward the prompt text to the script"
    );
    assert!(
        builder.contains("packaging/windows/factorseal-askpass.ps1"),
        "build-windows.ps1 does not ship the PowerShell companion"
    );
    assert!(
        packaging_path("windows/factorseal-askpass.ps1").is_file(),
        "the PowerShell companion source is missing"
    );
    assert!(
        helper.contains("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)"),
        "the PowerShell helper does not emit password bytes as BOM-free UTF-8"
    );
}

#[test]
fn both_gui_launchers_start_the_vault_at_login() {
    // Login start is only safe because a helper can prompt without a console.
    // If either trigger is removed, the askpass wiring has become pointless
    // and this test should be revisited rather than deleted.
    let plist = packaging("macos/dev.factorseal.plist");
    let task = packaging("windows/factorseal-task.xml.in");

    assert!(
        plist.contains("<key>RunAtLoad</key><true/>"),
        "the LaunchAgent no longer starts at login"
    );
    assert!(
        task.contains("<LogonTrigger>"),
        "the scheduled task no longer starts at logon"
    );
}
