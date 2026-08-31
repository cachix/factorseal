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

fn repository_file(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is missing or unreadable: {error}", path.display()))
}

fn png_dimensions(relative: &str) -> (u32, u32) {
    let path = packaging_path(relative);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{} is missing or unreadable: {error}", path.display()));
    assert_eq!(
        &bytes[..8],
        b"\x89PNG\r\n\x1a\n",
        "{} is not a PNG",
        path.display()
    );
    (
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
    )
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

    // Keep the script in Resources so the outer app signature seals it as a
    // resource instead of treating it as unsigned nested code in MacOS.
    let helper = plist_askpass_argument(&plist);
    let factorseal = "/Applications/Factorseal.app/Contents/MacOS/factorseal";
    assert!(
        plist.contains(factorseal),
        "the LaunchAgent no longer starts the expected binary"
    );
    assert!(
        helper.starts_with("/Applications/Factorseal.app/Contents/Resources/"),
        "the askpass helper is not installed as a signed app resource: {helper}"
    );

    // ...and the packager must actually put it there.
    let name = Path::new(&helper).file_name().unwrap().to_str().unwrap();
    assert!(
        builder.contains(&format!("cp packaging/macos/{name} \"$app/Resources/\"")),
        "build-unix.sh does not install {name} into the app bundle"
    );
    assert!(
        builder.contains(&format!("\"$app/Resources/{name}\"")),
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
fn the_windows_package_ships_a_reproducible_login_task_installer() {
    let installer = packaging("windows/install-factorseal-task.ps1");
    let builder = packaging("build-windows.ps1");

    assert!(builder.contains("packaging/windows/install-factorseal-task.ps1"));
    assert!(packaging_path("windows/install-factorseal-task.ps1").is_file());
    assert!(installer.contains(".Replace('@INSTALL_DIR@'"));
    assert!(installer.contains(".Replace('@USER_SID@'"));
    assert!(installer.contains(".Replace('@ROOT_ARGUMENTS@'"));
    assert!(installer.contains("Register-ScheduledTask"));
    assert!(installer.contains("Get-AuthenticodeSignature"));
    assert!(installer.contains("AllowUnsignedDevelopmentArtifact"));
}

#[test]
fn the_windows_builder_can_sign_and_verify_a_release_binary() {
    let builder = packaging("build-windows.ps1");

    assert!(builder.contains("SigningCertificateThumbprint"));
    assert!(builder.contains("TimestampUrl"));
    assert!(builder.contains("signtool.exe"));
    assert!(builder.contains("Get-AuthenticodeSignature"));
    assert!(builder.contains("SignatureStatus]::Valid"));
    assert!(builder.contains("unsigned development archive"));
    assert!(builder.contains("if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }"));
}

#[test]
fn the_store_msix_has_partner_center_identity_and_a_cli_alias() {
    let manifest = packaging("windows/msix/AppxManifest.xml.in");
    let builder = packaging("build-windows-msix.ps1");

    for placeholder in [
        "@IDENTITY_NAME@",
        "@PUBLISHER@",
        "@PUBLISHER_DISPLAY_NAME@",
        "@VERSION@",
        "@ARCHITECTURE@",
    ] {
        assert!(manifest.contains(placeholder));
        assert!(builder.contains(placeholder));
    }
    assert!(manifest.contains("EntryPoint=\"Windows.FullTrustApplication\""));
    assert!(manifest.contains("AppListEntry=\"none\""));
    assert!(manifest.contains("Category=\"windows.appExecutionAlias\""));
    assert!(manifest.contains("Alias=\"factorseal.exe\""));
    assert!(manifest.contains("<rescap:Capability Name=\"runFullTrust\""));
    assert!(builder.contains("makeappx.exe"));
    assert!(builder.contains("The fourth PackageVersion component must be zero"));
    assert!(builder.contains("does not match the native build host"));
    assert!(builder.contains("Microsoft Store ingestion"));
    assert!(builder.contains("Get-AuthenticodeSignature"));

    // The archive-only login task depends on an interim shell prompt. Do not
    // silently carry that integration into the Store package.
    assert!(!builder.contains("factorseal-task.xml.in"));
    assert!(!builder.contains("factorseal-askpass"));

    for (name, dimensions) in [
        ("Square150x150Logo.png", (150, 150)),
        ("Square44x44Logo.png", (44, 44)),
        ("StoreLogo.png", (50, 50)),
    ] {
        assert_eq!(
            png_dimensions(&format!("windows/msix/Assets/{name}")),
            dimensions
        );
    }
}

#[test]
fn tagged_releases_build_and_attest_the_store_msix_in_windows_ci() {
    let workflow = repository_file(".github/workflows/release-windows-store.yml");

    assert!(workflow.contains("tags:"));
    assert!(workflow.contains("'v*'"));
    assert!(workflow.contains("workflow_dispatch:"));
    assert!(workflow.contains("default: development"));
    assert!(workflow.contains("- partner-center"));
    for variable in [
        "FACTORSEAL_STORE_IDENTITY_NAME",
        "FACTORSEAL_STORE_PUBLISHER",
        "FACTORSEAL_STORE_PUBLISHER_DISPLAY_NAME",
    ] {
        assert!(workflow.contains(variable));
    }
    assert!(workflow.contains("must match Cargo.toml version"));
    assert!(workflow.contains("./packaging/build-windows-msix.ps1"));
    assert!(workflow.contains("actions/attest-build-provenance@v3"));
    assert!(workflow.contains("actions/upload-artifact@v4"));
    assert!(workflow.contains("gh release create"));
    assert!(workflow.contains("--draft"));
    assert!(workflow.contains("gh release upload"));
    assert!(workflow.contains("if: github.event_name == 'push'"));
}

#[test]
fn both_desktop_launchers_start_the_agent_at_login() {
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

#[test]
fn every_background_launcher_uses_the_agent_command() {
    let linux = packaging("linux/factorseal.service.in");
    let macos = packaging("macos/dev.factorseal.plist");
    let windows = packaging("windows/factorseal-task.xml.in");

    assert!(linux.contains("systemd-ask-password agent"));
    assert!(macos.contains("<string>agent</string>"));
    assert!(windows.contains("factorseal-askpass.cmd\" agent"));
}

#[test]
fn every_release_archive_ships_a_one_command_acceptance_runner() {
    let unix = packaging("build-unix.sh");
    assert!(unix.contains("acceptance/$platform.sh"));
    assert!(unix.contains("$stage/$archive/run-acceptance.sh"));
    assert!(unix.contains("$output_dir/$archive-acceptance.sh"));

    let windows = packaging("build-windows.ps1");
    assert!(windows.contains("acceptance/windows.ps1"));
    assert!(windows.contains("run-acceptance.ps1"));
    assert!(windows.contains("install-factorseal-task.ps1"));
}

#[test]
fn macos_builds_support_local_and_team_signing() {
    let builder = packaging("build-unix.sh");
    let preparer = packaging("macos/prepare-app.sh");
    let signer = packaging("macos/sign-app.sh");
    let entitlements = packaging("macos/Factorseal.entitlements.in");

    assert!(builder.contains("FACTORSEAL_MACOS_SIGNING_IDENTITY"));
    assert!(builder.contains("FACTORSEAL_MACOS_PROVISIONING_PROFILE"));
    assert!(builder.contains("FACTORSEAL_MACOS_PROVISIONING_PROFILE is required"));
    assert!(builder.contains("FACTORSEAL_MACOS_SIGNING_IDENTITY is required"));
    assert!(builder.contains("signing_identity=-"));
    assert!(signer.contains("Contents/embedded.provisionprofile"));
    assert!(signer.contains("rm -f \"$app/Contents/embedded.provisionprofile\""));
    assert!(signer.contains("--entitlements \"$entitlements\""));
    assert!(signer.contains("codesign --verify --deep --strict"));
    assert!(signer.contains("find \"$app/Contents\" -type f"));
    assert!(signer.contains("find \"$app/Contents\" -depth -type d"));
    assert!(signer.contains("DeveloperCertificates.$certificate_index"));
    assert!(signer.contains("This app cannot use Factorseal's protected macOS Keychain storage"));
    assert!(entitlements.contains("com.apple.application-identifier"));
    assert!(entitlements.contains("com.apple.developer.team-identifier"));
    assert!(entitlements.contains("keychain-access-groups"));
    assert_eq!(entitlements.matches("@APPLICATION_ID@").count(), 2);

    assert!(builder.contains("macos_deployment_target=11.0"));
    assert!(builder.contains("MACOSX_DEPLOYMENT_TARGET=$macos_deployment_target"));
    assert!(preparer.contains("install_name_tool -change"));
    assert!(preparer.contains("/usr/lib/libiconv.2.dylib"));
    assert!(preparer.contains("otool -l"));
    assert!(preparer.contains("/nix/store/"));
    assert!(preparer.contains("expected macOS deployment target $deployment_target in $candidate"));

    let assemble = builder
        .find("cp packaging/macos/factorseal-askpass")
        .unwrap();
    let prepare = builder.find("sh packaging/macos/prepare-app.sh").unwrap();
    let sign = builder.find("sh packaging/macos/sign-app.sh").unwrap();
    let archive = builder.find("tar -C \"$stage\"").unwrap();
    assert!(assemble < prepare && prepare < sign && sign < archive);
}
