//! Per-user native host registration, shared by Desktop and the development CLI.
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
};
pub const FIREFOX_ID: &str = "factorseal@factorseal.dev";
/// Development ID derived from the public key in manifest.chromium.json.
pub const CHROMIUM_ID: &str = "eljopjcihlpjipbefddajpoiefpfgdca";
#[derive(Serialize, Deserialize)]
pub struct Config {
    pub root: PathBuf,
    #[serde(default)]
    pub desktop: Option<PathBuf>,
    #[serde(default)]
    pub desktop_identity: Option<PathBuf>,
}
fn write_changed(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if std::fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(());
    }
    crate::security::write_private_file(path, bytes)
}
/// Refresh the native host registration and Desktop launch paths at startup.
pub fn configure(
    root: &Path,
    bridge: &Path,
    desktop: &Path,
    desktop_identity: &Path,
) -> io::Result<()> {
    let dirs = directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .ok_or_else(|| io::Error::other("no user data directory"))?;
    std::fs::create_dir_all(dirs.config_dir())?;
    write_changed(
        &dirs.config_dir().join("browser-host.json"),
        &serde_json::to_vec(&Config {
            root: std::path::absolute(root)?,
            desktop: Some(desktop.to_path_buf()),
            desktop_identity: Some(desktop_identity.to_path_buf()),
        })?,
    )?;
    let mut failure = None;
    for browser in ["firefox", "chrome", "chromium", "edge"] {
        if let Err(error) = install(browser, None, None, &dirs, bridge) {
            failure = Some(error);
        }
    }
    failure.map_or(Ok(()), Err)
}
pub fn install(
    browser: &str,
    id: Option<&str>,
    root: Option<&Path>,
    dirs: &directories::ProjectDirs,
    bridge: &Path,
) -> io::Result<()> {
    let firefox = browser == "firefox";
    if !["firefox", "chrome", "chromium", "edge"].contains(&browser) {
        return Err(io::Error::other(
            "choose firefox, chrome, chromium, or edge",
        ));
    }
    let id = id.unwrap_or(if firefox { FIREFOX_ID } else { CHROMIUM_ID });
    if id.len() > 128
        || id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c))
    {
        return Err(io::Error::other("invalid extension ID"));
    }
    if !firefox && (id.len() != 32 || !id.bytes().all(|c| (b'a'..=b'p').contains(&c))) {
        return Err(io::Error::other(
            "pass Chromium's 32-character extension ID with --extension-id",
        ));
    }
    let base = directories::BaseDirs::new().ok_or_else(|| io::Error::other("no home directory"))?;
    #[cfg(target_os = "linux")]
    let folder = if firefox {
        base.home_dir().join(".mozilla/native-messaging-hosts")
    } else {
        base.config_dir()
            .join(match browser {
                "chrome" => "google-chrome",
                "edge" => "microsoft-edge",
                _ => "chromium",
            })
            .join("NativeMessagingHosts")
    };
    #[cfg(target_os = "macos")]
    let folder = base
        .home_dir()
        .join("Library/Application Support")
        .join(match browser {
            "firefox" => "Mozilla/NativeMessagingHosts",
            "chrome" => "Google/Chrome/NativeMessagingHosts",
            "edge" => "Microsoft Edge/NativeMessagingHosts",
            _ => "Chromium/NativeMessagingHosts",
        });
    #[cfg(target_os = "windows")]
    let folder = {
        let _ = base;
        dirs.config_dir().join("native-messaging").join(browser)
    };
    std::fs::create_dir_all(&folder)?;
    let path = folder.join("dev.factorseal.browser.json");
    write_manifest(&path, bridge, id, firefox)?;
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt as _;
        let vendor = match browser {
            "firefox" => r"Mozilla",
            "edge" => r"Microsoft\Edge",
            "chrome" => r"Google\Chrome",
            _ => r"Chromium",
        };
        let key = format!(r"HKCU\Software\{vendor}\NativeMessagingHosts\dev.factorseal.browser");
        if !std::process::Command::new("reg.exe")
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: registration runs at Desktop startup.
            .args(["add", &key, "/ve", "/t", "REG_SZ", "/d"])
            .arg(&path)
            .arg("/f")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?
            .success()
        {
            return Err(io::Error::other("native host registry installation failed"));
        }
    }
    if let Some(root) = root {
        std::fs::create_dir_all(dirs.config_dir())?;
        write_changed(
            &dirs.config_dir().join("browser-host.json"),
            &serde_json::to_vec(&Config {
                root: std::path::absolute(root)?,
                desktop: None,
                desktop_identity: None,
            })?,
        )?;
    }
    Ok(())
}

fn write_manifest(path: &Path, bridge: &Path, id: &str, firefox: bool) -> io::Result<()> {
    let mut manifest = serde_json::json!({"name":"dev.factorseal.browser","description":"FactorSeal browser integration","path":bridge,"type":"stdio"});
    if firefox {
        manifest["allowed_extensions"] = serde_json::json!([id]);
    } else {
        manifest["allowed_origins"] = serde_json::json!([format!("chrome-extension://{id}/")]);
    }
    write_changed(path, &serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_stable_and_refreshes_moved_executables() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("host.json");
        let first = directory.path().join("first-bridge");
        let moved = directory.path().join("moved-bridge");
        write_manifest(&path, &first, CHROMIUM_ID, false).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        write_manifest(&path, &first, CHROMIUM_ID, false).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        write_manifest(&path, &moved, CHROMIUM_ID, false).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(manifest["path"], serde_json::json!(moved));
        assert_eq!(
            manifest["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{CHROMIUM_ID}/")])
        );
        assert!(manifest.get("allowed_extensions").is_none());
        write_manifest(&path, &first, FIREFOX_ID, true).unwrap();
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            manifest["allowed_extensions"],
            serde_json::json!([FIREFOX_ID])
        );
        assert!(manifest.get("allowed_origins").is_none());
    }

    #[test]
    fn legacy_host_config_ignores_removed_disable_flag() {
        let config: Config =
            serde_json::from_value(serde_json::json!({"root": "/test-vault", "enabled": false}))
                .unwrap();
        assert!(config.desktop.is_none());
        let saved = serde_json::to_value(&config).unwrap();
        assert!(saved.get("enabled").is_none());
        assert_eq!(saved["root"], "/test-vault");
    }
}
