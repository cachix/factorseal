//! Installation hints only. Profile metadata never grants vault access.
use super::Browser;
use crate::browser::registration::{CHROMIUM_ID, FIREFOX_ID};
use std::{io::Read, path::Path};

/// Check standard profiles, including Chromium's unpacked development extensions.
/// A false result means not detected, not necessarily absent (e.g. temporary add-ons).
#[must_use]
pub fn extension_installed(browser: Browser) -> bool {
    let Some(base) = directories::BaseDirs::new() else {
        return false;
    };
    #[cfg(target_os = "linux")]
    let roots = match browser {
        Browser::Firefox => vec![
            base.home_dir().join(".mozilla/firefox"),
            base.config_dir().join("mozilla/firefox"),
        ],
        Browser::Chrome => vec![base.config_dir().join("google-chrome")],
        Browser::Chromium => vec![base.config_dir().join("chromium")],
        Browser::Edge => vec![base.config_dir().join("microsoft-edge")],
    };
    #[cfg(target_os = "macos")]
    let roots = vec![
        base.home_dir()
            .join("Library/Application Support")
            .join(match browser {
                Browser::Firefox => "Firefox/Profiles",
                Browser::Chrome => "Google/Chrome",
                Browser::Chromium => "Chromium",
                Browser::Edge => "Microsoft Edge",
            }),
    ];
    #[cfg(target_os = "windows")]
    let roots = vec![match browser {
        Browser::Firefox => base.config_dir().join("Mozilla/Firefox/Profiles"),
        Browser::Chrome => base.data_local_dir().join("Google/Chrome/User Data"),
        Browser::Chromium => base.data_local_dir().join("Chromium/User Data"),
        Browser::Edge => base.data_local_dir().join("Microsoft/Edge/User Data"),
    }];
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let roots: Vec<std::path::PathBuf> = {
        let _ = base;
        Vec::new()
    };
    roots.iter().any(|root| in_profiles(root, browser))
}

fn in_profiles(root: &Path, browser: Browser) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.take(128).filter_map(Result::ok).any(|entry| {
        let profile = entry.path();
        if browser == Browser::Firefox {
            json(&profile.join("extensions.json")).is_some_and(|value| {
                value["addons"]
                    .as_array()
                    .is_some_and(|addons| addons.iter().any(|addon| addon["id"] == FIREFOX_ID))
            })
        } else {
            ["Preferences", "Secure Preferences"].iter().any(|file| {
                json(&profile.join(file))
                    .is_some_and(|value| value["extensions"]["settings"][CHROMIUM_ID].is_object())
            })
        }
    })
}

fn json(path: &Path) -> Option<serde_json::Value> {
    // Bound reads even if a browser replaces the file during discovery.
    const LIMIT: u64 = 16 * 1024 * 1024;
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > LIMIT {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unpacked_extensions_without_pairing_or_host_registration() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("NativeMessagingHosts")).unwrap();
        assert!(!in_profiles(root.path(), Browser::Chromium));
        let profile = root.path().join("Profile 2");
        std::fs::create_dir(&profile).unwrap();
        for file in ["Preferences", "Secure Preferences"] {
            let value = serde_json::json!({"extensions":{"settings":{
                CHROMIUM_ID: {"location":4,"path":"/development/factorseal/dist/chromium"}
            }}});
            std::fs::write(profile.join(file), value.to_string()).unwrap();
            assert!(in_profiles(root.path(), Browser::Chromium));
            std::fs::write(profile.join(file), b"{}").unwrap();
        }
        assert!(!in_profiles(root.path(), Browser::Chromium));
    }

    #[test]
    fn firefox_detection_ignores_other_addons_and_tolerates_partial_writes() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("test.default");
        std::fs::create_dir(&profile).unwrap();
        let file = profile.join("extensions.json");
        for contents in [r#"{"addons":[{"id":"other@example.org"}]}"#, "{"] {
            std::fs::write(&file, contents).unwrap();
            assert!(!in_profiles(root.path(), Browser::Firefox));
        }
        std::fs::write(
            &file,
            serde_json::json!({"addons":[{"id":FIREFOX_ID}]}).to_string(),
        )
        .unwrap();
        assert!(in_profiles(root.path(), Browser::Firefox));
    }
}
