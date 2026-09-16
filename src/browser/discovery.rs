//! Best-effort browser discovery and extension installation metadata.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
mod extension;
pub use extension::extension_installed;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Browser {
    Firefox,
    Chrome,
    Chromium,
    Edge,
}
impl Browser {
    pub const ALL: [Self; 4] = [Self::Firefox, Self::Chrome, Self::Chromium, Self::Edge];
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Firefox => "Firefox",
            Self::Chrome => "Chrome",
            Self::Chromium => "Chromium",
            Self::Edge => "Edge",
        }
    }
    #[must_use]
    pub fn install_url(self) -> &'static str {
        match self {
            Self::Firefox => {
                "https://github.com/cachix/factorseal/tree/main/extensions/browser#firefox"
            }
            _ => {
                "https://github.com/cachix/factorseal/tree/main/extensions/browser#chromium-chrome-and-edge"
            }
        }
    }
    fn executables(self) -> &'static [&'static str] {
        match self {
            Self::Firefox => &["firefox", "firefox-esr"],
            Self::Chrome => &["google-chrome", "google-chrome-stable"],
            Self::Chromium => &["chromium", "chromium-browser"],
            Self::Edge => &["microsoft-edge", "microsoft-edge-stable"],
        }
    }
}

#[must_use]
pub fn installed() -> Vec<Browser> {
    let search: Vec<_> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
    Browser::ALL
        .into_iter()
        .filter(|browser| {
            on_path(*browser, &search)
                || platform_paths(*browser, home.as_deref())
                    .iter()
                    .any(|p| p.is_file())
        })
        .collect()
}
fn on_path(browser: Browser, search: &[PathBuf]) -> bool {
    search.iter().any(|dir| {
        browser.executables().iter().any(|name| {
            #[cfg(windows)]
            let name = format!("{name}.exe");
            dir.join(name).is_file()
        })
    })
}
fn platform_paths(browser: Browser, home: Option<&Path>) -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let app = match browser {
            Browser::Firefox => "Firefox.app/Contents/MacOS/firefox",
            Browser::Chrome => "Google Chrome.app/Contents/MacOS/Google Chrome",
            Browser::Chromium => "Chromium.app/Contents/MacOS/Chromium",
            Browser::Edge => "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        };
        let mut paths = vec![Path::new("/Applications").join(app)];
        if let Some(home) = home {
            paths.push(home.join("Applications").join(app));
        }
        paths
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        let relative = match browser {
            Browser::Firefox => "Mozilla Firefox/firefox.exe",
            Browser::Chrome => "Google/Chrome/Application/chrome.exe",
            Browser::Chromium => "Chromium/Application/chrome.exe",
            Browser::Edge => "Microsoft/Edge/Application/msedge.exe",
        };
        ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(|root| PathBuf::from(root).join(relative))
            .collect()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = home;
        browser
            .executables()
            .iter()
            .map(|name| Path::new("/usr/bin").join(name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_executables_without_confusing_registration_with_installation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("chromium/NativeMessagingHosts")).unwrap();
        let search = vec![dir.path().to_path_buf()];
        assert!(!on_path(Browser::Chromium, &search));
        let name = if cfg!(windows) {
            "firefox.exe"
        } else {
            "firefox"
        };
        std::fs::write(dir.path().join(name), b"test executable").unwrap();
        assert!(on_path(Browser::Firefox, &search));
        assert!(!on_path(Browser::Chrome, &search));
    }
}
