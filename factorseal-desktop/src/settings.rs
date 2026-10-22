use std::{
    io::Write as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::appearance::Choice;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct DesktopSettings {
    pub(crate) device_name: Option<String>,
    pub(crate) theme: Choice,
    pub(crate) ui_scale: u16,
    pub(crate) text_size: Option<u16>,
    pub(crate) font: Option<String>,
    pub(crate) reduced_motion: bool,
    pub(crate) website_icons: bool,
    pub(crate) automatic_crash_reports: bool,
    pub(crate) idle_seconds: u64,
    pub(crate) maximum_seconds: u64,
    pub(crate) generator: crate::password_generator::Options,
    pub(crate) window: Option<WindowPlacement>,
    pub(crate) page: Option<Page>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct WindowPlacement {
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) width: f32,
    pub(crate) height: f32,
    pub(crate) maximized: bool,
}

impl WindowPlacement {
    fn is_valid(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|value| value.is_finite())
            && self.width > 0.
            && self.height > 0.
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Page {
    PersonalSecrets,
    Devices,
    TransferCredentials,
    BackupVault,
    Category(factorseal::DocumentKind),
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            device_name: None,
            theme: Choice::default(),
            ui_scale: 100,
            text_size: None,
            font: None,
            reduced_motion: false,
            website_icons: true,
            automatic_crash_reports: true,
            idle_seconds: 300,
            maximum_seconds: 28_800,
            generator: crate::password_generator::Options::default(),
            window: None,
            page: None,
        }
    }
}

impl DesktopSettings {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.device_name.as_ref().is_none_or(|name| {
                !name.trim().is_empty() && name.len() <= 80 && !name.chars().any(char::is_control)
            }),
            "Device name must contain 1–80 bytes and no control characters"
        );
        ensure!(
            (80..=200).contains(&self.ui_scale),
            "UI scale is outside the supported range"
        );
        ensure!(
            self.text_size.is_none_or(|size| (12..=24).contains(&size)),
            "text size is outside the supported range"
        );
        ensure!(
            self.font
                .as_ref()
                .is_none_or(|font| !font.trim().is_empty()),
            "font name is empty"
        );
        ensure!(
            self.generator.is_valid(),
            "password generator options are outside the supported range"
        );
        ensure!(
            self.window.as_ref().is_none_or(WindowPlacement::is_valid),
            "window placement is invalid"
        );
        crate::runtime::lease_policy(self.idle_seconds, self.maximum_seconds)
            .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

pub(crate) fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .map(|dirs| dirs.config_dir().join("preferences.json"))
}

fn lenient(contents: &[u8]) -> Result<DesktopSettings> {
    let stored: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(contents)?;
    let mut settings = DesktopSettings::default();
    for _ in 0..2 {
        for (key, value) in &stored {
            let serde_json::Value::Object(mut candidate) = serde_json::to_value(&settings)? else {
                unreachable!("settings serialize as an object");
            };
            candidate.insert(key.clone(), value.clone());
            if let Ok(next) =
                serde_json::from_value::<DesktopSettings>(serde_json::Value::Object(candidate))
                && next.validate().is_ok()
            {
                settings = next;
            }
        }
    }
    Ok(settings)
}

pub(crate) fn load(path: &Path) -> Result<DesktopSettings> {
    for candidate in [path.to_path_buf(), path.with_file_name("desktop.json")] {
        match std::fs::read(candidate) {
            Ok(contents) => return lenient(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let settings = match std::fs::read(path.with_file_name("desktop-theme.json")) {
        Ok(contents) => DesktopSettings {
            theme: serde_json::from_slice(&contents)?,
            ..DesktopSettings::default()
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DesktopSettings::default(),
        Err(error) => return Err(error.into()),
    };
    settings.validate()?;
    Ok(settings)
}

pub(crate) fn save(path: &Path, settings: &DesktopSettings) -> Result<()> {
    settings.validate()?;
    let parent = path
        .parent()
        .context("desktop settings path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(settings)?)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_existing_theme_ids_remain_compatible() {
        for choice in Choice::all() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("preferences.json");
            let settings = DesktopSettings {
                theme: choice,
                ..DesktopSettings::default()
            };
            save(&path, &settings).unwrap();
            assert_eq!(load(&path).unwrap(), settings);
        }
    }

    #[test]
    fn migrates_theme_and_round_trips_all_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preferences.json");
        assert_eq!(load(&path).unwrap(), DesktopSettings::default());
        std::fs::write(
            path.with_file_name("desktop-theme.json"),
            "\"gruvbox-dark\"",
        )
        .unwrap();
        assert_eq!(load(&path).unwrap().theme, Choice::GruvboxDark);
        let settings = DesktopSettings {
            device_name: Some("My laptop".to_owned()),
            theme: Choice::Dracula,
            ui_scale: 150,
            text_size: Some(20),
            font: Some("Ubuntu Sans".to_owned()),
            reduced_motion: true,
            website_icons: false,
            automatic_crash_reports: false,
            idle_seconds: 60,
            maximum_seconds: 3600,
            generator: crate::password_generator::Options {
                style: crate::password_generator::Style::Random,
                length: 32,
                words: 18,
                digits: false,
                symbols: true,
            },
            window: Some(WindowPlacement {
                x: 120.,
                y: -40.,
                width: 900.,
                height: 640.,
                maximized: true,
            }),
            page: Some(Page::Category(factorseal::DocumentKind::SecretSpecProject)),
        };
        save(&path.with_file_name("desktop.json"), &settings).unwrap();
        assert_eq!(load(&path).unwrap(), settings);
        save(&path, &settings).unwrap();
        save(
            &path.with_file_name("desktop.json"),
            &DesktopSettings::default(),
        )
        .unwrap();
        assert_eq!(load(&path).unwrap(), settings);
        let invalid = DesktopSettings {
            idle_seconds: 7200,
            ..settings.clone()
        };
        assert!(save(&path, &invalid).is_err());
        assert_eq!(load(&path).unwrap(), settings);
    }

    #[test]
    fn unreadable_window_state_keeps_other_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("preferences.json");
        std::fs::write(
            &path,
            r#"{"theme":"dracula","window":{"x":0,"y":0,"width":-5,"height":600,"maximized":false},"page":{"category":"no-such-kind"}}"#,
        )
        .unwrap();
        let settings = load(&path).unwrap();
        assert_eq!(settings.theme, Choice::Dracula);
        assert_eq!(settings.window, None);
        assert_eq!(settings.page, None);
        std::fs::write(
            &path,
            r#"{"theme":"dracula","generator":{"length":3},"idle_seconds":0,"window":"wide","page":"devices"}"#,
        )
        .unwrap();
        let settings = load(&path).unwrap();
        assert_eq!(settings.theme, Choice::Dracula);
        assert_eq!(settings.generator, DesktopSettings::default().generator);
        assert_eq!(
            settings.idle_seconds,
            DesktopSettings::default().idle_seconds
        );
        assert_eq!(settings.page, Some(Page::Devices));
        std::fs::write(&path, r#"{"idle_seconds":36000,"maximum_seconds":43200}"#).unwrap();
        let settings = load(&path).unwrap();
        assert_eq!(
            (settings.idle_seconds, settings.maximum_seconds),
            (36000, 43200)
        );
        std::fs::write(&path, r#"{"window":"wide","page":"devices"}"#).unwrap();
        let settings = load(&path).unwrap();
        assert_eq!(settings.window, None);
        assert_eq!(settings.page, Some(Page::Devices));
        std::fs::write(
            &path,
            r#"{"theme":"dracula","page":{"personal-item":"0123abcd"}}"#,
        )
        .unwrap();
        let settings = load(&path).unwrap();
        assert_eq!(settings.theme, Choice::Dracula);
        assert_eq!(settings.page, None);
    }
}
