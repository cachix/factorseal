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
    pub(crate) theme: Choice,
    pub(crate) ui_scale: u16,
    pub(crate) text_size: Option<u16>,
    pub(crate) font: Option<String>,
    pub(crate) reduced_motion: bool,
    pub(crate) idle_seconds: u64,
    pub(crate) maximum_seconds: u64,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            theme: Choice::default(),
            ui_scale: 100,
            text_size: None,
            font: None,
            reduced_motion: false,
            idle_seconds: 300,
            maximum_seconds: 28_800,
        }
    }
}

impl DesktopSettings {
    pub(crate) fn validate(&self) -> Result<()> {
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
        crate::runtime::lease_policy(self.idle_seconds, self.maximum_seconds)
            .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

pub(crate) fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .map(|dirs| dirs.config_dir().join("preferences.json"))
}

pub(crate) fn load(path: &Path) -> Result<DesktopSettings> {
    for candidate in [path.to_path_buf(), path.with_file_name("desktop.json")] {
        match std::fs::read(candidate) {
            Ok(contents) => {
                let settings: DesktopSettings = serde_json::from_slice(&contents)?;
                settings.validate()?;
                return Ok(settings);
            }
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
            theme: Choice::Dracula,
            ui_scale: 150,
            text_size: Some(20),
            font: Some("Ubuntu Sans".to_owned()),
            reduced_motion: true,
            idle_seconds: 60,
            maximum_seconds: 3600,
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
}
