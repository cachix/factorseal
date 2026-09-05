use std::path::PathBuf;

use anyhow::{Context as _, Result};
use gpui::{App, Global, Hsla};
use gpui_component::theme::{Theme, ThemeMode};
use native_theme::theme::ColorMode;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Choice {
    #[default]
    #[serde(rename = "factorseal")]
    FactorSeal,
    System,
    OneDark,
    Dracula,
    SolarizedLight,
    SolarizedDark,
    Nord,
    CatppuccinMocha,
    GruvboxLight,
    GruvboxDark,
    OneLight,
    DraculaLight,
    NordLight,
    TokyoNight,
    TokyoNightDay,
    CatppuccinLatte,
    CatppuccinFrappe,
    CatppuccinMacchiato,
}

impl Choice {
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        [
            Self::FactorSeal,
            Self::System,
            Self::GruvboxLight,
            Self::GruvboxDark,
            Self::OneLight,
            Self::OneDark,
            Self::DraculaLight,
            Self::Dracula,
            Self::SolarizedLight,
            Self::SolarizedDark,
            Self::NordLight,
            Self::Nord,
            Self::TokyoNightDay,
            Self::TokyoNight,
            Self::CatppuccinLatte,
            Self::CatppuccinFrappe,
            Self::CatppuccinMacchiato,
            Self::CatppuccinMocha,
        ]
        .into_iter()
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::FactorSeal => "FactorSeal",
            Self::System => "System",
            Self::GruvboxLight => "Gruvbox Light",
            Self::GruvboxDark => "Gruvbox Dark",
            Self::OneLight => "One Light",
            Self::OneDark => "One Dark",
            Self::DraculaLight => "Dracula Light",
            Self::Dracula => "Dracula",
            Self::SolarizedLight => "Solarized Light",
            Self::SolarizedDark => "Solarized Dark",
            Self::NordLight => "Nord Light",
            Self::Nord => "Nord",
            Self::TokyoNightDay => "Tokyo Night Day",
            Self::TokyoNight => "Tokyo Night",
            Self::CatppuccinLatte => "Catppuccin Latte",
            Self::CatppuccinFrappe => "Catppuccin Frappé",
            Self::CatppuccinMacchiato => "Catppuccin Macchiato",
            Self::CatppuccinMocha => "Catppuccin Mocha",
        }
    }

    fn preset(self) -> Option<(&'static str, ColorMode)> {
        match self {
            Self::FactorSeal | Self::System => None,
            Self::GruvboxLight => Some(("gruvbox", ColorMode::Light)),
            Self::GruvboxDark => Some(("gruvbox", ColorMode::Dark)),
            Self::OneLight => Some(("one-dark", ColorMode::Light)),
            Self::OneDark => Some(("one-dark", ColorMode::Dark)),
            Self::DraculaLight => Some(("dracula", ColorMode::Light)),
            Self::Dracula => Some(("dracula", ColorMode::Dark)),
            Self::SolarizedLight => Some(("solarized", ColorMode::Light)),
            Self::SolarizedDark => Some(("solarized", ColorMode::Dark)),
            Self::NordLight => Some(("nord", ColorMode::Light)),
            Self::Nord => Some(("nord", ColorMode::Dark)),
            Self::TokyoNightDay => Some(("tokyo-night", ColorMode::Light)),
            Self::TokyoNight => Some(("tokyo-night", ColorMode::Dark)),
            Self::CatppuccinLatte => Some(("catppuccin-latte", ColorMode::Light)),
            Self::CatppuccinFrappe => Some(("catppuccin-frappe", ColorMode::Dark)),
            Self::CatppuccinMacchiato => Some(("catppuccin-macchiato", ColorMode::Dark)),
            Self::CatppuccinMocha => Some(("catppuccin-mocha", ColorMode::Dark)),
        }
    }
}

struct Preferences {
    settings: crate::settings::DesktopSettings,
    path: Option<PathBuf>,
    system_theme: Theme,
    system_input: Hsla,
}

impl Global for Preferences {}

fn resolve(choice: Choice, system: &Theme, system_input: Hsla) -> Result<(Theme, Hsla)> {
    let mut theme = system.clone();
    let input = if let Some((preset, mode)) = choice.preset() {
        let resolved = native_theme::theme::Theme::preset(preset)?
            .resolve(mode)?
            .variant;
        theme.mode = if matches!(mode, ColorMode::Light) {
            ThemeMode::Light
        } else {
            ThemeMode::Dark
        };
        crate::theming::apply_native_theme(&mut theme, &resolved);
        theme.font_family = system.font_family.clone();
        theme.font_size = system.font_size;
        let color = resolved.input.background_color;
        gpui::rgba(u32::from_be_bytes([color.r, color.g, color.b, color.a])).into()
    } else if choice == Choice::FactorSeal {
        crate::branding::apply(&mut theme);
        crate::theming::sync_component_colors(&mut theme);
        theme.input_background()
    } else {
        system_input
    };
    Ok((theme, input))
}

pub(crate) fn initialize(cx: &mut App) {
    let path = crate::settings::path();
    let settings = path
        .as_deref()
        .map_or_else(
            || Ok(crate::settings::DesktopSettings::default()),
            crate::settings::load,
        )
        .unwrap_or_else(|error| {
            eprintln!("could not read desktop settings: {error:#}");
            crate::settings::DesktopSettings::default()
        });
    cx.set_global(Preferences {
        settings,
        path,
        system_theme: Theme::global(cx).clone(),
        system_input: crate::theming::input_background(cx),
    });
    if let Err(error) = apply_selected(cx) {
        eprintln!("could not apply desktop theme: {error:#}");
    }
}

fn apply_selected(cx: &mut App) -> Result<()> {
    let preferences = cx.global::<Preferences>();
    let (mut theme, input) = resolve(
        preferences.settings.theme,
        &preferences.system_theme,
        preferences.system_input,
    )?;
    let settings = &preferences.settings;
    if let Some(font) = &settings.font {
        theme.font_family = font.clone().into();
    }
    if let Some(size) = settings.text_size {
        theme.font_size = gpui::px(f32::from(size));
    }
    theme.font_size *= f32::from(settings.ui_scale) / 100.;
    let reduced_motion = settings.reduced_motion;
    *Theme::global_mut(cx) = theme;
    cx.set_reduce_motion(reduced_motion);
    crate::theming::set_input_background(input, cx);
    Theme::sync_base(cx);
    crate::app::refresh_tray_icon(cx);
    cx.refresh_windows();
    Ok(())
}

pub(crate) fn current(cx: &App) -> &crate::settings::DesktopSettings {
    &cx.global::<Preferences>().settings
}

pub(crate) fn use_launch_lease(lease: crate::runtime::LeasePolicy, cx: &mut App) {
    let settings = &mut cx.global_mut::<Preferences>().settings;
    settings.idle_seconds = lease.idle_timeout.as_secs();
    settings.maximum_seconds = lease.maximum_lifetime.as_secs();
}

pub(crate) fn scale(cx: &App) -> f32 {
    f32::from(current(cx).ui_scale) / 100.
}

pub(crate) fn rem_size(cx: &App) -> gpui::Pixels {
    let preferences = cx.global::<Preferences>();
    let text_scale = preferences.settings.text_size.map_or(1., |size| {
        f32::from(size) / f32::from(preferences.system_theme.font_size)
    });
    gpui::px(16. * scale(cx) * text_scale)
}

pub(crate) fn update(settings: crate::settings::DesktopSettings, cx: &mut App) -> Result<()> {
    let preferences = cx.global::<Preferences>();
    let security_changed = preferences.settings.idle_seconds != settings.idle_seconds
        || preferences.settings.maximum_seconds != settings.maximum_seconds;
    resolve(
        settings.theme,
        &preferences.system_theme,
        preferences.system_input,
    )?;
    let path = preferences
        .path
        .as_deref()
        .context("desktop configuration directory is unavailable")?;
    crate::settings::save(path, &settings)?;
    if security_changed {
        crate::app::set_next_lease(
            crate::runtime::lease_policy(settings.idle_seconds, settings.maximum_seconds)
                .map_err(anyhow::Error::msg)?,
            cx,
        );
    }
    cx.global_mut::<Preferences>().settings = settings;
    apply_selected(cx)
}

#[cfg(target_os = "linux")]
pub(crate) fn system_changed(cx: &mut App) {
    let theme = Theme::global(cx).clone();
    let input = crate::theming::input_background(cx);
    let preferences = cx.global_mut::<Preferences>();
    preferences.system_theme = theme;
    preferences.system_input = input;
    if let Err(error) = apply_selected(cx) {
        eprintln!("could not refresh desktop theme: {error:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additional_bundled_variants_have_distinct_palettes() {
        for preset in ["gruvbox", "one-dark", "dracula", "nord", "tokyo-night"] {
            let theme = native_theme::theme::Theme::preset(preset).unwrap();
            let light = theme.resolve(ColorMode::Light).unwrap().variant;
            let dark = theme.resolve(ColorMode::Dark).unwrap().variant;
            assert_ne!(
                light.window.background_color, dark.window.background_color,
                "{preset}"
            );
            assert_ne!(
                light.defaults.text_color, dark.defaults.text_color,
                "{preset}"
            );
        }
        for (preset, mode) in [
            ("catppuccin-latte", ColorMode::Light),
            ("catppuccin-frappe", ColorMode::Dark),
            ("catppuccin-macchiato", ColorMode::Dark),
        ] {
            let theme = native_theme::theme::Theme::preset(preset)
                .unwrap()
                .resolve(mode)
                .unwrap()
                .variant;
            assert_ne!(
                theme.window.background_color, theme.defaults.text_color,
                "{preset}"
            );
        }
    }

    #[test]
    fn every_theme_resolves_and_system_colors_are_restored() {
        let system = Theme {
            colors: gpui_component::ThemeColor {
                background: gpui::rgb(0x0012_3456).into(),
                ..Theme::default().colors
            },
            ..Theme::default()
        };
        let input = gpui::rgb(0x0065_4321).into();
        for choice in Choice::all() {
            let (theme, _) = resolve(choice, &system, input).unwrap();
            assert_eq!(
                theme.tokens.button_primary.background,
                theme.button_primary.into()
            );
            let (restored, restored_input) = resolve(Choice::System, &system, input).unwrap();
            assert_eq!(restored.background, system.background);
            assert_eq!(restored_input, input);
        }
    }
}
