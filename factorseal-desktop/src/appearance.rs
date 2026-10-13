use std::{path::PathBuf, sync::LazyLock};

use anyhow::{Context as _, Result};
use gpui::{App, Global, Hsla, Styled, rems};
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    themes: Vec<ThemeEntry>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ThemeEntry {
    id: Choice,
    label: String,
    preset: Option<String>,
    mode: Option<Variant>,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Variant {
    Light,
    Dark,
}

static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    toml::from_str(include_str!("../themes/catalog.toml")).expect("invalid embedded theme catalog")
});

impl Choice {
    pub(crate) fn all() -> impl Iterator<Item = Self> {
        CATALOG.themes.iter().map(|entry| entry.id)
    }

    fn entry(self) -> &'static ThemeEntry {
        CATALOG
            .themes
            .iter()
            .find(|entry| entry.id == self)
            .expect("theme missing from embedded catalog")
    }

    pub(crate) fn label(self) -> &'static str {
        &self.entry().label
    }

    fn preset(self) -> Option<(&'static str, ColorMode)> {
        let entry = self.entry();
        entry.preset.as_deref().zip(entry.mode).map(|(name, mode)| {
            (
                name,
                match mode {
                    Variant::Light => ColorMode::Light,
                    Variant::Dark => ColorMode::Dark,
                },
            )
        })
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
        crate::theming::map_app_tokens(&mut theme);
        theme.input_background()
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
    #[cfg(target_os = "linux")]
    {
        theme.font_family = crate::theming::installed_or_bundled_font(theme.font_family, cx);
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

pub(crate) fn remember(change: impl Fn(&mut crate::settings::DesktopSettings), cx: &mut App) {
    let preferences = cx.global_mut::<Preferences>();
    let before = preferences.settings.clone();
    change(&mut preferences.settings);
    if preferences.settings == before {
        return;
    }
    let Some(path) = preferences.path.clone() else {
        return;
    };
    let result = crate::settings::load(&path).and_then(|mut stored| {
        change(&mut stored);
        crate::settings::save(&path, &stored)
    });
    if let Err(error) = result {
        factorseal::diagnostics::event("desktop", "save_settings", "error");
        eprintln!("could not save settings: {error:#}");
    }
}

pub(crate) fn scale(cx: &App) -> f32 {
    f32::from(current(cx).ui_scale) / 100.
}

const BODY_REMS: f32 = 14. / 16.;
const DEFAULT_TEXT_SIZE: f32 = 14.;

pub(crate) fn rem_size(cx: &App) -> gpui::Pixels {
    let preferences = cx.global::<Preferences>();
    let system = cx
        .global::<crate::theming::ThemeState>()
        .backend
        .is_some()
        .then_some(preferences.system_theme.font_size);
    rem_for(text_size(preferences.settings.text_size, system), scale(cx))
}

fn text_size(chosen: Option<u16>, system: Option<gpui::Pixels>) -> f32 {
    chosen
        .map(f32::from)
        .or(system.map(f32::from))
        .unwrap_or(DEFAULT_TEXT_SIZE)
}

fn rem_for(text_size: f32, scale: f32) -> gpui::Pixels {
    gpui::px(text_size * scale / BODY_REMS)
}

pub(crate) trait TypeScale: Styled + Sized {
    fn text_caption(self) -> Self {
        self.text_size(rems(13. / 16.))
    }

    fn text_body(self) -> Self {
        self.text_size(rems(BODY_REMS))
    }

    fn text_lead(self) -> Self {
        self.text_size(rems(1.))
    }

    fn text_heading(self) -> Self {
        self.text_size(rems(20. / 16.))
    }

    fn text_title(self) -> Self {
        self.text_size(rems(24. / 16.))
    }
}

impl<T: Styled> TypeScale for T {}

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
    crate::crash_reporting::set_enabled(settings.automatic_crash_reports);
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
    fn embedded_catalog_preserves_theme_ids_and_valid_sources() {
        let expected = [
            "factorseal",
            "system",
            "gruvbox-light",
            "gruvbox-dark",
            "one-light",
            "one-dark",
            "dracula-light",
            "dracula",
            "solarized-light",
            "solarized-dark",
            "nord-light",
            "nord",
            "tokyo-night-day",
            "tokyo-night",
            "catppuccin-latte",
            "catppuccin-frappe",
            "catppuccin-macchiato",
            "catppuccin-mocha",
        ];
        let ids: Vec<_> = Choice::all()
            .map(|choice| serde_json::to_value(choice).unwrap())
            .collect();
        assert_eq!(ids, expected.map(serde_json::Value::from));
        for entry in &CATALOG.themes {
            assert!(!entry.label.trim().is_empty());
            let builtin = matches!(entry.id, Choice::FactorSeal | Choice::System);
            assert_eq!(entry.preset.is_none(), builtin);
            assert_eq!(entry.mode.is_none(), builtin);
        }
    }

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
    fn bundled_themes_keep_text_readable_and_borders_visible() {
        use crate::theming::contrast;

        let system = Theme::default();
        let input = system.input_background();
        for choice in Choice::all().filter(|choice| choice.preset().is_some()) {
            let (theme, _) = resolve(choice, &system, input).unwrap();
            for surface in [theme.background, theme.popover, theme.muted, theme.sidebar] {
                assert!(contrast(theme.foreground, surface) >= 4.5, "{choice:?}");
                assert!(
                    contrast(theme.muted_foreground, surface) >= 4.5,
                    "{choice:?}"
                );
                assert!(contrast(theme.border, surface) >= 1.4, "{choice:?}");
                assert!(contrast(theme.link, surface) >= 4.5, "{choice:?}");
                assert!(contrast(theme.danger, surface) >= 4.5, "{choice:?}");
            }
            assert!(
                contrast(theme.popover_foreground, theme.popover) >= 4.5,
                "{choice:?}"
            );
            assert!(
                contrast(theme.sidebar_foreground, theme.sidebar) >= 4.5,
                "{choice:?}"
            );
            for text in [theme.foreground, theme.muted_foreground] {
                assert!(contrast(text, theme.list_active) >= 4.5, "{choice:?}");
            }
            for (text, fill) in [
                (theme.danger_foreground, theme.danger),
                (theme.accent_foreground, theme.accent),
                (theme.sidebar_accent_foreground, theme.sidebar_accent),
                (theme.sidebar_primary_foreground, theme.sidebar_primary),
            ] {
                assert!(contrast(text, fill) >= 4.5, "{choice:?}");
            }
            for fill in [theme.primary, theme.primary_hover, theme.primary_active] {
                assert!(
                    contrast(theme.primary_foreground, fill) >= 4.5,
                    "{choice:?}"
                );
            }
            for fill in [
                theme.secondary,
                theme.secondary_hover,
                theme.secondary_active,
            ] {
                assert!(
                    contrast(theme.secondary_foreground, fill) >= 4.5,
                    "{choice:?}"
                );
            }
            assert_eq!(theme.input, theme.border, "{choice:?}");
            assert_eq!(theme.ring, theme.foreground, "{choice:?}");
        }
    }

    #[test]
    fn readable_text_is_lifted_only_as_far_as_needed() {
        use crate::theming::contrast;

        let mut theme = Theme {
            mode: ThemeMode::Dark,
            ..Theme::default()
        };
        theme.background = gpui::rgb_to_hsla(gpui::rgb(0x0028_2c34));
        theme.popover = gpui::rgb_to_hsla(gpui::rgb(0x003e_4451));
        theme.muted = theme.background;
        theme.sidebar = theme.background;
        theme.foreground = gpui::rgb_to_hsla(gpui::rgb(0x00ab_b2bf));
        theme.muted_foreground = gpui::rgb_to_hsla(gpui::rgb(0x005c_6370));
        theme.border = theme.popover;
        crate::theming::map_app_tokens(&mut theme);
        let muted = contrast(theme.muted_foreground, theme.popover);
        assert!((4.5..5.5).contains(&muted), "{muted}");
        let border = contrast(theme.border, theme.popover);
        assert!((1.4..1.7).contains(&border), "{border}");
    }

    #[test]
    fn visible_theme_border_is_kept() {
        let mut theme = Theme {
            mode: ThemeMode::Dark,
            ..Theme::default()
        };
        theme.background = gpui::rgb_to_hsla(gpui::rgb(0x0028_2a36));
        theme.popover = gpui::rgb_to_hsla(gpui::rgb(0x0034_3746));
        theme.muted = theme.popover;
        theme.sidebar = theme.background;
        theme.foreground = gpui::rgb_to_hsla(gpui::rgb(0x00f8_f8f2));
        let border = gpui::rgb_to_hsla(gpui::rgb(0x0062_72a4));
        theme.border = border;
        crate::theming::map_app_tokens(&mut theme);
        assert_eq!(theme.border, border);
        assert_eq!(theme.input, border);
    }

    #[test]
    fn every_theme_resolves_and_system_colors_are_restored() {
        let system = Theme {
            colors: gpui_component::ThemeColor {
                background: gpui::rgb_to_hsla(gpui::rgb(0x0012_3456)),
                ..Theme::default().colors
            },
            ..Theme::default()
        };
        let input = gpui::rgb_to_hsla(gpui::rgb(0x0065_4321));
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

    #[test]
    fn body_text_matches_the_text_size_at_every_scale() {
        for (text_size, scale) in [(14., 1.), (16., 1.), (20., 1.5), (12., 0.8)] {
            let body = gpui::rems(BODY_REMS).to_pixels(rem_for(text_size, scale));
            assert!((f32::from(body) - text_size * scale).abs() < 0.001);
        }
        assert_eq!(rem_for(14., 1.), gpui::px(16.));
    }

    #[test]
    fn text_size_prefers_the_chosen_size_then_the_native_theme_then_14_px() {
        assert_eq!(
            gpui::px(text_size(Some(20), Some(gpui::px(12.)))),
            gpui::px(20.)
        );
        assert_eq!(
            gpui::px(text_size(None, Some(gpui::px(12.)))),
            gpui::px(12.)
        );
        assert_eq!(gpui::px(text_size(None, None)), gpui::px(14.));
        assert_eq!(rem_for(text_size(None, None), 1.), gpui::px(16.));
    }
}
