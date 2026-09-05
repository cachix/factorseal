use std::sync::LazyLock;

use gpui::{Hsla, px, rgb};
use gpui_component::{scroll::ScrollbarMode, theme::Theme};

pub(crate) const MARK_ASSET: &str = "factorseal-mark.svg";
pub(crate) const MICRO_MARK_ASSET: &str = "factorseal-mark-micro.svg";
pub(crate) const SEARCH_ASSET: &str = "factorseal-search.svg";
pub(crate) const CLOSE_ASSET: &str = "factorseal-close.svg";
pub(crate) const TAGLINE: &str = "Your secrets stay here.";

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Palette {
    canvas: u32,
    surface: u32,
    raised: u32,
    ink: u32,
    quiet: u32,
    border: u32,
    secondary: u32,
    secondary_hover: u32,
    selection: u32,
    success: u32,
    danger: u32,
    primary_hover: u32,
    primary_active: u32,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    dark: Palette,
    light: Palette,
    warning: u32,
    overlay: u32,
    overlay_opacity: f32,
    scrollbar_opacity: f32,
    scrollbar_thumb_opacity: f32,
    scrollbar_thumb_hover_opacity: f32,
    radius: f32,
    radius_lg: f32,
    tile_radius: f32,
    shadow: bool,
    tile_shadow: bool,
}

static DEFINITION: LazyLock<Definition> = LazyLock::new(|| {
    toml::from_str(include_str!("../themes/factorseal.toml"))
        .expect("invalid embedded FactorSeal theme")
});

fn color(hex: u32) -> Hsla {
    rgb(hex).into()
}

/// Apply `FactorSeal`'s Ink brand to the native component theme.
///
/// We retain the system light/dark preference and typography, then replace the
/// visual tokens so the application remains recognizably `FactorSeal` on every
/// desktop environment.
pub(crate) fn apply(theme: &mut Theme) {
    let definition = &*DEFINITION;
    let palette = if theme.is_dark() {
        definition.dark
    } else {
        definition.light
    };
    let Palette {
        canvas,
        surface,
        raised,
        ink,
        quiet,
        border,
        secondary,
        secondary_hover,
        selection,
        success,
        danger,
        primary_hover,
        primary_active,
    } = palette;

    theme.background = color(canvas);
    theme.foreground = color(ink);
    theme.border = color(border);
    theme.input = color(border);
    theme.caret = color(ink);
    theme.ring = color(ink);
    theme.selection = color(selection);

    theme.muted = color(raised);
    theme.muted_foreground = color(quiet);
    theme.secondary = color(secondary);
    theme.secondary_foreground = color(ink);
    theme.secondary_hover = color(secondary_hover);
    theme.secondary_active = color(selection);

    theme.primary = color(ink);
    theme.primary_foreground = color(canvas);
    theme.primary_hover = color(primary_hover);
    theme.primary_active = color(primary_active);

    theme.accent = color(secondary_hover);
    theme.accent_foreground = color(ink);
    theme.popover = color(surface);
    theme.popover_foreground = color(ink);
    theme.group_box = color(surface);
    theme.group_box_foreground = color(ink);
    theme.colors.list = color(surface);
    theme.list_hover = color(secondary);
    theme.list_active = color(selection);
    theme.list_active_border = color(ink);

    theme.sidebar = color(raised);
    theme.sidebar_foreground = color(ink);
    theme.sidebar_accent = color(secondary_hover);
    theme.sidebar_accent_foreground = color(ink);
    theme.sidebar_border = color(border);
    theme.sidebar_primary = color(ink);
    theme.scrollbar_mode = ScrollbarMode::Always;
    theme.scrollbar = color(canvas).opacity(definition.scrollbar_opacity);
    theme.scrollbar_thumb = color(quiet).opacity(definition.scrollbar_thumb_opacity);
    theme.scrollbar_thumb_hover = color(quiet).opacity(definition.scrollbar_thumb_hover_opacity);
    theme.sidebar_primary_foreground = color(canvas);

    theme.link = color(ink);
    theme.link_hover = color(quiet);
    theme.link_active = color(ink);
    theme.success = color(success);
    theme.success_foreground = color(canvas);
    theme.success_hover = color(success);
    theme.success_active = color(success);
    theme.danger = color(danger);
    theme.danger_foreground = color(canvas);
    theme.danger_hover = color(danger);
    theme.danger_active = color(danger);
    theme.warning = color(definition.warning);
    theme.warning_foreground = color(canvas);
    theme.info = color(ink);
    theme.info_foreground = color(canvas);
    theme.progress_bar = color(ink);

    theme.title_bar = color(canvas);
    theme.title_bar_border = color(border);
    theme.window_border = color(border);
    theme.overlay = color(definition.overlay).opacity(definition.overlay_opacity);

    theme.radius = px(definition.radius);
    theme.radius_lg = px(definition.radius_lg);
    theme.shadow = definition.shadow;
    theme.tile_shadow = definition.tile_shadow;
    theme.tile_radius = px(definition.tile_radius);
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui_component::theme::ThemeMode;

    #[test]
    fn embedded_palette_preserves_brand_colors_and_system_typography() {
        for (mode, background, foreground, hover) in [
            (ThemeMode::Light, 0x00f7_f3ea, 0x0015_1515, 0x002b_2b29),
            (ThemeMode::Dark, 0x0015_1515, 0x00f7_f3ea, 0x00e8_e3da),
        ] {
            let mut theme = Theme {
                mode,
                font_family: "Test font".into(),
                font_size: px(19.),
                ..Theme::default()
            };
            apply(&mut theme);
            assert_eq!(theme.mode, mode);
            assert_eq!(theme.background, color(background));
            assert_eq!(theme.foreground, color(foreground));
            assert_eq!(theme.primary_hover, color(hover));
            assert_eq!(theme.font_family.as_ref(), "Test font");
            assert_eq!(theme.font_size, px(19.));
        }
    }
}
