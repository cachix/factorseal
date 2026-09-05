use gpui::{Hsla, px, rgb};
use gpui_component::{scroll::ScrollbarMode, theme::Theme};

pub(crate) const MARK_ASSET: &str = "factorseal-mark.svg";
pub(crate) const MICRO_MARK_ASSET: &str = "factorseal-mark-micro.svg";
pub(crate) const SEARCH_ASSET: &str = "factorseal-search.svg";
pub(crate) const CLOSE_ASSET: &str = "factorseal-close.svg";
pub(crate) const TAGLINE: &str = "Your secrets stay here.";

#[derive(Clone, Copy)]
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
}

const DARK: Palette = Palette {
    canvas: 0x0015_1515,
    surface: 0x001d_1d1b,
    raised: 0x0024_2421,
    ink: 0x00f7_f3ea,
    quiet: 0x00b9_b5ac,
    border: 0x003b_3934,
    secondary: 0x0029_2825,
    secondary_hover: 0x0034_322e,
    selection: 0x003c_3933,
    success: 0x0081_c995,
    danger: 0x00f2_8b82,
};

const LIGHT: Palette = Palette {
    canvas: 0x00f7_f3ea,
    surface: 0x00ff_fcf6,
    raised: 0x00ef_eae1,
    ink: 0x0015_1515,
    quiet: 0x0068_635b,
    border: 0x00d9_d2c7,
    secondary: 0x00e9_e3d9,
    secondary_hover: 0x00dd_d6ca,
    selection: 0x00d7_d0c5,
    success: 0x002f_6b4f,
    danger: 0x00a3_3d32,
};

fn color(hex: u32) -> Hsla {
    rgb(hex).into()
}

/// Apply `FactorSeal`'s Ink brand to the native component theme.
///
/// We retain the system light/dark preference and typography, then replace the
/// visual tokens so the application remains recognizably `FactorSeal` on every
/// desktop environment.
pub(crate) fn apply(theme: &mut Theme) {
    let dark = theme.is_dark();
    let palette = if dark { DARK } else { LIGHT };
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
    theme.primary_hover = if dark {
        color(0x00e8_e3da)
    } else {
        color(0x002b_2b29)
    };
    theme.primary_active = if dark {
        color(0x00d8_d2c8)
    } else {
        color(0x0000_0000)
    };

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
    theme.scrollbar = color(canvas).opacity(0.0);
    theme.scrollbar_thumb = color(quiet).opacity(0.32);
    theme.scrollbar_thumb_hover = color(quiet).opacity(0.56);
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
    theme.warning = color(0x00a1_5c22);
    theme.warning_foreground = color(canvas);
    theme.info = color(ink);
    theme.info_foreground = color(canvas);
    theme.progress_bar = color(ink);

    theme.title_bar = color(canvas);
    theme.title_bar_border = color(border);
    theme.window_border = color(border);
    theme.overlay = color(0x0015_1515).opacity(0.56);

    theme.radius = px(7.);
    theme.radius_lg = px(12.);
    theme.shadow = false;
    theme.tile_shadow = false;
    theme.tile_radius = px(12.);
}
