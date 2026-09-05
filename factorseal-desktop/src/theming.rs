use std::fmt;

use gpui::{App, Global};

#[cfg(target_os = "linux")]
use std::{
    env, io,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[cfg(target_os = "linux")]
use anyhow::{Context as _, Result, bail};
#[cfg(target_os = "linux")]
use detect_desktop_environment::DesktopEnvironment;
#[cfg(target_os = "linux")]
use futures_util::{FutureExt as _, StreamExt as _};
#[cfg(target_os = "linux")]
use gpui::Task;
#[cfg(target_os = "linux")]
use notify::Watcher as _;

/// Native toolkit used to resolve the current desktop theme.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Backend {
    Gtk,
    Qt,
}

impl Backend {
    #[cfg(target_os = "linux")]
    const fn probe_argument(self) -> &'static str {
        match self {
            Self::Gtk => "--gtk-theme-probe",
            Self::Qt => "--qt-theme-probe",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Gtk => "GTK",
            Self::Qt => "Qt",
        })
    }
}

/// Theme status used by the automatic native-theme monitor.
#[derive(Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct ThemeState {
    pub(crate) backend: Option<Backend>,
    pub(crate) summary: String,
    pub(crate) error: Option<String>,
    pub(crate) monitor_status: String,
    pub(crate) automatic_refreshes: u64,
    pub(crate) last_change_source: Option<&'static str>,
}

impl Global for ThemeState {}

struct InputBackground(gpui::Hsla);

impl Global for InputBackground {}

pub(crate) fn set_input_background(color: gpui::Hsla, cx: &mut App) {
    cx.set_global(InputBackground(color));
}

pub(crate) fn input_background(cx: &App) -> gpui::Hsla {
    cx.try_global::<InputBackground>().map_or_else(
        || gpui_component::theme::Theme::global(cx).input_background(),
        |background| background.0,
    )
}

#[cfg(target_os = "linux")]
struct LoadedTheme {
    backend: Backend,
    summary: String,
    mode: gpui_component::ThemeMode,
    resolved: native_theme::theme::ResolvedTheme,
}

#[cfg(target_os = "linux")]
struct ThemeMonitor {
    _file_watcher: Option<notify::RecommendedWatcher>,
    _portal_task: Task<()>,
    _refresh_task: Task<()>,
}

#[cfg(target_os = "linux")]
impl Global for ThemeMonitor {}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChangeSource {
    Portal,
    Files,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChangeSources {
    portal: bool,
    files: bool,
}

#[cfg(target_os = "linux")]
impl ChangeSources {
    fn add(&mut self, source: ChangeSource) {
        match source {
            ChangeSource::Portal => self.portal = true,
            ChangeSource::Files => self.files = true,
        }
    }

    const fn label(self) -> &'static str {
        match (self.portal, self.files) {
            (true, true) => "desktop portal and theme files",
            (true, false) => "desktop portal",
            (false, true) => "theme files",
            (false, false) => "theme monitor",
        }
    }
}

/// Load the native theme and start monitoring it for changes.
pub(crate) fn initialize(cx: &mut App) {
    #[cfg(target_os = "linux")]
    initialize_linux(cx);

    #[cfg(not(target_os = "linux"))]
    cx.set_global(ThemeState {
        backend: None,
        summary: "Using gpui-component's platform default theme".to_owned(),
        error: None,
        monitor_status: "native GTK/Qt monitoring is only enabled on Linux".to_owned(),
        automatic_refreshes: 0,
        last_change_source: None,
    });

    crate::appearance::initialize(cx);
}

#[cfg(target_os = "linux")]
fn initialize_linux(cx: &mut App) {
    let initial = load_automatic();
    let state = match initial {
        Ok(loaded) => {
            install_theme(&loaded, cx);
            ThemeState {
                backend: Some(loaded.backend),
                summary: loaded.summary,
                error: None,
                monitor_status: "starting".to_owned(),
                automatic_refreshes: 0,
                last_change_source: None,
            }
        }
        Err(error) => ThemeState {
            backend: None,
            summary: "Using gpui-component's default theme".to_owned(),
            error: Some(format!("Native theme detection failed: {error:#}")),
            monitor_status: "starting".to_owned(),
            automatic_refreshes: 0,
            last_change_source: None,
        },
    };
    cx.set_global(state);
    setup_theme_monitor(cx);
}

/// Reload the native theme and repaint all GPUI windows.
#[cfg(target_os = "linux")]
fn refresh_native_theme(cx: &mut App) {
    match load_automatic() {
        Ok(loaded) => {
            install_theme(&loaded, cx);
            let backend = loaded.backend;
            let summary = loaded.summary;
            eprintln!("active theme backend is {backend}: {summary}");
            let state = cx.global_mut::<ThemeState>();
            state.backend = Some(backend);
            state.summary = summary;
            state.error = None;
            crate::appearance::system_changed(cx);
        }
        Err(error) => {
            let state = cx.global_mut::<ThemeState>();
            state.error = Some(format!("Theme refresh failed: {error:#}"));
        }
    }
    crate::app::refresh_tray_icon(cx);
    cx.refresh_windows();
}

#[cfg(target_os = "linux")]
fn add_config_candidates(paths: &mut Vec<PathBuf>, root: &Path) {
    for name in [
        "gtk-3.0",
        "gtk-4.0",
        "qt5ct",
        "qt6ct",
        "Kvantum",
        "kdeglobals",
        "Trolltech.conf",
    ] {
        paths.push(root.join(name));
    }
}

#[cfg(target_os = "linux")]
fn add_data_candidates(paths: &mut Vec<PathBuf>, root: &Path) {
    paths.push(root.join("themes"));
    paths.push(root.join("color-schemes"));
}

#[cfg(target_os = "linux")]
fn candidate_theme_paths(
    home: Option<&Path>,
    config_home: Option<&Path>,
    data_home: Option<&Path>,
    config_dirs: &[PathBuf],
    data_dirs: &[PathBuf],
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(config_home) = config_home {
        add_config_candidates(&mut paths, config_home);
    }
    if let Some(data_home) = data_home {
        add_data_candidates(&mut paths, data_home);
    }
    if let Some(home) = home {
        paths.push(home.join(".themes"));
    }

    for root in config_dirs {
        add_config_candidates(&mut paths, root);
    }
    for root in data_dirs {
        add_data_candidates(&mut paths, root);
    }

    paths.sort_unstable();
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
fn theme_watch_paths() -> Vec<PathBuf> {
    let xdg_directories = xdg::BaseDirectories::new();
    let home = env::var_os("HOME").map(PathBuf::from);
    let config_home = xdg_directories.get_config_home();
    let data_home = xdg_directories.get_data_home();
    let config_dirs = xdg_directories.get_config_dirs();
    let data_dirs = xdg_directories.get_data_dirs();
    let mut paths = candidate_theme_paths(
        home.as_deref(),
        config_home.as_deref(),
        data_home.as_deref(),
        &config_dirs,
        &data_dirs,
    );

    if let Some(extra) = env::var_os("NATIVE_THEME_WATCH_PATH") {
        paths.extend(env::split_paths(&extra));
    }
    paths.retain(|path| path.exists());
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[cfg(target_os = "linux")]
fn is_theme_setting(namespace: &str, key: &str) -> bool {
    if namespace == ashpd::desktop::settings::APPEARANCE_NAMESPACE {
        return true;
    }

    let namespace = namespace.to_ascii_lowercase();
    let key = key.to_ascii_lowercase();
    namespace.contains("interface")
        && ["theme", "color", "contrast", "font", "icon", "cursor"]
            .iter()
            .any(|part| key.contains(part))
}

#[cfg(target_os = "linux")]
fn create_file_watcher(
    paths: &[PathBuf],
    sender: smol::channel::Sender<ChangeSource>,
) -> Result<(notify::RecommendedWatcher, usize)> {
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
        let Ok(event) = result else {
            return;
        };
        if matches!(
            event.kind,
            notify::EventKind::Create(_)
                | notify::EventKind::Modify(_)
                | notify::EventKind::Remove(_)
        ) {
            let _ = sender.try_send(ChangeSource::Files);
        }
    })?;

    let mut watched_path_count = 0;
    for path in paths {
        let mode = if path.is_dir() {
            notify::RecursiveMode::Recursive
        } else {
            notify::RecursiveMode::NonRecursive
        };
        match watcher.watch(path, mode) {
            Ok(()) => watched_path_count += 1,
            Err(error) => eprintln!("could not watch {}: {error}", path.display()),
        }
    }
    if watched_path_count == 0 {
        bail!("no GTK or Qt theme locations were available to watch");
    }
    Ok((watcher, watched_path_count))
}

#[cfg(target_os = "linux")]
async fn watch_portal(
    sender: smol::channel::Sender<ChangeSource>,
    executor: gpui::BackgroundExecutor,
) {
    const RETRY_DELAY: Duration = Duration::from_secs(5);

    loop {
        match ashpd::desktop::settings::Settings::new().await {
            Ok(settings) => match settings.receive_setting_changed().await {
                Ok(mut changes) => {
                    while let Some(setting) = changes.next().await {
                        if is_theme_setting(setting.namespace(), setting.key()) {
                            let _ = sender.try_send(ChangeSource::Portal);
                        }
                    }
                    eprintln!("desktop settings portal stream ended; reconnecting");
                }
                Err(error) => {
                    eprintln!("could not subscribe to desktop theme changes: {error}");
                }
            },
            Err(error) => eprintln!("could not connect to desktop settings portal: {error}"),
        }
        executor.timer(RETRY_DELAY).await;
    }
}

#[cfg(target_os = "linux")]
fn setup_theme_monitor(cx: &mut App) {
    const DEBOUNCE: Duration = Duration::from_millis(750);
    const CHANNEL_CAPACITY: usize = 32;

    let (sender, receiver) = smol::channel::bounded(CHANNEL_CAPACITY);
    let paths = theme_watch_paths();
    let (file_watcher, watched_paths) = match create_file_watcher(&paths, sender.clone()) {
        Ok((watcher, count)) => (Some(watcher), count),
        Err(error) => {
            eprintln!("theme file monitoring unavailable: {error}");
            (None, 0)
        }
    };

    let executor = cx.background_executor().clone();
    let portal_task = executor.spawn(watch_portal(sender, executor.clone()));
    let refresh_task = cx.spawn(async move |cx| {
        'events: while let Ok(source) = receiver.recv().await {
            let mut sources = ChangeSources::default();
            sources.add(source);

            loop {
                let next_event = receiver.recv().fuse();
                let quiet_period = cx.background_executor().timer(DEBOUNCE).fuse();
                futures_util::pin_mut!(next_event, quiet_period);
                futures_util::select_biased! {
                    next = next_event => match next {
                        Ok(source) => sources.add(source),
                        Err(_) => break 'events,
                    },
                    () = quiet_period => break,
                }
            }

            cx.update(|cx| {
                refresh_native_theme(cx);
                let state = cx.global_mut::<ThemeState>();
                state.automatic_refreshes += 1;
                state.last_change_source = Some(sources.label());
                cx.refresh_windows();
                eprintln!("automatic theme refresh from {}", sources.label());
            });
        }
    });

    cx.global_mut::<ThemeState>().monitor_status =
        format!("XDG portal and {watched_paths} GTK/Qt filesystem locations");
    cx.set_global(ThemeMonitor {
        _file_watcher: file_watcher,
        _portal_task: portal_task,
        _refresh_task: refresh_task,
    });
}

#[cfg(target_os = "linux")]
fn preference_from(
    explicit: Option<&str>,
    desktop: Option<DesktopEnvironment>,
    kde_full_session: bool,
) -> [Backend; 2] {
    match explicit
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("gtk") => return [Backend::Gtk, Backend::Qt],
        Some("qt") => return [Backend::Qt, Backend::Gtk],
        _ => {}
    }

    let qt_desktop = desktop.is_some_and(DesktopEnvironment::qt);
    if qt_desktop || kde_full_session {
        [Backend::Qt, Backend::Gtk]
    } else {
        [Backend::Gtk, Backend::Qt]
    }
}

#[cfg(target_os = "linux")]
fn preferred_backends() -> [Backend; 2] {
    let explicit = env::var("NATIVE_THEME_BACKEND").ok();
    preference_from(
        explicit.as_deref(),
        DesktopEnvironment::detect(),
        env::var_os("KDE_FULL_SESSION").is_some(),
    )
}

#[cfg(target_os = "linux")]
fn run_probe(backend: Backend) -> Result<Vec<u8>> {
    let executable = env::current_exe().context("could not locate factorseal-desktop")?;
    let output = Command::new(executable)
        .arg(backend.probe_argument())
        .output()
        .with_context(|| format!("failed to start the {backend} theme probe"))?;

    if !output.status.success() {
        bail!(
            "{backend} theme probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}

#[cfg(target_os = "linux")]
fn load_backend(backend: Backend) -> Result<LoadedTheme> {
    let json = run_probe(backend)?;

    match backend {
        Backend::Gtk => {
            let snapshot: native_theme_gtk::ThemeSnapshot =
                serde_json::from_slice(&json).context("GTK probe returned invalid JSON")?;
            let mut bridge = snapshot.resolve_native_theme()?;
            bridge.resolved.popover.background_color = bridge.resolved.tooltip.background_color;
            bridge.resolved.popover.font = bridge.resolved.tooltip.font.clone();
            bridge.resolved.sidebar.background_color = bridge.resolved.defaults.surface_color;
            bridge.resolved.sidebar.font.color = bridge.resolved.defaults.text_color;
            bridge.resolved.sidebar.border.color = bridge.resolved.defaults.border.color;
            bridge.resolved.sidebar.hover_background =
                bridge.resolved.defaults.selection_background;
            bridge.resolved.sidebar.selection_background =
                bridge.resolved.defaults.selection_background;
            bridge.resolved.sidebar.selection_text_color =
                bridge.resolved.defaults.selection_text_color;
            let mode = if bridge.mode.is_dark() {
                "dark"
            } else {
                "light"
            };
            let summary = format!(
                "GTK theme: {} · GTK {} · {mode}",
                snapshot.identity.theme_name, snapshot.identity.toolkit_version
            );
            Ok(LoadedTheme {
                backend,
                summary,
                resolved: bridge.resolved,
                mode: if bridge.mode.is_dark() {
                    gpui_component::ThemeMode::Dark
                } else {
                    gpui_component::ThemeMode::Light
                },
            })
        }
        Backend::Qt => {
            let snapshot: native_theme_qt::ThemeSnapshot =
                serde_json::from_slice(&json).context("Qt probe returned invalid JSON")?;
            let bridge = snapshot.resolve_native_theme()?;
            let mode = if bridge.mode.is_dark() {
                "dark"
            } else {
                "light"
            };
            let summary = format!(
                "Qt style: {} · Qt {} · {mode}",
                snapshot.identity.style_name, snapshot.identity.toolkit_version
            );
            Ok(LoadedTheme {
                backend,
                summary,
                resolved: bridge.resolved,
                mode: if bridge.mode.is_dark() {
                    gpui_component::ThemeMode::Dark
                } else {
                    gpui_component::ThemeMode::Light
                },
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn load_automatic() -> Result<LoadedTheme> {
    let [preferred, fallback] = preferred_backends();
    match load_backend(preferred) {
        Ok(theme) => Ok(theme),
        Err(preferred_error) => load_backend(fallback)
            .with_context(|| format!("preferred {preferred} backend failed: {preferred_error:#}")),
    }
}

#[cfg(target_os = "linux")]
fn install_theme(loaded: &LoadedTheme, cx: &mut App) {
    use gpui_component::theme::Theme;

    Theme::change(loaded.mode, None, cx);
    let theme = Theme::global_mut(cx);
    apply_native_theme(theme, &loaded.resolved);
    let background = loaded.resolved.input.background_color;
    cx.set_global(InputBackground(
        gpui::rgba(u32::from_be_bytes([
            background.r,
            background.g,
            background.b,
            background.a,
        ]))
        .into(),
    ));
    Theme::sync_base(cx);
}

pub(crate) fn apply_native_theme(
    theme: &mut gpui_component::theme::Theme,
    native: &native_theme::theme::ResolvedTheme,
) {
    let color = |value: native_theme::color::Rgba| -> gpui::Hsla {
        gpui::rgba(u32::from_be_bytes([value.r, value.g, value.b, value.a])).into()
    };
    let defaults = &native.defaults;
    theme.font_family = defaults.font.family.to_string().into();
    theme.font_size = gpui::px(defaults.font.size);
    theme.background = color(native.window.background_color);
    theme.foreground = color(defaults.text_color);
    theme.border = color(defaults.border.color);
    theme.input = color(native.input.border.color);
    theme.caret = color(native.input.caret_color);
    theme.ring = color(defaults.focus_ring_color);
    theme.selection = color(native.input.selection_background);
    theme.muted = color(defaults.surface_color);
    theme.muted_foreground = color(defaults.muted_color);
    theme.secondary = color(native.button.background_color);
    theme.secondary_foreground = color(native.button.font.color);
    theme.secondary_hover = color(native.button.hover_background);
    theme.secondary_active = color(
        native
            .button
            .active_background
            .unwrap_or(native.button.hover_background),
    );
    theme.primary = color(native.button.primary_background);
    theme.primary_foreground = color(native.button.primary_text_color);
    theme.primary_hover = theme.primary;
    theme.primary_active = theme.primary;
    theme.accent = color(defaults.accent_color);
    theme.accent_foreground = color(defaults.accent_text_color);
    theme.popover = color(native.popover.background_color);
    theme.popover_foreground = color(native.popover.font.color);
    theme.group_box = color(defaults.surface_color);
    theme.group_box_foreground = theme.foreground;
    theme.colors.list = color(native.list.background_color);
    theme.list_hover = color(native.list.hover_background);
    theme.list_active = color(native.list.selection_background);
    theme.list_active_border = color(native.list.border.color);
    theme.sidebar = color(native.sidebar.background_color);
    theme.sidebar_foreground = color(native.sidebar.font.color);
    theme.sidebar_accent = color(native.sidebar.hover_background);
    theme.sidebar_accent_foreground = theme.sidebar_foreground;
    theme.sidebar_border = color(native.sidebar.border.color);
    theme.sidebar_primary = color(native.sidebar.selection_background);
    theme.sidebar_primary_foreground = color(native.sidebar.selection_text_color);
    theme.link = color(defaults.link_color);
    theme.link_hover = color(native.link.hover_text_color);
    theme.link_active = color(native.link.active_text_color);
    theme.success = color(defaults.success_color);
    theme.success_foreground = color(defaults.success_text_color);
    theme.success_hover = theme.success;
    theme.success_active = theme.success;
    theme.danger = color(defaults.danger_color);
    theme.danger_foreground = color(defaults.danger_text_color);
    theme.danger_hover = theme.danger;
    theme.danger_active = theme.danger;
    theme.warning = color(defaults.warning_color);
    theme.warning_foreground = color(defaults.warning_text_color);
    theme.info = color(defaults.info_color);
    theme.info_foreground = color(defaults.info_text_color);
    theme.progress_bar = theme.primary;
    theme.title_bar = color(native.window.title_bar_background);
    theme.title_bar_border = color(native.window.border.color);
    theme.window_border = theme.title_bar_border;
    theme.scrollbar = color(native.scrollbar.track_color);
    theme.scrollbar_thumb = color(native.scrollbar.thumb_color);
    theme.scrollbar_thumb_hover = color(native.scrollbar.thumb_hover_color);
    theme.radius = gpui::px(defaults.border.corner_radius);
    theme.radius_lg = gpui::px(defaults.border.corner_radius_lg);
    theme.shadow = defaults.border.shadow_enabled;
    theme.tile_shadow = native.card.border.shadow_enabled;
    theme.tile_radius = gpui::px(native.card.border.corner_radius);
    sync_component_colors(theme);
}

pub(crate) fn sync_component_colors(theme: &mut gpui_component::theme::Theme) {
    theme.tab = theme.background;
    theme.tab_foreground = theme.muted_foreground;
    theme.tab_active = theme.popover;
    theme.tab_active_foreground = theme.foreground;
    theme.tab_bar = theme.background;
    theme.button = theme.secondary;
    theme.button_foreground = theme.secondary_foreground;
    theme.button_hover = theme.secondary_hover;
    theme.button_active = theme.secondary_active;
    theme.button_primary = theme.primary;
    theme.button_primary_foreground = theme.primary_foreground;
    theme.button_primary_hover = theme.primary_hover;
    theme.button_primary_active = theme.primary_active;
    theme.button_secondary = theme.secondary;
    theme.button_secondary_foreground = theme.secondary_foreground;
    theme.button_secondary_hover = theme.secondary_hover;
    theme.button_secondary_active = theme.secondary_active;
    theme.button_danger = theme.danger;
    theme.button_danger_foreground = theme.danger_foreground;
    theme.button_danger_hover = theme.danger_hover;
    theme.button_danger_active = theme.danger_active;
    theme.button_success = theme.success;
    theme.button_success_foreground = theme.success_foreground;
    theme.button_success_hover = theme.success_hover;
    theme.button_success_active = theme.success_active;
    theme.button_info = theme.info;
    theme.button_info_foreground = theme.info_foreground;
    theme.button_info_hover = theme.info;
    theme.button_info_active = theme.info;
    theme.button_warning = theme.warning;
    theme.button_warning_foreground = theme.warning_foreground;
    theme.button_warning_hover = theme.warning;
    theme.button_warning_active = theme.warning;
    theme.tokens = (&theme.colors).into();
}

/// Emit a toolkit snapshot for the parent process, then terminate.
#[cfg(target_os = "linux")]
fn emit_probe(backend: Backend) -> Result<()> {
    match backend {
        Backend::Gtk => serde_json::to_writer(io::stdout(), &native_theme_gtk::probe()?)?,
        Backend::Qt => serde_json::to_writer(io::stdout(), &native_theme_qt::probe()?)?,
    }
    Ok(())
}

/// Emit a toolkit snapshot for the parent process, then terminate.
#[cfg(target_os = "linux")]
pub(crate) fn exit_after_probe(backend: Backend) -> ! {
    match emit_probe(backend) {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

/// Resolve and print the automatically selected theme without opening GPUI.
#[cfg(target_os = "linux")]
pub(crate) fn exit_after_probe_only() -> ! {
    match load_automatic() {
        Ok(loaded) => {
            println!("{}: {}", loaded.backend, loaded.summary);
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{path::Path, thread, time::Duration};

    use super::{
        Backend, ChangeSource, ChangeSources, DesktopEnvironment, candidate_theme_paths,
        create_file_watcher, is_theme_setting, preference_from,
    };

    #[test]
    fn native_palette_and_typography_survive_repeated_theme_changes() {
        use native_theme::theme::{ColorMode, Theme};

        let mut target = gpui_component::theme::Theme::default();
        for preset in ["adwaita", "kde-breeze", "adwaita"] {
            for mode in [ColorMode::Light, ColorMode::Dark] {
                let native = Theme::preset(preset)
                    .unwrap()
                    .resolve(mode)
                    .unwrap()
                    .variant;
                super::apply_native_theme(&mut target, &native);
                let background = native.window.background_color;
                let expected: gpui::Hsla = gpui::rgba(u32::from_be_bytes([
                    background.r,
                    background.g,
                    background.b,
                    background.a,
                ]))
                .into();
                assert_eq!(target.background, expected);
                assert_eq!(target.button_primary, target.primary);
                assert_eq!(target.button_primary_foreground, target.primary_foreground);
                assert_eq!(
                    target.tokens.button_primary.background,
                    target.primary.into()
                );
                assert_eq!(target.tokens.popover.background, target.popover.into());
                assert_eq!(
                    target.tokens.scrollbar_thumb.background,
                    target.scrollbar_thumb.into()
                );
                assert_eq!(
                    target.font_family.as_ref(),
                    native.defaults.font.family.as_ref()
                );
                assert_eq!(target.font_size, gpui::px(native.defaults.font.size));
                assert_eq!(
                    target.radius,
                    gpui::px(native.defaults.border.corner_radius)
                );
            }
        }
    }

    #[test]
    fn explicit_backend_wins() {
        assert_eq!(
            preference_from(Some("gtk"), Some(DesktopEnvironment::Kde), true),
            [Backend::Gtk, Backend::Qt]
        );
        assert_eq!(
            preference_from(Some("QT"), Some(DesktopEnvironment::Gnome), false),
            [Backend::Qt, Backend::Gtk]
        );
    }

    #[test]
    fn kde_and_lxqt_prefer_qt() {
        assert_eq!(
            preference_from(None, Some(DesktopEnvironment::Kde), false),
            [Backend::Qt, Backend::Gtk]
        );
        assert_eq!(
            preference_from(None, Some(DesktopEnvironment::Lxqt), false),
            [Backend::Qt, Backend::Gtk]
        );
    }

    #[test]
    fn other_desktops_prefer_gtk() {
        assert_eq!(
            preference_from(None, Some(DesktopEnvironment::Gnome), false),
            [Backend::Gtk, Backend::Qt]
        );
        assert_eq!(
            preference_from(Some("invalid"), Some(DesktopEnvironment::Xfce), false),
            [Backend::Gtk, Backend::Qt]
        );
    }

    #[test]
    fn theme_paths_cover_toolkit_and_desktop_locations() {
        let paths = candidate_theme_paths(
            Some(Path::new("/home/test")),
            Some(Path::new("/config")),
            Some(Path::new("/data")),
            &[
                Path::new("/etc/xdg").to_owned(),
                Path::new("/opt/xdg").to_owned(),
            ],
            &[
                Path::new("/usr/share").to_owned(),
                Path::new("/opt/share").to_owned(),
            ],
        );

        for expected in [
            "/config/gtk-4.0",
            "/config/qt6ct",
            "/data/themes",
            "/home/test/.themes",
            "/etc/xdg/gtk-3.0",
            "/opt/xdg/Kvantum",
            "/usr/share/color-schemes",
            "/opt/share/themes",
        ] {
            assert!(paths.iter().any(|path| path == Path::new(expected)));
        }
    }

    #[test]
    fn portal_filter_accepts_theme_settings_only() {
        assert!(is_theme_setting(
            "org.freedesktop.appearance",
            "color-scheme"
        ));
        assert!(is_theme_setting("org.gnome.desktop.interface", "gtk-theme"));
        assert!(is_theme_setting(
            "org.gnome.desktop.interface",
            "cursor-theme"
        ));
        assert!(!is_theme_setting(
            "org.gnome.desktop.interface",
            "clock-format"
        ));
        assert!(!is_theme_setting("org.example.power", "percentage"));
    }

    #[test]
    fn change_sources_merge_for_debounced_refreshes() {
        let mut sources = ChangeSources::default();
        sources.add(ChangeSource::Portal);
        sources.add(ChangeSource::Files);
        assert_eq!(sources.label(), "desktop portal and theme files");
    }

    #[test]
    fn file_watcher_reports_theme_directory_changes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (sender, receiver) = smol::channel::bounded(4);
        let (_watcher, count) =
            create_file_watcher(&[directory.path().to_owned()], sender).expect("file watcher");
        assert_eq!(count, 1);

        std::fs::write(directory.path().join("gtk.css"), "/* changed */")
            .expect("write watched file");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match receiver.try_recv() {
                Ok(ChangeSource::Files) => break,
                Ok(ChangeSource::Portal) | Err(smol::channel::TryRecvError::Empty)
                    if std::time::Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                result => panic!("theme file event was not received: {result:?}"),
            }
        }
    }
}
