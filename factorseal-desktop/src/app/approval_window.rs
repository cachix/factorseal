//! Shared presentation for security approval windows.
use super::{App, Bounds, WindowBounds, WindowOptions, px, size};

pub(super) fn options(layered: bool, title: &str, app_id: &str, cx: &App) -> WindowOptions {
    #[cfg(target_os = "linux")]
    use gpui::layer_shell::{KeyboardInteractivity, Layer, LayerShellOptions};
    let bounds = Bounds::centered(None, size(px(500.), px(640.)), cx);
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(420.), px(420.))),
        titlebar: (!layered).then(|| gpui::TitlebarOptions {
            title: Some(title.into()),
            ..Default::default()
        }),
        app_id: Some(app_id.to_owned()),
        #[cfg(target_os = "linux")]
        kind: if layered {
            gpui::WindowKind::LayerShell(LayerShellOptions {
                namespace: app_id.to_owned(),
                layer: Layer::Overlay,
                // No anchors: center the requested size without reserving space
                // or changing the layout of the user's tiled windows.
                keyboard_interactivity: KeyboardInteractivity::Exclusive,
                ..Default::default()
            })
        } else {
            gpui::WindowKind::Dialog
        },
        #[cfg(not(target_os = "linux"))]
        kind: gpui::WindowKind::Dialog,
        ..Default::default()
    }
}
