use gpui::{Pixels, Size, point};

use super::{App, Bounds, Window, WindowBounds, px, size};
use crate::settings::WindowPlacement;

pub(super) const MINIMUM_SIZE: Size<Pixels> = Size {
    width: px(640.),
    height: px(480.),
};
const DEFAULT_WIDTH: Pixels = px(1040.);
const VISIBLE_EDGE: Pixels = px(48.);

pub(super) fn initial(default_height: Pixels, cx: &App) -> WindowBounds {
    let Some(saved) = crate::appearance::current(cx).window else {
        return WindowBounds::centered(size(DEFAULT_WIDTH, default_height), cx);
    };
    let displays: Vec<_> = cx
        .displays()
        .iter()
        .map(|display| display.bounds())
        .collect();
    let bounds = on_screen(saved, &displays)
        .unwrap_or_else(|| Bounds::centered(None, saved_size(saved), cx));
    if saved.maximized {
        WindowBounds::Maximized(bounds)
    } else {
        WindowBounds::Windowed(bounds)
    }
}

pub(super) fn of(window: &Window) -> WindowPlacement {
    placement(window.inner_window_bounds())
}

fn placement(bounds: WindowBounds) -> WindowPlacement {
    let (bounds, maximized) = match bounds {
        WindowBounds::Windowed(bounds) | WindowBounds::Fullscreen(bounds) => (bounds, false),
        WindowBounds::Maximized(bounds) => (bounds, true),
    };
    WindowPlacement {
        x: bounds.origin.x.into(),
        y: bounds.origin.y.into(),
        width: bounds.size.width.into(),
        height: bounds.size.height.into(),
        maximized,
    }
}

fn saved_size(saved: WindowPlacement) -> Size<Pixels> {
    size(
        px(saved.width).max(MINIMUM_SIZE.width),
        px(saved.height).max(MINIMUM_SIZE.height),
    )
}

fn on_screen(saved: WindowPlacement, displays: &[Bounds<Pixels>]) -> Option<Bounds<Pixels>> {
    let bounds = Bounds::new(point(px(saved.x), px(saved.y)), saved_size(saved));
    displays
        .iter()
        .any(|display| {
            let visible = display.intersect(&bounds).size;
            visible.width >= VISIBLE_EDGE && visible.height >= VISIBLE_EDGE
        })
        .then_some(bounds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saved(x: f32, y: f32, width: f32, height: f32) -> WindowPlacement {
        WindowPlacement {
            x,
            y,
            width,
            height,
            maximized: false,
        }
    }

    fn display(x: f32, width: f32) -> Bounds<Pixels> {
        Bounds::new(point(px(x), px(0.)), size(px(width), px(1080.)))
    }

    #[test]
    fn keeps_a_window_that_is_still_on_a_display() {
        let displays = [display(0., 1920.), display(1920., 2560.)];
        assert_eq!(
            on_screen(saved(2100., 80., 900., 700.), &displays),
            Some(Bounds::new(
                point(px(2100.), px(80.)),
                size(px(900.), px(700.))
            ))
        );
        assert!(on_screen(saved(-860., 10., 900., 700.), &displays[..1]).is_none());
        assert!(on_screen(saved(-850., 10., 900., 700.), &displays[..1]).is_some());
    }

    #[test]
    fn drops_the_position_of_a_window_on_a_missing_display() {
        let displays = [display(0., 1920.)];
        assert!(on_screen(saved(2100., 80., 900., 700.), &displays).is_none());
        assert!(on_screen(saved(0., 0., 900., 700.), &[]).is_none());
    }

    #[test]
    fn restores_no_smaller_than_the_minimum_size() {
        assert_eq!(
            saved_size(saved(0., 0., 300., 900.)),
            size(px(640.), px(900.))
        );
    }

    #[test]
    fn records_maximized_windows_with_their_restore_size() {
        let bounds = Bounds::new(point(px(10.), px(20.)), size(px(800.), px(600.)));
        assert_eq!(
            placement(WindowBounds::Maximized(bounds)),
            WindowPlacement {
                maximized: true,
                ..saved(10., 20., 800., 600.)
            }
        );
        assert!(!placement(WindowBounds::Fullscreen(bounds)).maximized);
    }
}
