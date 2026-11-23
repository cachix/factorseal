#![allow(clippy::unused_self)]

use super::{App, Arc, Context, DesktopRuntime, DesktopView, Div, div};

pub(super) fn setup(_root: &std::path::Path, _runtime: Arc<DesktopRuntime>, _cx: &mut App) {}

impl DesktopView {
    pub(super) fn render_browser(&self, _cx: &mut Context<Self>) -> Div {
        div()
    }

    pub(super) const fn browsers_available(&self, _cx: &App) -> bool {
        false
    }

    pub(super) const fn browser_settings(
        &self,
        _cx: &mut Context<Self>,
    ) -> Option<crate::settings_view::Browsers> {
        None
    }
}
