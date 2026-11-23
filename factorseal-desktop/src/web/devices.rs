#![allow(clippy::unused_self)]

use super::{App, Arc, Button, Context, DesktopRuntime, DesktopView, Div, Window, div};
use crate::controls::button;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PairingScreen {}

pub(super) struct DeviceRow {
    pub(super) name: String,
    pub(super) local: bool,
}

impl DeviceRow {
    pub(super) const fn access(&self) -> &'static str {
        ""
    }
}

#[derive(Default)]
pub(super) struct View {}

impl DesktopView {
    pub(super) const fn visible_pairing(&self) -> Option<PairingScreen> {
        None
    }

    pub(super) fn poll_devices(_runtime: Arc<DesktopRuntime>, _cx: &mut Context<Self>) {}

    pub(super) const fn forget_device_pairing(&mut self) {}

    pub(super) fn cancel_device_pairing(&mut self, _cx: &mut Context<Self>) {}

    pub(super) fn submit_pairing_code(&mut self, _cx: &mut Context<Self>) {}

    pub(super) fn submit_device_name(&mut self, _cx: &mut Context<Self>) {}

    pub(super) fn render_device_pairing(
        &self,
        screen: PairingScreen,
        _cx: &mut Context<Self>,
    ) -> Div {
        match screen {}
    }

    pub(super) const fn device_list(&self, _cx: &App) -> Vec<DeviceRow> {
        Vec::new()
    }

    pub(super) const fn only_this_device(&self, _cx: &App) -> bool {
        false
    }

    pub(super) fn connect_device_button(&self, _cx: &mut Context<Self>) -> Button {
        button("connect-device")
    }

    pub(super) fn render_connect_first_device(&self, _cx: &mut Context<Self>) -> Div {
        div()
    }

    pub(super) const fn render_device_setup(&self, _cx: &mut Context<Self>) -> Option<Div> {
        None
    }

    pub(super) fn start_device_rename(&mut self, _window: &mut Window, _cx: &mut Context<Self>) {}

    pub(super) fn render_device_detail(
        &self,
        _row: &DeviceRow,
        _alone: bool,
        _cx: &mut Context<Self>,
    ) -> Div {
        div()
    }
}
