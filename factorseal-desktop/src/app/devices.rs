use super::totp::unix_now;
use super::{
    App, Arc, Button, Context, DesktopRuntime, DesktopView, Div, Input, SecretInputState, Snapshot,
    VaultSelection, div, h_flex, px, v_flex,
};
use crate::appearance::TypeScale as _;
use crate::branding::Glyph;
use factorseal::desktop_worker::sync::network::Action;
use factorseal::personal::sync::TransportBinding;
use gpui::prelude::*;
use gpui_component::scroll::ScrollableElement as _;
use gpui_component::{
    ActiveTheme as _, Disableable as _, FocusTrapElement as _, IconName, StyledExt as _,
    button::ButtonVariants as _,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PairingScreen {
    Choose,
    Show,
    Paste,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DeviceRow {
    pub(super) name: String,
    pub(super) local: bool,
    pub(super) reader: bool,
}

impl DeviceRow {
    pub(super) const fn access(&self) -> &'static str {
        if self.reader {
            "Personal secrets"
        } else {
            "Encrypted storage"
        }
    }
}
fn device_rows(
    devices: &[TransportBinding],
    endpoint: [u8; 32],
    local_name: Option<&str>,
) -> Vec<DeviceRow> {
    let local = devices.iter().find(|device| device.endpoint == endpoint);
    let name = local
        .map(|device| device.name.clone())
        .or_else(|| local_name.map(str::to_owned));
    name.map(|name| DeviceRow {
        name,
        local: true,
        reader: local.is_none_or(|device| device.reader.is_some()),
    })
    .into_iter()
    .chain(
        devices
            .iter()
            .filter(|device| device.endpoint != endpoint)
            .map(|device| DeviceRow {
                name: device.name.clone(),
                local: false,
                reader: device.reader.is_some(),
            }),
    )
    .collect()
}
fn shown_pairing(
    screen: Option<PairingScreen>,
    on_devices: bool,
    unsealed: bool,
) -> Option<PairingScreen> {
    screen.filter(|_| on_devices && unsealed)
}
fn saved_or_typed_name(saved: Option<&str>, typed: &str) -> String {
    saved.unwrap_or(typed).trim().to_owned()
}
fn countdown(expires: u64, now: u64) -> Option<String> {
    let left = expires.checked_sub(now).filter(|left| *left > 0)?;
    Some(format!("{}:{:02}", left / 60, left % 60))
}
impl DesktopView {
    pub(super) fn visible_pairing(&self) -> Option<PairingScreen> {
        shown_pairing(
            self.device_pairing,
            !self.settings_open && self.selected_vault_item == Some(VaultSelection::Devices),
            matches!(self.snapshot, Snapshot::Unsealed { .. }),
        )
    }
    fn pairing_name(&self, cx: &App) -> String {
        saved_or_typed_name(
            crate::appearance::current(cx).device_name.as_deref(),
            &self.device_name.read(cx).value(),
        )
    }
    pub(super) fn poll_devices(runtime: Arc<DesktopRuntime>, cx: &mut Context<Self>) {
        cx.spawn(async move |view, cx| {
            loop {
                smol::Timer::after(std::time::Duration::from_secs(3)).await;
                let runtime = Arc::clone(&runtime);
                let result = smol::unblock(move || runtime.sync_view()).await;
                if view
                    .update(cx, |view, cx| {
                        view.devices_loaded = true;
                        if let Ok(mut devices) = result {
                            if !matches!(view.snapshot, Snapshot::Unsealed { .. }) {
                                devices.state.invitation = None;
                                devices.state.request = None;
                            }
                            if view.devices.state.joining
                                && !devices.state.joining
                                && devices.state.group.is_some()
                            {
                                view.device_pairing = None;
                            }
                            view.devices = devices;
                            cx.notify();
                        } else if let Err(error) = result {
                            view.devices.error = Some(error);
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        cx.spawn(async move |view, cx| {
            loop {
                smol::Timer::after(std::time::Duration::from_secs(1)).await;
                if view
                    .update(cx, |view, cx| {
                        if matches!(view.device_pairing, Some(PairingScreen::Show))
                            && view.devices.state.invitation.is_some()
                        {
                            cx.notify();
                        }
                    })
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }
    fn device_action(&mut self, action: Action, cx: &mut Context<Self>) {
        if self.devices_busy {
            return;
        }
        self.devices_busy = true;
        self.devices_syncing = matches!(action, Action::Refresh);
        self.devices_notice = None;
        cx.notify();
        let runtime = Arc::clone(&self.runtime);
        let refresh = matches!(action, Action::Refresh);
        let approved = matches!(action, Action::Approve(_));
        let starts = matches!(action, Action::Invite(_) | Action::Join { .. });
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || {
                let devices = runtime.sync_manager()?.action(action)?;
                Ok::<_, String>((devices, refresh.then(|| runtime.inspect())))
            })
            .await;
            let _ = view.update(cx, |view, cx| {
                view.devices_busy = false;
                view.devices_syncing = false;
                match result {
                    Ok((mut devices, snapshot)) => {
                        if let Some(snapshot) = snapshot {
                            view.apply_snapshot(snapshot, cx);
                        }
                        if !matches!(view.snapshot, Snapshot::Unsealed { .. }) {
                            devices.state.invitation = None;
                            devices.state.request = None;
                        }
                        if approved {
                            view.device_pairing = None;
                        }
                        view.devices = devices;
                    }
                    Err(error) => view.devices_notice = Some(error),
                }
                let cancel = std::mem::take(&mut view.devices_cancel_queued)
                    || starts && view.device_pairing.is_none();
                if cancel {
                    view.device_action(Action::Cancel, cx);
                }
                cx.notify();
            });
        })
        .detach();
    }
    fn save_device_name(&mut self, cx: &mut Context<Self>) -> bool {
        let mut settings = crate::appearance::current(cx).clone();
        settings.device_name = Some(self.device_name.read(cx).value().trim().to_owned());
        let saved = match crate::appearance::update(settings, cx) {
            Ok(()) => {
                self.devices_notice = None;
                true
            }
            Err(error) => {
                self.devices_notice = Some(error.to_string());
                false
            }
        };
        cx.notify();
        saved
    }
    fn close_device_pairing(&mut self, cx: &mut Context<Self>) {
        self.device_pairing = None;
        self.pairing_ticket.update(cx, SecretInputState::clear);
        cx.notify();
    }
    fn pairing_approved_here(&self) -> bool {
        let state = &self.devices.state;
        state.joining
            && state
                .request
                .as_ref()
                .is_some_and(|request| !request.needs_merge_approval())
    }
    fn can_cancel_pairing(&self) -> bool {
        !self.devices_busy || self.devices.state.request.is_none() || self.pairing_approved_here()
    }
    pub(super) fn cancel_device_pairing(&mut self, cx: &mut Context<Self>) {
        if !self.can_cancel_pairing() {
            return;
        }
        let state = &self.devices.state;
        let pending = state.invitation.is_some() || state.request.is_some();
        if !self.pairing_approved_here() {
            if self.devices_busy {
                self.devices_cancel_queued = true;
            } else if pending {
                self.device_action(Action::Cancel, cx);
            }
        }
        self.close_device_pairing(cx);
    }
    fn render_device_welcome(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        v_flex().w_full().child(
            v_flex().w_full().max_w(gpui::rems(28.)).gap_5()
                .child(v_flex().gap_2()
                    .child(div().text_title().font_semibold().child("Name this device"))
                    .child(div().text_lead().text_color(theme.muted_foreground)
                        .child("Choose a name you’ll recognize when pairing and syncing your personal secrets.")))
                .child(v_flex().gap_2()
                    .child(div().text_body().font_medium().child("Device name"))
                    .child(crate::controls::hover_field("device-name-field", Input::new(&self.device_name)))
                    .child(div().text_caption().text_color(theme.muted_foreground)
                        .child("We’ve filled in your computer’s hostname. You can change it.")))
                .when_some(self.devices_notice.clone(), |panel, error| {
                    panel.child(div().text_body().text_color(theme.danger).child(error))
                })
                .child(h_flex().justify_end().child(
                    Button::new("save-device-name").primary().icon(IconName::ArrowRight).label("Continue")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.save_device_name(cx);
                        })))))
    }
    #[allow(clippy::too_many_lines)]
    fn render_device_review(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let state = &self.devices.state;
        let busy = self.devices_busy;
        let mut panel = v_flex().gap_4().w_full();
        let Some(request) = &state.request else {
            return panel;
        };
        let target = if state.joining {
            state.target.as_ref()
        } else {
            state.group.as_ref().or(state.introduction.as_ref())
        };
        let origin = request.origin();
        let target = target.and_then(|group| group.verified().ok());
        if let (Ok(origin), Some(target)) = (origin, target) {
            let mut devices = target.transports().to_vec();
            if let Some(origin) = origin {
                devices.extend_from_slice(origin.transports());
            } else {
                devices.push(TransportBinding {
                    endpoint: request.endpoint(),
                    reader: None,
                    name: request.name().into(),
                });
            }
            devices.sort_by_key(|device| device.endpoint);
            devices.dedup_by_key(|device| device.endpoint);
            panel = panel.child(div().font_semibold().child(format!("Connect these {} devices?", devices.len())))
                .child(div().text_body().child("Personal secrets and retained history from both vaults will be shared with all reader devices below. Device-specific secrets stay local."));
            let mut list = v_flex().rounded_lg().border_1().border_color(theme.border);
            for device in devices {
                list = list.child(
                    h_flex()
                        .px_4()
                        .py_2()
                        .gap_2()
                        .child(div().flex_1().child(device.name))
                        .when(device.endpoint == self.devices.endpoint, |row| {
                            row.child(
                                div()
                                    .text_caption()
                                    .text_color(theme.muted_foreground)
                                    .child("This device"),
                            )
                        }),
                );
            }
            panel = panel
                .child(list)
                .child(
                    div()
                        .text_body()
                        .child("Compare this code on both devices before approving."),
                )
                .child(
                    div()
                        .text_title()
                        .font_semibold()
                        .child(request.verification_code().unwrap_or_default()),
                );
            if let Ok(id) = request.id() {
                let waiting = !state.joining && request.needs_merge_approval();
                let approved_here = state.joining && !request.needs_merge_approval();
                panel = panel.child(
                    Button::new("approve-connection")
                        .primary()
                        .icon(IconName::Check)
                        .label(if waiting {
                            "Waiting for other device’s approval"
                        } else if approved_here {
                            "Approved here. Waiting for the other device."
                        } else {
                            "Codes match. Connect these devices."
                        })
                        .disabled(busy || waiting || approved_here)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.device_action(
                                if view.devices.state.joining {
                                    Action::ApproveJoin(id)
                                } else {
                                    Action::Approve(id)
                                },
                                cx,
                            );
                        })),
                );
            }
        } else {
            panel =
                panel.child(div().text_color(theme.danger).child(
                    "Could not verify the devices in this connection. Cancel and try again.",
                ));
        }
        panel
    }
    fn render_device_code(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let busy = self.devices_busy;
        let panel = v_flex().gap_3().w_full().items_center();
        let Some(invitation) = &self.devices.state.invitation else {
            return panel.child(
                Button::new("retry-pairing-code")
                    .icon(Glyph::Refresh)
                    .loading(busy)
                    .label(if busy {
                        "Creating code…"
                    } else {
                        "Create pairing code"
                    })
                    .disabled(busy)
                    .on_click(cx.listener(|view, _, _, cx| {
                        let name = view.pairing_name(cx);
                        view.device_action(Action::Invite(name), cx);
                    })),
            );
        };
        if countdown(invitation.expires(), unix_now()).is_none() {
            return panel
                .child(div().text_body().child("This pairing code has expired."))
                .child(
                    Button::new("renew-pairing-code")
                        .primary()
                        .icon(Glyph::Refresh)
                        .label("New pairing code")
                        .disabled(busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            let name = view.pairing_name(cx);
                            view.device_action(Action::Invite(name), cx);
                        })),
                );
        }
        panel
            .when_some(invitation.qr_modules().ok(), |panel, modules| {
                panel.child(qr(modules))
            })
            .child(
                div()
                    .text_body()
                    .text_center()
                    .text_color(theme.muted_foreground)
                    .child("Scan this code with the other device, or copy it and paste it there."),
            )
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn render_device_pairing(
        &self,
        screen: PairingScreen,
        cx: &mut Context<Self>,
    ) -> Div {
        let state = &self.devices.state;
        let busy = self.devices_busy;
        let title = if state.request.is_some() {
            "Review connection"
        } else {
            "Connect a device"
        };
        let mut panel = if state.request.is_some() {
            self.render_device_review(cx)
        } else {
            match screen {
                PairingScreen::Choose => v_flex().gap_3().w_full()
                    .child(div().text_body().child("Start on either device. Connecting combines the personal secrets of every device you approve."))
                    .child(Button::new("choose-show-code").primary().icon(Glyph::QrCode).label("Show pairing code")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.device_pairing = Some(PairingScreen::Show);
                            let name = view.pairing_name(cx);
                            view.device_action(Action::Invite(name), cx);
                        })))
                    .child(Button::new("choose-paste-code").icon(Glyph::Paste).label("Paste pairing code")
                        .on_click(cx.listener(|view, _, _, cx| { view.device_pairing = Some(PairingScreen::Paste); cx.notify(); }))),
                PairingScreen::Show => self.render_device_code(cx),
                PairingScreen::Paste => v_flex().gap_3().w_full()
                    .child(div().text_body().child("Paste the pairing code from the other device. You’ll review all affected devices before anything is connected."))
                    .child(div().font_medium().child("Pairing code"))
                    .child(self.pairing_ticket.clone())
                    .child(Button::new("use-pairing-code").primary().icon(IconName::ArrowRight).label("Review connection").disabled(busy)
                        .on_click(cx.listener(|view, _, _, cx| {
                            let ticket = zeroize::Zeroizing::new(view.pairing_ticket.read(cx).value().trim().to_owned());
                            let name = view.pairing_name(cx);
                            view.pairing_ticket.update(cx, SecretInputState::clear);
                            view.device_action(Action::Join { ticket, name }, cx);
                        }))),
            }
        };
        let theme = cx.theme().clone();
        if let Some(error) = self.devices_notice.as_ref().or(self.devices.error.as_ref()) {
            panel = panel.child(
                div()
                    .text_body()
                    .text_color(theme.danger)
                    .child(error.clone()),
            );
        }
        let approved_here = self.pairing_approved_here();
        if approved_here {
            panel =
                panel.child(div().text_body().text_color(theme.muted_foreground).child(
                    "Your approval has been sent. Closing this screen does not withdraw it.",
                ));
        }
        let left = state
            .invitation
            .as_ref()
            .filter(|_| state.request.is_none() && matches!(screen, PairingScreen::Show))
            .and_then(|invitation| countdown(invitation.expires(), unix_now()));
        div()
            .absolute()
            .inset_0()
            .occlude()
            .bg(theme.overlay)
            .flex()
            .items_start()
            .justify_center()
            .p_4()
            .pt(gpui::rems(5.5))
            .child(
                v_flex()
                    .w_full()
                    .max_w(gpui::rems(28.))
                    .max_h_full()
                    .gap_3()
                    .p_5()
                    .rounded_xl()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.popover)
                    .shadow_lg()
                    .focus_trap("device-pairing", &self.pairing_focus)
                    .child(
                        h_flex()
                            .justify_between()
                            .items_center()
                            .child(div().text_heading().font_semibold().child(title))
                            .when_some(left.clone(), |row, left| {
                                row.child(
                                    div()
                                        .text_body()
                                        .text_color(theme.muted_foreground)
                                        .child(format!("Expires in {left}")),
                                )
                            }),
                    )
                    .child(
                        v_flex()
                            .flex_shrink(1.)
                            .min_h_0()
                            .child(panel.overflow_y_scrollbar()),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .when(left.is_some(), |row| {
                                row.child(
                                    Button::new("copy-pairing-code")
                                        .icon(IconName::Copy)
                                        .label("Copy pairing code")
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            if let Some(invitation) = &view.devices.state.invitation
                                                && let Ok(ticket) = invitation.ticket()
                                            {
                                                cx.write_to_clipboard(
                                                    gpui::ClipboardItem::new_string(
                                                        ticket.to_string(),
                                                    ),
                                                );
                                            }
                                        })),
                                )
                            })
                            .child(div().flex_1())
                            .child(
                                Button::new("cancel-device-pairing")
                                    .icon(IconName::Close)
                                    .label(if approved_here { "Close" } else { "Cancel" })
                                    .disabled(!self.can_cancel_pairing())
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.cancel_device_pairing(cx);
                                    })),
                            ),
                    ),
            )
    }
    pub(super) fn needs_device_name(&self, cx: &App) -> bool {
        self.devices.devices.is_empty()
            && !self.devices.state.joining
            && crate::appearance::current(cx).device_name.is_none()
            && self.devices.error.is_none()
    }
    pub(super) fn device_list(&self, cx: &App) -> Vec<DeviceRow> {
        if !self.devices_loaded {
            return Vec::new();
        }
        let name = self.pairing_name(cx);
        device_rows(
            &self.devices.devices,
            self.devices.endpoint,
            Some(name.as_str()).filter(|name| !name.is_empty()),
        )
    }
    pub(super) fn connect_device_button(&self, cx: &mut Context<Self>) -> Button {
        let state = &self.devices.state;
        Button::new("connect-device")
            .flex_none()
            .primary()
            .icon(IconName::Plus)
            .tooltip(if state.request.is_some() || state.invitation.is_some() {
                "View connection"
            } else {
                "Connect a device"
            })
            .on_click(cx.listener(|view, _, window, cx| {
                view.device_pairing = Some(if view.devices.state.joining {
                    PairingScreen::Paste
                } else if view.devices.state.invitation.is_some() {
                    PairingScreen::Show
                } else {
                    PairingScreen::Choose
                });
                view.pairing_focus.focus(window, cx);
                cx.notify();
            }))
    }
    pub(super) fn render_device_placeholder(&self, cx: &mut Context<Self>) -> Option<Div> {
        if !self.devices_loaded {
            return Some(
                div()
                    .text_color(cx.theme().muted_foreground)
                    .child("Loading devices…"),
            );
        }
        self.needs_device_name(cx)
            .then(|| self.render_device_welcome(cx))
    }
    pub(super) fn render_device_rename(&self, cx: &mut Context<Self>) -> Div {
        h_flex()
            .w_full()
            .gap_2()
            .items_center()
            .child(div().flex_1().child(crate::controls::hover_field(
                "device-rename-field",
                Input::new(&self.device_name),
            )))
            .child(
                Button::new("save-device-rename")
                    .primary()
                    .icon(IconName::Check)
                    .label("Save")
                    .on_click(cx.listener(|view, _, _, cx| {
                        if view.save_device_name(cx) {
                            view.device_renaming = false;
                        }
                    })),
            )
            .child(
                Button::new("cancel-device-rename")
                    .ghost()
                    .icon(IconName::Close)
                    .label("Cancel")
                    .on_click(cx.listener(|view, _, window, cx| {
                        let name = crate::appearance::current(cx)
                            .device_name
                            .clone()
                            .unwrap_or_default();
                        view.device_name.update(cx, |input, cx| {
                            input.set_value(name, window, cx);
                        });
                        view.device_renaming = false;
                        view.devices_notice = None;
                        cx.notify();
                    })),
            )
    }
    pub(super) fn render_device_detail(
        &self,
        row: &DeviceRow,
        alone: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let state = &self.devices.state;
        let renaming = row.local && alone && self.device_renaming;
        v_flex()
            .w_full()
            .gap_4()
            .when(renaming, |panel| panel.child(self.render_device_rename(cx)))
            .when(state.conflicts > 0, |panel| {
                panel.child(div().p_3().rounded_lg().bg(theme.secondary).child(format!(
                    "{} items need conflict resolution",
                    state.conflicts
                )))
            })
            .child(
                h_flex()
                    .w_full()
                    .min_h_12()
                    .items_center()
                    .gap_4()
                    .py_1()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .w(gpui::rems(140. / 16.))
                            .flex_none()
                            .text_color(theme.muted_foreground)
                            .child("Access"),
                    )
                    .child(div().flex_1().child(row.access())),
            )
            .when(!alone, |panel| {
                panel.child(
                    h_flex().child(
                        Button::new("refresh-devices")
                            .icon(Glyph::Refresh)
                            .label(if self.devices_syncing {
                                "Syncing…"
                            } else {
                                "Sync now"
                            })
                            .loading(self.devices_syncing)
                            .disabled(self.devices_busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.device_action(Action::Refresh, cx);
                            })),
                    ),
                )
            })
            .when(alone, |panel| {
                panel.child(
                    div()
                        .text_body()
                        .text_color(theme.muted_foreground)
                        .child("Connect another device to start syncing your personal secrets."),
                )
            })
            .when_some(
                self.devices_notice
                    .as_ref()
                    .or(self.devices.error.as_ref())
                    .filter(|_| self.device_pairing.is_none()),
                |panel, error| panel.child(div().text_color(theme.danger).child(error.clone())),
            )
            .child(div().text_caption().text_color(theme.muted_foreground).child(
                "Sync runs automatically while FactorSeal is open, including when the vault is sealed.",
            ))
    }
}
fn qr_module(width: usize) -> f32 {
    #[allow(clippy::cast_precision_loss)]
    let module = 320. / (width + 8) as f32;
    module.floor().max(4.)
}
#[allow(clippy::cast_precision_loss)]
fn qr(modules: Vec<Vec<bool>>) -> impl gpui::IntoElement {
    let width = modules.len();
    let module = qr_module(width);
    let side = (width + 8) as f32 * module;
    gpui::canvas(
        |_, _, _| (),
        move |bounds, (), window, _| {
            window.paint_quad(gpui::fill(bounds, gpui::white()));
            for (y, row) in modules.iter().enumerate() {
                for (x, dark) in row.iter().enumerate() {
                    if *dark {
                        window.paint_quad(gpui::fill(
                            gpui::Bounds::new(
                                bounds.origin
                                    + gpui::point(
                                        px((x + 4) as f32 * module),
                                        px((y + 4) as f32 * module),
                                    ),
                                gpui::size(px(module), px(module)),
                            ),
                            gpui::black(),
                        ));
                    }
                }
            }
        },
    )
    .w(px(side))
    .h(px(side))
    .flex_shrink_0()
}
#[cfg(test)]
mod tests {
    use super::{
        DeviceRow, PairingScreen, TransportBinding, countdown, device_rows, qr_module,
        saved_or_typed_name, shown_pairing,
    };

    fn binding(endpoint: u8, name: &str, reader: bool) -> TransportBinding {
        serde_json::from_value(serde_json::json!({
            "endpoint": vec![endpoint; 32],
            "reader": reader.then(|| vec![endpoint; 32]),
            "name": name,
        }))
        .unwrap()
    }
    fn row(name: &str, local: bool, reader: bool) -> DeviceRow {
        DeviceRow {
            name: name.to_owned(),
            local,
            reader,
        }
    }

    #[test]
    fn this_device_is_listed_before_pairing() {
        assert_eq!(
            device_rows(&[], [1; 32], Some("Laptop")),
            vec![row("Laptop", true, true)]
        );
        assert!(device_rows(&[], [1; 32], None).is_empty());
    }

    #[test]
    fn this_device_comes_first_with_the_name_others_see() {
        let devices = [
            binding(3, "Phone", true),
            binding(1, "Laptop", true),
            binding(2, "Server", false),
        ];
        assert_eq!(
            device_rows(&devices, [1; 32], Some("Renamed later")),
            vec![
                row("Laptop", true, true),
                row("Phone", false, true),
                row("Server", false, false),
            ]
        );
        assert_eq!(
            device_rows(&devices, [1; 32], None)[0],
            row("Laptop", true, true)
        );
    }

    #[test]
    fn the_pairing_sheet_only_counts_while_it_is_on_screen() {
        let show = Some(PairingScreen::Show);
        assert_eq!(shown_pairing(show, true, true), show);
        assert_eq!(shown_pairing(show, false, true), None);
        assert_eq!(shown_pairing(show, true, false), None);
        assert_eq!(shown_pairing(None, true, true), None);
    }

    #[test]
    fn pairing_uses_the_saved_name_over_an_unsaved_rename() {
        assert_eq!(
            saved_or_typed_name(Some("Laptop"), "Half typed rena"),
            "Laptop"
        );
        assert_eq!(saved_or_typed_name(None, " workstation "), "workstation");
    }

    #[test]
    fn countdown_shows_minutes_and_seconds_until_expiry() {
        assert_eq!(countdown(400, 100).as_deref(), Some("5:00"));
        assert_eq!(countdown(400, 391).as_deref(), Some("0:09"));
        assert_eq!(countdown(400, 400), None);
        assert_eq!(countdown(400, 500), None);
    }

    #[test]
    fn qr_modules_grow_to_fill_the_sheet() {
        assert!((qr_module(49) - 5.).abs() < f32::EPSILON);
        assert!((qr_module(25) - 9.).abs() < f32::EPSILON);
        assert!((qr_module(177) - 4.).abs() < f32::EPSILON);
    }
}
