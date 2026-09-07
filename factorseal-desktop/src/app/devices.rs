use super::{
    Arc, Button, Context, DesktopRuntime, DesktopView, Div, Input, SecretInputState, Snapshot, div,
    h_flex, px, v_flex,
};
use factorseal::desktop_worker::sync::network::Action;
use gpui::prelude::*;
use gpui_component::scroll::ScrollableElement as _;
use gpui_component::{ActiveTheme as _, Disableable as _, button::ButtonVariants as _};
impl DesktopView {
    pub(super) fn poll_devices(runtime: Arc<DesktopRuntime>, cx: &mut Context<Self>) {
        cx.spawn(async move |view, cx| {
            loop {
                smol::Timer::after(std::time::Duration::from_secs(3)).await;
                let runtime = Arc::clone(&runtime);
                let result = smol::unblock(move || runtime.sync_view()).await;
                if view
                    .update(cx, |view, cx| {
                        if let Ok(mut devices) = result {
                            if !matches!(view.snapshot, Snapshot::Unsealed { .. }) {
                                devices.state.invitation = None;
                                devices.state.request = None;
                            }
                            view.devices = devices;
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
        self.devices_notice = None;
        cx.notify();
        let runtime = Arc::clone(&self.runtime);
        let refresh = matches!(action, Action::Refresh);
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || {
                let devices = runtime.sync_manager()?.action(action)?;
                Ok::<_, String>((devices, refresh.then(|| runtime.inspect())))
            })
            .await;
            let _ = view.update(cx, |view, cx| {
                view.devices_busy = false;
                match result {
                    Ok((mut devices, snapshot)) => {
                        if let Some(snapshot) = snapshot {
                            view.apply_snapshot(snapshot, cx);
                        }
                        if !matches!(view.snapshot, Snapshot::Unsealed { .. }) {
                            devices.state.invitation = None;
                            devices.state.request = None;
                        }
                        view.devices = devices;
                    }
                    Err(error) => view.devices_notice = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn render_devices(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let busy = self.devices_busy;
        let state = &self.devices.state;
        let can_invite = state.group.as_ref().is_none_or(|group| {
            self.devices.devices.iter().any(|device| {
                device.endpoint == self.devices.endpoint && device.reader == Some(group.controller)
            })
        });
        let mut panel=v_flex().gap_3()
            .child(div().text_lg().child("Your devices"))
            .child(div().text_sm().text_color(theme.muted_foreground).child("Only personal secrets sync. Devices can store encrypted updates while sealed. Keep FactorSeal open to receive and forward them."))
            .child(div().child(format!("{} paired devices · {} other devices reachable at last check",self.devices.devices.iter().filter(|device|device.reader.is_some()).count(),self.devices.reachable)))
            .child(div().child(format!("{} changes waiting to publish · {} items need conflict resolution",state.pending,state.conflicts)));
        for device in &self.devices.devices {
            panel = panel.child(div().child(format!(
                "{}{}{}",
                device.name,
                if device.endpoint == self.devices.endpoint {
                    " (this device)"
                } else {
                    ""
                },
                if device.reader.is_none() {
                    " · encrypted storage only"
                } else {
                    ""
                }
            )));
        }
        if !can_invite {
            let owner = state
                .group
                .as_ref()
                .and_then(|group| {
                    self.devices
                        .devices
                        .iter()
                        .find(|device| device.reader == Some(group.controller))
                })
                .map_or("the inviting device", |device| device.name.as_str());
            panel = panel.child(
                div()
                    .text_sm()
                    .child(format!("Add more devices from {owner}.")),
            );
        }
        if self.devices.devices.is_empty() && !state.joining {
            panel = panel
                .child(div().text_sm().child("This device’s name"))
                .child(Input::new(&self.device_name));
        }
        panel = panel.child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("invite-device")
                        .label("Pair a device")
                        .primary()
                        .disabled(busy || state.joining || !can_invite)
                        .on_click(cx.listener(|view, _, _, cx| {
                            let name = view.device_name.read(cx).value().to_string();
                            view.device_action(Action::Invite(name), cx);
                        })),
                )
                .child(
                    Button::new("refresh-devices")
                        .label("Sync now")
                        .disabled(busy)
                        .on_click(
                            cx.listener(|view, _, _, cx| view.device_action(Action::Refresh, cx)),
                        ),
                ),
        );
        if let Some(invitation) = &state.invitation
            && !state.joining
        {
            if let Ok(modules) = invitation.qr_modules() {
                panel = panel.child(qr(modules));
            }
            panel=panel.child(div().text_sm().child("Scan this QR on the other device, or copy and paste the ticket. Invitations expire after five minutes."))
                .child(Button::new("copy-pairing-ticket").label("Copy ticket").on_click(cx.listener(|view,_,_,cx|{
                    if let Some(invitation)=&view.devices.state.invitation && let Ok(ticket)=invitation.ticket() {
                        cx.write_to_clipboard(gpui::ClipboardItem::new_string(ticket.to_string()));
                    }
                })));
        }
        if let Some(request) = &state.request {
            panel=panel.child(div().child(format!("New device: {}",request.name())))
                .child(div().text_xl().child(request.verification_code().unwrap_or_default()))
                .child(div().text_sm().child(if state.joining {"Compare this code with the inviting device. Approve there only if both codes match."} else {"Compare this code on both devices before approving. Approved devices receive your personal secrets and retained history."}));
            if !state.joining
                && let Ok(id) = request.id()
            {
                panel = panel.child(
                    Button::new("approve-device")
                        .label("Codes match — approve device")
                        .primary()
                        .disabled(busy)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.device_action(Action::Approve(id), cx);
                        })),
                );
            }
        }
        if state.invitation.is_some() || state.request.is_some() {
            panel = panel.child(
                Button::new("cancel-device-pairing")
                    .label("Cancel pairing")
                    .disabled(busy)
                    .on_click(cx.listener(|view, _, _, cx| view.device_action(Action::Cancel, cx))),
            );
        }
        if self.devices.devices.is_empty() && !state.joining {
            panel = panel
                .child(div().child("Join from another device"))
                .child(self.pairing_ticket.clone())
                .child(
                    Button::new("join-device")
                        .label("Use pairing ticket")
                        .disabled(busy)
                        .on_click(cx.listener(|view, _, window, cx| {
                            let ticket = zeroize::Zeroizing::new(
                                view.pairing_ticket.read(cx).value().trim().to_string(),
                            );
                            let name = view.device_name.read(cx).value().to_string();
                            view.pairing_ticket.update(cx, SecretInputState::clear);
                            let _ = window;
                            view.device_action(Action::Join { ticket, name }, cx);
                        })),
                );
        }
        if let Some(error) = self.devices_notice.as_ref().or(self.devices.error.as_ref()) {
            panel = panel.child(div().text_color(theme.danger).child(error.clone()));
        }
        div().flex_1().min_h_0().child(panel.overflow_y_scrollbar())
    }
}
#[allow(clippy::cast_precision_loss)]
fn qr(modules: Vec<Vec<bool>>) -> impl gpui::IntoElement {
    let width = modules.len();
    let side = (width + 8) as f32 * 4.;
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
                                    + gpui::point(px((x + 4) as f32 * 4.), px((y + 4) as f32 * 4.)),
                                gpui::size(px(4.), px(4.)),
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
