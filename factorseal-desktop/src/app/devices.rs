use super::{
    Arc, Button, Context, DesktopRuntime, DesktopView, Div, Input, SecretInputState, Snapshot, div,
    h_flex, px, v_flex,
};
use factorseal::desktop_worker::sync::network::Action;
use gpui::prelude::*;
use gpui_component::scroll::ScrollableElement as _;
use gpui_component::{
    ActiveTheme as _, Disableable as _, StyledExt as _, button::ButtonVariants as _,
};
impl DesktopView {
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
    fn render_device_welcome(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        v_flex().size_full().items_center().justify_center().child(
            v_flex().w_full().max_w(gpui::rems(28.)).gap_5().p_6()
                .child(v_flex().gap_2()
                    .child(div().text_2xl().font_semibold().child("Name this device"))
                    .child(div().text_sm().text_color(theme.muted_foreground)
                        .child("Choose a name you’ll recognize when pairing and syncing your personal secrets.")))
                .child(v_flex().gap_2()
                    .child(div().text_sm().font_medium().child("Device name"))
                    .child(Input::new(&self.device_name))
                    .child(div().text_xs().text_color(theme.muted_foreground)
                        .child("We’ve filled in your computer’s hostname. You can change it.")))
                .when_some(self.devices_notice.clone(), |panel, error| {
                    panel.child(div().text_sm().text_color(theme.danger).child(error))
                })
                .child(h_flex().justify_end().child(
                    Button::new("save-device-name").primary().label("Continue")
                        .on_click(cx.listener(|view, _, _, cx| {
                            let mut settings = crate::appearance::current(cx).clone();
                            settings.device_name = Some(view.device_name.read(cx).value().trim().to_owned());
                            match crate::appearance::update(settings, cx) {
                                Ok(()) => view.devices_notice = None,
                                Err(error) => view.devices_notice = Some(error.to_string()),
                            }
                            cx.notify();
                        })))))
    }
    #[allow(clippy::too_many_lines)]
    pub(super) fn render_devices(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        if !self.devices_loaded {
            return div()
                .p_6()
                .text_color(theme.muted_foreground)
                .child("Loading devices…");
        }
        let busy = self.devices_busy;
        let state = &self.devices.state;
        let can_invite = state.group.as_ref().is_none_or(|group| {
            self.devices.devices.iter().any(|device| {
                device.endpoint == self.devices.endpoint && device.reader == Some(group.controller)
            })
        });
        if self.devices.devices.is_empty()
            && !state.joining
            && crate::appearance::current(cx).device_name.is_none()
            && self.devices.error.is_none()
        {
            return self.render_device_welcome(cx);
        }
        let mut panel = v_flex()
            .w_full()
            .gap_5()
            .when(state.conflicts > 0, |panel| {
                panel.child(div().p_3().rounded_lg().bg(theme.secondary).child(format!(
                    "{} items need conflict resolution",
                    state.conflicts
                )))
            });
        panel = panel.child(
            h_flex()
                .gap_2()
                .child(
                    Button::new("invite-device")
                        .label("Pair a device")
                        .primary()
                        .disabled(busy || state.joining || !can_invite)
                        .on_click(cx.listener(|view, _, _, cx| {
                            let name = view.device_name.read(cx).value().trim().to_string();
                            view.device_action(Action::Invite(name), cx);
                        })),
                )
                .child(
                    Button::new("refresh-devices")
                        .label("Sync now")
                        .disabled(busy || self.devices.devices.is_empty())
                        .on_click(
                            cx.listener(|view, _, _, cx| view.device_action(Action::Refresh, cx)),
                        ),
                ),
        );
        if self.devices.devices.is_empty() {
            panel = panel.child(v_flex().gap_2().p_6().rounded_lg()
                .border_1().border_color(theme.border)
                .child(div().font_semibold().child("Connect your first device"))
                .child(div().text_sm().text_color(theme.muted_foreground)
                    .child("Pair another device to start syncing, or join using a ticket from an existing device.")));
        } else {
            let mut table = v_flex()
                .w_full()
                .rounded_lg()
                .border_1()
                .border_color(theme.border)
                .overflow_hidden()
                .child(
                    h_flex()
                        .px_4()
                        .py_3()
                        .gap_3()
                        .bg(theme.secondary)
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(div().flex_1().child("DEVICE"))
                        .child(div().w(gpui::rems(10.)).child("ACCESS")),
                );
            for device in &self.devices.devices {
                let local = device.endpoint == self.devices.endpoint;
                table = table.child(
                    h_flex()
                        .px_4()
                        .py_4()
                        .gap_3()
                        .items_center()
                        .border_t_1()
                        .border_color(theme.border)
                        .child(
                            v_flex()
                                .flex_1()
                                .min_w_0()
                                .gap_1()
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .items_center()
                                        .child(div().font_medium().child(device.name.clone()))
                                        .when(local, |row| {
                                            row.child(
                                                div()
                                                    .px_2()
                                                    .py_1()
                                                    .rounded_md()
                                                    .bg(theme.secondary)
                                                    .text_xs()
                                                    .child("This device"),
                                            )
                                        }),
                                )
                                .when(
                                    device.reader.is_some_and(|reader| {
                                        state
                                            .group
                                            .as_ref()
                                            .is_some_and(|group| group.controller == reader)
                                    }),
                                    |row| {
                                        row.child(
                                            div()
                                                .text_xs()
                                                .text_color(theme.muted_foreground)
                                                .child("Manages pairing"),
                                        )
                                    },
                                ),
                        )
                        .child(
                            div()
                                .w(gpui::rems(10.))
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(if device.reader.is_some() {
                                    "Personal secrets"
                                } else {
                                    "Encrypted storage"
                                }),
                        ),
                );
            }
            panel = panel.child(table);
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
                            let name = view.device_name.read(cx).value().trim().to_string();
                            view.pairing_ticket.update(cx, SecretInputState::clear);
                            let _ = window;
                            view.device_action(Action::Join { ticket, name }, cx);
                        })),
                );
        }
        if let Some(error) = self.devices_notice.as_ref().or(self.devices.error.as_ref()) {
            panel = panel.child(div().text_color(theme.danger).child(error.clone()));
        }
        panel = panel.child(div().text_xs().text_color(theme.muted_foreground).child(
            "Sync runs automatically while FactorSeal is open, including when the vault is sealed.",
        ));
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
