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
#[derive(Clone, Copy)]
pub(super) enum PairingScreen {
    Choose,
    Show,
    Paste,
}
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
    fn render_device_pairing(&self, screen: PairingScreen, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let state = &self.devices.state;
        let busy = self.devices_busy;
        let mut panel = v_flex().gap_4().w_full();
        let title = if state.request.is_some() {
            "Review connection"
        } else {
            "Connect a device"
        };
        if let Some(request) = &state.request {
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
                    devices.push(factorseal::personal::sync::TransportBinding {
                        endpoint: request.endpoint(),
                        reader: None,
                        name: request.name().into(),
                    });
                }
                devices.sort_by_key(|device| device.endpoint);
                devices.dedup_by_key(|device| device.endpoint);
                panel = panel.child(div().font_semibold().child(format!("Connect these {} devices?", devices.len())))
                    .child(div().text_sm().child("Personal secrets and retained history from both vaults will be shared with all reader devices below. Device-specific secrets stay local."));
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
                                        .text_xs()
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
                            .text_sm()
                            .child("Compare this code on both devices before approving."),
                    )
                    .child(
                        div()
                            .text_2xl()
                            .font_semibold()
                            .child(request.verification_code().unwrap_or_default()),
                    );
                if let Ok(id) = request.id() {
                    let waiting = !state.joining && request.needs_merge_approval();
                    let approved_here = state.joining && !request.needs_merge_approval();
                    panel = panel.child(
                        Button::new("approve-connection")
                            .primary()
                            .label(if waiting {
                                "Waiting for other device’s approval"
                            } else if approved_here {
                                "Approved here — waiting for other device"
                            } else {
                                "Codes match — connect these devices"
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
                panel = panel.child(div().text_color(theme.danger).child(
                    "Could not verify the devices in this connection. Cancel and try again.",
                ));
            }
        } else {
            match screen {
                PairingScreen::Choose => {
                    panel = panel.child(div().text_sm().child("Start on either device. Connecting combines the personal secrets of every device you approve."))
                        .child(Button::new("choose-show-code").primary().label("Show pairing code")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.device_pairing = Some(PairingScreen::Show);
                                let name = view.device_name.read(cx).value().trim().to_owned();
                                view.device_action(Action::Invite(name), cx);
                            })))
                        .child(Button::new("choose-paste-code").label("Paste pairing ticket")
                            .on_click(cx.listener(|view, _, _, cx| { view.device_pairing = Some(PairingScreen::Paste); cx.notify(); })));
                }
                PairingScreen::Show => {
                    if let Some(invitation) = &state.invitation {
                        if let Ok(modules) = invitation.qr_modules() {
                            panel = panel.child(qr(modules));
                        }
                        panel = panel.child(div().text_sm().child("On the other device, open Connect a device → Paste pairing ticket. This code expires after five minutes."))
                            .child(Button::new("copy-pairing-ticket").label("Copy ticket").on_click(cx.listener(|view, _, _, cx| {
                                if let Some(invitation) = &view.devices.state.invitation && let Ok(ticket) = invitation.ticket() {
                                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(ticket.to_string()));
                                }
                            })));
                    } else {
                        panel = panel.child(
                            Button::new("retry-pairing-code")
                                .label(if busy {
                                    "Creating code…"
                                } else {
                                    "Create pairing code"
                                })
                                .disabled(busy)
                                .on_click(cx.listener(|view, _, _, cx| {
                                    let name = view.device_name.read(cx).value().trim().to_owned();
                                    view.device_action(Action::Invite(name), cx);
                                })),
                        );
                    }
                }
                PairingScreen::Paste => {
                    panel = panel.child(div().text_sm().child("Paste the ticket copied from the other device. You’ll review all affected devices before anything is connected."))
                        .child(div().font_medium().child("Pairing ticket"))
                        .child(self.pairing_ticket.clone())
                        .child(Button::new("use-pairing-ticket").primary().label("Review connection").disabled(busy)
                            .on_click(cx.listener(|view, _, _, cx| {
                                let ticket = zeroize::Zeroizing::new(view.pairing_ticket.read(cx).value().trim().to_owned());
                                let name = view.device_name.read(cx).value().trim().to_owned();
                                view.pairing_ticket.update(cx, SecretInputState::clear);
                                view.device_action(Action::Join { ticket, name }, cx);
                            })));
                }
            }
            panel = panel.child(div().text_xs().text_color(theme.muted_foreground).child(
                "Camera scanning is not built in yet. An external QR reader can copy the ticket.",
            ));
        }
        if let Some(error) = self.devices_notice.as_ref().or(self.devices.error.as_ref()) {
            panel = panel.child(
                div()
                    .text_sm()
                    .text_color(theme.danger)
                    .child(error.clone()),
            );
        }
        let approved_here = state.joining
            && state
                .request
                .as_ref()
                .is_some_and(|request| !request.needs_merge_approval());
        if approved_here {
            panel =
                panel.child(div().text_sm().text_color(theme.muted_foreground).child(
                    "Your approval has been sent. Closing this screen does not withdraw it.",
                ));
        }
        v_flex()
            .size_full()
            .gap_4()
            .child(
                h_flex()
                    .w_full()
                    .justify_between()
                    .items_center()
                    .child(div().text_lg().font_semibold().child(title))
                    .child(
                        h_flex()
                            .gap_2()
                            .when(
                                state.invitation.is_some() || state.request.is_some(),
                                |row| {
                                    row.child(
                                        Button::new("cancel-device-pairing")
                                            .label("Cancel connection")
                                            .disabled(busy || approved_here)
                                            .on_click(cx.listener(|view, _, _, cx| {
                                                view.device_action(Action::Cancel, cx);
                                                view.device_pairing = None;
                                                view.pairing_ticket
                                                    .update(cx, SecretInputState::clear);
                                                cx.notify();
                                            })),
                                    )
                                },
                            )
                            .child(Button::new("close-device-pairing").label("Close").on_click(
                                cx.listener(|view, _, _, cx| {
                                    view.device_pairing = None;
                                    view.pairing_ticket.update(cx, SecretInputState::clear);
                                    cx.notify();
                                }),
                            )),
                    ),
            )
            .child(div().flex_1().min_h_0().child(panel.overflow_y_scrollbar()))
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
        if self.devices.devices.is_empty()
            && !state.joining
            && crate::appearance::current(cx).device_name.is_none()
            && self.devices.error.is_none()
        {
            return self.render_device_welcome(cx);
        }
        if let Some(join) = self.device_pairing {
            return self.render_device_pairing(join, cx);
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
                    Button::new("connect-device")
                        .primary()
                        .label(if state.request.is_some() || state.invitation.is_some() {
                            "View connection"
                        } else {
                            "Connect a device"
                        })
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.device_pairing = Some(if view.devices.state.joining {
                                PairingScreen::Paste
                            } else if view.devices.state.invitation.is_some() {
                                PairingScreen::Show
                            } else {
                                PairingScreen::Choose
                            });
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("refresh-devices")
                        .label(if self.devices_syncing {
                            "Syncing…"
                        } else {
                            "Sync now"
                        })
                        .loading(self.devices_syncing)
                        .disabled(busy || self.devices.devices.is_empty())
                        .on_click(
                            cx.listener(|view, _, _, cx| view.device_action(Action::Refresh, cx)),
                        ),
                ),
        );
        if self.devices.devices.is_empty() {
            panel =
                panel.child(
                    v_flex()
                        .gap_2()
                        .p_6()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.border)
                        .child(div().font_semibold().child("Connect your first device"))
                        .child(div().text_sm().text_color(theme.muted_foreground).child(
                            "Connect another device to start syncing your personal secrets.",
                        )),
                );
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
                            v_flex().flex_1().min_w_0().gap_1().child(
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
            panel = panel.child(table).when(
                self.devices
                    .devices
                    .iter()
                    .all(|device| device.endpoint == self.devices.endpoint),
                |panel| {
                    panel.child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child("No other devices paired yet."),
                    )
                },
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
