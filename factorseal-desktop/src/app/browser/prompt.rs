//! Browser consent uses the same compact approval surface as access grants.
use super::*;

#[derive(Default)]
struct BrowserWindow(Option<(AnyWindowHandle, gpui::Entity<BrowserView>)>);
impl Global for BrowserWindow {}

struct BrowserView {
    request: Prompt,
    snapshot: Snapshot,
    password: gpui::Entity<SecretInputState>,
    group: Option<factorseal::UnlockGroup>,
    details: bool,
    error: Option<String>,
    pair_after_unlock: bool,
    _submit: Subscription,
}

pub(super) fn setup(cx: &mut App) {
    cx.set_global(BrowserWindow::default());
}

fn close(cx: &mut App) {
    if let Some((handle, view)) = cx.global_mut::<BrowserWindow>().0.take() {
        view.update(cx, |view, cx| {
            view.password.update(cx, SecretInputState::clear);
        });
        let _ = handle.update(cx, |_, window, _| window.remove_window());
    }
}

fn deny(session: &str, generation: u64, cx: &mut App) {
    if let Ok(mut hub) = cx.global::<BrowserGlobal>().hub.lock() {
        if !hub
            .prompt()
            .is_some_and(|prompt| prompt.session == session && prompt.generation == generation)
        {
            return;
        }
        hub.deny(session);
    }
    close(cx);
}

/// Keep one dialog bound to its original request. Cancellation, expiration,
/// sealing, and completion close it; a new session gets a fresh review surface.
pub(super) fn sync(request: Option<Prompt>, cx: &mut App) {
    let Some(request) = request else {
        close(cx);
        return;
    };
    let snapshot = cx.global::<DesktopWindow>().snapshot.clone();
    if let Some((_, view)) = cx.global::<BrowserWindow>().0.clone() {
        if view.read(cx).request.session == request.session
            && view.read(cx).request.generation == request.generation
        {
            view.update(cx, |view, cx| {
                if matches!(snapshot, Snapshot::Unsealed { .. }) {
                    view.password.update(cx, SecretInputState::clear);
                }
                view.snapshot = snapshot;
                view.request = request;
                if view.pair_after_unlock {
                    if matches!(view.snapshot, Snapshot::Unsealed { owned: true, .. })
                        && view.request.state == "awaiting_approval"
                    {
                        view.pair_after_unlock = false;
                        view.approve(None, cx);
                    } else if !matches!(view.snapshot, Snapshot::Unlocking { .. }) {
                        // Failed unlocks must not leave consent armed for a later unlock.
                        view.pair_after_unlock = false;
                    }
                }
                cx.notify();
            });
            return;
        }
        close(cx);
    }
    open(&request, &snapshot, cx);
}

fn open(request: &Prompt, snapshot: &Snapshot, cx: &mut App) {
    let session = request.session.clone();
    let generation = request.generation;
    let mut entity = None;
    let mut build = |window: &mut Window, cx: &mut App| {
        let session = session.clone();
        window.on_window_should_close(cx, move |_, cx| {
            let session = session.clone();
            cx.defer(move |cx| deny(&session, generation, cx));
            false
        });
        let view = cx.new(|cx| {
            let password =
                cx.new(|cx| SecretInputState::new(window, cx).placeholder("FactorSeal password"));
            password.update(cx, |input, cx| input.focus(window, cx));
            let submit = cx.subscribe_in(
                &password,
                window,
                |view: &mut BrowserView, _, event: &InputEvent, _, cx| {
                    if matches!(
                        event,
                        InputEvent::PressEnter {
                            secondary: false,
                            ..
                        }
                    ) {
                        // Submit the same action shown on the unlock button.
                        view.unlock(cx);
                    }
                },
            );
            BrowserView {
                request: request.clone(),
                group: snapshot
                    .metadata()
                    .map(|metadata| metadata.preferred_unlock_group().clone()),
                snapshot: snapshot.clone(),
                password,
                details: false,
                error: None,
                pair_after_unlock: false,
                _submit: submit,
            }
        });
        entity = Some(view.clone());
        cx.new(|cx| Root::new(view, window, cx))
    };
    let layered = cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some();
    let options = |layered, cx: &App| {
        super::super::approval_window::options(
            layered,
            "FactorSeal — Browser access",
            "dev.factorseal.BrowserAccess",
            cx,
        )
    };
    let mut opened = cx.open_window(options(layered, cx), &mut build);
    if opened.is_err() && layered {
        opened = cx.open_window(options(false, cx), &mut build);
    }
    match opened {
        Ok(handle) => cx.global_mut::<BrowserWindow>().0 = Some((handle.into(), entity.unwrap())),
        Err(error) => {
            eprintln!("FactorSeal: could not open browser approval window: {error}");
            deny(&request.session, request.generation, cx);
        }
    }
}

impl BrowserView {
    fn unlock(&mut self, cx: &mut Context<Self>) {
        let Snapshot::Sealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let group = self
            .group
            .clone()
            .unwrap_or_else(|| metadata.preferred_unlock_group().clone());
        let value = self.password.read(cx).value();
        if group.requires(factorseal::UnlockFactorKind::Password) && value.is_empty() {
            self.error = Some("Enter your FactorSeal password.".into());
            cx.notify();
            return;
        }
        let password = if group.requires(factorseal::UnlockFactorKind::Password) {
            Zeroizing::new(value.as_bytes().to_vec())
        } else {
            Zeroizing::new(Vec::new())
        };
        self.password.update(cx, SecretInputState::clear);
        let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
        match runtime.unlock(metadata.clone(), group.clone(), password) {
            Ok(()) => {
                // This view is bound to the reviewed session and generation;
                // cancellation or replacement discards this consent with it.
                self.pair_after_unlock = self.request.site == "Pair browser profile";
                self.snapshot = Snapshot::Unlocking { metadata, group };
                self.error = None;
            }
            Err(error) => self.error = Some(error.to_owned()),
        }
        cx.notify();
    }

    fn approve(&self, index: Option<usize>, cx: &App) {
        if let Ok(mut hub) = cx.global::<BrowserGlobal>().hub.lock() {
            hub.approve(&self.request.session, self.request.generation, index);
        }
    }
}

impl Render for BrowserView {
    #[allow(clippy::too_many_lines)] // Keep the security review and its explicit consent controls together.
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        window.set_rem_size(crate::appearance::rem_size(cx));
        let theme = cx.theme().clone();
        let unsealed = matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. });
        let unlocking = matches!(self.snapshot, Snapshot::Unlocking { .. });
        let reviewing = self.request.state == "awaiting_approval";
        let pairing = self.request.site == "Pair browser profile";
        let revoking = self.request.site == "Disconnect browser profile";
        let title = if pairing {
            "Pair browser profile"
        } else if revoking {
            "Disconnect browser profile"
        } else {
            "Fill a login"
        };
        let mut summary = v_flex().p_4().gap_3().rounded_lg().bg(theme.muted)
            .child(div().text_lg().font_semibold().child(if pairing || revoking { "Browser extension".to_owned() } else { self.request.site.clone() }))
            .child(if pairing { "Allow this browser profile to request logins. Every fill still needs your approval." } else if revoking { "Remove this profile’s permission to request logins." } else { "Choose one account to fill once. The browser will check the original page again." });
        if pairing || revoking {
            summary = summary.child(
                div()
                    .text_sm()
                    .child(format!("Profile key: {}…", &self.request.key[..16])),
            );
        }
        let mut requests = v_flex().gap_4().child(summary).child(
            Button::new("browser-technical-details")
                .ghost()
                .small()
                .label(if self.details {
                    "Hide technical details −"
                } else {
                    "Technical details +"
                })
                .on_click(cx.listener(|view, _, _, cx| {
                    view.details = !view.details;
                    cx.notify();
                })),
        );
        if self.details {
            requests = requests.child(
                div()
                    .text_xs()
                    .child(format!("Profile public key: {}", self.request.key)),
            );
        }
        if reviewing {
            for (index, candidate) in self.request.candidates.iter().enumerate() {
                requests = requests.child(
                    Button::new(("browser-account", index))
                        .label(format!("{} · {}", candidate.title, candidate.username))
                        .on_click(cx.listener(move |view, _, _, cx| view.approve(Some(index), cx))),
                );
            }
        }
        let mut groups = h_flex().gap_2().flex_wrap();
        if let Some(metadata) = self.snapshot.metadata() {
            for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
                let selected = self.group.as_ref() == Some(group);
                let group = group.clone();
                groups = groups.child(
                    Button::new(("browser-factor", index))
                        .label(group.to_string())
                        .selected(selected)
                        .disabled(unlocking)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.group = Some(group.clone());
                            cx.notify();
                        })),
                );
            }
        }
        let needs_password = !unsealed
            && self
                .group
                .as_ref()
                .is_some_and(|group| group.requires(factorseal::UnlockFactorKind::Password));
        let error = self.error.clone().or_else(|| match &self.snapshot {
            Snapshot::Sealed { error, .. } | Snapshot::Unsealed { error, .. } => error.clone(),
            Snapshot::Error(error) => Some(error.clone()),
            _ => None,
        });
        let status = if unlocking {
            "Unlocking your vault…"
        } else if !unsealed {
            "Unlock your vault to continue here."
        } else {
            match self.request.state.as_str() {
                "awaiting_approval" if pairing => {
                    "Pairing stays in effect until this profile is disconnected."
                }
                "awaiting_approval" => "Applies only to this request.",
                "matching" => "Checking for matching logins…",
                "awaiting_context" | "releasing" => "Checking the original page before filling…",
                _ => "Saving browser authorization…",
            }
        };
        v_flex()
            .size_full()
            .border_1()
            .border_color(theme.border)
            .capture_key_down(cx.listener(|view, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" {
                    cx.stop_propagation();
                    let session = view.request.session.clone();
                    let generation = view.request.generation;
                    cx.defer(move |cx| deny(&session, generation, cx));
                }
            }))
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .text_size(theme.font_size)
            .child(
                v_flex()
                    .p_6()
                    .gap_2()
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(brand_mark(22., theme.foreground))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child("FactorSeal"),
                            ),
                    )
                    .child(div().text_xl().font_semibold().child(title)),
            )
            .child(
                div()
                    .id("browser-request-details")
                    .flex_1()
                    .min_h_0()
                    .px_6()
                    .overflow_y_scrollbar()
                    .pb_4()
                    .child(requests),
            )
            .child(
                v_flex()
                    .p_6()
                    .gap_3()
                    .border_t_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(status),
                    )
                    .when(
                        !unsealed
                            && self.snapshot.metadata().is_some_and(|metadata| {
                                metadata.unlock_policy().groups().len() > 1
                            }),
                        |element| element.child(groups),
                    )
                    .when(needs_password && !unlocking, |element| {
                        element.child(field_label("Vault password", self.password.clone()))
                    })
                    .when_some(error, |element, error| {
                        element.child(error_banner(error, theme.danger))
                    })
                    .when(
                        matches!(self.snapshot, Snapshot::Uninitialized { .. }),
                        |element| {
                            element.child(
                                div()
                                    .text_sm()
                                    .child("Set up your vault in FactorSeal Desktop first."),
                            )
                        },
                    )
                    .child(
                        h_flex()
                            .justify_end()
                            .gap_2()
                            .child(Button::new("deny-browser").ghost().label("Deny").on_click(
                                cx.listener(|view, _, _, cx| {
                                    let session = view.request.session.clone();
                                    let generation = view.request.generation;
                                    cx.defer(move |cx| deny(&session, generation, cx));
                                }),
                            ))
                            .when(!unsealed || pairing || revoking, |element| {
                                element.child(
                                    Button::new("approve-browser")
                                        .primary()
                                        .disabled(
                                            unlocking
                                                || (unsealed && !reviewing)
                                                || !matches!(
                                                    self.snapshot,
                                                    Snapshot::Sealed { .. }
                                                        | Snapshot::Unsealed { owned: true, .. }
                                                ),
                                        )
                                        .label(if unlocking {
                                            "Unlocking…"
                                        } else if !unsealed {
                                            if pairing {
                                                "Unlock & Pair"
                                            } else {
                                                "Unlock to continue"
                                            }
                                        } else if !reviewing {
                                            "Saving…"
                                        } else if revoking {
                                            "Disconnect profile"
                                        } else {
                                            "Pair browser"
                                        })
                                        .on_click(cx.listener(|view, _, _, cx| {
                                            if matches!(view.snapshot, Snapshot::Sealed { .. }) {
                                                view.unlock(cx);
                                            } else {
                                                view.approve(None, cx);
                                            }
                                        })),
                                )
                            }),
                    ),
            )
    }
}
