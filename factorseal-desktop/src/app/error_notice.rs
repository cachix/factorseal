use super::*;

pub(super) const MISSING_UNLOCK_PASSWORD: &str =
    "Enter the password required by this unlock method.";

const UNKNOWN_CAUSE: &str = "Something went wrong. Try again, or copy the details to report it.";

const KNOWN_CAUSES: [(&[&str], &str); 4] = [
    (
        &[
            "socket parent must be a private directory",
            "is accessible by group or other users",
        ],
        "Other users can open the vault folder. Make it private to you, then try again.",
    ),
    (
        &[
            "could not monitor Linux session lifecycle",
            "Linux lifecycle monitor",
        ],
        "FactorSeal could not reach the system bus it uses to seal the vault when you lock the screen. Check that you are signed in to a desktop session, then try again.",
    ),
    (
        &[
            "another Factorseal vault is already accepting connections",
            "another or incompatible service owns the endpoint",
        ],
        "Another FactorSeal is already running this vault. Close it, then try again.",
    ),
    (
        &[
            "Factorseal CLI must be installed beside Desktop",
            "could not start vault worker",
            "The vault worker ",
        ],
        "FactorSeal could not start its vault helper. Reinstall FactorSeal, then try again.",
    ),
];

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ErrorNotice {
    pub(super) message: String,
    pub(super) details: Option<String>,
}

pub(super) fn error_notice(error: &str) -> ErrorNotice {
    if error == MISSING_UNLOCK_PASSWORD
        || error == factorseal::VaultError::PasswordRejected.to_string()
    {
        return ErrorNotice {
            message: error.to_owned(),
            details: None,
        };
    }
    let message = KNOWN_CAUSES
        .iter()
        .find(|(needles, _)| needles.iter().any(|needle| error.contains(needle)))
        .map_or(UNKNOWN_CAUSE, |(_, message)| message);
    ErrorNotice {
        message: message.to_owned(),
        details: Some(error.to_owned()),
    }
}

impl DesktopView {
    pub(super) fn reset_error_details(&mut self) {
        self.error_details_open = false;
        self.error_details_copied = false;
    }

    fn copy_error_details(&mut self, details: String, cx: &mut Context<Self>) {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(details));
        self.error_details_copied = true;
        cx.notify();
        cx.spawn(async move |view, cx| {
            smol::Timer::after(std::time::Duration::from_secs(2)).await;
            let _ = view.update(cx, |view, cx| {
                view.error_details_copied = false;
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn render_error_notice(
        &self,
        error: &str,
        retry: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let ErrorNotice { message, details } = error_notice(error);
        let Some(details) = details else {
            return error_banner(message, theme.danger);
        };
        let copied = details.clone();
        v_flex()
            .w_full()
            .gap_3()
            .px_4()
            .py_3()
            .rounded_lg()
            .bg(theme.danger.opacity(0.1))
            .child(div().text_color(theme.danger).child(message))
            .when(self.error_details_open, |notice| {
                notice.child(
                    div()
                        .w_full()
                        .px_3()
                        .py_2()
                        .rounded_md()
                        .bg(theme.background)
                        .font_family(theme.mono_font_family.clone())
                        .text_caption()
                        .text_color(theme.muted_foreground)
                        .child(details),
                )
            })
            .child(
                h_flex()
                    .gap_2()
                    .flex_wrap()
                    .when(retry, |actions| {
                        actions.child(button("error-retry").label("Try again").on_click(
                            cx.listener(|view, _, _, cx| {
                                view.reset_error_details();
                                refresh_desktop_snapshot(Arc::clone(&view.runtime), cx);
                            }),
                        ))
                    })
                    .child(
                        button("error-details")
                            .ghost()
                            .label(if self.error_details_open {
                                "Hide details"
                            } else {
                                "Show details"
                            })
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.error_details_open = !view.error_details_open;
                                cx.notify();
                            })),
                    )
                    .child(
                        button("error-copy-details")
                            .ghost()
                            .label(if self.error_details_copied {
                                "Copied"
                            } else {
                                "Copy details"
                            })
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.copy_error_details(copied.clone(), cx);
                            })),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_messages_pass_through_without_details() {
        for error in [
            MISSING_UNLOCK_PASSWORD.to_owned(),
            factorseal::VaultError::PasswordRejected.to_string(),
        ] {
            assert_eq!(
                error_notice(&error),
                ErrorNotice {
                    message: error.clone(),
                    details: None,
                }
            );
        }
    }

    #[test]
    fn known_causes_get_a_plain_sentence_and_keep_the_raw_text() {
        for (error, start) in [
            (
                "invalid vault protocol message: Linux vault socket parent must be a private directory owned by this user",
                "Other users can open the vault folder.",
            ),
            (
                "vault protection operation failed: vault root `/tmp/vault` is accessible by group or other users (mode 755)",
                "Other users can open the vault folder.",
            ),
            (
                "invalid vault protocol message: could not monitor Linux session lifecycle: Failed to connect to address",
                "FactorSeal could not reach the system bus",
            ),
            (
                "another or incompatible service owns the endpoint",
                "Another FactorSeal is already running this vault.",
            ),
            (
                "The vault worker closed its connection before replying. This may indicate an incompatible CLI or a worker crash.",
                "FactorSeal could not start its vault helper.",
            ),
        ] {
            let notice = error_notice(error);
            assert!(notice.message.starts_with(start), "{}", notice.message);
            assert_eq!(notice.details.as_deref(), Some(error));
        }
    }

    #[test]
    fn unknown_errors_get_a_generic_sentence_and_keep_the_raw_text() {
        let notice = error_notice("vault protection operation failed: tpm2 busy");
        assert_eq!(notice.message, UNKNOWN_CAUSE);
        assert_eq!(
            notice.details.as_deref(),
            Some("vault protection operation failed: tpm2 busy")
        );
    }
}
