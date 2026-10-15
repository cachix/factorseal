use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use gpui::{Animation, AnimationExt as _, Rems, relative};
use gpui_component::Icon;

use super::*;

const CLIPBOARD_CLEAR_DELAY: Duration = Duration::from_secs(30);
pub(super) const COPY_BUTTON_WIDTH: Rems = rems(100. / 16.);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum CopiedField {
    Draft(usize),
    Saved(usize),
}

pub(super) fn can_generate(kind: PersonalSecretKind, field: &PersonalDraftField) -> bool {
    can_generate_value(kind, &field.field_type, &field.id)
}

pub(super) fn can_generate_value(
    kind: PersonalSecretKind,
    field_type: &PersonalFieldType,
    id: &str,
) -> bool {
    *field_type == PersonalFieldType::Concealed
        && (kind == PersonalSecretKind::Generic || id == "password" || id == "passphrase")
}

impl DesktopView {
    pub(super) fn copy_personal_value(
        &mut self,
        value: String,
        field: CopiedField,
        cx: &mut Context<Self>,
    ) {
        static NEXT_COPY: AtomicU64 = AtomicU64::new(0);
        let copy = NEXT_COPY.fetch_add(1, Ordering::Relaxed);
        let marker = format!("factorseal:{}:{copy}", std::process::id());
        cx.write_to_clipboard(gpui::ClipboardItem::new_string_with_metadata(
            value,
            marker.clone(),
        ));
        self.copied_personal_field = Some(field);
        self.clipboard_notice = Some(copy);
        cx.notify();
        cx.spawn(async move |view, cx| {
            smol::Timer::after(std::time::Duration::from_secs(2)).await;
            let _ = view.update(cx, |view, cx| {
                if view.copied_personal_field == Some(field) {
                    view.copied_personal_field = None;
                    cx.notify();
                }
            });
        })
        .detach();
        // Only clear our own clipboard entry; preserve anything copied afterwards.
        cx.spawn(async move |view, cx| {
            smol::Timer::after(CLIPBOARD_CLEAR_DELAY).await;
            cx.update(|cx| {
                if cx
                    .read_from_clipboard()
                    .as_ref()
                    .and_then(gpui::ClipboardItem::metadata)
                    == Some(&marker)
                {
                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(String::new()));
                }
            });
            let _ = view.update(cx, |view, cx| view.dismiss_clipboard_notice(copy, cx));
        })
        .detach();
    }

    fn dismiss_clipboard_notice(&mut self, copy: u64, cx: &mut Context<Self>) {
        if self.clipboard_notice == Some(copy) {
            self.clipboard_notice = None;
            cx.notify();
        }
    }

    pub(super) fn render_notices(&self, cx: &mut Context<Self>) -> Option<Div> {
        if self.clipboard_notice.is_none() && self.change_toast.is_none() {
            return None;
        }
        Some(
            v_flex()
                .absolute()
                .left_0()
                .right_0()
                .bottom(rems(8. / 16.))
                .items_center()
                .gap_2()
                .children(self.render_change_toast(cx))
                .children(self.render_clipboard_notice(cx)),
        )
    }

    fn notice(cx: &App) -> Div {
        let theme = cx.theme();
        h_flex()
            .relative()
            .items_center()
            .gap_2()
            .pl_3()
            .pr_1()
            .py_1()
            .rounded_md()
            .overflow_hidden()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .text_color(theme.popover_foreground)
            .shadow_md()
            .text_caption()
    }

    fn render_change_toast(&self, cx: &mut Context<Self>) -> Option<Div> {
        let toast = self.change_toast.as_ref()?;
        let theme = cx.theme();
        let undo = toast.undo;
        Some(
            Self::notice(cx)
                .child(if toast.error {
                    Icon::new(IconName::CircleX)
                        .small()
                        .text_color(theme.danger)
                } else {
                    Icon::new(IconName::Check).small().text_color(theme.success)
                })
                .child(toast.message.clone())
                .when_some(undo, |notice, direction| {
                    notice.child(
                        Button::new("personal-change-toast")
                            .ghost()
                            .xsmall()
                            .label(match direction {
                                personal_history::Direction::Undo => "Undo",
                                personal_history::Direction::Redo => "Redo",
                            })
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.step_personal_history(direction, cx);
                            })),
                    )
                })
                .child(
                    Button::new("dismiss-change-toast")
                        .ghost()
                        .xsmall()
                        .icon(IconName::Close)
                        .tooltip("Dismiss")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.change_toast = None;
                            cx.notify();
                        })),
                ),
        )
    }

    fn render_clipboard_notice(&self, cx: &mut Context<Self>) -> Option<Div> {
        let copy = self.clipboard_notice?;
        let theme = cx.theme();
        Some(
            Self::notice(cx)
                .child(Icon::new(IconName::Check).small().text_color(theme.success))
                .child("Copied to clipboard")
                .child(div().text_color(theme.muted_foreground).with_animation(
                    ("clipboard-clear-text", copy),
                    Animation::new(CLIPBOARD_CLEAR_DELAY).with_max_fps(30.),
                    |text, elapsed| text.child(clipboard_clear_text(seconds_left(elapsed))),
                ))
                .child(
                    Button::new("dismiss-clipboard-notice")
                        .ghost()
                        .xsmall()
                        .icon(IconName::Close)
                        .tooltip("Dismiss")
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.dismiss_clipboard_notice(copy, cx);
                        })),
                )
                .child(
                    div()
                        .absolute()
                        .left_0()
                        .bottom_0()
                        .h(px(2.))
                        .bg(theme.primary)
                        .with_animation(
                            ("clipboard-clear", copy),
                            Animation::new(CLIPBOARD_CLEAR_DELAY).with_max_fps(30.),
                            |fill, elapsed| fill.w(relative(1. - elapsed)),
                        ),
                ),
        )
    }
}

fn seconds_left(elapsed: f32) -> u64 {
    let left = CLIPBOARD_CLEAR_DELAY.mul_f32(1. - elapsed);
    left.as_secs() + u64::from(left.subsec_nanos() > 0)
}

fn clipboard_clear_text(seconds: u64) -> String {
    if seconds == 1 {
        "Clears in 1 second".into()
    } else {
        format!("Clears in {seconds} seconds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_notice_counts_down_to_the_clear() {
        assert_eq!(
            clipboard_clear_text(seconds_left(0.)),
            "Clears in 30 seconds"
        );
        assert_eq!(
            clipboard_clear_text(seconds_left(0.5)),
            "Clears in 15 seconds"
        );
        assert_eq!(
            clipboard_clear_text(seconds_left(0.99)),
            "Clears in 1 second"
        );
    }

    #[test]
    fn generation_is_available_for_passwords_but_not_external_credentials() {
        assert!(can_generate_value(
            PersonalSecretKind::Login,
            &PersonalFieldType::Concealed,
            "password"
        ));
        assert!(can_generate_value(
            PersonalSecretKind::SshKey,
            &PersonalFieldType::Concealed,
            "passphrase"
        ));
        assert!(can_generate_value(
            PersonalSecretKind::Generic,
            &PersonalFieldType::Concealed,
            "custom"
        ));
        assert!(!can_generate_value(
            PersonalSecretKind::Login,
            &PersonalFieldType::Text,
            "username"
        ));
        assert!(!can_generate_value(
            PersonalSecretKind::Login,
            &PersonalFieldType::Totp,
            "totp"
        ));
        assert!(!can_generate_value(
            PersonalSecretKind::Card,
            &PersonalFieldType::Concealed,
            "cvv"
        ));
        assert!(!can_generate_value(
            PersonalSecretKind::ApiCredential,
            &PersonalFieldType::Concealed,
            "credential"
        ));
    }
}
