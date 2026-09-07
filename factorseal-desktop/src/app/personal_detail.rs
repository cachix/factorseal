use std::collections::HashSet;

use super::*;

#[derive(Default)]
pub(super) struct PersonalDetail {
    item: Option<PersonalSecret>,
    error: Option<String>,
    revealed: HashSet<usize>,
    generation: u64,
}

impl PersonalDetail {
    pub(super) fn clear(&mut self) {
        self.item = None;
        self.error = None;
        self.revealed.clear();
        self.generation = self.generation.wrapping_add(1);
    }
}

fn field_is_secret(field: &PersonalField) -> bool {
    field.concealed || field.field_type.concealed()
}

fn field_text(field: &PersonalField, revealed: bool) -> String {
    if field_is_secret(field) && !revealed {
        "••••••••".into()
    } else {
        field.text().map_or_else(
            || serde_json::to_string_pretty(&field.value).unwrap_or_default(),
            ToOwned::to_owned,
        )
    }
}

impl DesktopView {
    pub(super) fn load_personal_item(
        &mut self,
        entry: factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) {
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let runtime = Arc::clone(&self.runtime);
        let generation = self.personal_detail.generation;
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || runtime.read_personal_item(&metadata, &entry)).await;
            let _ = view.update(cx, |view, cx| {
                // Navigation or sealing invalidates an in-flight read.
                if view.personal_detail.generation != generation
                    || !matches!(view.snapshot, Snapshot::Unsealed { .. })
                {
                    return;
                }
                match result {
                    Ok(item) => view.personal_detail.item = Some(item),
                    Err(error) => view.personal_detail.error = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn render_personal_item(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let (title, kind) = vault_entry_label(entry);
        let mut panel = v_flex().w_full().gap_4().p_6().child(
            h_flex()
                .items_center()
                .flex_wrap()
                .gap_2()
                .text_xl()
                .font_semibold()
                .child(
                    div()
                        .id("personal-item-breadcrumb")
                        .cursor_pointer()
                        .hover(|style| style.text_color(theme.muted_foreground))
                        .child("Personal secrets")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.show_personal_panel(PersonalPanel::Overview, cx);
                        })),
                )
                .child(div().text_color(theme.muted_foreground).child("→"))
                .child(title)
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(kind),
                ),
        );
        if let Some(error) = &self.personal_detail.error {
            return panel.child(error_banner(error.clone(), theme.danger));
        }
        let Some(item) = &self.personal_detail.item else {
            return panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new().small())
                    .child("Loading item…"),
            );
        };
        let mut index = 0;
        for section in &item.sections {
            if !section.fields.is_empty() {
                panel = panel.child(div().font_semibold().child(section.label.clone()));
            }
            for field in &section.fields {
                panel = panel.child(self.render_personal_value(
                    index,
                    &field.label,
                    field_text(field, self.personal_detail.revealed.contains(&index)),
                    field_is_secret(field),
                    cx,
                ));
                index += 1;
            }
        }
        if let Some(notes) = &item.notes {
            let text = if self.personal_detail.revealed.contains(&index) {
                notes.clone()
            } else {
                "••••••••".into()
            };
            panel = panel.child(self.render_personal_value(index, "Notes", text, true, cx));
        }
        panel
    }

    fn copy_saved_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let fields: Vec<_> = item
            .sections
            .iter()
            .flat_map(|section| &section.fields)
            .collect();
        let value = if let Some(field) = fields.get(index) {
            field_text(field, true)
        } else if index == fields.len() {
            let Some(notes) = &item.notes else {
                return;
            };
            notes.clone()
        } else {
            return;
        };
        self.copy_personal_value(value, personal_actions::CopiedField::Saved(index), cx);
    }

    fn render_personal_value(
        &self,
        index: usize,
        label: &str,
        text: String,
        secret: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        v_flex()
            .gap_2()
            .p_3()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(label.to_owned()),
            )
            .child(
                h_flex()
                    .items_start()
                    .gap_3()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .whitespace_normal()
                            .child(if text.is_empty() {
                                "Not set".into()
                            } else {
                                text
                            }),
                    )
                    .child(
                        Button::new(("copy-personal-field", index))
                            .flex_none()
                            .small()
                            .label(
                                if self.copied_personal_field
                                    == Some(personal_actions::CopiedField::Saved(index))
                                {
                                    "Copied"
                                } else {
                                    "Copy"
                                },
                            )
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.copy_saved_personal_field(index, cx);
                            })),
                    )
                    .when(secret, |row| {
                        row.child(
                            Button::new(("reveal-personal-field", index))
                                .flex_none()
                                .small()
                                .label(if self.personal_detail.revealed.contains(&index) {
                                    "Hide"
                                } else {
                                    "Reveal"
                                })
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    if !view.personal_detail.revealed.remove(&index) {
                                        view.personal_detail.revealed.insert(index);
                                    }
                                    cx.notify();
                                })),
                        )
                    }),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concealed_values_only_appear_after_reveal() {
        let mut field = PersonalField::new(
            "password",
            "Password",
            PersonalFieldType::Concealed,
            "secret value",
        );
        assert_eq!(field_text(&field, false), "••••••••");
        assert_eq!(field_text(&field, true), "secret value");
        field.concealed = false;
        assert_eq!(field_text(&field, false), "••••••••");
        let mut field =
            PersonalField::new("username", "Username", PersonalFieldType::Text, "alice");
        assert_eq!(field_text(&field, false), "alice");
        field.concealed = true;
        assert_eq!(field_text(&field, false), "••••••••");
    }

    #[test]
    fn clearing_details_discards_values_reveals_and_pending_reads() {
        let mut detail = PersonalDetail {
            item: Some(PersonalSecret::generic("Test".into(), "secret".into())),
            ..PersonalDetail::default()
        };
        detail.revealed.insert(0);
        let generation = detail.generation;
        detail.clear();
        assert!(detail.item.is_none());
        assert!(detail.revealed.is_empty());
        assert_ne!(detail.generation, generation);
    }
}
