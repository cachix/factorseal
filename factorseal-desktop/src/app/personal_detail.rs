use std::collections::{HashMap, HashSet};

use super::*;

#[derive(Default)]
pub(super) struct PersonalDetail {
    item: Option<PersonalSecret>,
    error: Option<String>,
    revealed: HashSet<usize>,
    generation: u64,
    inputs: HashMap<usize, PersonalValueInput>,
    subscriptions: Vec<Subscription>,
}

struct PersonalValueInput {
    input: gpui::Entity<SecretInputState>,
    revision: u64,
    dirty: bool,
    error: Option<String>,
}

impl PersonalDetail {
    pub(super) fn has_pending_changes(&self) -> bool {
        self.inputs.values().any(|input| input.dirty)
    }

    pub(super) fn clear(&mut self) {
        self.subscriptions.clear();
        self.inputs.clear();
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

const NAME_INDEX: usize = usize::MAX;

fn edited_item(item: &PersonalSecret, index: usize, value: &str) -> Result<PersonalSecret, String> {
    let encoded = item.encode().map_err(|error| error.to_string())?;
    let mut updated =
        PersonalSecret::decode_current(&encoded).map_err(|error| error.to_string())?;
    if index == NAME_INDEX {
        if value.trim().is_empty() {
            return Err("Give this item a name.".into());
        }
        value.trim().clone_into(&mut updated.title);
    } else {
        let mut fields: Vec<_> = updated
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.fields)
            .collect();
        if let Some(field) = fields.get_mut(index) {
            field.value = if field.value.is_string() {
                serde_json::Value::String(value.to_owned())
            } else {
                serde_json::from_str(value)
                    .map_err(|_| "Enter valid JSON for this structured field.".to_owned())?
            };
        } else if index == fields.len() {
            updated.notes = (!value.is_empty()).then(|| value.to_owned());
        } else {
            return Err("This field is no longer available.".into());
        }
    }
    Ok(updated)
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
                    Ok(item) => {
                        view.initialize_personal_inputs(&item, cx);
                        view.personal_detail.item = Some(item);
                    }
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
            panel = panel.child(error_banner(error.clone(), theme.danger));
        }
        let Some(item) = &self.personal_detail.item else {
            return panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new().small())
                    .child("Loading item…"),
            );
        };
        panel = panel.child(self.render_personal_value(NAME_INDEX, "Name", false, cx));
        let mut index = 0;
        for section in &item.sections {
            if !section.fields.is_empty() {
                panel = panel.child(div().font_semibold().child(section.label.clone()));
            }
            for field in &section.fields {
                panel = panel.child(self.render_personal_value(
                    index,
                    &field.label,
                    field_is_secret(field),
                    cx,
                ));
                index += 1;
            }
        }
        panel = panel.child(self.render_personal_value(index, "Notes", true, cx));
        panel
    }

    fn initialize_personal_inputs(&mut self, item: &PersonalSecret, cx: &mut Context<Self>) {
        self.add_personal_input(NAME_INDEX, &item.title, false, cx);
        let mut index = 0;
        for field in item.sections.iter().flat_map(|section| &section.fields) {
            let value = Zeroizing::new(field_text(field, true));
            self.add_personal_input(index, &value, field_is_secret(field), cx);
            index += 1;
        }
        self.add_personal_input(index, item.notes.as_deref().unwrap_or_default(), true, cx);
    }

    fn add_personal_input(
        &mut self,
        index: usize,
        value: &str,
        masked: bool,
        cx: &mut Context<Self>,
    ) {
        let input = cx.new(|cx| SecretInputState::from_value(value, masked, cx));
        let subscription = cx.subscribe(&input, move |view, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                view.schedule_personal_save(index, cx);
            }
        });
        self.personal_detail.subscriptions.push(subscription);
        self.personal_detail.inputs.insert(
            index,
            PersonalValueInput {
                input,
                revision: 0,
                dirty: false,
                error: None,
            },
        );
    }

    fn schedule_personal_save(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(input) = self.personal_detail.inputs.get_mut(&index) else {
            return;
        };
        input.revision = input.revision.wrapping_add(1);
        input.dirty = true;
        input.error = None;
        let revision = input.revision;
        let generation = self.personal_detail.generation;
        self.copied_personal_field = None;
        cx.notify();
        cx.spawn(async move |view, cx| {
            smol::Timer::after(std::time::Duration::from_millis(500)).await;
            let _ = view.update(cx, |view, cx| {
                if view.personal_detail.generation == generation
                    && view
                        .personal_detail
                        .inputs
                        .get(&index)
                        .is_some_and(|input| input.dirty && input.revision == revision)
                    && matches!(view.snapshot, Snapshot::Unsealed { .. })
                {
                    view.save_personal_field(index, cx);
                }
            });
        })
        .detach();
    }

    pub(super) fn flush_personal_changes(&mut self, cx: &mut Context<Self>) -> bool {
        let dirty: Vec<_> = self
            .personal_detail
            .inputs
            .iter()
            .filter_map(|(index, input)| input.dirty.then_some(*index))
            .collect();
        for index in dirty {
            self.save_personal_field(index, cx);
        }
        !self.personal_detail.has_pending_changes()
    }

    fn save_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let result = if input.input.read(cx).allocation_failed() {
            Err("Could not allocate secure memory. Re-enter the value.".into())
        } else {
            edited_item(item, index, &input.input.read(cx).value()).and_then(|updated| {
                self.runtime
                    .put_personal_secret(&updated)
                    .map(|contents| (updated, contents))
            })
        };
        match result {
            Ok((updated, updated_contents)) => {
                if let Some(entry) = updated_contents.entries.iter().find(|entry| {
                    matches!(&self.selected_vault_item, Some(VaultSelection::Entry(selected)) if entry.address == selected.address && entry.partition == selected.partition)
                }) {
                    self.selected_vault_item = Some(VaultSelection::Entry(entry.clone()));
                }
                if let Snapshot::Unsealed {
                    contents,
                    contents_error,
                    ..
                } = &mut self.snapshot
                {
                    *contents = updated_contents;
                    *contents_error = None;
                }
                self.personal_detail.item = Some(updated);
                if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
                    input.dirty = false;
                    input.error = None;
                }
            }
            Err(error) => {
                if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
                    input.error = Some(format!("Not saved: {error}"));
                }
            }
        }
        cx.notify();
    }

    fn copy_saved_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        let value = input.input.read(cx).value().to_string();
        self.copy_personal_value(value, personal_actions::CopiedField::Saved(index), cx);
    }

    fn render_personal_value(
        &self,
        index: usize,
        label: &str,
        secret: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return div();
        };
        let value = div().flex_1().min_w_0().child(input.input.clone());
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
                    .child(value)
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
                                    if let Some(input) = view.personal_detail.inputs.get(&index) {
                                        input.input.update(cx, |input, cx| {
                                            input.set_masked(
                                                !view.personal_detail.revealed.contains(&index),
                                                cx,
                                            );
                                        });
                                    }
                                    cx.notify();
                                })),
                        )
                    }),
            )
            .when(input.revision > 0 || input.error.is_some(), |row| {
                row.child(
                    div()
                        .text_xs()
                        .text_color(if input.error.is_some() {
                            theme.danger
                        } else {
                            theme.muted_foreground
                        })
                        .child(input.error.clone().unwrap_or_else(|| {
                            if input.dirty {
                                "Saving…".into()
                            } else {
                                "Saved".into()
                            }
                        })),
                )
            })
            .when(input.error.is_some(), |row| {
                row.child(
                    Button::new(("retry-personal-save", index))
                        .small()
                        .label("Retry")
                        .on_click(
                            cx.listener(move |view, _, _, cx| view.save_personal_field(index, cx)),
                        ),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_preserves_identity_metadata_and_other_fields() {
        let mut original = PersonalSecret::generic("Test".into(), "secret".into());
        original.tags.push("work".into());
        original.favorite = true;
        original.source = Some(serde_json::json!({"imported": true}));
        original.sections[0].fields.push(PersonalField::new(
            "username",
            "Username",
            PersonalFieldType::Text,
            "alice",
        ));
        let updated = edited_item(&original, 0, "replacement").unwrap();
        let mut expected = serde_json::to_value(&original).unwrap();
        expected["sections"][0]["fields"][0]["value"] = "replacement".into();
        assert_eq!(serde_json::to_value(&updated).unwrap(), expected);
        assert_eq!(original.sections[0].fields[0].text(), Some("secret"));
        let renamed = edited_item(&updated, NAME_INDEX, " New name ").unwrap();
        assert_eq!(renamed.id, original.id);
        assert_eq!(renamed.title, "New name");
        assert!(edited_item(&updated, NAME_INDEX, "  ").is_err());
    }

    #[test]
    fn notes_and_structured_values_round_trip() {
        let mut original = PersonalSecret::generic("Test".into(), "secret".into());
        original.sections[0].fields[0].field_type = PersonalFieldType::Address;
        original.sections[0].fields[0].value = serde_json::json!({"street": "First"});
        assert!(edited_item(&original, 0, "invalid JSON").is_err());
        let updated = edited_item(&original, 0, r#"{"street":"Second"}"#).unwrap();
        assert_eq!(
            updated.sections[0].fields[0].value,
            serde_json::json!({"street": "Second"})
        );
        let updated = edited_item(&updated, 1, "Some notes").unwrap();
        assert_eq!(updated.notes.as_deref(), Some("Some notes"));
        assert!(edited_item(&updated, 1, "").unwrap().notes.is_none());
        assert!(edited_item(&updated, 2, "missing field").is_err());
    }

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
