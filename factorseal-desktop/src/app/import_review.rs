use std::collections::HashMap;

use factorseal::transfer::{
    UnusableData,
    import_plan::{ImportChange, ImportChoice, ImportComparison, ImportValue, ReviewItem},
};

use super::*;
use crate::runtime::{ReviewedImport, TransferSummary};

#[derive(Clone, Copy)]
enum ReviewRow {
    Group(bool),
    Item(usize),
}

pub(super) struct ImportReview {
    prepared: Option<ReviewedImport>,
    items: Vec<ReviewItem>,
    choices: Vec<ImportChoice>,
    details: HashMap<usize, Vec<ImportComparison>>,
    order: Vec<usize>,
    visible: Vec<usize>,
    rows: Vec<ReviewRow>,
    list: gpui::ListState,
    pub(super) focus_search: bool,
    is_restore: bool,
    file_name: Option<String>,
    #[cfg(feature = "apple-credential-exchange")]
    pub(super) system: Option<u64>,
}

impl ImportReview {
    pub(super) fn new(
        prepared: ReviewedImport,
        is_restore: bool,
        file_name: Option<String>,
    ) -> Self {
        let items = prepared.items().to_vec();
        let choices = items
            .iter()
            .map(|item| {
                if item.existing {
                    ImportChoice::Skip
                } else {
                    ImportChoice::Add
                }
            })
            .collect();
        let mut order: Vec<_> = (0..items.len()).collect();
        order.sort_by_cached_key(|&index| {
            vault_entry_label(&items[index].item.metadata)
                .0
                .to_lowercase()
        });
        let mut review = Self {
            prepared: Some(prepared),
            items,
            choices,
            details: HashMap::new(),
            order,
            visible: Vec::new(),
            rows: Vec::new(),
            list: gpui::ListState::new(0, gpui::ListAlignment::Top, px(400.)),
            focus_search: true,
            is_restore,
            file_name,
            #[cfg(feature = "apple-credential-exchange")]
            system: None,
        };
        review.filter("");
        review
    }

    pub(super) fn filter(&mut self, query: &str) {
        let query = query.trim().to_lowercase();
        self.visible = self
            .order
            .iter()
            .copied()
            .filter(|&index| {
                let metadata = &self.items[index].item.metadata;
                let (title, _) = vault_entry_label(metadata);
                [
                    Some(title.as_str()),
                    metadata.display_username.as_deref(),
                    metadata.display_website.as_deref(),
                ]
                .into_iter()
                .flatten()
                .any(|value| value.to_lowercase().contains(&query))
            })
            .collect();
        self.details.clear();
        self.rows.clear();
        for existing in [false, true] {
            let group: Vec<_> = self
                .visible
                .iter()
                .copied()
                .filter(|&index| self.items[index].existing == existing)
                .collect();
            if !group.is_empty() {
                self.rows.push(ReviewRow::Group(existing));
                self.rows.extend(group.into_iter().map(ReviewRow::Item));
            }
        }
        self.list.reset(self.rows.len());
    }

    #[cfg(feature = "apple-credential-exchange")]
    pub(super) fn system(prepared: ReviewedImport, generation: u64) -> Self {
        Self {
            system: Some(generation),
            ..Self::new(prepared, false, None)
        }
    }

    pub(super) fn scroll(&self, forward: bool) {
        self.list.scroll_by(px(if forward { 80. } else { -80. }));
    }

    fn counts(&self) -> (usize, usize, usize) {
        let added = self
            .choices
            .iter()
            .filter(|choice| **choice == ImportChoice::Add)
            .count();
        let replaced = self
            .choices
            .iter()
            .filter(|choice| **choice == ImportChoice::Replace)
            .count();
        (added, replaced, self.choices.len() - added - replaced)
    }
}

pub(super) const fn retained_label(data: UnusableData) -> &'static str {
    match data {
        UnusableData::Passkeys => "Passkeys",
        UnusableData::PasswordHistory => "Password history",
        UnusableData::WebsiteMatching => "Website match rules",
        UnusableData::PasswordReprompt => "Password re-prompt settings",
        UnusableData::FieldTypes => "Custom field types",
        UnusableData::Other => "Other source data",
    }
}

fn change_label(change: &ImportChange) -> &str {
    match change {
        ImportChange::Title => "Title",
        ImportChange::Kind => "Item type",
        ImportChange::Notes => "Notes",
        ImportChange::Folder => "Folder",
        ImportChange::Tags => "Tags",
        ImportChange::Favorite => "Favorite",
        ImportChange::Archived => "Archived",
        ImportChange::Source => "Saved source data",
        ImportChange::Field(label) => label,
        ImportChange::OtherFields => "Other fields",
    }
}

pub(super) fn render_saved_data(data: &[UnusableData], guide: bool, cx: &App) -> Div {
    let names = data
        .iter()
        .copied()
        .map(retained_label)
        .collect::<Vec<_>>()
        .join(", ");
    v_flex().gap_1().w_full().min_w_0()
        .child(div().font_semibold().child("Saved with this item"))
        .child(div().whitespace_normal().text_color(cx.theme().muted_foreground).child(if guide {
            format!("FactorSeal will keep this data with the item, but cannot use it yet: {names}.")
        } else { names }))
}

impl DesktopView {
    pub(super) fn open_import_review(&mut self, review: ImportReview) {
        self.transfer_busy = false;
        self.transfer_notice = None;
        if self.is_unsealed() {
            self.import_review = Some(review);
        }
    }

    pub(super) fn cancel_import_review(&mut self, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        #[cfg(feature = "apple-credential-exchange")]
        if self
            .import_review
            .as_ref()
            .is_some_and(|review| review.system.is_some())
        {
            self.cancel_system_transfer();
        }
        self.import_review = None;
        self.transfer_notice = None;
        cx.notify();
    }

    fn choose_import_items(&mut self, indices: &[usize], selected: bool, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        if let Some(review) = &mut self.import_review {
            for &index in indices {
                review.choices[index] = if !selected
                    || (review.items[index].existing && review.items[index].changes.is_empty())
                {
                    ImportChoice::Skip
                } else if review.items[index].existing {
                    ImportChoice::Replace
                } else {
                    ImportChoice::Add
                };
            }
        }
        cx.notify();
    }

    fn confirm_import_review(&mut self, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let Some(review) = &mut self.import_review else {
            return;
        };
        let (added, replaced, _) = review.counts();
        if added + replaced == 0 {
            return;
        }
        let Some(prepared) = review.prepared.take() else {
            return;
        };
        let choices = review.choices.clone();
        let restore = review.is_restore;
        #[cfg(feature = "apple-credential-exchange")]
        let system = review.system;
        let generation = self.transfer_generation;
        review.details.clear();
        self.transfer_busy = true;
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |view, cx| {
            let result =
                smol::unblock(move || runtime.commit_import(&metadata, prepared, &choices))
                    .await
                    .map(|(summary, contents)| TransferCompletion {
                        summary: Some(summary),
                        contents: Some(contents),
                        path: std::path::PathBuf::default(),
                    });
            let _ = view.update(cx, |view, cx| {
                if view.transfer_generation != generation || !view.is_unsealed() {
                    return;
                }
                #[cfg(feature = "apple-credential-exchange")]
                if let Some(generation) = system
                    && !view.finish_system_import(generation)
                {
                    return;
                }
                view.import_review = None;
                view.finish_transfer(true, restore, result);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn render_import_review(
        &self,
        review: &ImportReview,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let mut page = v_flex().size_full().min_w_0().min_h_0().gap_3()
            .child(div().text_title().font_semibold().child(if review.is_restore { "Review restore" } else { "Review import" }))
            .when_some(review.file_name.clone(), |page, name| page.child(div().truncate().text_color(theme.muted_foreground).child(name)))
            .child(div().whitespace_normal().text_color(theme.muted_foreground).child("Choose what to add. Existing items stay unchanged unless you choose Replace."))
            .when(!review.items.is_empty(), |page| page.child(Input::new(&self.import_search).w_full()));
        if review.visible.is_empty() {
            page = page.child(if review.items.is_empty() {
                "No items in this file."
            } else {
                "No items match your search."
            });
        }
        if let Some(TransferNotice::Error(message)) = &self.transfer_notice {
            page = page.child(error_banner(message.clone(), theme.danger));
        }
        let view = cx.entity().downgrade();
        page = page.child(
            div()
                .flex_1()
                .min_h_0()
                .w_full()
                .relative()
                .child(
                    gpui::list(review.list.clone(), move |position, _, cx| {
                        view.update(cx, |view, cx| {
                            let Some(review) = &view.import_review else {
                                return div().into_any_element();
                            };
                            let row = match review.rows.get(position) {
                                Some(ReviewRow::Group(existing)) => {
                                    view.render_import_group(review, *existing, cx)
                                }
                                Some(ReviewRow::Item(index)) => {
                                    view.render_import_row(review, *index, cx)
                                }
                                None => div(),
                            };
                            div().w_full().child(row).into_any_element()
                        })
                        .unwrap_or_else(|_| div().into_any_element())
                    })
                    .size_full(),
                )
                .vertical_scrollbar(&review.list),
        );
        page.child(
            div()
                .text_color(theme.muted_foreground)
                .whitespace_normal()
                .child(
                    "Keep your old vault until you have checked your important logins and codes.",
                ),
        )
        .child(self.render_import_footer(review, cx))
    }

    fn render_import_footer(&self, review: &ImportReview, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let (added, replaced, skipped) = review.counts();
        let count = added + replaced;
        let action = if review.is_restore {
            "Restore"
        } else {
            "Import"
        };
        let label = if self.transfer_busy {
            if review.is_restore {
                "Restoring…"
            } else {
                "Importing…"
            }
            .to_owned()
        } else {
            format!(
                "{action} {count} {}",
                if count == 1 { "item" } else { "items" }
            )
        };
        v_flex()
            .w_full()
            .pt_3()
            .border_t_1()
            .border_color(theme.border)
            .gap_2()
            .when(count == 0 && !review.items.is_empty(), |footer| {
                footer.child(
                    div()
                        .text_color(theme.muted_foreground)
                        .child("Select at least one item to continue."),
                )
            })
            .child(
                h_flex()
                    .w_full()
                    .flex_wrap()
                    .justify_between()
                    .gap_3()
                    .child(div().flex_1().min_w(px(180.)).child(format!(
                        "{added} to add · {replaced} to replace · {skipped} skipped"
                    )))
                    .child(
                        button("cancel-import-review")
                            .label("Cancel")
                            .disabled(self.transfer_busy)
                            .on_click(cx.listener(|view, _, _, cx| view.cancel_import_review(cx))),
                    )
                    .child(
                        button("confirm-import-review")
                            .primary()
                            .label(label)
                            .loading(self.transfer_busy)
                            .disabled(self.transfer_busy || count == 0)
                            .on_click(cx.listener(|view, _, _, cx| view.confirm_import_review(cx))),
                    ),
            )
    }

    fn render_import_group(
        &self,
        review: &ImportReview,
        existing: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let group: Vec<_> = review
            .visible
            .iter()
            .copied()
            .filter(|&index| {
                review.items[index].existing == existing
                    && (!existing || !review.items[index].changes.is_empty())
            })
            .collect();
        let selected = group
            .iter()
            .all(|&index| review.choices[index] != ImportChoice::Skip);
        v_flex()
            .w_full()
            .pt_3()
            .pb_2()
            .gap_2()
            .child(
                h_flex()
                    .w_full()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap_2()
                    .child(div().font_semibold().child(if existing {
                        "Already in your vault"
                    } else {
                        "New items"
                    }))
                    .when(!group.is_empty(), |header| {
                        header.child(
                            button(if existing {
                                "select-existing-import"
                            } else {
                                "select-new-import"
                            })
                            .small()
                            .ghost()
                            .label(match (existing, selected) {
                                (true, true) => "Keep all",
                                (true, false) => "Replace all",
                                (false, true) => "Deselect all",
                                (false, false) => "Select all",
                            })
                            .disabled(self.transfer_busy)
                            .on_click(cx.listener(
                                move |view, _, _, cx| {
                                    view.choose_import_items(&group, !selected, cx);
                                },
                            )),
                        )
                    }),
            )
            .when(existing, |group| {
                group.child(
                    div()
                        .text_color(cx.theme().muted_foreground)
                        .whitespace_normal()
                        .child(
                            "Replace uses the whole incoming item, including its fields and notes.",
                        ),
                )
            })
    }

    fn show_import_details(
        &mut self,
        index: usize,
        revealed: Option<Vec<usize>>,
        cx: &mut Context<Self>,
    ) {
        if self.transfer_busy {
            return;
        }
        let Some(review) = &mut self.import_review else {
            return;
        };
        let opening = revealed.is_some() && !review.details.contains_key(&index);
        self.transfer_notice = None;
        if let Some(revealed) = revealed {
            let Some(prepared) = &review.prepared else {
                return;
            };
            match prepared.comparisons(index, &revealed) {
                Ok(details) => {
                    review.details.insert(index, details);
                }
                Err(error) => {
                    self.transfer_notice = Some(TransferNotice::Error(error.to_string()));
                }
            }
        } else {
            review.details.remove(&index);
        }
        if let Some(position) = review
            .rows
            .iter()
            .position(|row| matches!(row, ReviewRow::Item(candidate) if *candidate == index))
        {
            review.list.splice(position..position + 1, 1);
            if opening {
                review.list.scroll_to(gpui::ListOffset {
                    item_ix: position,
                    offset_in_item: px(0.),
                });
            }
        }
        cx.notify();
    }

    fn render_import_row(
        &self,
        review: &ImportReview,
        index: usize,
        cx: &mut Context<Self>,
    ) -> Div {
        let item = &review.items[index];
        let metadata = &item.item.metadata;
        let (title, kind) = vault_entry_label(metadata);
        let expanded = review.details.contains_key(&index);
        let unchanged = item.existing && item.changes.is_empty();
        let theme = cx.theme().clone();
        let action = if item.existing { "Replace" } else { "Import" };
        let heading = h_flex()
            .w_full()
            .min_w_0()
            .items_start()
            .gap_3()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .whitespace_normal()
                    .font_semibold()
                    .child(title.clone()),
            )
            .child(
                div()
                    .text_color(theme.muted_foreground)
                    .child(if unchanged { "No changes" } else { action }),
            );
        let row = v_flex()
            .w_full()
            .min_w_0()
            .gap_1()
            .px_3()
            .py_3()
            .border_b_1()
            .border_color(theme.border);
        let row = if unchanged {
            row.child(div().pl_6().py_1().child(heading))
        } else {
            row.child(
                Checkbox::new(("choose-import-item", index))
                    .w_full()
                    .items_start()
                    .py_1()
                    .accessibility_label(format!("{action} {title}"))
                    .checked(review.choices[index] != ImportChoice::Skip)
                    .child(heading)
                    .disabled(self.transfer_busy)
                    .on_click(cx.listener(move |view, selected: &bool, _, cx| {
                        view.choose_import_items(&[index], *selected, cx);
                    })),
            )
        };
        row.child(v_flex().w_full().min_w_0().pl_6().gap_1()
            .child(div().whitespace_normal().text_color(theme.muted_foreground).child(
                [metadata.display_username.clone(), metadata.display_website.clone(), Some(kind)]
                    .into_iter().flatten().filter(|value| !value.is_empty()).collect::<Vec<_>>().join(" · ")
            ))
            .when(!item.item.unusable.is_empty(), |body| {
                let names = item.item.unusable.iter().copied().map(retained_label).collect::<Vec<_>>().join(", ");
                body.child(div().pt_1().whitespace_normal().text_color(theme.muted_foreground).child(
                    format!("FactorSeal will keep this data with the item, but cannot use it yet: {names}.")
                ))
            })
            .when(!item.changes.is_empty(), |body| {
                body.child(button(("import-item-details", index)).self_start().ghost().small()
                    .icon(if expanded { IconName::ChevronUp } else { IconName::ChevronDown })
                    .label(if expanded { "Hide details" } else { "View details" })
                    .disabled(self.transfer_busy)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.show_import_details(index, (!expanded).then(Vec::new), cx);
                    })))
            })
            .when_some(review.details.get(&index), |body, details| {
                body.child(v_flex().w_full().min_w_0().gap_3().p_3().rounded_md().bg(theme.muted)
                    .children(details.iter().enumerate().map(|(position, comparison)| {
                        self.render_import_comparison(index, position, details, comparison, cx)
                    })))
            }))
    }

    fn render_import_comparison(
        &self,
        index: usize,
        position: usize,
        details: &[ImportComparison],
        comparison: &ImportComparison,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        let concealed = comparison.current.concealed || comparison.incoming.concealed;
        let visible = comparison.current.value.is_some() || comparison.incoming.value.is_some();
        let mut revealed: Vec<_> = details
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                (row.current.concealed || row.incoming.concealed)
                    && (row.current.value.is_some() || row.incoming.value.is_some())
            })
            .map(|(position, _)| position)
            .collect();
        if visible {
            revealed.retain(|value| *value != position);
        } else {
            revealed.push(position);
        }
        let label = match &comparison.section {
            Some(section) => format!("{section} · {}", change_label(&comparison.change)),
            None => change_label(&comparison.change).to_owned(),
        };
        v_flex()
            .w_full()
            .min_w_0()
            .gap_2()
            .when(position > 0, |row| {
                row.pt_3().border_t_1().border_color(theme.border)
            })
            .child(
                h_flex()
                    .w_full()
                    .flex_wrap()
                    .justify_between()
                    .gap_2()
                    .child(div().font_semibold().whitespace_normal().child(label))
                    .when(
                        concealed && (comparison.current.filled || comparison.incoming.filled),
                        |row| {
                            row.child(
                                button(gpui::SharedString::from(format!(
                                    "import-value-{index}-{position}"
                                )))
                                .small()
                                .ghost()
                                .label(if visible { "Hide value" } else { "Show value" })
                                .disabled(self.transfer_busy)
                                .on_click(cx.listener(
                                    move |view, _, _, cx| {
                                        view.show_import_details(index, Some(revealed.clone()), cx);
                                    },
                                )),
                            )
                        },
                    ),
            )
            .child(
                h_flex()
                    .w_full()
                    .items_start()
                    .flex_wrap()
                    .gap_3()
                    .child(Self::render_import_value(
                        "In your vault",
                        &comparison.current,
                        cx,
                    ))
                    .child(Self::render_import_value(
                        "Incoming item",
                        &comparison.incoming,
                        cx,
                    )),
            )
    }

    fn render_import_value(label: &'static str, value: &ImportValue, cx: &App) -> Div {
        let text = value.value.as_ref().map_or_else(
            || if value.filled { "Hidden" } else { "Empty" }.to_owned(),
            |value| String::from_utf8_lossy(value.expose()).into_owned(),
        );
        v_flex()
            .flex_1()
            .min_w(px(140.))
            .gap_1()
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(label),
            )
            .when_some(value.context.clone(), |cell, context| {
                cell.child(
                    div()
                        .text_sm()
                        .whitespace_normal()
                        .text_color(cx.theme().muted_foreground)
                        .child(context),
                )
            })
            .child(div().whitespace_normal().child(text))
    }

    pub(super) fn render_import_complete(
        restore: bool,
        summary: TransferSummary,
        cx: &mut Context<Self>,
    ) -> Div {
        v_flex().w_full().min_w_0().gap_4()
            .child(div().text_title().font_semibold().child(if restore { "Restore complete" } else { "Import complete" }))
            .child(format!("{} added · {} replaced · {} skipped", summary.added, summary.replaced, summary.skipped + summary.kept_existing))
            .when(summary.preserved_only > 0, |page| page.child(div().whitespace_normal().child("Some data was saved for safekeeping. You can review it in the imported items.")))
            .child(div().whitespace_normal().text_color(cx.theme().muted_foreground).child("Keep your old vault until you have checked your important logins and codes."))
            .child(h_flex().flex_wrap().gap_2()
                .child(button("import-another").label("Choose another file").on_click(cx.listener(|view, _, _, cx| { view.import_complete = None; cx.notify(); })))
                .child(button("import-done").primary().label("Done").on_click(cx.listener(|view, _, _, cx| view.show_personal_panel(PersonalPanel::Overview, cx)))))
    }
}
