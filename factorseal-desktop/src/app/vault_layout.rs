use super::*;

#[derive(Default)]
pub(super) struct Navigation {
    page: String,
    depth: u8,
    direction: i8,
}

impl Navigation {
    pub(super) fn visit(&mut self, page: String, depth: u8) {
        if self.page != page {
            self.direction = match depth.cmp(&self.depth) {
                std::cmp::Ordering::Less => -1,
                std::cmp::Ordering::Equal => 0,
                std::cmp::Ordering::Greater => 1,
            };
            self.page = page;
            self.depth = depth;
        }
    }

    fn animate<E: IntoElement + Styled + 'static>(&self, element: E) -> impl IntoElement {
        crate::motion::navigate(
            gpui::ElementId::Name(self.page.clone().into()),
            self.direction,
            element,
        )
    }
}

impl DesktopView {
    pub(super) fn current_list(&self) -> Option<VaultSelection> {
        if self.settings_open {
            None
        } else {
            list_selection(self.selected_vault_item.as_ref())
        }
    }

    pub(super) fn navigation_page(
        &self,
        compact: bool,
        single_pane: bool,
        cx: &App,
    ) -> (String, u8) {
        let searching = self.showing_search_results(cx);
        let opened = self.settings_open || self.selected_vault_item.is_some() || searching;
        let drilled = compact && self.shows_single_item();
        let section = self
            .on_section_page()
            .then(|| self.selected_section(cx))
            .flatten()
            .filter(|_| drilled);
        let page = format!(
            "page-{:?}-{}-{searching}-{drilled}-{section:?}",
            vault_page(self.selected_vault_item.as_ref(), self.personal_panel),
            self.settings_open,
        );
        (page, u8::from(single_pane && opened) + u8::from(drilled))
    }

    pub(super) fn shown_list(&self, compact: bool) -> Option<VaultSelection> {
        self.current_list()
            .filter(|_| !(compact && self.shows_single_item()))
    }

    pub(super) fn shows_single_item(&self) -> bool {
        if self.on_section_page() {
            return self.section_opened;
        }
        match &self.selected_vault_item {
            Some(VaultSelection::Entry(_)) => true,
            Some(VaultSelection::PersonalSecrets) => self.personal_panel == PersonalPanel::NewItem,
            _ => false,
        }
    }

    pub(super) fn list_header(title: &'static str, cx: &App) -> Div {
        let theme = cx.theme();
        h_flex()
            .flex_none()
            .w_full()
            .pt_6()
            .pb_4()
            .items_center()
            .justify_between()
            .gap_3()
            .px_4()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div()
                    .min_w_0()
                    .min_h_8()
                    .flex()
                    .items_center()
                    .text_heading()
                    .font_semibold()
                    .child(div().min_w_0().truncate().child(text("list-title", title))),
            )
    }

    pub(super) fn list_row(
        id: impl Into<gpui::ElementId>,
        selected: bool,
        cx: &App,
    ) -> gpui::Stateful<Div> {
        let theme = cx.theme();
        // A button for screen readers; callers name it with `aria_label`.
        h_flex()
            .id(id)
            .role(gpui::Role::Button)
            .relative()
            .w_full()
            .items_center()
            .gap_2()
            .px_4()
            .py_2p5()
            .border_b_1()
            .border_color(theme.border)
            .fill_control(selected, cx)
            .tab_stop(false)
            .when(selected, |row| row.bg(theme.list_active))
    }

    pub(super) fn render_sidebar_brand(cx: &mut Context<Self>) -> impl IntoElement {
        let foreground = cx.theme().foreground;
        div().flex_none().px_3().pt_5().child(
            breadcrumb::crumb_link("vault-home", "Back to your vault", cx)
                .h_flex()
                .w_full()
                .mx_0()
                .px_0()
                .items_center()
                .gap_1()
                .child(div().ml(rems(-0.325)).child(brand_mark(52., foreground)))
                .child(
                    div()
                        .text_size(rems(1.95))
                        .line_height(rems(2.25))
                        .font_semibold()
                        .child(text("factorseal", "FactorSeal")),
                )
                .on_click(cx.listener(|view, _, _, cx| view.show_vault_browser(cx))),
        )
    }

    pub(super) fn render_sidebar_nav(&self, cx: &mut Context<Self>) -> gpui::Stateful<Div> {
        let muted = cx.theme().muted_foreground;
        let selected = |selection: &VaultSelection| {
            !self.settings_open && self.selected_vault_item.as_ref() == Some(selection)
        };
        let page = |id: &'static str,
                    icon: gpui_component::Icon,
                    name: &'static str,
                    selection: VaultSelection| {
            let disabled = self.transfer_busy
                && matches!(
                    selection,
                    VaultSelection::TransferCredentials | VaultSelection::BackupVault
                );
            sidebar_item(id, selected(&selection), cx)
                .aria_label(name)
                .when(disabled, |item| item.text_color(muted))
                .child(sidebar_label(icon, name))
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.select_vault_item(selection.clone(), cx);
                }))
        };
        v_flex()
            .id("vault-pages")
            .role(gpui::Role::TabList)
            .aria_label("Pages")
            .flex_none()
            .gap_1()
            .px_3()
            .child(page(
                "vault-devices",
                IconName::Network.into(),
                "Devices",
                VaultSelection::Devices,
            ))
            .child(page(
                "transfer-credentials",
                Glyph::Transfer.into(),
                "Transfer credentials",
                VaultSelection::TransferCredentials,
            ))
            .child(page(
                "backup-vault",
                IconName::HardDrive.into(),
                "Back up vault",
                VaultSelection::BackupVault,
            ))
            .child(
                sidebar_item("open-settings", self.settings_open, cx)
                    .aria_label("Settings")
                    .child(sidebar_label(IconName::Settings, "Settings"))
                    .on_click(cx.listener(|view, _, _, cx| view.open_settings(cx))),
            )
    }

    pub(super) fn render_sidebar_footer(&self, cx: &mut Context<Self>) -> Div {
        let Snapshot::Unsealed {
            idle_deadline,
            absolute_deadline,
            owned,
            ..
        } = &self.snapshot
        else {
            return div();
        };
        let theme = cx.theme().clone();
        let tooltip =
            format!("Idle deadline: {idle_deadline}\nAbsolute deadline: {absolute_deadline}");
        h_flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap_2()
            .mx_3()
            .px_3()
            .py_3()
            .border_t_1()
            .border_color(theme.sidebar_border)
            .child(
                h_flex()
                    .id("unsealed-status")
                    .min_w_0()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_none()
                            .w(rems(8. / 16.))
                            .h(rems(8. / 16.))
                            .rounded_full()
                            .bg(theme.success),
                    )
                    .child(
                        div()
                            .min_w_0()
                            .truncate()
                            .child(text("unsealed", "Unsealed")),
                    )
                    .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx)),
            )
            .child(
                button("seal-vault")
                    .flex_none()
                    .small()
                    .icon(Glyph::Lock)
                    .label("Seal")
                    .disabled(!*owned)
                    .on_click(cx.listener(|view, _, _, cx| view.seal(cx))),
            )
    }

    fn render_list_header(
        list: &VaultSelection,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> Div {
        if let VaultSelection::Category(kind) = list {
            Self::list_header(category_guidance(*kind).title, cx)
        } else {
            let has_items = contents.entries.iter().any(is_personal_secret);
            Self::list_header("Personal secrets", cx).when(has_items, |header| {
                header.child(
                    button("new-personal-secret")
                        .flex_none()
                        .primary()
                        .icon(IconName::Plus)
                        .tooltip("New item")
                        .accessibility_label("New item")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.show_personal_panel(PersonalPanel::NewItem, cx);
                        })),
                )
            })
        }
    }

    fn render_list_rows(
        &self,
        list: &VaultSelection,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> Div {
        let entries: Vec<_> = if let VaultSelection::Category(kind) = list {
            category_entries(&contents.entries, *kind).collect()
        } else {
            sorted_personal_entries(&contents.entries, "")
        };
        if !entries.is_empty() {
            return self.render_entry_rows(&entries, "", cx);
        }
        let icon = Self::empty_list_icon(cx);
        if matches!(list, VaultSelection::Category(_)) {
            Self::empty_state(icon, "No items yet", "Follow the steps to add one.", cx)
        } else {
            Self::empty_state(
                icon,
                "No personal secrets yet",
                "Add a login or a note, or import from another password manager.",
                cx,
            )
            .child(self.render_empty_vault_actions(cx))
        }
    }

    fn render_search_results(&self, contents: &VaultContents, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let highlight = theme.warning.opacity(0.35);
        let query = self.search_query(cx);
        let results = search_results(&contents.entries, &query);
        let result_count: usize = results.iter().map(|(_, entries)| entries.len()).sum();
        let cursor = self.search_cursor.min(result_count.saturating_sub(1));
        let mut list = v_flex()
            .id("vault-search-results")
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.search_scroll);
        let mut first_index = 0;
        for (group_index, (title, entries)) in results.iter().enumerate() {
            for (index, entry) in entries.iter().enumerate() {
                let row_index = first_index + index;
                let selected = is_selected_entry(self.selected_vault_item.as_ref(), entry);
                let row = self
                    .render_entry_row(entry, &query, cx)
                    .when(row_index == cursor, |row| row.keyboard_cursor(selected, cx));
                list = list.child(
                    v_flex()
                        .flex_none()
                        .when(index == 0, |group| {
                            group.child(
                                div()
                                    .px_4()
                                    .pb_2()
                                    .when(group_index > 0, gpui::Styled::pt_4)
                                    .when(group_index == 0, gpui::Styled::pt_3)
                                    .border_b_1()
                                    .border_color(theme.border)
                                    .text_caption()
                                    .font_semibold()
                                    .text_color(theme.muted_foreground)
                                    .child(highlighted_text(
                                        (*title).to_owned(),
                                        &query,
                                        highlight,
                                    )),
                            )
                        })
                        .child(row),
                );
            }
            first_index += entries.len();
        }
        if results.is_empty() {
            list = list.child(self.render_entry_rows(&[], &query, cx).flex_none());
        }
        v_flex()
            .size_full()
            .child(
                h_flex()
                    .flex_none()
                    .w_full()
                    .pt_6()
                    .pb_4()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .px_4()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .min_w_0()
                            .truncate()
                            .text_heading()
                            .font_semibold()
                            .child(text("search-results", "Search results")),
                    )
                    .child(
                        div()
                            .flex_none()
                            .px_2()
                            .py(rems(2. / 16.))
                            .rounded_full()
                            .bg(theme.muted)
                            .text_body()
                            .text_color(theme.muted_foreground)
                            .child(text(
                                "result-count",
                                format!(
                                    "{result_count} {}",
                                    if result_count == 1 { "item" } else { "items" }
                                ),
                            )),
                    ),
            )
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(list)
                    .vertical_scrollbar(&self.search_scroll),
            )
    }

    fn render_vault_page_content(
        &self,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let detail = self.render_vault_detail(contents, cx);
        if self.shortcuts.compact {
            return detail.into_any_element();
        }
        crate::motion::enter(
            format!(
                "vault-page-{:?}",
                vault_page(self.selected_vault_item.as_ref(), self.personal_panel)
            ),
            detail,
        )
        .into_any_element()
    }

    fn render_detail_pane(&self, contents: &VaultContents, cx: &mut Context<Self>) -> Div {
        let scrolls_itself = match &self.selected_vault_item {
            Some(VaultSelection::PersonalSecrets) => self.personal_panel == PersonalPanel::NewItem,
            Some(VaultSelection::Entry(entry)) => is_personal_secret(entry),
            _ => false,
        };
        let detail = self.render_vault_page_content(contents, cx);
        div().flex_1().min_w_0().min_h_0().h_full().map(|pane| {
            if scrolls_itself {
                pane.child(
                    div()
                        .id("vault-detail")
                        .size_full()
                        .overflow_hidden()
                        .child(detail),
                )
            } else {
                pane.child(self.scroll_detail(detail))
            }
        })
    }

    fn render_vault_main(
        &self,
        contents: &VaultContents,
        compact: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        if self.on_section_page() {
            return self.render_section_layout(compact, cx);
        }
        let theme = cx.theme().clone();
        if self.showing_search_results(cx) {
            return if compact && self.shows_single_item() {
                self.render_detail_pane(contents, cx)
            } else if compact {
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .h_full()
                    .child(self.render_search_results(contents, cx))
            } else {
                h_flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(
                        div()
                            .w(rems(280. / 16.))
                            .flex_none()
                            .h_full()
                            .border_r_1()
                            .border_color(theme.border)
                            .child(crate::motion::fade(
                                "search-results",
                                self.render_search_results(contents, cx),
                            )),
                    )
                    .child(self.render_detail_pane(contents, cx))
            };
        }
        match self.shown_list(compact) {
            None => self.render_detail_pane(contents, cx),
            Some(list) if compact => div().flex_1().min_w_0().min_h_0().h_full().child(
                self.scroll_list(
                    v_flex()
                        .w_full()
                        .child(Self::render_list_header(&list, contents, cx))
                        .child(self.render_list_rows(&list, contents, cx))
                        .child(self.render_vault_page_content(contents, cx)),
                ),
            ),
            Some(list) => h_flex()
                .flex_1()
                .min_w_0()
                .h_full()
                .child(
                    div()
                        .w(rems(280. / 16.))
                        .flex_none()
                        .h_full()
                        .border_r_1()
                        .border_color(theme.border)
                        .child(crate::motion::enter(
                            format!("vault-list-{list:?}"),
                            v_flex()
                                .size_full()
                                .child(Self::render_list_header(&list, contents, cx))
                                .child(div().flex_1().min_h_0().child(
                                    self.scroll_list(self.render_list_rows(&list, contents, cx)),
                                )),
                        )),
                )
                .child(self.render_detail_pane(contents, cx)),
        }
    }

    pub(super) fn render_vault_back(&self, search: bool, cx: &mut Context<Self>) -> Div {
        h_flex()
            .w_full()
            .flex_none()
            .items_center()
            .px_4()
            .py_2()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                button("vault-back")
                    .ghost()
                    .small()
                    .flex_none()
                    .icon(IconName::ChevronLeft)
                    .label("Back")
                    .on_click(cx.listener(|view, _, window, cx| {
                        if view.showing_search_results(cx) && !view.shows_single_item() {
                            view.clear_vault_search(window, cx);
                        } else {
                            view.show_vault_parent(cx);
                        }
                    })),
            )
            .when(search, |row| {
                row.child(div().flex_1().min_w_0().child(self.render_vault_search(cx)))
            })
    }

    pub(super) fn render_unsealed(
        &self,
        contents: &VaultContents,
        errors: (Option<&str>, Option<&str>),
        compact: bool,
        single_pane: bool,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let (contents_error, error) = errors;
        let panes = vault_panes(
            single_pane,
            self.settings_open
                || self.selected_vault_item.is_some()
                || self.showing_search_results(cx),
        );
        let back = panes == VaultPanes::Main || compact && self.shows_single_item();
        let vault = h_flex()
            .size_full()
            .when(panes != VaultPanes::Main, |vault| {
                vault.child(self.render_vault_sidebar(contents, panes == VaultPanes::Sidebar, cx))
            })
            .when(panes != VaultPanes::Sidebar, |vault| {
                let page = v_flex()
                    .size_full()
                    .when(back, |main| {
                        main.child(self.render_vault_back(panes == VaultPanes::Main, cx))
                    })
                    .child(
                        h_flex()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .child(self.render_vault_main(contents, compact, cx)),
                    )
                    .when_some(contents_error.map(str::to_owned), |main, error| {
                        main.child(
                            div()
                                .flex_none()
                                .px_6()
                                .py_3()
                                .text_color(theme.danger)
                                .child(text(
                                    "could-not-load-vault",
                                    format!("Could not load vault contents: {error}"),
                                )),
                        )
                    })
                    .when_some(error.map(str::to_owned), |main, error| {
                        main.child(
                            div()
                                .flex_none()
                                .px_6()
                                .py_3()
                                .text_color(theme.danger)
                                .child(text("error", error)),
                        )
                    });
                vault.child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .overflow_hidden()
                        .bg(theme.popover)
                        .map(|main| {
                            if compact && !single_pane {
                                main.child(self.navigation.animate(page))
                            } else {
                                main.child(page)
                            }
                        }),
                )
            });
        let vault = if single_pane {
            div()
                .size_full()
                .overflow_hidden()
                .child(self.navigation.animate(vault))
        } else {
            vault
        };
        vault.relative().when(self.qr_target().is_some(), |vault| {
            vault.child(Self::qr_drop_zone(cx))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_slide_forward_into_items_and_back_out_of_them() {
        let mut navigation = Navigation::default();
        navigation.visit("list".into(), 0);
        navigation.visit("item".into(), 1);
        assert_eq!(navigation.direction, 1);
        navigation.visit("item".into(), 1);
        assert_eq!(navigation.direction, 1);
        navigation.visit("list".into(), 0);
        assert_eq!(navigation.direction, -1);
        navigation.visit("other list".into(), 0);
        assert_eq!(navigation.direction, 0);
    }
}
