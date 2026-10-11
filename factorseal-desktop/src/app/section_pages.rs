use crate::settings_view::Section;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SectionRow {
    Settings(Section),
    Transfer { import: bool },
    Backup { restore: bool },
    Device(usize),
}

pub(super) fn transfer_rows(backup: bool) -> [SectionRow; 2] {
    [false, true].map(|second| {
        if backup {
            SectionRow::Backup { restore: second }
        } else {
            SectionRow::Transfer { import: second }
        }
    })
}

impl SectionRow {
    fn title(self) -> &'static str {
        match self {
            Self::Settings(section) => section.label(),
            Self::Transfer { import: false } => "Export credentials",
            Self::Transfer { import: true } => "Import credentials",
            Self::Backup { restore: false } => "Create backup",
            Self::Backup { restore: true } => "Restore backup",
            Self::Device(_) => "",
        }
    }

    fn icon(self) -> gpui_component::Icon {
        match self {
            Self::Settings(section) => section.icon(),
            Self::Transfer { import: false } | Self::Backup { restore: false } => {
                Glyph::Download.into()
            }
            Self::Transfer { import: true } | Self::Backup { restore: true } => {
                Glyph::Upload.into()
            }
            Self::Device(_) => IconName::Network.into(),
        }
    }
}

impl DesktopView {
    pub(super) fn on_section_page(&self) -> bool {
        self.settings_open
            || matches!(
                self.selected_vault_item,
                Some(
                    VaultSelection::Devices
                        | VaultSelection::TransferCredentials
                        | VaultSelection::BackupVault
                )
            )
    }

    pub(super) fn section_rows(&self, cx: &App) -> Vec<SectionRow> {
        if self.settings_open {
            return Section::visible(self.browsers_available(cx))
                .into_iter()
                .map(SectionRow::Settings)
                .collect();
        }
        match self.selected_vault_item {
            Some(VaultSelection::TransferCredentials) => transfer_rows(false).to_vec(),
            Some(VaultSelection::BackupVault) => transfer_rows(true).to_vec(),
            Some(VaultSelection::Devices) => (0..self.device_list(cx).len())
                .map(SectionRow::Device)
                .collect(),
            _ => Vec::new(),
        }
    }

    fn selected_section(&self, cx: &App) -> Option<SectionRow> {
        if self.settings_open {
            let section = self.settings.read(cx).section(self.browsers_available(cx));
            return Some(SectionRow::Settings(section));
        }
        match self.selected_vault_item {
            Some(VaultSelection::TransferCredentials) => Some(SectionRow::Transfer {
                import: self.transfer_is_import,
            }),
            Some(VaultSelection::BackupVault) => Some(SectionRow::Backup {
                restore: self.transfer_is_import,
            }),
            Some(VaultSelection::Devices) => {
                let count = self.device_list(cx).len();
                (count > 0).then(|| SectionRow::Device(self.selected_device.min(count - 1)))
            }
            _ => None,
        }
    }

    pub(super) fn open_section(&mut self, row: SectionRow, cx: &mut Context<Self>) {
        match row {
            SectionRow::Settings(section) => {
                self.settings
                    .update(cx, |settings, cx| settings.set_section(section, cx));
            }
            SectionRow::Transfer { import } | SectionRow::Backup { restore: import } => {
                self.select_transfer_direction(import, cx);
            }
            SectionRow::Device(index) => {
                if self.selected_device != index {
                    self.device_renaming = false;
                }
                self.selected_device = index;
            }
        }
        self.section_opened = true;
        if let Some(position) = self
            .section_rows(cx)
            .iter()
            .position(|candidate| *candidate == row)
        {
            self.shortcuts.cursor = position;
        }
        cx.notify();
    }

    fn section_list_title(&self) -> &'static str {
        if self.settings_open {
            return "Settings";
        }
        self.selected_vault_item
            .as_ref()
            .and_then(VaultSelection::page_title)
            .unwrap_or_default()
    }

    fn section_row_text(&self, row: SectionRow, cx: &App) -> (String, Option<&'static str>) {
        match row {
            SectionRow::Device(index) => self.device_list(cx).get(index).map_or_else(
                || (String::new(), None),
                |device| {
                    (
                        device.name.clone(),
                        Some(if device.local {
                            "This device"
                        } else {
                            device.access()
                        }),
                    )
                },
            ),
            row => (row.title().to_owned(), None),
        }
    }

    pub(super) fn render_section_list(&self, cx: &mut Context<Self>) -> Div {
        let header = Self::list_header(self.section_list_title(), cx).when(
            self.selected_vault_item == Some(VaultSelection::Devices)
                && !self.settings_open
                && !self.device_list(cx).is_empty()
                && !self.needs_device_name(cx),
            |header| header.child(self.connect_device_button(cx)),
        );
        let rows = self.section_rows(cx);
        let selected = self.selected_section(cx);
        let highlighted = self
            .shortcuts
            .list_focused
            .then(|| self.shortcuts.cursor.min(rows.len().saturating_sub(1)));
        let theme = cx.theme().clone();
        let mut list = v_flex()
            .w_full()
            .when(!rows.is_empty(), |list| {
                list.track_focus(&self.shortcuts.list)
            })
            .key_context(shortcuts::LIST_CONTEXT);
        for (index, row) in rows.into_iter().enumerate() {
            let (title, detail) = self.section_row_text(row, cx);
            let current = (self.section_opened || !self.shortcuts.compact) && Some(row) == selected;
            list = list.child(
                Self::list_row(("section-row", index), current, cx)
                    .child(
                        icon_tile(2., &theme)
                            .child(row.icon().size(rems(1.)).text_color(theme.foreground)),
                    )
                    .child(list_row_text(title, detail, &theme))
                    .when(highlighted == Some(index), |row| {
                        row.keyboard_cursor(current, cx)
                            .child(self.reveal_when_moved(index == 0))
                    })
                    .on_click(cx.listener(move |view, _, _, cx| view.open_section(row, cx))),
            );
        }
        v_flex()
            .size_full()
            .child(header)
            .child(div().flex_1().min_h_0().child(self.scroll_list(list)))
    }

    fn section_header(
        icon: gpui_component::Icon,
        title: impl IntoElement,
        detail: Option<&'static str>,
        cx: &App,
    ) -> Div {
        let theme = cx.theme();
        h_flex()
            .min_w_0()
            .items_center()
            .gap_4()
            .child(
                icon_tile(56. / 16., theme)
                    .child(icon.size(rems(28. / 16.)).text_color(theme.foreground)),
            )
            .child(v_flex().flex_1().min_w_0().gap_1().child(title).when_some(
                detail,
                |header, detail| {
                    header.child(
                        div()
                            .text_body()
                            .text_color(theme.muted_foreground)
                            .child(detail),
                    )
                },
            ))
    }

    fn section_title(title: impl Into<gpui::SharedString>) -> Div {
        div()
            .min_w_0()
            .text_title()
            .font_semibold()
            .truncate()
            .child(title.into())
    }

    pub(super) fn render_section_pane(&self, cx: &mut Context<Self>) -> Div {
        let pane = v_flex().w_full().gap_4().p_6();
        if self.selected_vault_item == Some(VaultSelection::Devices)
            && !self.settings_open
            && let Some(placeholder) = self.render_device_placeholder(cx)
        {
            return pane.child(placeholder);
        }
        let Some(row) = self.selected_section(cx) else {
            return pane;
        };
        let (title, detail) = self.section_row_text(row, cx);
        let content = match row {
            SectionRow::Settings(_) => {
                let browsers = self.browser_settings(cx);
                let protection = link(
                    "settings-security-link",
                    self.security_label(),
                    "https://factorseal.dev/security",
                    cx,
                )
                .into_any_element();
                self.settings.update(cx, |settings, cx| {
                    settings.content(browsers, protection, cx)
                })
            }
            SectionRow::Transfer { .. } => self.render_transfer_detail(false, cx),
            SectionRow::Backup { .. } => self.render_transfer_detail(true, cx),
            SectionRow::Device(index) => {
                let devices = self.device_list(cx);
                let alone = devices.iter().all(|device| device.local);
                match devices.get(index) {
                    Some(device) => self.render_device_detail(device, alone, cx),
                    None => div(),
                }
            }
        };
        let rename = match row {
            SectionRow::Device(index) => {
                self.device_list(cx)
                    .get(index)
                    .is_some_and(|device| device.local)
                    && self.device_list(cx).iter().all(|device| device.local)
                    && !self.device_renaming
            }
            _ => false,
        };
        let title = h_flex()
            .min_w_0()
            .items_center()
            .gap_2()
            .child(Self::section_title(title))
            .when(rename, |title| {
                title.child(
                    Button::new("rename-device")
                        .ghost()
                        .flex_none()
                        .label("Rename")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.device_renaming = true;
                            cx.notify();
                        })),
                )
            });
        let content = if matches!(row, SectionRow::Transfer { .. } | SectionRow::Backup { .. }) {
            content.max_w(rems(820. / 16.))
        } else {
            content
        };
        pane.child(Self::section_header(row.icon(), title, detail, cx))
            .child(content)
    }

    pub(super) fn render_section_layout(&self, compact: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        if compact {
            let page = if self.section_opened {
                self.scroll_detail(self.render_section_pane(cx))
            } else {
                self.render_section_list(cx)
            };
            return div().flex_1().min_w_0().min_h_0().h_full().child(page);
        }
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
                    .child(self.render_section_list(cx)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .min_h_0()
                    .h_full()
                    .child(crate::motion::enter(
                        format!("section-{:?}", self.selected_section(cx)),
                        self.scroll_detail(self.render_section_pane(cx)),
                    )),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_and_backup_pages_list_both_directions() {
        assert_eq!(
            transfer_rows(false).map(SectionRow::title),
            ["Export credentials", "Import credentials"]
        );
        assert_eq!(
            transfer_rows(true).map(SectionRow::title),
            ["Create backup", "Restore backup"]
        );
    }
}
