use gpui::SharedString;

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CrumbTarget {
    PersonalSecrets,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Crumb {
    label: SharedString,
    target: Option<CrumbTarget>,
}

impl Crumb {
    fn page(label: impl Into<SharedString>) -> Self {
        Self {
            label: label.into(),
            target: None,
        }
    }

    const fn link(label: &'static str, target: CrumbTarget) -> Self {
        Self {
            label: SharedString::new_static(label),
            target: Some(target),
        }
    }
}

pub(super) fn trail(
    settings_open: bool,
    selection: Option<&VaultSelection>,
    personal_panel: PersonalPanel,
) -> Vec<Crumb> {
    let personal_secrets = || Crumb::link("Personal secrets", CrumbTarget::PersonalSecrets);
    if settings_open {
        return vec![Crumb::page("Settings")];
    }
    match selection {
        Some(VaultSelection::PersonalSecrets) if personal_panel == PersonalPanel::NewItem => {
            vec![personal_secrets(), Crumb::page("New Item")]
        }
        Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => {
            vec![personal_secrets(), Crumb::page(vault_entry_label(entry).0)]
        }
        selection => selection
            .and_then(VaultSelection::page_title)
            .map(Crumb::page)
            .into_iter()
            .collect(),
    }
}

impl DesktopView {
    fn open_crumb(&mut self, target: CrumbTarget, cx: &mut Context<Self>) {
        match target {
            CrumbTarget::PersonalSecrets => self.show_personal_panel(PersonalPanel::Overview, cx),
        }
    }

    fn open_home(&mut self, cx: &mut Context<Self>) {
        if self.settings_open {
            self.settings_open = false;
            cx.notify();
        } else {
            self.show_vault_browser(cx);
        }
    }

    pub(super) fn render_breadcrumb(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let trail = trail(
            self.settings_open,
            self.selected_vault_item.as_ref(),
            self.personal_panel,
        );
        let home = h_flex()
            .id("vault-home")
            .flex_none()
            .items_center()
            .gap_2()
            .when(!trail.is_empty(), |home| {
                home.cursor_pointer()
                    .hover(|style| style.text_color(theme.muted_foreground))
                    .on_click(cx.listener(|view, _, _, cx| view.open_home(cx)))
            })
            .child(brand_mark(36., theme.foreground))
            .child(
                div()
                    .text_size(rems(23. / 16.))
                    .font_semibold()
                    .child("FactorSeal"),
            );
        trail.into_iter().enumerate().fold(
            h_flex().min_w_0().items_center().gap_2().child(home),
            |row, (index, crumb)| {
                row.child(
                    gpui_component::Icon::new(IconName::ChevronRight)
                        .flex_none()
                        .text_color(theme.muted_foreground),
                )
                .child(
                    div()
                        .id(("breadcrumb", index))
                        .min_w_0()
                        .truncate()
                        .text_lg()
                        .font_semibold()
                        .when_some(crumb.target, |element, target| {
                            element
                                .cursor_pointer()
                                .hover(|style| style.text_color(theme.muted_foreground))
                                .on_click(
                                    cx.listener(move |view, _, _, cx| view.open_crumb(target, cx)),
                                )
                        })
                        .child(crumb.label),
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_ref()).collect()
    }

    fn personal_entry(name: &str) -> VaultSelection {
        VaultSelection::Entry(Box::new(factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some(name.into()),
            display_type: Some("Login".into()),
            updated_at: None,
            document_kind: factorseal::DocumentKind::LocalKeyring,
            partition: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: factorseal::SecretAddress::new("internal-id", None).unwrap(),
        }))
    }

    #[test]
    fn home_and_vault_tabs_have_no_trail() {
        for selection in [
            None,
            Some(VaultSelection::PersonalSecrets),
            Some(VaultSelection::Category(
                factorseal::DocumentKind::SecretSpecProject,
            )),
        ] {
            assert!(trail(false, selection.as_ref(), PersonalPanel::Overview).is_empty());
        }
    }

    #[test]
    fn dedicated_pages_follow_the_logo() {
        for (selection, title) in [
            (VaultSelection::Devices, "Devices"),
            (VaultSelection::TransferCredentials, "Transfer credentials"),
            (VaultSelection::BackupVault, "Back up vault"),
        ] {
            assert_eq!(
                trail(false, Some(&selection), PersonalPanel::Overview),
                [Crumb::page(title)]
            );
        }
    }

    #[test]
    fn settings_replaces_the_vault_trail() {
        assert_eq!(
            labels(&trail(
                true,
                Some(&personal_entry("Example")),
                PersonalPanel::Overview
            )),
            ["Settings"]
        );
    }

    #[test]
    fn personal_pages_link_back_to_the_overview() {
        let link = Crumb::link("Personal secrets", CrumbTarget::PersonalSecrets);
        assert_eq!(
            trail(
                false,
                Some(&VaultSelection::PersonalSecrets),
                PersonalPanel::NewItem
            ),
            [link.clone(), Crumb::page("New Item")]
        );
        assert_eq!(
            trail(
                false,
                Some(&personal_entry("Example")),
                PersonalPanel::Overview
            ),
            [link, Crumb::page("Example")]
        );
    }
}
