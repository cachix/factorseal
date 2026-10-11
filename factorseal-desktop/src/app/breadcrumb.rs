use gpui::{ElementId, MouseButton, SharedString, Stateful};

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CrumbTarget {
    PersonalSecrets,
    Category(factorseal::DocumentKind),
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
            vec![personal_secrets(), Crumb::page("New item")]
        }
        Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => {
            vec![personal_secrets(), Crumb::page(vault_entry_label(entry).0)]
        }
        Some(VaultSelection::Entry(entry)) => vec![
            Crumb::link(
                category_guidance(entry.document_kind).title,
                CrumbTarget::Category(entry.document_kind),
            ),
            Crumb::page(vault_entry_label(entry).0),
        ],
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
            CrumbTarget::Category(kind) => {
                self.select_vault_item(VaultSelection::Category(kind), cx);
            }
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

    pub(super) fn render_breadcrumb(&self, compact: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let trail = trail(
            self.settings_open,
            self.selected_vault_item.as_ref(),
            self.personal_panel,
        );
        let last = trail.len().saturating_sub(1);
        let home = if trail.is_empty() {
            div().id("vault-home")
        } else {
            crumb_link("vault-home", "Back to your vault", cx)
                .on_click(cx.listener(|view, _, _, cx| view.open_home(cx)))
        }
        .h_flex()
        .flex_none()
        .gap_2()
        .child(brand_mark(36., theme.foreground))
        .when(!compact || trail.is_empty(), |home| {
            home.child(div().text_title().font_semibold().child("FactorSeal"))
        });
        trail.into_iter().enumerate().fold(
            h_flex().flex_1().min_w_0().gap_2().child(home),
            |row, (index, crumb)| {
                let id = ("breadcrumb", index);
                let element = match crumb.target {
                    Some(target) => crumb_link(id, crumb.label.clone(), cx)
                        .on_click(cx.listener(move |view, _, _, cx| view.open_crumb(target, cx))),
                    None => div().id(id),
                };
                row.child(
                    gpui_component::Icon::new(IconName::ChevronRight)
                        .flex_none()
                        .text_color(theme.muted_foreground),
                )
                .child(
                    element
                        .flex()
                        .min_w_0()
                        .when(index == last, |element| {
                            element.flex_shrink(100.).min_w(rems(5.))
                        })
                        .text_heading()
                        .font_semibold()
                        .child(div().min_w_0().truncate().child(crumb.label)),
                )
            },
        )
    }
}

pub(super) fn crumb_link(
    id: impl Into<ElementId>,
    name: impl Into<SharedString>,
    cx: &App,
) -> Stateful<Div> {
    div()
        .id(id)
        .role(gpui::Role::Link)
        .aria_label(name)
        .text_control(cx)
        .on_mouse_down(MouseButton::Left, |_, window, _| window.prevent_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(trail: &[Crumb]) -> Vec<&str> {
        trail.iter().map(|crumb| crumb.label.as_ref()).collect()
    }

    fn entry(kind: factorseal::DocumentKind, partition: &[u8], name: &str) -> VaultSelection {
        VaultSelection::Entry(Box::new(factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some(name.into()),
            display_type: Some("Login".into()),
            display_username: None,
            updated_at: None,
            favorite: false,
            document_kind: kind,
            partition: partition.to_vec(),
            address: factorseal::SecretAddress::new("internal-id", None).unwrap(),
        }))
    }

    fn personal_entry(name: &str) -> VaultSelection {
        entry(
            factorseal::DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
            name,
        )
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
            [link.clone(), Crumb::page("New item")]
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

    #[test]
    fn other_items_link_back_to_their_category() {
        let kind = factorseal::DocumentKind::NetworkManagerWifi;
        assert_eq!(
            trail(
                false,
                Some(&entry(kind, b"system", "Home network")),
                PersonalPanel::Overview
            ),
            [
                Crumb::link("Wi-Fi passwords", CrumbTarget::Category(kind)),
                Crumb::page("Home network")
            ]
        );
    }
}
