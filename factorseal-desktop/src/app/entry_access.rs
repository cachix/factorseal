use super::*;
use factorseal::{Permission, PermissionState, PermissionTarget, VaultEntryMetadata};

pub(super) fn scope_label(permission: &Permission) -> &'static str {
    match permission.target.as_deref() {
        Some(PermissionTarget::Entry { .. } | PermissionTarget::ProjectEntry { .. }) => {
            "This entry"
        }
        Some(PermissionTarget::Project { .. }) => "Inherited from project",
        Some(PermissionTarget::Namespace { .. }) => "Inherited from namespace",
        Some(PermissionTarget::DocumentKind) => "Inherited from secret type",
        None => "Unknown scope",
    }
}

pub(super) fn entry_label(permission: &Permission) -> Option<String> {
    let (PermissionTarget::Entry { address, .. } | PermissionTarget::ProjectEntry { address, .. }) =
        permission.target.as_deref()?
    else {
        return None;
    };
    Some(match address {
        factorseal::SecretAddress::SecretSpec { address } => {
            let (name, profile) = secret_spec_address_label(address);
            format!("{name} · {profile}")
        }
        factorseal::SecretAddress::Local { item, field } => field
            .as_ref()
            .map_or_else(|| item.clone(), |field| format!("{item} · {field}")),
    })
}

pub(super) fn lifetime_label(permission: &Permission) -> String {
    let deadline = match permission.state {
        PermissionState::Pending { .. } => return "Awaiting approval".to_owned(),
        PermissionState::Granted { expires_at, .. } => expires_at,
    };
    let Some(deadline) = deadline else {
        return "Until revoked".to_owned();
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if deadline <= now {
        "Expired".to_owned()
    } else {
        format!("Expires in {} minutes", (deadline - now).div_ceil(60))
    }
}

impl DesktopView {
    pub(super) fn render_entry_access(
        entry: &VaultEntryMetadata,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut panel = v_flex()
            .gap_3()
            .child(div().text_lg().font_semibold().child("Access"));
        if contents.permissions_loading {
            return panel.child("Loading access…");
        }
        if let Some(error) = &contents.permissions_error {
            return panel.child(format!("Could not load access: {error}"));
        }
        let mut count = 0_usize;
        for permission in contents
            .permissions
            .iter()
            .filter(|permission| permission.applies_to_entry(entry))
        {
            count += 1;
            let mut details = vec![
                ("Application", permission.principal.application_id.clone()),
                (
                    "Operation",
                    permission_operation_label(permission.operation).to_owned(),
                ),
                ("Scope", scope_label(permission).to_owned()),
                ("Lifetime", lifetime_label(permission)),
            ];
            if let Some(
                PermissionTarget::Project {
                    project, base_dir, ..
                }
                | PermissionTarget::ProjectEntry {
                    project, base_dir, ..
                },
            ) = permission.target.as_deref()
            {
                details.push(("Project", project.clone()));
                details.push((
                    "Project folder",
                    base_dir
                        .clone()
                        .unwrap_or_else(|| "No folder recorded".to_owned()),
                ));
            }
            let mut card = v_flex()
                .gap_2()
                .child(Self::render_detail_rows(details, cx));
            if matches!(permission.state, PermissionState::Granted { .. }) {
                let id = permission.id.clone();
                let inherited = !matches!(
                    permission.target.as_deref(),
                    Some(PermissionTarget::Entry { .. } | PermissionTarget::ProjectEntry { .. })
                );
                if inherited {
                    card = card.child(div().text_sm().text_color(cx.theme().muted_foreground).child("Revoking this grant removes its access to every entry in its scope."));
                }
                card = card.child(
                    Button::new(("revoke-entry-access", count))
                        .small()
                        .label(if inherited {
                            "Revoke inherited grant"
                        } else {
                            "Revoke access"
                        })
                        .on_click(
                            cx.listener(move |view, _, _, cx| view.revoke_access(id.clone(), cx)),
                        ),
                );
            }
            panel = panel.child(card);
        }
        if count == 0 {
            panel = panel.child("No recorded access grants apply to this entry.");
        }
        panel
    }
}
