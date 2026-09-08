use super::*;
use factorseal::{
    Permission, PermissionChange, PermissionState, UnlockFactorKind, UnlockGroup, VaultAction,
};

pub(super) struct ApprovalForm {
    permission: Permission,
    group: UnlockGroup,
    duration: u64,
    password: gpui::Entity<SecretInputState>,
}

impl DesktopView {
    #[allow(clippy::too_many_lines)]
    pub(super) fn render_permission_controls(
        &self,
        permission: &Permission,
        cx: &mut Context<Self>,
    ) -> Div {
        let mut panel = v_flex().gap_3();
        if let Some(error) = &self.permission_error {
            panel = panel.child(error_banner(error.clone(), cx.theme().danger));
        }
        if self.permission_busy {
            return panel.child(
                "Confirming access… Complete the device authorization prompt if one appears.",
            );
        }
        if let Some(form) = &self.permission_form {
            if &form.permission != permission {
                return panel.child("This request changed. Select it again to review.");
            }
            let Some(metadata) = self.snapshot.metadata() else {
                return panel;
            };
            let mut groups = h_flex().gap_2().flex_wrap();
            for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
                let chosen = group.clone();
                groups = groups.child(
                    Button::new(("approve-group", index))
                        .label(group.to_string())
                        .selected(group == &form.group)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            if let Some(form) = &mut view.permission_form {
                                form.password.update(cx, SecretInputState::clear);
                                form.group = chosen.clone();
                            }
                            cx.notify();
                        })),
                );
            }
            let mut durations = h_flex().gap_2().flex_wrap();
            for (index, (label, seconds)) in
                [("5 minutes", 300), ("1 hour", 3600), ("8 hours", 28_800)]
                    .into_iter()
                    .enumerate()
            {
                durations = durations.child(
                    Button::new(("approve-duration", index))
                        .label(label)
                        .selected(seconds == form.duration)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            if let Some(form) = &mut view.permission_form {
                                form.duration = seconds;
                            }
                            cx.notify();
                        })),
                );
            }
            panel = panel
                .child("Confirm an unlock method to grant access.")
                .child(groups)
                .child("Access duration (also ends when the vault seals)")
                .child(durations);
            if form.group.requires(UnlockFactorKind::Password) {
                panel = panel.child(field_label("Password", form.password.clone()));
            }
            return panel.child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("confirm-permission")
                            .primary()
                            .label("Grant access")
                            .on_click(cx.listener(|view, _, _, cx| view.confirm_permission(cx))),
                    )
                    .child(
                        Button::new("cancel-permission")
                            .label("Cancel")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.clear_permission_form(cx);
                                cx.notify();
                            })),
                    ),
            );
        }
        let selected = permission.clone();
        let id = permission.id.clone();
        let buttons = match permission.state {
            PermissionState::Pending { .. } => h_flex()
                .gap_2()
                .child(
                    Button::new("approve-permission")
                        .primary()
                        .label("Approve…")
                        .on_click(cx.listener(move |view, _, window, cx| {
                            let Some(metadata) = view.snapshot.metadata() else {
                                return;
                            };
                            view.permission_form = Some(ApprovalForm {
                                permission: selected.clone(),
                                group: metadata.preferred_unlock_group().clone(),
                                duration: 3600,
                                password: cx.new(|cx| {
                                    SecretInputState::new(window, cx).placeholder("Vault password")
                                }),
                            });
                            view.permission_error = None;
                            cx.notify();
                        })),
                )
                .child(
                    Button::new("deny-permission")
                        .label("Deny")
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.change_permission(
                                VaultAction::DenyPermission { id: id.clone() },
                                PermissionChange::Denied,
                                cx,
                            );
                        })),
                ),
            PermissionState::Granted { .. } => h_flex().child(
                Button::new("revoke-permission")
                    .label("Revoke access")
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.change_permission(
                            VaultAction::RevokePermission { id: id.clone() },
                            PermissionChange::Revoked,
                            cx,
                        );
                    })),
            ),
        };
        panel.child(buttons)
    }

    pub(super) fn clear_permission_form(&mut self, cx: &mut Context<Self>) {
        if let Some(form) = self.permission_form.take() {
            form.password.update(cx, SecretInputState::clear);
        }
        self.permission_error = None;
    }

    fn confirm_permission(&mut self, cx: &mut Context<Self>) {
        if self.permission_busy {
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let Some(form) = &self.permission_form else {
            return;
        };
        let password = if form.group.requires(UnlockFactorKind::Password) {
            let value = form.password.read(cx).value();
            if value.is_empty() {
                self.permission_error =
                    Some("Enter the password required by this unlock method.".into());
                cx.notify();
                return;
            }
            Zeroizing::new(value.as_bytes().to_vec())
        } else {
            Zeroizing::new(Vec::new())
        };
        let metadata = metadata.clone();
        let form = self.permission_form.take().unwrap();
        form.password.update(cx, SecretInputState::clear);
        let runtime = Arc::clone(&self.runtime);
        self.permission_busy = true;
        self.permission_error = None;
        cx.notify();
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || {
                runtime.approve_permission(
                    &metadata,
                    &form.permission,
                    form.duration,
                    form.group,
                    password,
                )
            })
            .await;
            let _ = view.update(cx, |view, cx| {
                view.permission_busy = false;
                view.permission_error = result.err();
                cx.notify();
            });
        })
        .detach();
    }

    fn change_permission(
        &mut self,
        action: VaultAction,
        expected: PermissionChange,
        cx: &mut Context<Self>,
    ) {
        if self.permission_busy {
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let runtime = Arc::clone(&self.runtime);
        self.permission_busy = true;
        self.permission_error = None;
        cx.notify();
        cx.spawn(async move |view, cx| {
            let result =
                smol::unblock(move || runtime.change_permission(&metadata, action, expected)).await;
            let _ = view.update(cx, |view, cx| {
                view.permission_busy = false;
                view.permission_error = result.err();
                cx.notify();
            });
        })
        .detach();
    }

    pub(super) fn update_permissions(
        &mut self,
        result: Result<Vec<Permission>, String>,
        cx: &mut Context<Self>,
    ) {
        if let Ok(permissions) = &result
            && let Some(VaultSelection::Permission(selected)) = &self.selected_vault_item
        {
            let current = permissions
                .iter()
                .find(|permission| permission.id == selected.id);
            if current != Some(selected) {
                self.clear_permission_form(cx);
                self.selected_vault_item = current.cloned().map(VaultSelection::Permission);
            }
        }
        if let Snapshot::Unsealed { contents, .. } = &mut self.snapshot {
            contents.permissions_loading = true;
            contents.complete_permissions(result);
            cx.notify();
        }
    }
}

impl DesktopView {
    pub(super) fn render_permission_detail(
        &self,
        permission: &Permission,
        cx: &mut Context<Self>,
    ) -> Div {
        let application = permission
            .application
            .project
            .as_deref()
            .unwrap_or(&permission.principal.application_id)
            .to_owned();
        let state = match permission.state {
            factorseal::PermissionState::Pending { .. } => "Pending",
            factorseal::PermissionState::Granted { .. } => "Granted",
        };
        let mut details = vec![
            ("Type", permission_access_type(permission.scope).to_owned()),
            (
                "Operation",
                permission_operation_label(permission.operation).to_owned(),
            ),
            ("State", state.to_owned()),
            (
                "Application ID",
                permission.principal.application_id.clone(),
            ),
        ];
        details.push(("User", permission.principal.user_id.clone()));
        details.push((
            "Executable digest",
            hex_digest(&permission.principal.executable_digest),
        ));
        if let Some(signer) = &permission.principal.signer_id {
            details.push(("Signer", signer.clone()));
        }
        if let Some(destination) = &permission.ssh_destination {
            details.push(("SSH user", destination.user.clone()));
            details.push((
                "Host keys (forwarding order)",
                destination.host_keys.join(" → "),
            ));
        } else if permission.operation == factorseal::PermissionOperation::SshSign {
            details.push((
                "Signing scope",
                "Unrestricted: this application can sign arbitrary data with this key.".into(),
            ));
        }
        let expiry = match permission.state {
            factorseal::PermissionState::Pending { expires_at, .. } => Some(expires_at),
            factorseal::PermissionState::Granted { expires_at, .. } => expires_at,
        };
        details.push((
            "Expires (Unix time)",
            expiry.map_or_else(|| "When vault seals".into(), |time| time.to_string()),
        ));
        if let Some(fingerprint) = &permission.key_fingerprint {
            details.push(("SSH key fingerprint", fingerprint.clone()));
            if let Some(reason) = &permission.application.reason {
                details.push(("Key", reason.clone()));
            }
        }
        if let Some(project) = &permission.application.project {
            details.push(("Project", project.clone()));
        }
        if let Some(profile) = &permission.application.profile {
            details.push(("Profile", profile.clone()));
        }
        if let Some(base_dir) = &permission.application.base_dir {
            details.push(("Base directory", base_dir.clone()));
        }
        v_flex()
            .size_full()
            .gap_4()
            .p_6()
            .child(div().text_xl().font_semibold().child(application))
            .child(Self::render_detail_rows(details, cx))
            .child(self.render_permission_controls(permission, cx))
    }
}
