#[cfg(target_os = "linux")]
use super::*;
#[cfg(not(target_os = "linux"))]
use super::{Context, DesktopView, Div, div};

#[cfg(target_os = "linux")]
#[derive(Default)]
pub(super) struct State {
    busy: bool,
    report: Option<factorseal::WifiMigrationReport>,
    error: Option<String>,
}

impl DesktopView {
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub(super) fn render_wifi_migration(
        &self,
        kind: factorseal::DocumentKind,
        cx: &mut Context<Self>,
    ) -> Div {
        #[cfg(target_os = "linux")]
        {
            if kind != factorseal::DocumentKind::NetworkManagerWifi {
                return div();
            }
            let theme = cx.theme();
            let mut content = v_flex().gap_3()
                .child("Move saved passwords from NetworkManager and your current keyring into FactorSeal. Use this when FactorSeal is your only Wi-Fi secret agent. Existing connections stay active; one-time passwords are left unchanged.")
                .child(Button::new("migrate-wifi-passwords")
                    .primary()
                    .label(if self.wifi_migration.busy { "Moving Wi-Fi passwords…" } else { "Move existing Wi-Fi passwords" })
                    .disabled(self.wifi_migration.busy)
                    .on_click(cx.listener(|view, _, _, cx| view.start_wifi_migration(cx))));
            if let Some(error) = &self.wifi_migration.error {
                content = content.child(error_banner(error.clone(), theme.danger));
            }
            if let Some(report) = &self.wifi_migration.report {
                if report.entries.is_empty() {
                    content = content.child("No Wi-Fi connections were found.");
                }
                for entry in &report.entries {
                    content = content.child(
                        v_flex()
                            .gap_1()
                            .child(div().font_semibold().child(entry.connection.clone()))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(if entry.migrated {
                                        theme.muted_foreground
                                    } else {
                                        theme.danger
                                    })
                                    .child(entry.message.clone()),
                            ),
                    );
                }
            }
            content
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (kind, cx);
            div()
        }
    }

    #[cfg(target_os = "linux")]
    fn start_wifi_migration(&mut self, cx: &mut Context<Self>) {
        if self.wifi_migration.busy {
            return;
        }
        let Some(host) = cx.global::<SecretServiceGlobal>().0.as_ref() else {
            self.wifi_migration.error =
                Some("The Wi-Fi integration is unavailable. Restart FactorSeal and retry.".into());
            cx.notify();
            return;
        };
        let receiver = match host.migrate_wifi() {
            Ok(receiver) => receiver,
            Err(error) => {
                self.wifi_migration.error = Some(error.to_string());
                cx.notify();
                return;
            }
        };
        self.wifi_migration.busy = true;
        self.wifi_migration.error = None;
        self.wifi_migration.report = None;
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |view, cx| {
            let result = receiver
                .await
                .map_err(|_| {
                    "Wi-Fi migration stopped. Verified copies remain in the vault; retry to finish."
                        .to_owned()
                })
                .and_then(|result| result.map_err(|error| error.to_string()));
            let _ = view.update(cx, |view, cx| {
                view.wifi_migration.busy = false;
                match result {
                    Ok(report) => view.wifi_migration.report = Some(report),
                    Err(error) => view.wifi_migration.error = Some(error),
                }
                refresh_desktop_snapshot(runtime, cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}
