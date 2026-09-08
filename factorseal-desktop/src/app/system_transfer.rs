use super::*;
use crate::apple_exchange::{self, Event};

#[derive(Default)]
pub(super) struct State {
    active: bool,
    generation: u64,
}

pub(super) fn setup(cx: &mut App) {
    let Some(receiver) = apple_exchange::install() else {
        return;
    };
    apple_exchange::set_unlocked(cx.global::<DesktopStatus>().unsealed);
    cx.spawn(async move |cx| {
        while let Ok(event) = receiver.recv().await {
            cx.update(|cx| {
                open_desktop(&OpenDesktop, cx);
                let holder = Arc::clone(&cx.global::<DesktopWindow>().view);
                let view = holder.lock().ok().and_then(|view| view.clone());
                if let Some(view) = view {
                    view.update(cx, |view, cx| view.system_transfer_event(event, cx));
                } else {
                    apple_exchange::finish();
                }
            });
        }
    })
    .detach();
}

impl DesktopView {
    pub(super) fn render_system_transfer(&self, is_import: bool, cx: &mut Context<Self>) -> Div {
        let panel = v_flex()
            .gap_2()
            .child(div().font_semibold().child("Transfer with another app"));
        if is_import {
            panel.child("Start a transfer in your other password manager and choose FactorSeal. You will review the credentials here before importing.")
        } else {
            panel.child(
                Button::new("system-credential-export")
                    .label("Choose destination app…")
                    .disabled(self.transfer_busy)
                    .on_click(cx.listener(|view, _, _, cx| view.export_system_credentials(cx))),
            )
        }
    }

    pub(super) fn cancel_system_transfer(&mut self) {
        if self.system_transfer.active {
            self.system_transfer.active = false;
            self.system_transfer.generation = self.system_transfer.generation.wrapping_add(1);
            self.transfer_busy = false;
            apple_exchange::finish();
        }
    }

    fn begin_system_transfer(&mut self) -> Option<u64> {
        if self.transfer_busy {
            return None;
        }
        self.system_transfer.active = true;
        self.system_transfer.generation = self.system_transfer.generation.wrapping_add(1);
        self.transfer_busy = true;
        self.transfer_notice = None;
        Some(self.system_transfer.generation)
    }

    fn system_transfer_current(&self, generation: u64) -> bool {
        self.system_transfer.active
            && self.system_transfer.generation == generation
            && matches!(self.snapshot, Snapshot::Unsealed { .. })
    }

    fn system_transfer_event(&mut self, event: Event, cx: &mut Context<Self>) {
        match event {
            Event::Open => {
                if self.begin_system_transfer().is_none() {
                    apple_exchange::finish();
                }
                // The ordinary foreground view provides the unlock UI.
            }
            Event::Import(data) => self.review_system_import(data, cx),
            Event::Exported | Event::Cancelled | Event::Failed => {
                if self.system_transfer.active {
                    self.cancel_system_transfer();
                    self.transfer_notice = match event {
                        Event::Exported => Some(TransferNotice::Success("Credentials delivered to the destination app. Verify important logins there before removing the source.".into())),
                        Event::Failed => Some(TransferNotice::Error("System transfer could not complete. The destination may have cancelled, or the SDK may not support all supplied data. Use an encrypted CXF file to retain the complete source.".into())),
                        _ => None,
                    };
                }
            }
        }
        cx.notify();
    }

    fn export_system_credentials(&mut self, cx: &mut Context<Self>) {
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let Some(generation) = self.begin_system_transfer() else {
            return;
        };
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || runtime.export_system_credentials(&metadata)).await;
            let _ = view.update(cx, |view, cx| {
                if !view.system_transfer_current(generation) {
                    return;
                }
                match result {
                    Ok(data) if apple_exchange::export(&data) => {}
                    Ok(_) => view.system_transfer_event(Event::Failed, cx),
                    Err(error) => {
                        view.cancel_system_transfer();
                        view.transfer_notice = Some(TransferNotice::Error(error));
                    }
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn review_system_import(&mut self, data: Zeroizing<Vec<u8>>, cx: &mut Context<Self>) {
        let generation = self.system_transfer.generation;
        if !self.system_transfer_current(generation) {
            apple_exchange::finish();
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let runtime = Arc::clone(&self.runtime);
        let replace = self.transfer_replace_existing;
        self.selected_vault_item = Some(VaultSelection::TransferCredentials);
        self.transfer_is_import = true;
        cx.spawn(async move |view, cx| {
            let prepared = smol::unblock(move || {
                crate::runtime::PreparedImport::manager(TransferFormat::CxfAge, &data)
                    .map_err(|error| error.to_string())
            }).await;
            if !view.update(cx, |view, _| view.system_transfer_current(generation)).unwrap_or(false) { return; }
            let result = match prepared {
                Ok(prepared) => {
                    let preview = format!("{} items are ready to import. {} contain data without full functional support.\n\nExisting items will be {}. Keep the source vault until you have verified important credentials.",
                        prepared.len(), prepared.preserved_only(), if replace { "replaced" } else { "kept" });
                    let decision = rfd::AsyncMessageDialog::new().set_title("Review import")
                        .set_description(preview).set_buttons(rfd::MessageButtons::OkCancel).show().await;
                    if !view.update(cx, |view, _| view.system_transfer_current(generation)).unwrap_or(false) { return; }
                    if decision != rfd::MessageDialogResult::Ok {
                        let _ = view.update(cx, |view, cx| view.system_transfer_event(Event::Cancelled, cx));
                        return;
                    }
                    smol::unblock(move || runtime.commit_import(&metadata, prepared, replace)).await
                        .map(|(summary, contents)| TransferCompletion {
                            summary: Some(summary), contents: Some(contents), path: std::path::PathBuf::default(),
                        })
                }
                Err(error) => Err(error),
            };
            let _ = view.update(cx, |view, cx| {
                if !view.system_transfer_current(generation) { return; }
                view.cancel_system_transfer();
                view.finish_transfer(true, false, result);
                cx.notify();
            });
        }).detach();
    }
}
