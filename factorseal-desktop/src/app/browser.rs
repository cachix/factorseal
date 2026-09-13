//! Desktop owns all browser consent; the native bridge never receives manager authority.
use super::*;
use factorseal::browser::{
    WorkerAction,
    desktop::{Hub, Prompt},
};
use std::sync::Mutex;
mod prompt;
struct BrowserGlobal {
    hub: Arc<Mutex<Hub>>,
    cache: std::path::PathBuf,
    registration_error: Arc<Mutex<bool>>,
    saved: Arc<std::sync::atomic::AtomicBool>,
}
impl Global for BrowserGlobal {}

#[allow(clippy::too_many_lines)] // Keep the endpoint, worker, and UI lifetime wiring together.
pub(super) fn setup(root: &std::path::Path, runtime: Arc<DesktopRuntime>, cx: &mut App) {
    prompt::setup(cx);
    let hub = Hub::shared();
    let registration_error = Arc::new(Mutex::new(false));
    let saved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cache = root.join("browser-pairings.json");
    if std::fs::metadata(&cache).is_ok_and(|m| m.len() <= 64 * 1024)
        && let Ok(bytes) = std::fs::read(&cache)
        && let Ok(mut keys) = serde_json::from_slice::<std::collections::HashSet<String>>(&bytes)
    {
        keys.retain(|key| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()));
        if let Ok(mut h) = hub.lock() {
            h.paired = keys;
        }
    }
    cx.set_global(BrowserGlobal {
        hub: Arc::clone(&hub),
        cache: cache.clone(),
        registration_error: Arc::clone(&registration_error),
        saved: Arc::clone(&saved),
    });
    let registration_root = root.to_path_buf();
    std::thread::spawn(move || {
        let Ok(identity) = std::env::current_exe() else {
            return;
        };
        let launcher = std::env::var_os("FACTORSEAL_DESKTOP_EXECUTABLE")
            .map_or_else(|| identity.clone(), std::path::PathBuf::from);
        let executable = std::env::var_os("FACTORSEAL_CLI_EXECUTABLE")
            .map_or_else(|| identity.clone(), std::path::PathBuf::from);
        let bridge = executable.with_file_name(if cfg!(windows) {
            "factorseal-browser.exe"
        } else {
            "factorseal-browser"
        });
        let result = if bridge.is_file() {
            factorseal::browser::registration::configure(
                &registration_root,
                &bridge,
                &launcher,
                &identity,
            )
        } else {
            Err(std::io::Error::other("browser bridge is missing"))
        };
        if let Ok(mut failed) = registration_error.lock() {
            *failed = result.is_err();
        }
        if result.is_err() {
            eprintln!("factorseal-desktop: browser registration could not be updated");
        }
    });
    let server = Arc::clone(&hub);
    let server_root = root.to_path_buf();
    std::thread::spawn(move || {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let executable =
            std::env::var_os("FACTORSEAL_CLI_EXECUTABLE").map_or(exe, std::path::PathBuf::from);
        let bridge = executable.with_file_name(if cfg!(windows) {
            "factorseal-browser.exe"
        } else {
            "factorseal-browser"
        });
        if !bridge.is_file() {
            return;
        }
        // Vault initialization deliberately rejects a pre-existing root. Wait
        // for initialization instead of creating its directory for the socket.
        while !server_root.join("factorseal.json").is_file() {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let handler = Arc::new(move |request| {
            server.lock().map_or_else(
                |_| factorseal::browser::Response::finished("unavailable"),
                |mut h| h.handle(request),
            )
        });
        if factorseal::browser::transport::serve(&server_root, &bridge, handler.as_ref()).is_err() {
            eprintln!("factorseal-desktop: browser endpoint could not start");
        }
    });
    let worker_hub = Arc::clone(&hub);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let work = worker_hub
                .lock()
                .map(|mut h| h.take_work())
                .unwrap_or_default();
            for work in work {
                let result = runtime.browser_request(work.action.clone());
                if matches!(work.action, WorkerAction::Save { .. })
                    && matches!(result, Ok(factorseal::browser::WorkerReply::Done))
                {
                    saved.store(true, std::sync::atomic::Ordering::Release);
                }
                if let Ok(mut h) = worker_hub.lock() {
                    h.complete(&work, result);
                    if matches!(
                        work.action,
                        WorkerAction::Pair { .. } | WorkerAction::Revoke { .. }
                    ) && let Ok(bytes) = serde_json::to_vec(&h.paired)
                    {
                        let _ = factorseal::transfer::write_private_file(&cache, &bytes);
                    }
                }
            }
        }
    });
    cx.spawn(async move |cx| {
        loop {
            smol::Timer::after(std::time::Duration::from_millis(200)).await;
            cx.update(|cx| {
                if cx
                    .global::<BrowserGlobal>()
                    .saved
                    .swap(false, std::sync::atomic::Ordering::AcqRel)
                {
                    refresh_desktop_snapshot(Arc::clone(&cx.global::<RuntimeGlobal>().0), cx);
                }
                let unsealed = matches!(
                    &cx.global::<DesktopWindow>().snapshot,
                    Snapshot::Unsealed { owned: true, .. }
                );
                let external = matches!(
                    &cx.global::<DesktopWindow>().snapshot,
                    Snapshot::Unsealed { owned: false, .. }
                );
                let prompt = if let Ok(mut h) = hub.lock() {
                    h.snapshot(unsealed);
                    let p = h.prompt();
                    if external {
                        if let Some(p) = &p {
                            h.deny(&p.session);
                        }
                        None
                    } else {
                        p
                    }
                } else {
                    None
                };
                prompt::sync(prompt, cx);
                let holder = Arc::clone(&cx.global::<DesktopWindow>().view);
                if let Ok(holder) = holder.lock()
                    && let Some(view) = holder.as_ref()
                {
                    view.update(cx, |_, cx| cx.notify());
                }
            });
        }
    })
    .detach();
}
impl DesktopView {
    #[allow(clippy::too_many_lines)] // Declarative pairing, unlock, and account-selection controls.
    pub(super) fn render_browser(&self, cx: &mut Context<Self>) -> Div {
        let Some(global) = cx.try_global::<BrowserGlobal>() else {
            return div();
        };
        let hub = Arc::clone(&global.hub);
        let cache = global.cache.clone();
        if self.settings_open && matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. }) {
            let keys = hub
                .lock()
                .map(|h| h.paired.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let mut panel = v_flex().gap_2().child("Paired browser profiles");
            if global.registration_error.lock().is_ok_and(|failed| *failed) {
                panel = panel.child("Browser setup failed. Check that the bridge is installed, then restart Desktop to retry.");
            }
            for (index, key) in keys.into_iter().enumerate() {
                let runtime = Arc::clone(&self.runtime);
                let hub = Arc::clone(&hub);
                let cache = cache.clone();
                let label = format!("Disconnect {}…", &key[..key.len().min(16)]);
                panel = panel.child(
                    Button::new(("browser-revoke", index))
                        .label(label)
                        .on_click(cx.listener(move |_, _, _, cx| {
                            let runtime = Arc::clone(&runtime);
                            let hub = Arc::clone(&hub);
                            let key = key.clone();
                            let cache = cache.clone();
                            cx.spawn(async move |_, _| {
                                let revoked = key.clone();
                                if smol::unblock(move || {
                                    runtime.browser_request(WorkerAction::Revoke { key })
                                })
                                .await
                                .is_ok()
                                    && let Ok(mut h) = hub.lock()
                                {
                                    h.revoked(&revoked);
                                    if let Ok(bytes) = serde_json::to_vec(&h.paired) {
                                        let _ = factorseal::transfer::write_private_file(
                                            &cache, &bytes,
                                        );
                                    }
                                }
                            })
                            .detach();
                        })),
                );
            }
            return panel;
        }
        div()
    }
}
