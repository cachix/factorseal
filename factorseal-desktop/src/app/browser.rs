//! Desktop owns all browser consent; the native bridge never receives manager authority.
use super::*;
use factorseal::browser::discovery::Browser;
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
    installed: Arc<Mutex<Vec<Browser>>>,
}
impl Global for BrowserGlobal {}

#[allow(clippy::too_many_lines)] // Keep the endpoint, worker, and UI lifetime wiring together.
pub(super) fn setup(root: &std::path::Path, runtime: Arc<DesktopRuntime>, cx: &mut App) {
    prompt::setup(cx);
    let hub = Hub::shared();
    let registration_error = Arc::new(Mutex::new(false));
    let saved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cache = root.join("browser-pairings.json");
    let profiles = root.join("browser-profiles.json");
    let installed = Arc::new(Mutex::new(Vec::new()));
    if std::fs::metadata(&cache).is_ok_and(|m| m.len() <= 64 * 1024)
        && let Ok(bytes) = std::fs::read(&cache)
        && let Ok(mut keys) = serde_json::from_slice::<std::collections::HashSet<String>>(&bytes)
    {
        keys.retain(|key| key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()));
        if let Ok(mut h) = hub.lock() {
            h.paired = keys;
        }
    }
    if std::fs::metadata(&profiles).is_ok_and(|m| m.len() <= 64 * 1024)
        && let Ok(bytes) = std::fs::read(&profiles)
        && let Ok(labels) =
            serde_json::from_slice::<std::collections::HashMap<String, Browser>>(&bytes)
        && let Ok(mut h) = hub.lock()
    {
        h.browsers = labels
            .into_iter()
            .filter(|(key, _)| h.paired.contains(key))
            .collect();
    }
    cx.set_global(BrowserGlobal {
        hub: Arc::clone(&hub),
        cache: cache.clone(),
        registration_error: Arc::clone(&registration_error),
        saved: Arc::clone(&saved),
        installed: Arc::clone(&installed),
    });
    let registration_root = root.to_path_buf();
    std::thread::spawn(move || {
        if let Ok(mut found) = installed.lock() {
            *found = factorseal::browser::discovery::installed();
        }
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
        let mut last_profiles = Some(std::collections::HashMap::new());
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
            let work = worker_hub
                .lock()
                .map(|mut h| h.take_work())
                .unwrap_or_default();
            let labels = worker_hub.lock().ok().map(|h| {
                h.browsers
                    .iter()
                    .filter(|(key, _)| h.paired.contains(*key))
                    .map(|(key, browser)| (key.clone(), *browser))
                    .collect::<std::collections::HashMap<_, _>>()
            });
            if labels != last_profiles
                && let Some(labels) = &labels
                && let Ok(bytes) = serde_json::to_vec(labels)
                && factorseal::transfer::write_private_file(&profiles, &bytes).is_ok()
            {
                last_profiles = Some(labels.clone());
            }
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
        let mut was_unsealed = false;
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
                if unsealed && !was_unsealed {
                    let installed = Arc::clone(&cx.global::<BrowserGlobal>().installed);
                    std::thread::spawn(move || {
                        let found = factorseal::browser::discovery::installed();
                        if let Ok(mut installed) = installed.lock() {
                            *installed = found;
                        }
                    });
                }
                was_unsealed = unsealed;
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
        if !matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. }) {
            return div();
        }
        let installed = global
            .installed
            .lock()
            .map(|b| b.clone())
            .unwrap_or_default();
        let (paired, labels) = hub
            .lock()
            .map(|h| (h.paired.clone(), h.browsers.clone()))
            .unwrap_or_default();
        let count = |browser| {
            paired
                .iter()
                .filter(|key| labels.get(*key) == Some(&browser))
                .count()
        };
        let unknown = paired.iter().any(|key| !labels.contains_key(key));
        if !self.settings_open && installed.iter().all(|browser| count(*browser) > 0) {
            return div();
        }
        let mut panel = v_flex()
            .py_3()
            .gap_2()
            .flex_none()
            .child(div().font_semibold().child("Connect your browsers"));
        for (index, browser) in Browser::ALL.into_iter().enumerate() {
            let paired_count = count(browser);
            if !(installed.contains(&browser) || self.settings_open && paired_count > 0) {
                continue;
            }
            let state = if paired_count > 0 {
                format!(
                    "{paired_count} paired {}",
                    if paired_count == 1 {
                        "profile"
                    } else {
                        "profiles"
                    }
                )
            } else if unknown {
                "Pairing not identified".into()
            } else {
                "Not paired".into()
            };
            panel = panel.child(
                h_flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(div().child(format!("{} · {state}", browser.name())))
                    .when(paired_count == 0, |row| {
                        row.child(
                            Button::new(("install-browser-extension", index))
                                .small()
                                .label("Install extension")
                                .on_click(move |_, _, cx| cx.open_url(browser.install_url())),
                        )
                    }),
            );
        }
        if unknown {
            panel = panel.child(
                div()
                    .text_sm()
                    .child("Reload existing extensions to identify their paired browsers."),
            );
        }
        if installed.iter().any(|browser| count(*browser) == 0) {
            panel = panel.child(div().text_sm().child(
                "Developer preview · Install the extension, then choose Pair with Desktop.",
            ));
        }
        if self.settings_open {
            let keys = hub
                .lock()
                .map(|h| h.paired.iter().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            panel = panel.child(div().font_semibold().child("Paired browser profiles"));
            if global.registration_error.lock().is_ok_and(|failed| *failed) {
                panel = panel.child("Browser setup failed. Check that the bridge is installed, then restart Desktop to retry.");
            }
            for (index, key) in keys.into_iter().enumerate() {
                let runtime = Arc::clone(&self.runtime);
                let hub = Arc::clone(&hub);
                let cache = cache.clone();
                let browser = labels.get(&key).map_or("Browser", |browser| browser.name());
                let label = format!("Disconnect {browser} · {}…", &key[..key.len().min(16)]);
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
        panel
    }
}
