//! Desktop owns all browser consent; the native bridge never receives manager authority.
use super::*;
use factorseal::browser::discovery::Browser;
use factorseal::browser::{
    OneTimePassword, WorkerAction,
    desktop::{Hub, Prompt},
};
use std::sync::Mutex;
mod prompt;
struct BrowserGlobal {
    hub: Arc<Mutex<Hub>>,
    cache: std::path::PathBuf,
    registration_error: Arc<Mutex<bool>>,
    saved: Arc<std::sync::atomic::AtomicBool>,
    installed: Arc<Mutex<Vec<(Browser, bool)>>>,
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
        let found = discover_browsers();
        if let Ok(mut installed) = installed.lock() {
            *installed = found;
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
                if matches!(
                    work.action,
                    WorkerAction::Save { .. } | WorkerAction::SaveOneTime { .. }
                ) && matches!(result, Ok(factorseal::browser::WorkerReply::Done))
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
        let mut last_browser_scan = std::time::Instant::now();
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
                if unsealed && (!was_unsealed || last_browser_scan.elapsed().as_secs() >= 10) {
                    last_browser_scan = std::time::Instant::now();
                    let installed = Arc::clone(&cx.global::<BrowserGlobal>().installed);
                    std::thread::spawn(move || {
                        let found = discover_browsers();
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
                    if let Some((session, generation, image)) = h.take_image() {
                        read_one_time_password(Arc::clone(&hub), session, generation, image, cx);
                    }
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
fn read_one_time_password(
    hub: Arc<Mutex<Hub>>,
    session: String,
    generation: u64,
    image: Zeroizing<Vec<u8>>,
    cx: &App,
) {
    cx.spawn(async move |_| {
        let scanned = smol::unblock(move || totp::scan(&image))
            .await
            .ok()
            .map(|mut link| {
                let origin = totp::origin(&link);
                OneTimePassword {
                    link: std::mem::take(&mut *link),
                    issuer: origin.issuer,
                    account: origin.account,
                }
            });
        if let Ok(mut h) = hub.lock() {
            h.scanned(&session, generation, scanned);
        }
    })
    .detach();
}
fn discover_browsers() -> Vec<(Browser, bool)> {
    factorseal::browser::discovery::installed()
        .into_iter()
        .map(|browser| {
            (
                browser,
                factorseal::browser::discovery::extension_installed(browser),
            )
        })
        .collect()
}

fn browser_state(paired_count: usize, extension_installed: bool) -> String {
    if paired_count > 0 {
        format!(
            "Extension paired · {paired_count} {}",
            if paired_count == 1 {
                "profile"
            } else {
                "profiles"
            }
        )
    } else if extension_installed {
        "Extension installed · Not paired".into()
    } else {
        "Extension not detected".into()
    }
}

fn browser_status_visible(
    settings_open: bool,
    detected: Option<bool>,
    paired_count: usize,
) -> bool {
    paired_count > 0 || detected.is_some_and(|extension| settings_open || extension)
}

struct Detected {
    installed: Vec<(Browser, bool)>,
    paired: Vec<String>,
    labels: std::collections::HashMap<String, Browser>,
}

impl Detected {
    fn read(global: &BrowserGlobal) -> Self {
        let installed = global
            .installed
            .lock()
            .map(|b| b.clone())
            .unwrap_or_default();
        let (mut paired, labels) = global
            .hub
            .lock()
            .map(|h| {
                (
                    h.paired.iter().cloned().collect::<Vec<_>>(),
                    h.browsers.clone(),
                )
            })
            .unwrap_or_default();
        paired.sort_unstable();
        Self {
            installed,
            paired,
            labels,
        }
    }

    fn count(&self, browser: Browser) -> usize {
        self.paired
            .iter()
            .filter(|key| self.labels.get(*key) == Some(&browser))
            .count()
    }

    fn browsers(
        &self,
        settings_open: bool,
    ) -> impl Iterator<Item = (usize, Browser, usize, bool)> + '_ {
        Browser::ALL
            .into_iter()
            .enumerate()
            .filter_map(move |(index, browser)| {
                let paired_count = self.count(browser);
                let detected = self
                    .installed
                    .iter()
                    .find(|(found, _)| *found == browser)
                    .map(|(_, extension)| *extension);
                browser_status_visible(settings_open, detected, paired_count).then_some((
                    index,
                    browser,
                    paired_count,
                    detected == Some(true),
                ))
            })
    }
}

impl DesktopView {
    pub(super) fn render_browser(&self, cx: &mut Context<Self>) -> Div {
        let Some(global) = cx.try_global::<BrowserGlobal>() else {
            return div();
        };
        if !matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. }) {
            return div();
        }
        let detected = Detected::read(global);
        let theme = cx.theme().clone();
        v_flex()
            .mt_2()
            .flex_none()
            .w_full()
            .max_w(rems(420. / 16.))
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .overflow_hidden()
            .children(detected.browsers(false).map(
                |(_, browser, paired_count, extension_installed)| {
                    let status = if paired_count > 0 {
                        theme.success
                    } else if extension_installed {
                        theme.warning
                    } else {
                        theme.muted_foreground
                    };
                    h_flex()
                        .id(gpui::ElementId::Name(browser.name().into()))
                        .items_center()
                        .gap_3()
                        .px_4()
                        .py_3()
                        .border_b_1()
                        .border_color(theme.border)
                        .child(
                            icon_tile(2., &theme).child(
                                gpui_component::Icon::new(IconName::Globe)
                                    .size(rems(1.))
                                    .text_color(theme.foreground),
                            ),
                        )
                        .child(
                            v_flex()
                                .min_w_0()
                                .child(div().font_semibold().child(text("name", browser.name())))
                                .child(
                                    h_flex()
                                        .items_center()
                                        .gap_2()
                                        .text_caption()
                                        .text_color(theme.muted_foreground)
                                        .child(div().size_2().rounded_full().bg(status))
                                        .child(browser_state(paired_count, extension_installed)),
                                ),
                        )
                },
            ))
            .child(
                h_flex().p_2().justify_end().child(
                    button("open-browser-settings")
                        .ghost()
                        .small()
                        .icon(IconName::Globe)
                        .label("Browser extensions")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.open_settings(cx);
                            view.open_section(
                                section_pages::SectionRow::Settings(
                                    crate::settings_view::Section::Browsers,
                                ),
                                cx,
                            );
                        })),
                ),
            )
    }

    pub(super) fn browsers_available(&self, cx: &App) -> bool {
        cx.try_global::<BrowserGlobal>().is_some()
            && matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. })
    }

    pub(super) fn browser_settings(
        &self,
        cx: &mut Context<Self>,
    ) -> Option<crate::settings_view::Browsers> {
        use crate::settings_view::{BrowserRow, Browsers};
        let global = cx.try_global::<BrowserGlobal>()?;
        if !matches!(self.snapshot, Snapshot::Unsealed { owned: true, .. }) {
            return None;
        }
        let hub = Arc::clone(&global.hub);
        let cache = global.cache.clone();
        let registration_failed = global.registration_error.lock().is_ok_and(|failed| *failed);
        let detected = Detected::read(global);
        let rows = detected
            .browsers(true)
            .map(
                |(index, browser, paired_count, extension_installed)| BrowserRow {
                    name: browser.name(),
                    state: browser_state(paired_count, extension_installed).into(),
                    install: (paired_count == 0 && !extension_installed).then(|| {
                        button(("install-browser-extension", index))
                            .small()
                            .icon(IconName::ExternalLink)
                            .label("Install extension")
                            .on_click(move |_, _, cx| cx.open_url(browser.install_url()))
                            .into_any_element()
                    }),
                },
            )
            .collect();
        let mut notes = Vec::new();
        if detected
            .paired
            .iter()
            .any(|key| !detected.labels.contains_key(key))
        {
            notes.push("Reload existing extensions to identify their paired browsers.");
        }
        if detected
            .installed
            .iter()
            .any(|(browser, _)| detected.count(*browser) == 0)
        {
            notes.push("Developer preview · Install the extension, then choose Pair with Desktop.");
        }
        let paired = detected
            .paired
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let runtime = Arc::clone(&self.runtime);
                let hub = Arc::clone(&hub);
                let cache = cache.clone();
                let key = key.clone();
                let browser = detected
                    .labels
                    .get(&key)
                    .map_or("Browser", |browser| browser.name());
                let label = format!("Disconnect {browser} · {}…", &key[..key.len().min(16)]);
                button(("browser-revoke", index))
                    .small()
                    .icon(IconName::CircleX)
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
                                    let _ =
                                        factorseal::transfer::write_private_file(&cache, &bytes);
                                }
                            }
                        })
                        .detach();
                    }))
                    .into_any_element()
            })
            .collect();
        Some(Browsers {
            rows,
            notes,
            error: registration_failed.then_some(
                "Browser setup failed. Check that the bridge is installed, then restart Desktop to retry.",
            ),
            paired,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_lists_only_browsers_with_the_extension() {
        assert!(!browser_status_visible(false, None, 0));
        assert!(!browser_status_visible(false, Some(false), 0));
        assert!(browser_status_visible(false, Some(true), 0));
        assert!(browser_status_visible(false, None, 1));
        assert!(browser_status_visible(true, Some(false), 0));
        assert!(!browser_status_visible(true, None, 0));
    }
}
