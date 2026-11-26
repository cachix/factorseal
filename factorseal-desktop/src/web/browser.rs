#![allow(clippy::unused_self)]

use super::*;
use std::sync::Mutex;

#[path = "../app/browser/prompt.rs"]
mod prompt;

const PROFILE_KEY: &str = "3f9a1c07b2e4d685a1c9e07f3b2d4c68e5f1a0b9c7d3e2f4a6b8c0d1e3f5a7b9";
const RELEASE_MS: u128 = 900;

#[derive(Clone, Debug)]
struct Candidate {
    title: String,
    username: String,
    one_time: bool,
}

#[derive(Clone, Debug)]
struct Prompt {
    session: String,
    generation: u64,
    site: String,
    key: String,
    state: String,
    candidates: Vec<Candidate>,
    save_username: Option<String>,
    one_time: bool,
    code: Option<String>,
}

#[derive(Default)]
struct Hub {
    prompt: Option<Prompt>,
    generation: u64,
    released: Option<(web_time::Instant, Option<String>)>,
}

impl Hub {
    fn prompt(&mut self) -> Option<Prompt> {
        if self
            .released
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed().as_millis() >= RELEASE_MS)
            && let Some((_, username)) = self.released.take()
        {
            self.prompt = None;
            crate::site::report_browser(true, username.as_deref());
        }
        self.prompt.clone()
    }

    fn deny(&mut self, _session: &str) {
        self.prompt = None;
        self.released = None;
        crate::site::report_browser(false, None);
    }

    fn approve(&mut self, _session: &str, generation: u64, index: Option<usize>) {
        let Some(prompt) = &mut self.prompt else {
            return;
        };
        if prompt.generation != generation || prompt.state != "awaiting_approval" {
            return;
        }
        let username = index
            .and_then(|index| prompt.candidates.get(index))
            .map(|candidate| candidate.username.clone());
        prompt.state = "releasing".into();
        self.released = Some((web_time::Instant::now(), username));
    }

    fn request(&mut self, site: String, candidates: Vec<Candidate>) {
        self.generation += 1;
        self.released = None;
        self.prompt = Some(Prompt {
            session: "browser-demo".into(),
            generation: self.generation,
            site,
            key: PROFILE_KEY.into(),
            state: "awaiting_approval".into(),
            candidates,
            save_username: None,
            one_time: false,
            code: None,
        });
    }
}

struct BrowserGlobal {
    hub: Arc<Mutex<Hub>>,
}
impl Global for BrowserGlobal {}

pub(super) fn setup(_root: &std::path::Path, _runtime: Arc<DesktopRuntime>, cx: &mut App) {
    prompt::setup(cx);
    let hub = Arc::new(Mutex::new(Hub::default()));
    cx.set_global(BrowserGlobal {
        hub: Arc::clone(&hub),
    });
    cx.spawn(async move |cx| {
        loop {
            cx.background_executor()
                .timer(std::time::Duration::from_millis(200))
                .await;
            cx.update(|cx| {
                let prompt = hub.lock().ok().and_then(|mut hub| hub.prompt());
                prompt::sync(prompt, cx);
            });
        }
    })
    .detach();
}

pub(crate) fn request(site: String, cx: &mut App) {
    let candidates = match &cx.global::<DesktopWindow>().snapshot {
        Snapshot::Unsealed { contents, .. } if site != "Pair browser profile" => contents
            .entries
            .iter()
            .filter(|entry| {
                site.strip_prefix("https://")
                    .is_some_and(|host| entry.display_website.as_deref() == Some(host))
            })
            .map(|entry| Candidate {
                title: entry.display_name.clone().unwrap_or_default(),
                username: entry.display_username.clone().unwrap_or_default(),
                one_time: false,
            })
            .collect(),
        _ => Vec::new(),
    };
    if let Ok(mut hub) = cx.global::<BrowserGlobal>().hub.lock() {
        hub.request(site, candidates);
    }
}

pub(crate) fn cancel(cx: &mut App) {
    if let Ok(mut hub) = cx.global::<BrowserGlobal>().hub.lock() {
        hub.prompt = None;
        hub.released = None;
    }
}

impl DesktopView {
    pub(super) fn render_browser(&self, _cx: &mut Context<Self>) -> Div {
        div()
    }

    pub(super) const fn browsers_available(&self, _cx: &App) -> bool {
        false
    }

    pub(super) const fn browser_settings(
        &self,
        _cx: &mut Context<Self>,
    ) -> Option<crate::settings_view::Browsers> {
        None
    }
}
