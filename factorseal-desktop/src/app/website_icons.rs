use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use factorseal::isolation::network::icon::{Icon, IconManager};
use factorseal::personal::website::is_public_host;
use gpui::RenderImage;

const MAX_IN_FLIGHT: usize = 4;
const MAX_REQUESTS: usize = 256;
const MAX_ATTEMPTS: u8 = 2;

type Open = fn() -> Result<IconManager, String>;

pub(super) struct Helper {
    open: Open,
    manager: Mutex<Option<Arc<IconManager>>>,
    stopped: AtomicBool,
}

impl Helper {
    fn new(open: Open) -> Self {
        Self {
            open,
            manager: Mutex::new(None),
            stopped: AtomicBool::new(false),
        }
    }

    pub(super) fn fetch(&self, host: &str) -> Option<Icon> {
        let manager = {
            let mut slot = self.manager.lock().ok()?;
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            if slot.is_none() {
                match (self.open)() {
                    Ok(manager) => *slot = Some(Arc::new(manager)),
                    Err(error) => {
                        eprintln!("could not start the website icon helper: {error}");
                        self.stopped.store(true, Ordering::Release);
                        return None;
                    }
                }
            }
            Arc::clone(slot.as_ref()?)
        };
        manager.fetch(host)
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(manager) = self.manager.lock().ok().and_then(|mut slot| slot.take()) {
            manager.stop();
        }
    }
}

pub(super) struct Batch {
    pub(super) helper: Arc<Helper>,
    pub(super) generation: u64,
    pub(super) hosts: Vec<String>,
}

pub(super) struct WebsiteIcons {
    open: Open,
    helper: Option<Arc<Helper>>,
    icons: HashMap<String, Arc<RenderImage>>,
    attempts: HashMap<String, u8>,
    in_flight: HashSet<String>,
    requests: usize,
    generation: u64,
}

impl WebsiteIcons {
    pub(super) fn new(open: Open) -> Self {
        Self {
            open,
            helper: None,
            icons: HashMap::new(),
            attempts: HashMap::new(),
            in_flight: HashSet::new(),
            requests: 0,
            generation: 0,
        }
    }

    pub(super) fn icon(&self, entry: &factorseal::VaultEntryMetadata) -> Option<Arc<RenderImage>> {
        self.icons.get(entry.display_website.as_deref()?).cloned()
    }

    fn wipe(&mut self) -> Vec<Arc<RenderImage>> {
        if let Some(helper) = self.helper.take() {
            helper.stop();
        }
        self.attempts.clear();
        self.in_flight.clear();
        self.requests = 0;
        self.generation += 1;
        self.icons.drain().map(|(_, icon)| icon).collect()
    }

    pub(super) fn refresh(
        &mut self,
        enabled: bool,
        entries: Option<&[factorseal::VaultEntryMetadata]>,
    ) -> (Option<Batch>, Vec<Arc<RenderImage>>) {
        match entries {
            Some(entries) if enabled => (self.next(entries), Vec::new()),
            _ => (None, self.wipe()),
        }
    }

    fn next(&mut self, entries: &[factorseal::VaultEntryMetadata]) -> Option<Batch> {
        let mut hosts = Vec::new();
        for host in entries
            .iter()
            .filter(|entry| super::is_personal_secret(entry))
            .filter_map(|entry| entry.display_website.as_deref())
            .filter(|host| is_public_host(host))
        {
            if self.in_flight.len() >= MAX_IN_FLIGHT || self.requests >= MAX_REQUESTS {
                break;
            }
            let attempts = self.attempts.get(host).copied().unwrap_or_default();
            if self.icons.contains_key(host)
                || self.in_flight.contains(host)
                || attempts >= MAX_ATTEMPTS
            {
                continue;
            }
            self.attempts.insert(host.to_owned(), attempts + 1);
            self.in_flight.insert(host.to_owned());
            self.requests += 1;
            hosts.push(host.to_owned());
        }
        if hosts.is_empty() {
            return None;
        }
        let open = self.open;
        let helper = Arc::clone(
            self.helper
                .get_or_insert_with(|| Arc::new(Helper::new(open))),
        );
        Some(Batch {
            helper,
            generation: self.generation,
            hosts,
        })
    }

    pub(super) fn finish(&mut self, generation: u64, host: &str, icon: Option<&Icon>) -> bool {
        if generation != self.generation || !self.in_flight.remove(host) {
            return false;
        }
        let Some(image) = icon.and_then(render_image) else {
            return false;
        };
        self.icons.insert(host.to_owned(), image);
        true
    }
}

fn render_image(icon: &Icon) -> Option<Arc<RenderImage>> {
    let mut bgra = icon.rgba().to_vec();
    for pixel in bgra.as_chunks_mut::<4>().0 {
        pixel.swap(0, 2);
    }
    let buffer = image::RgbaImage::from_raw(icon.width(), icon.height(), bgra)?;
    Some(Arc::new(RenderImage::new([image::Frame::new(buffer)])))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable() -> Result<IconManager, String> {
        Err("no helper in tests".into())
    }

    fn entries(hosts: &[&str]) -> Vec<factorseal::VaultEntryMetadata> {
        hosts
            .iter()
            .enumerate()
            .map(|(index, host)| factorseal::VaultEntryMetadata {
                access_project: None,
                display_name: Some(format!("Item {index}")),
                display_type: Some("Login".into()),
                display_username: None,
                display_website: Some((*host).into()),
                updated_at: None,
                favorite: false,
                document_kind: factorseal::DocumentKind::LocalKeyring,
                partition: super::super::PERSONAL_SECRET_NAMESPACE.to_vec(),
                address: factorseal::SecretAddress::new(format!("item-{index}"), None).unwrap(),
            })
            .collect()
    }

    fn pixel() -> Icon {
        Icon::new(1, 1, vec![1, 2, 3, 255]).unwrap()
    }

    #[test]
    fn requests_are_deduplicated_bounded_and_only_for_public_domains() {
        let mut icons = WebsiteIcons::new(unavailable);
        let vault = entries(&[
            "github.com",
            "github.com",
            "localhost",
            "192.168.1.1",
            "router.local",
            "app.cachix.org",
            "console.hetzner.cloud",
            "studio.youtube.com",
            "discourse.nixos.org",
        ]);
        let first = icons.next(&vault).unwrap();
        assert_eq!(
            first.hosts,
            [
                "github.com",
                "app.cachix.org",
                "console.hetzner.cloud",
                "studio.youtube.com"
            ]
        );
        assert!(icons.next(&vault).is_none());
        assert!(icons.finish(first.generation, "github.com", Some(&pixel())));
        assert_eq!(icons.next(&vault).unwrap().hosts, ["discourse.nixos.org"]);
        assert!(icons.icon(&vault[1]).is_some());
        assert!(icons.icon(&vault[2]).is_none());
    }

    #[test]
    fn failed_hosts_are_retried_once_per_unseal() {
        let mut icons = WebsiteIcons::new(unavailable);
        let vault = entries(&["github.com"]);
        for _ in 0..MAX_ATTEMPTS {
            let batch = icons.next(&vault).unwrap();
            assert!(!icons.finish(batch.generation, "github.com", None));
        }
        assert!(icons.next(&vault).is_none());
        icons.refresh(true, None);
        assert_eq!(icons.next(&vault).unwrap().hosts, ["github.com"]);
    }

    #[test]
    fn total_requests_are_bounded_per_unseal() {
        let mut icons = WebsiteIcons::new(unavailable);
        let hosts: Vec<_> = (0..MAX_REQUESTS + 10)
            .map(|index| format!("site{index}.com"))
            .collect();
        let vault = entries(&hosts.iter().map(String::as_str).collect::<Vec<_>>());
        let mut requested = 0;
        while let Some(batch) = icons.next(&vault) {
            for host in &batch.hosts {
                icons.finish(batch.generation, host, None);
            }
            requested += batch.hosts.len();
        }
        assert_eq!(requested, MAX_REQUESTS);
    }

    #[test]
    fn turning_icons_off_forgets_them() {
        let mut icons = WebsiteIcons::new(unavailable);
        let vault = entries(&["github.com"]);
        let (Some(batch), _) = icons.refresh(true, Some(&vault)) else {
            panic!("expected a request");
        };
        assert!(icons.finish(batch.generation, "github.com", Some(&pixel())));
        let (none, dropped) = icons.refresh(false, Some(&vault));
        assert!(none.is_none());
        assert_eq!(dropped.len(), 1);
        assert!(icons.icon(&vault[0]).is_none());
        assert!(batch.helper.stopped.load(Ordering::Acquire));
    }

    #[test]
    fn turned_off_icons_send_no_requests() {
        let mut icons = WebsiteIcons::new(unavailable);
        let vault = entries(&["github.com"]);
        let (batch, _) = icons.refresh(false, Some(&vault));
        assert!(batch.is_none());
        assert!(icons.helper.is_none());
        assert!(icons.attempts.is_empty());
        assert_eq!(icons.requests, 0);
    }

    #[test]
    fn sealing_forgets_icons_stops_the_helper_and_drops_late_results() {
        let mut icons = WebsiteIcons::new(unavailable);
        let vault = entries(&["github.com", "studio.youtube.com"]);
        let (Some(batch), _) = icons.refresh(true, Some(&vault)) else {
            panic!("expected requests while unsealed");
        };
        assert!(icons.finish(batch.generation, "github.com", Some(&pixel())));
        assert!(icons.icon(&vault[0]).is_some());
        let (sealed, dropped) = icons.refresh(true, None);
        assert!(sealed.is_none());
        assert_eq!(dropped.len(), 1);
        assert!(icons.attempts.is_empty() && icons.in_flight.is_empty());
        assert!(icons.icon(&vault[0]).is_none());
        assert!(batch.helper.stopped.load(Ordering::Acquire));
        assert_eq!(batch.helper.fetch("studio.youtube.com"), None);
        assert!(!icons.finish(batch.generation, "studio.youtube.com", Some(&pixel())));
        assert!(icons.icon(&vault[1]).is_none());
        assert!(icons.helper.is_none());
    }

    #[test]
    fn rendered_icons_keep_their_pixels_in_gpu_order() {
        let image = render_image(&Icon::new(1, 1, vec![1, 2, 3, 4]).unwrap()).unwrap();
        assert_eq!(image.as_bytes(0), Some(&[3, 2, 1, 4][..]));
    }
}
