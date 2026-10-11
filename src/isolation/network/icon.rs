use serde::{Deserialize, Serialize};

pub const MAX_SIDE: u32 = 64;
const SERVICE: &str = "icons.duckduckgo.com";
const MAX_BYTES: usize = 64 * 1024;
const MAX_SOURCE_SIDE: u32 = 512;
const MAX_DECODE_ALLOCATION: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Pixels", into = "Pixels")]
pub struct Icon {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pixels {
    width: u32,
    height: u32,
    rgba: Vec<u8>,
}

impl Icon {
    #[must_use]
    pub fn new(width: u32, height: u32, rgba: Vec<u8>) -> Option<Self> {
        let valid = (1..=MAX_SIDE).contains(&width)
            && (1..=MAX_SIDE).contains(&height)
            && u64::try_from(rgba.len()).ok() == Some(u64::from(width) * u64::from(height) * 4);
        valid.then_some(Self {
            width,
            height,
            rgba,
        })
    }

    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub fn rgba(&self) -> &[u8] {
        &self.rgba
    }
}

impl TryFrom<Pixels> for Icon {
    type Error = &'static str;

    fn try_from(pixels: Pixels) -> Result<Self, Self::Error> {
        Self::new(pixels.width, pixels.height, pixels.rgba).ok_or("invalid icon pixels")
    }
}

impl From<Icon> for Pixels {
    fn from(icon: Icon) -> Self {
        Self {
            width: icon.width,
            height: icon.height,
            rgba: icon.rgba,
        }
    }
}

#[must_use]
pub fn url(host: &str) -> Option<String> {
    crate::personal::website::is_public_host(host)
        .then(|| format!("https://{SERVICE}/ip3/{host}.ico"))
}

fn is_service(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(SERVICE)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Icon> {
    use image::{ImageFormat, ImageReader, Limits, imageops::FilterType};
    if bytes.len() > MAX_BYTES {
        return None;
    }
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    if !matches!(reader.format(), Some(ImageFormat::Png | ImageFormat::Ico)) {
        return None;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_SIDE);
    limits.max_image_height = Some(MAX_SOURCE_SIDE);
    limits.max_alloc = Some(MAX_DECODE_ALLOCATION);
    reader.limits(limits);
    let image = reader.decode().ok()?;
    let image = if image.width() > MAX_SIDE || image.height() > MAX_SIDE {
        image.resize(MAX_SIDE, MAX_SIDE, FilterType::Triangle)
    } else {
        image
    };
    let rgba = image.into_rgba8();
    Icon::new(rgba.width(), rgba.height(), rgba.into_raw())
}

#[cfg(any(unix, windows))]
mod native {
    use super::super::{MAXIMUM, ToChild, ToParent};
    use super::{Icon, MAX_BYTES, decode, is_service, url};
    use crate::isolation::{codec, process, sandbox};
    use process::Channel;
    use std::{
        collections::HashMap,
        io,
        path::Path,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        time::Duration,
    };

    const MAX_CONCURRENT: usize = 4;
    const MAX_PENDING: usize = 8;
    const MAX_REDIRECTS: usize = 2;
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    const WAIT: Duration = Duration::from_secs(30);
    const USER_AGENT: &str = "Mozilla/5.0";

    type Pending = Mutex<HashMap<u64, mpsc::SyncSender<Option<Icon>>>>;

    pub struct IconManager {
        owner: Arc<Mutex<process::Owner>>,
        writer: Mutex<Channel>,
        pending: Arc<Pending>,
        live: Arc<AtomicBool>,
        sequence: AtomicU64,
        listener: Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl IconManager {
        pub fn open(executable: &Path) -> Result<Self, String> {
            if cfg!(windows) {
                return Err("website icons are unavailable on this platform".into());
            }
            let (owner, mut channel) = process::spawn(executable, None).map_err(err)?;
            let owner = Arc::new(Mutex::new(owner));
            process::send(
                &mut channel,
                &super::super::Bootstrap::Icons { version: 1 },
                16384,
            )
            .map_err(err)?;
            let writer = Mutex::new(channel.try_clone().map_err(err)?);
            let pending = Arc::new(Pending::default());
            let live = Arc::new(AtomicBool::new(true));
            let (ready, started) = mpsc::sync_channel(1);
            let listener = {
                let (owner, pending, live) =
                    (Arc::clone(&owner), Arc::clone(&pending), Arc::clone(&live));
                std::thread::Builder::new()
                    .name("factorseal-icon-control".into())
                    .spawn(move || {
                        let result = listen(&mut channel, &pending, &ready);
                        live.store(false, Ordering::Release);
                        if let Ok(mut owner) = owner.lock() {
                            owner.stop();
                        }
                        let _ = ready.try_send(Err(result.err().unwrap_or_default()));
                        if let Ok(mut pending) = pending.lock() {
                            pending.clear();
                        }
                    })
                    .map_err(err)?
            };
            let manager = Self {
                owner,
                writer,
                pending,
                live,
                sequence: AtomicU64::new(1),
                listener: Mutex::new(Some(listener)),
            };
            started
                .recv_timeout(WAIT)
                .map_err(err)
                .and_then(|result| result)?;
            Ok(manager)
        }

        #[must_use]
        pub fn fetch(&self, host: &str) -> Option<Icon> {
            url(host)?;
            if !self.live.load(Ordering::Acquire) {
                return None;
            }
            let mut writer = self.writer.lock().ok()?;
            let id = self.sequence.fetch_add(1, Ordering::Relaxed);
            let (sender, receiver) = mpsc::sync_channel(1);
            {
                let mut pending = self.pending.lock().ok()?;
                if pending.len() >= MAX_PENDING {
                    return None;
                }
                pending.insert(id, sender);
            }
            let request = ToChild::Icon {
                id,
                host: host.to_owned(),
            };
            let sent = process::send(&mut writer, &request, MAXIMUM);
            drop(writer);
            let icon = sent
                .ok()
                .and_then(|()| receiver.recv_timeout(WAIT).ok())
                .flatten();
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(&id);
            }
            icon
        }

        pub fn stop(&self) {
            self.live.store(false, Ordering::Release);
            if let Ok(mut owner) = self.owner.lock() {
                owner.stop();
            }
        }
    }

    impl Drop for IconManager {
        fn drop(&mut self) {
            self.stop();
            if let Some(listener) = self.listener.lock().ok().and_then(|mut slot| slot.take()) {
                let _ = listener.join();
            }
        }
    }

    fn listen(
        channel: &mut Channel,
        pending: &Pending,
        ready: &mpsc::SyncSender<Result<(), String>>,
    ) -> Result<(), String> {
        match process::receive(channel, MAXIMUM).map_err(err)? {
            ToParent::Ready => ready.send(Ok(())).map_err(err)?,
            ToParent::StartupFailed(error) => {
                return Err(format!("icon helper could not start: {error}"));
            }
            _ => return Err("unexpected icon helper startup".into()),
        }
        loop {
            match process::receive(channel, MAXIMUM).map_err(err)? {
                ToParent::Icon { id, icon } => {
                    if let Some(sender) = pending.lock().map_err(err)?.remove(&id) {
                        let _ = sender.try_send(icon);
                    }
                }
                ToParent::Failed(error) => return Err(format!("icon helper stopped: {error}")),
                _ => return Err("unexpected icon helper reply".into()),
            }
        }
    }

    pub(in crate::isolation::network) fn serve() -> io::Result<()> {
        sandbox::network(None).inspect_err(|error| {
            let _ = codec::send(
                &mut io::stdout().lock(),
                &ToParent::StartupFailed(format!("sandbox: {error}")),
                MAXIMUM,
            );
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let client = client().map_err(io::Error::other)?;
        let mut channel = process::stdio_channel()?;
        process::send(&mut channel, &ToParent::Ready, MAXIMUM)?;
        let (replies, outgoing) = mpsc::sync_channel::<(u64, Option<Icon>)>(MAX_PENDING);
        let mut writer = channel.try_clone()?;
        std::thread::Builder::new()
            .name("factorseal-icon-replies".into())
            .spawn(move || {
                while let Ok((id, icon)) = outgoing.recv() {
                    if process::send(&mut writer, &ToParent::Icon { id, icon }, MAXIMUM).is_err() {
                        break;
                    }
                }
            })?;
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
        let mut previous = 0;
        loop {
            let ToChild::Icon { id, host } = process::receive(&mut channel, MAXIMUM)? else {
                return Err(io::Error::other("unexpected icon helper request"));
            };
            if id <= previous {
                return Err(io::Error::other("replayed icon request"));
            }
            previous = id;
            let (client, permits, replies) =
                (client.clone(), Arc::clone(&permits), replies.clone());
            runtime.spawn(async move {
                let icon = match permits.acquire_owned().await {
                    Ok(_permit) => fetch(&client, &host).await,
                    Err(_) => None,
                };
                let _ = replies.try_send((id, icon));
            });
        }
    }

    fn client() -> Result<reqwest::Client, String> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(err)?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
        reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .no_proxy()
            .referer(false)
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() < MAX_REDIRECTS && is_service(attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .user_agent(USER_AGENT)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(err)
    }

    async fn fetch(client: &reqwest::Client, host: &str) -> Option<Icon> {
        let mut response = client.get(url(host)?).send().await.ok()?;
        if !response.status().is_success()
            || !is_service(response.url())
            || response
                .content_length()
                .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > MAX_BYTES {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        decode(&body)
    }

    fn err(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::*;

        fn helper() -> std::path::PathBuf {
            crate::isolation::helper_executable(
                &std::env::current_exe().unwrap(),
                "factorseal-network",
            )
            .unwrap()
        }

        #[test]
        fn icon_helper_never_sends_a_request_for_hosts_that_are_not_public_domains() {
            let manager = IconManager::open(&helper()).unwrap();
            for host in [
                "localhost",
                "127.0.0.1",
                "router.local",
                "evil.com/x?y",
                "user@github.com",
                "github.com:8443",
                "GitHub.com",
            ] {
                assert_eq!(manager.fetch(host), None);
            }
            assert_eq!(manager.sequence.load(Ordering::Relaxed), 1);
        }

        #[test]
        #[ignore = "requires network access to icons.duckduckgo.com"]
        fn sandboxed_icon_helper_fetches_and_decodes_public_website_icons() {
            let manager = IconManager::open(&helper()).unwrap();
            for host in ["github.com", "console.hetzner.cloud", "studio.youtube.com"] {
                let icon = manager.fetch(host).expect(host);
                assert!(icon.width() <= super::super::MAX_SIDE, "{host}");
                assert!(icon.height() <= super::super::MAX_SIDE, "{host}");
            }
            assert_eq!(manager.fetch("app.cachix.org"), None);
        }

        #[test]
        fn stopped_icon_helper_exits_and_fails_every_later_fetch() {
            let manager = IconManager::open(&helper()).unwrap();
            manager.stop();
            manager
                .listener
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .join()
                .unwrap();
            assert!(!manager.live.load(Ordering::Acquire));
            assert_eq!(manager.fetch("github.com"), None);
            assert_eq!(manager.sequence.load(Ordering::Relaxed), 1);
        }

        #[test]
        fn icon_helper_rejects_sync_requests() {
            let (_owner, mut channel) = process::spawn(&helper(), None).unwrap();
            process::send(
                &mut channel,
                &super::super::super::Bootstrap::Icons { version: 1 },
                16384,
            )
            .unwrap();
            assert!(matches!(
                process::receive::<ToParent>(&mut channel, MAXIMUM).unwrap(),
                ToParent::Ready
            ));
            process::send(&mut channel, &ToChild::View(1), MAXIMUM).unwrap();
            assert!(matches!(
                process::receive::<ToParent>(&mut channel, MAXIMUM),
                Ok(ToParent::Failed(_)) | Err(_)
            ));
        }
    }
}

#[cfg(any(unix, windows))]
pub use native::IconManager;
#[cfg(any(unix, windows))]
pub(super) use native::serve;

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        image::RgbaImage::from_pixel(width, height, image::Rgba([10, 20, 30, 255]))
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();
        bytes
    }

    #[test]
    fn icon_url_is_fixed_and_only_the_validated_host_varies() {
        assert_eq!(
            url("github.com").as_deref(),
            Some("https://icons.duckduckgo.com/ip3/github.com.ico")
        );
        for host in [
            "",
            "github.com/../../evil",
            "evil.com?x=",
            "evil.com#",
            "user@evil.com",
            "evil.com:443",
            "http://evil.com",
            "localhost",
            "10.0.0.1",
            "[::1]",
            "nas.lan",
        ] {
            assert_eq!(url(host), None, "{host}");
        }
        assert!(is_service(
            &reqwest::Url::parse(&url("github.com").unwrap()).unwrap()
        ));
        for denied in [
            "http://icons.duckduckgo.com/ip3/github.com.ico",
            "https://icons.duckduckgo.com:8443/ip3/github.com.ico",
            "https://user@icons.duckduckgo.com/",
            "https://duckduckgo.com/",
            "https://icons.duckduckgo.com.evil.com/",
            "https://github.com/favicon.ico",
        ] {
            assert!(
                !is_service(&reqwest::Url::parse(denied).unwrap()),
                "{denied}"
            );
        }
    }

    #[test]
    fn decoded_icons_are_small_rgba_pixels() {
        let small = decode(&png(16, 16)).unwrap();
        assert_eq!((small.width(), small.height()), (16, 16));
        assert_eq!(&small.rgba()[..4], [10, 20, 30, 255]);
        let large = decode(&png(256, 128)).unwrap();
        assert_eq!((large.width(), large.height()), (64, 32));
        assert_eq!(large.rgba().len(), 64 * 32 * 4);
        assert_eq!(decode(&png(1024, 16)), None);
        assert_eq!(decode(b"<svg xmlns='http://www.w3.org/2000/svg'/>"), None);
        assert_eq!(decode(&[0; 16]), None);
        let mut padded = png(16, 16);
        padded.resize(MAX_BYTES + 1, 0);
        assert_eq!(decode(&padded), None);
    }

    #[test]
    fn icon_pixels_are_validated_when_received() {
        assert!(Icon::new(64, 64, vec![0; 64 * 64 * 4]).is_some());
        assert!(Icon::new(65, 1, vec![0; 65 * 4]).is_none());
        assert!(Icon::new(0, 0, Vec::new()).is_none());
        assert!(Icon::new(2, 2, vec![0; 15]).is_none());
        let forged = crate::isolation::codec::encode(
            &Pixels {
                width: 128,
                height: 1,
                rgba: vec![0; 512],
            },
            super::super::MAXIMUM,
        )
        .unwrap();
        assert!(crate::isolation::codec::decode::<Icon>(&forged, super::super::MAXIMUM).is_err());
        let valid = crate::isolation::codec::encode(
            &Icon::new(1, 1, vec![1, 2, 3, 4]).unwrap(),
            super::super::MAXIMUM,
        )
        .unwrap();
        assert_eq!(
            crate::isolation::codec::decode::<Icon>(&valid, super::super::MAXIMUM)
                .unwrap()
                .rgba(),
            [1, 2, 3, 4]
        );
    }
}
