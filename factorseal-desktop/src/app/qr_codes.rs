use std::path::PathBuf;

use gpui_component::Icon;
use zeroize::Zeroizing;

use super::item_editor::QrTarget;
use super::totp;
use super::*;

const DROP_QR_CODE: &str = "Drop to add the one-time password";
const QR_CLIPBOARD_CLEARED: &str = "Removed the QR code from the clipboard.";
const LINK_CLIPBOARD_CLEARED: &str = "Removed the setup link from the clipboard.";
const MAX_IMAGE_FILE: u64 = 32 * 1024 * 1024;
const SCAN_SCREEN: &str = "Scan QR code on screen";
const SCREEN_NO_CODE: &str = "No QR code found on your screen.";
const SCREEN_FAILED: &str = "Could not capture your screen.";
#[cfg(target_os = "macos")]
const DISPLAYS: usize = 8;

pub(super) struct QrScan {
    target: QrTarget,
    row: Option<usize>,
    clipboard: Option<Copied>,
    result: Result<Zeroizing<String>, &'static str>,
}

#[derive(Clone, Copy)]
struct Copied {
    fingerprint: u64,
    cleared: &'static str,
}

enum Pasted {
    Image(gpui::Image),
    File(PathBuf),
    Link(Zeroizing<String>, Copied),
}

fn text_fingerprint(text: &str) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::hash::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

fn fingerprint(item: &gpui::ClipboardItem) -> Option<u64> {
    match pasted_image(item) {
        Some(image) => Some(image.id),
        None => Some(text_fingerprint(&Zeroizing::new(item.text()?))),
    }
}

fn pasted_image(item: &gpui::ClipboardItem) -> Option<gpui::Image> {
    item.entries().iter().find_map(|entry| match entry {
        gpui::ClipboardEntry::Image(image) => Some(image.clone()),
        _ => None,
    })
}

fn pasted(item: &gpui::ClipboardItem) -> Option<Pasted> {
    let file = item.entries().iter().find_map(|entry| match entry {
        gpui::ClipboardEntry::ExternalPaths(paths) => paths.paths().first().cloned(),
        _ => None,
    });
    file.map(Pasted::File)
        .or_else(|| pasted_image(item).map(Pasted::Image))
        .or_else(|| {
            let text = Zeroizing::new(item.text()?);
            let copied = Copied {
                fingerprint: text_fingerprint(&text),
                cleared: LINK_CLIPBOARD_CLEARED,
            };
            totp::setup_link(&text)
                .map(|link| Pasted::Link(link, copied))
                .or_else(|| file_path(&text).map(Pasted::File))
        })
}

fn matching_entry<'a>(
    entries: &'a [factorseal::VaultEntryMetadata],
    origin: &totp::Origin,
) -> Option<&'a factorseal::VaultEntryMetadata> {
    let same = |text: Option<&String>, wanted: &str| {
        text.is_some_and(|text| text.trim().eq_ignore_ascii_case(wanted.trim()))
    };
    let issuer = origin.issuer.as_deref()?;
    let account = origin.account.as_deref();
    let named: Vec<_> = entries
        .iter()
        .filter(|entry| is_personal_secret(entry) && same(entry.display_name.as_ref(), issuer))
        .filter(|entry| {
            let username = entry
                .display_username
                .as_ref()
                .filter(|username| !username.trim().is_empty());
            username
                .zip(account)
                .is_none_or(|(username, account)| same(Some(username), account))
        })
        .collect();
    if let [entry] = named.as_slice() {
        return Some(entry);
    }
    let account = account?;
    let mut owned = named
        .into_iter()
        .filter(|entry| same(entry.display_username.as_ref(), account));
    owned.next().filter(|_| owned.next().is_none())
}

#[cfg(target_os = "linux")]
async fn screen_qr_code() -> Result<Zeroizing<String>, &'static str> {
    let capture = ashpd::desktop::screenshot::Screenshot::request()
        .interactive(false)
        .modal(true)
        .send()
        .await
        .and_then(|request| request.response())
        .map_err(|_| SCREEN_FAILED)?;
    let path = file_path(capture.uri().as_str()).ok_or(SCREEN_FAILED)?;
    smol::unblock(move || {
        let bytes = std::fs::read(&path).map(Zeroizing::new);
        let _ = std::fs::remove_file(&path);
        screen_code([totp::scan_screen(&bytes.map_err(|_| SCREEN_FAILED)?)])
    })
    .await
}

#[cfg(target_os = "macos")]
async fn screen_qr_code() -> Result<Zeroizing<String>, &'static str> {
    smol::unblock(|| {
        let folder = tempfile::tempdir().map_err(|_| SCREEN_FAILED)?;
        let paths: Vec<_> = (1..=DISPLAYS)
            .map(|display| folder.path().join(format!("{display}.png")))
            .collect();
        let captured = std::process::Command::new("/usr/sbin/screencapture")
            .args(["-x", "-t", "png"])
            .args(&paths)
            .status()
            .is_ok_and(|status| status.success());
        if !captured {
            return Err(SCREEN_FAILED);
        }
        screen_code(
            paths
                .iter()
                .filter_map(|path| std::fs::read(path).ok().map(Zeroizing::new))
                .map(|bytes| totp::scan(&bytes)),
        )
    })
    .await
}

#[cfg(target_os = "windows")]
async fn screen_qr_code() -> Result<Zeroizing<String>, &'static str> {
    smol::unblock(|| {
        let (pixels, width, height) = super::windows_screen::capture().ok_or(SCREEN_FAILED)?;
        screen_code([totp::scan_luma(&pixels, width, height)])
    })
    .await
}

fn screen_code(
    scans: impl IntoIterator<Item = Result<Zeroizing<String>, totp::Scan>>,
) -> Result<Zeroizing<String>, &'static str> {
    let mut found = false;
    for scan in scans {
        match scan {
            Ok(code) => return Ok(code),
            Err(totp::Scan::NotOneTime) => found = true,
            Err(totp::Scan::NoCode) => {}
        }
    }
    Err(if found {
        totp::Scan::NotOneTime.message()
    } else {
        SCREEN_NO_CODE
    })
}

fn image_file(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, totp::Scan> {
    use std::io::Read as _;
    let size = std::fs::metadata(path)
        .ok()
        .filter(|file| file.is_file() && file.len() <= MAX_IMAGE_FILE)
        .ok_or(totp::Scan::NoCode)?
        .len();
    let file = std::fs::File::open(path).map_err(|_| totp::Scan::NoCode)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(usize::try_from(size).unwrap_or(0)));
    file.take(MAX_IMAGE_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| totp::Scan::NoCode)?;
    if bytes.len() as u64 > MAX_IMAGE_FILE {
        return Err(totp::Scan::NoCode);
    }
    Ok(bytes)
}

pub(super) fn file_path(text: &str) -> Option<PathBuf> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))?;
    let path = match url::Url::parse(line) {
        Ok(uri) if uri.scheme() == "file" => uri.to_file_path().ok()?,
        _ => PathBuf::from(line),
    };
    path.is_absolute().then_some(path)
}

impl DesktopView {
    pub(super) fn qr_button(&self, key: usize, cx: &mut Context<Self>) -> Button {
        button(("editor-qr", key))
            .ghost()
            .icon(Glyph::QrCode)
            .tooltip(SCAN_SCREEN)
            .accessibility_label(SCAN_SCREEN)
            .loading(self.qr_capturing)
            .on_click(cx.listener(move |view, _, _, cx| view.scan_qr_screen(key, cx)))
    }

    fn scan_qr_screen(&mut self, row: usize, cx: &mut Context<Self>) {
        let Some(target) = self.qr_target().filter(|_| !self.qr_capturing) else {
            return;
        };
        self.qr_capturing = true;
        let generation = self.qr_generation;
        cx.spawn(async move |view, cx| {
            let result = screen_qr_code().await;
            let _ = view.update(cx, |view, cx| {
                view.qr_capturing = false;
                if view.qr_generation == generation {
                    view.qr_scan = Some(QrScan {
                        target,
                        row: Some(row),
                        clipboard: None,
                        result,
                    });
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn paste_qr(&mut self, into_text: bool, cx: &mut Context<Self>) -> bool {
        let Some(item) = cx.read_from_clipboard() else {
            return false;
        };
        let pasted = pasted(&item)
            .filter(|_| self.qr_target().is_some())
            .filter(|pasted| match pasted {
                Pasted::Link(..) => true,
                Pasted::Image(_) => !into_text || item.text().is_none(),
                Pasted::File(_) => !into_text,
            });
        let Some(pasted) = pasted else {
            return false;
        };
        self.take_pasted(pasted, None, cx);
        true
    }

    pub(super) fn paste_into_row(
        &mut self,
        item: &gpui::ClipboardItem,
        row: usize,
        cx: &mut Context<Self>,
    ) {
        if let Some(pasted) = pasted(item) {
            self.take_pasted(pasted, Some(row), cx);
        }
    }

    fn take_pasted(&mut self, pasted: Pasted, row: Option<usize>, cx: &mut Context<Self>) {
        match pasted {
            Pasted::Image(image) => {
                let clipboard = Some(Copied {
                    fingerprint: image.id,
                    cleared: QR_CLIPBOARD_CLEARED,
                });
                let bytes = Zeroizing::new(image.bytes);
                self.read_qr_code(move || totp::scan(&bytes), row, clipboard, cx);
            }
            Pasted::File(path) => self.read_qr_file(path, row, cx),
            Pasted::Link(link, copied) => {
                self.read_qr_code(move || Ok(link), row, Some(copied), cx);
            }
        }
    }

    pub(super) fn drop_qr_code(&mut self, paths: &gpui::ExternalPaths, cx: &mut Context<Self>) {
        if let Some(path) = paths.paths().first().cloned() {
            self.read_qr_file(path, None, cx);
        }
    }

    pub(super) fn read_qr_file(
        &mut self,
        path: PathBuf,
        row: Option<usize>,
        cx: &mut Context<Self>,
    ) {
        self.read_qr_code(move || totp::scan(&image_file(&path)?), row, None, cx);
    }

    fn read_qr_code(
        &mut self,
        read: impl FnOnce() -> Result<Zeroizing<String>, totp::Scan> + Send + 'static,
        row: Option<usize>,
        clipboard: Option<Copied>,
        cx: &mut Context<Self>,
    ) {
        let Some(target) = self.qr_target() else {
            return;
        };
        let generation = self.qr_generation;
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(read).await.map_err(totp::Scan::message);
            let _ = view.update(cx, |view, cx| {
                if view.qr_generation == generation {
                    view.qr_scan = Some(QrScan {
                        target,
                        row,
                        clipboard,
                        result,
                    });
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub(super) fn apply_qr_scan(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(scan) = self.qr_scan.take() else {
            return;
        };
        let Some(target) = self.qr_target() else {
            return;
        };
        if scan.target != target {
            let opening = matches!(scan.target, QrTarget::Item(_)) && target == QrTarget::Vault;
            if opening && scan.result.is_ok() {
                self.qr_scan = Some(scan);
            }
            return;
        }
        match scan.result {
            Ok(link) if target == QrTarget::Vault => self.place_qr_code(link, scan.clipboard, cx),
            Ok(link) => {
                if let Some(copied) = scan.clipboard {
                    self.clear_qr_clipboard(copied, cx);
                }
                self.use_qr_code(&link, scan.row, window, cx);
            }
            Err(problem) => self.show_qr_problem(problem, scan.row, cx),
        }
    }

    fn place_qr_code(
        &mut self,
        link: Zeroizing<String>,
        clipboard: Option<Copied>,
        cx: &mut Context<Self>,
    ) {
        let entry = self
            .unsealed_contents()
            .and_then(|contents| matching_entry(&contents.entries, &totp::origin(&link)))
            .cloned();
        let target = if let Some(entry) = entry {
            let id = personal_item_id(&entry).map(str::to_owned);
            self.select_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
            id.map(QrTarget::Item)
        } else {
            self.show_personal_panel(PersonalPanel::NewItem, cx);
            Some(QrTarget::NewItem)
        };
        if let Some(target) = target {
            self.qr_scan = Some(QrScan {
                target,
                row: None,
                clipboard,
                result: Ok(link),
            });
        }
        cx.notify();
    }

    fn clear_qr_clipboard(&mut self, copied: Copied, cx: &mut Context<Self>) {
        if cx.read_from_clipboard().as_ref().and_then(fingerprint) == Some(copied.fingerprint) {
            cx.write_to_clipboard(gpui::ClipboardItem::new_string(String::new()));
            self.show_toast(copied.cleared, None, false, cx);
        }
    }

    pub(super) fn forget_qr_scan(&mut self) {
        self.qr_scan = None;
        self.qr_generation = self.qr_generation.wrapping_add(1);
    }

    pub(super) fn paste_qr_action(
        &mut self,
        _: &gpui_component::input::Paste,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.paste_qr(true, cx) {
            cx.stop_propagation();
        }
    }

    pub(super) fn qr_drop_zone(cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        div()
            .id("qr-drop-zone")
            .absolute()
            .inset_0()
            .m_3()
            .flex()
            .items_center()
            .justify_center()
            .rounded_lg()
            .border_2()
            .border_color(theme.ring)
            .bg(theme.background.opacity(0.92))
            .transitions(|transitions| transitions.opacity(crate::motion::hover()))
            .opacity(0.)
            .drag_over::<gpui::ExternalPaths>(|style, _, _, _| style.opacity(1.))
            .on_drop(cx.listener(|view, paths: &gpui::ExternalPaths, _, cx| {
                view.drop_qr_code(paths, cx);
            }))
            .child(
                v_flex()
                    .items_center()
                    .gap_3()
                    .text_color(theme.foreground)
                    .child(Icon::from(Glyph::QrCode).size(rems(2.5)))
                    .child(div().text_lead().child(DROP_QR_CODE)),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, username: &str) -> factorseal::VaultEntryMetadata {
        factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some(name.into()),
            display_type: Some("Login".into()),
            display_username: Some(username.into()),
            display_website: None,
            favorite: false,
            updated_at: None,
            document_kind: factorseal::DocumentKind::LocalKeyring,
            partition: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: factorseal::SecretAddress::new(format!("{name}-{username}"), None).unwrap(),
        }
    }

    fn origin(issuer: Option<&str>, account: Option<&str>) -> totp::Origin {
        totp::Origin {
            issuer: issuer.map(Into::into),
            account: account.map(Into::into),
        }
    }

    #[test]
    fn codes_go_to_the_one_item_named_after_their_issuer() {
        let entries = [
            entry("GitHub", "alice"),
            entry("GitLab", "alice"),
            entry("GitLab", "bob"),
            entry("GitHub test", "alice"),
            entry("Hetzner", ""),
        ];
        let found = |issuer, account| {
            matching_entry(&entries, &origin(issuer, account)).map(|entry| entry.address.clone())
        };
        assert_eq!(
            found(Some(" github "), None),
            Some(entries[0].address.clone())
        );
        assert_eq!(
            found(Some("GitLab"), Some("BOB")),
            Some(entries[2].address.clone())
        );
        assert_eq!(found(Some("GitLab"), Some("carol")), None);
        assert_eq!(found(Some("GitLab"), None), None);
        assert_eq!(found(Some("GitHub"), Some("bob")), None);
        assert_eq!(
            found(Some("Hetzner"), Some("alice")),
            Some(entries[4].address.clone())
        );
        assert_eq!(found(None, Some("alice")), None);
    }

    #[test]
    fn image_files_are_read_only_when_they_are_small_regular_files() {
        let folder = tempfile::tempdir().unwrap();
        let small = folder.path().join("small.png");
        std::fs::write(&small, b"picture").unwrap();
        assert_eq!(
            image_file(&small).map(|bytes| bytes.to_vec()),
            Ok(b"picture".to_vec())
        );
        let large = folder.path().join("large.png");
        std::fs::File::create(&large)
            .unwrap()
            .set_len(MAX_IMAGE_FILE + 1)
            .unwrap();
        for path in [
            folder.path(),
            large.as_path(),
            std::path::Path::new("/dev/zero"),
        ] {
            assert_eq!(image_file(path).err(), Some(totp::Scan::NoCode), "{path:?}");
        }
    }

    #[test]
    fn pasted_setup_links_remember_the_clipboard_they_came_from() {
        let item = gpui::ClipboardItem::new_string(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP".to_owned(),
        );
        let Some(Pasted::Link(_, copied)) = pasted(&item) else {
            panic!("not a setup link");
        };
        assert_eq!(fingerprint(&item), Some(copied.fingerprint));
        assert_ne!(
            fingerprint(&gpui::ClipboardItem::new_string("other".to_owned())),
            Some(copied.fingerprint)
        );
    }

    #[test]
    fn pasted_text_names_a_file_by_path_or_file_link() {
        #[cfg(unix)]
        {
            assert_eq!(
                file_path("/home/alice/QR code.png"),
                Some(PathBuf::from("/home/alice/QR code.png"))
            );
            assert_eq!(
                file_path("# copied\nfile:///home/alice/QR%20code.png\nfile:///tmp/b.png\n"),
                Some(PathBuf::from("/home/alice/QR code.png"))
            );
            assert_eq!(
                file_path("file://localhost/tmp/a.png"),
                Some(PathBuf::from("/tmp/a.png"))
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(
                file_path(r"C:\Users\alice\QR code.png"),
                Some(PathBuf::from(r"C:\Users\alice\QR code.png"))
            );
            assert_eq!(
                file_path("file:///C:/Users/alice/QR%20code.png"),
                Some(PathBuf::from(r"C:\Users\alice\QR code.png"))
            );
        }
        for text in [
            "",
            "QR code.png",
            "JBSWY3DPEHPK3PXP",
            "https://example.com/a.png",
        ] {
            assert_eq!(file_path(text), None, "{text}");
        }
    }
}
