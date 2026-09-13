//! In-memory boundary with the Swift bridge. Called only from GPUI's main
//! thread; the bridge owns `AppKit`'s delegate and async system operations.
use zeroize::Zeroizing;

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum Event {
    Import(Zeroizing<Vec<u8>>),
    Exported,
    Cancelled,
    Failed,
    Open,
}

#[cfg(target_os = "macos")]
mod native {
    #![allow(unsafe_code)]
    use super::Event;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    use zeroize::Zeroizing;

    static SENDER: OnceLock<smol::channel::Sender<Event>> = OnceLock::new();
    static AVAILABLE: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" {
        fn factorseal_apple_install(callback: extern "C" fn(u32, *const u8, isize)) -> bool;
        fn factorseal_apple_set_unlocked(unlocked: bool);
        fn factorseal_apple_finish();
        fn factorseal_apple_export(bytes: *const u8, count: isize) -> bool;
    }

    extern "C" fn receive(kind: u32, bytes: *const u8, count: isize) {
        let event = match kind {
            1 if !bytes.is_null() && (1..=128 * 1024 * 1024).contains(&count) => {
                // SAFETY: Swift lends a contiguous Data buffer for this callback
                // only. Copy before returning; never retain its pointer.
                let data = unsafe { std::slice::from_raw_parts(bytes, count.cast_unsigned()) };
                Event::Import(Zeroizing::new(data.to_vec()))
            }
            2 => Event::Exported,
            3 => Event::Cancelled,
            5 => Event::Open,
            _ => Event::Failed,
        };
        if let Some(sender) = SENDER.get() {
            let _ = sender.try_send(event);
        }
    }

    pub(super) fn install() -> Option<smol::channel::Receiver<Event>> {
        let (sender, receiver) = smol::channel::bounded(8);
        SENDER.set(sender).ok()?;
        // SAFETY: called during GPUI setup on the main thread. The callback is
        // process-lifetime code and does not unwind or access AppKit.
        let installed = unsafe { factorseal_apple_install(receive) };
        AVAILABLE.store(installed, Ordering::Relaxed);
        installed.then_some(receiver)
    }

    pub(super) fn available() -> bool {
        AVAILABLE.load(Ordering::Relaxed)
    }
    pub(super) fn set_unlocked(unlocked: bool) {
        // SAFETY: GPUI snapshot updates execute on the main thread.
        unsafe { factorseal_apple_set_unlocked(unlocked) }
    }
    pub(super) fn finish() {
        // SAFETY: GPUI event handling executes on the main thread.
        unsafe { factorseal_apple_finish() }
    }
    pub(super) fn export(data: &[u8]) -> bool {
        let Ok(count) = isize::try_from(data.len()) else {
            return false;
        };
        // SAFETY: called on the main thread. Swift copies these bytes before
        // returning, and never retains the Rust allocation.
        unsafe { factorseal_apple_export(data.as_ptr(), count) }
    }
}

pub(crate) fn install() -> Option<smol::channel::Receiver<Event>> {
    #[cfg(target_os = "macos")]
    return native::install();
    #[cfg(not(target_os = "macos"))]
    None
}

pub(crate) fn available() -> bool {
    #[cfg(target_os = "macos")]
    return native::available();
    #[cfg(not(target_os = "macos"))]
    false
}

pub(crate) fn set_unlocked(unlocked: bool) {
    #[cfg(target_os = "macos")]
    native::set_unlocked(unlocked);
    #[cfg(not(target_os = "macos"))]
    let _ = unlocked;
}

pub(crate) fn finish() {
    #[cfg(target_os = "macos")]
    native::finish();
}

pub(crate) fn export(data: &[u8]) -> bool {
    #[cfg(target_os = "macos")]
    return native::export(data);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = data;
        false
    }
}
