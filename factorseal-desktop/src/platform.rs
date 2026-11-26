#[cfg(not(target_family = "wasm"))]
pub(crate) use smol::unblock;

#[cfg(target_family = "wasm")]
pub(crate) fn unblock<T>(work: impl FnOnce() -> T) -> std::future::Ready<T> {
    std::future::ready(work())
}

#[cfg(not(target_family = "wasm"))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn chosen_path(file: &rfd::FileHandle) -> Option<std::path::PathBuf> {
    Some(file.path().to_owned())
}

#[cfg(target_family = "wasm")]
pub(crate) const fn chosen_path(_file: &rfd::FileHandle) -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn host_name() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

#[cfg(target_family = "wasm")]
pub(crate) fn host_name() -> String {
    "john-laptop".to_owned()
}
