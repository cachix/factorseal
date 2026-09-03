//! Native vault transport selection for the Factorseal CLI.

use std::path::Path;
use std::sync::Arc;

#[cfg(target_os = "windows")]
use factorseal::Vault;
use factorseal::{CallerIdentity, NativeVaultClient, VaultMetadata, VaultService};
#[cfg(target_os = "linux")]
use factorseal::{
    LinuxVaultClient, LinuxVaultLifecycle, LinuxVaultOptions, linux_caller_identity_for_executable,
    serve_linux_vault_with_lifecycle,
};
#[cfg(target_os = "macos")]
use factorseal::{
    MacosVaultClient, MacosVaultLifecycle, MacosVaultOptions, macos_caller_identity_for_executable,
    serve_macos_vault_with_lifecycle,
};
#[cfg(target_os = "windows")]
use factorseal::{
    WindowsVaultClient, WindowsVaultLifecycle, WindowsVaultOptions, default_windows_pipe_name,
    serve_windows_vault_with_lifecycle, windows_caller_identity_for_executable,
};

use super::CliError;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::DEFAULT_UNIX_SOCKET;

#[cfg(target_os = "linux")]
pub(super) type NativeVaultLifecycle = LinuxVaultLifecycle;
#[cfg(target_os = "macos")]
pub(super) type NativeVaultLifecycle = MacosVaultLifecycle;
#[cfg(target_os = "windows")]
pub(super) type NativeVaultLifecycle = WindowsVaultLifecycle;

#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) fn prepare_lifecycle() -> Result<NativeVaultLifecycle, CliError> {
    Ok(NativeVaultLifecycle::new()?)
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Linux and Windows lifecycle setup is fallible at the shared call site"
)]
pub(super) fn prepare_lifecycle() -> Result<NativeVaultLifecycle, CliError> {
    Ok(NativeVaultLifecycle::new())
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation must inspect vault metadata to derive its pipe"
)]
pub(super) fn native_client(
    root: &Path,
    socket: Option<&Path>,
) -> Result<NativeVaultClient, CliError> {
    let socket = socket.map_or_else(|| root.join(DEFAULT_UNIX_SOCKET), Path::to_owned);
    Ok(LinuxVaultClient::new(socket))
}

#[cfg(target_os = "macos")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the Windows implementation must inspect vault metadata to derive its pipe"
)]
pub(super) fn native_client(
    root: &Path,
    socket: Option<&Path>,
) -> Result<NativeVaultClient, CliError> {
    let socket = socket.map_or_else(|| root.join(DEFAULT_UNIX_SOCKET), Path::to_owned);
    Ok(MacosVaultClient::new(socket))
}

#[cfg(target_os = "windows")]
pub(super) fn native_client(
    root: &Path,
    socket: Option<&Path>,
) -> Result<NativeVaultClient, CliError> {
    if let Some(pipe_name) = socket {
        return Ok(WindowsVaultClient::new(
            pipe_name.to_string_lossy().into_owned(),
        ));
    }
    let device = Vault::inspect(root)?;
    Ok(WindowsVaultClient::for_installation(
        device.installation_id(),
    ))
}

#[cfg(target_os = "linux")]
pub(super) fn serve_vault(
    _device: &VaultMetadata,
    service: &Arc<VaultService>,
    root: &Path,
    socket: Option<&Path>,
    lifecycle: &NativeVaultLifecycle,
) -> Result<(), CliError> {
    let socket = socket.map_or_else(|| root.join(DEFAULT_UNIX_SOCKET), Path::to_owned);
    serve_linux_vault_with_lifecycle(service, &LinuxVaultOptions::new(socket), Some(lifecycle))?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub(super) fn serve_vault(
    _device: &VaultMetadata,
    service: &Arc<VaultService>,
    root: &Path,
    socket: Option<&Path>,
    lifecycle: &NativeVaultLifecycle,
) -> Result<(), CliError> {
    let socket = socket.map_or_else(|| root.join(DEFAULT_UNIX_SOCKET), Path::to_owned);
    serve_macos_vault_with_lifecycle(service, &MacosVaultOptions::new(socket), Some(lifecycle))?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub(super) fn serve_vault(
    device: &VaultMetadata,
    service: &Arc<VaultService>,
    _root: &Path,
    socket: Option<&Path>,
    lifecycle: &NativeVaultLifecycle,
) -> Result<(), CliError> {
    let pipe_name = socket.map_or_else(
        || default_windows_pipe_name(device.installation_id()),
        |path| path.to_string_lossy().into_owned(),
    );
    serve_windows_vault_with_lifecycle(
        service,
        &WindowsVaultOptions::new(pipe_name),
        Some(lifecycle),
    )?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn serve_vault(
    _device: &VaultMetadata,
    _service: &Arc<VaultService>,
    _root: &Path,
    _socket: Option<&Path>,
    _lifecycle: &(),
) -> Result<(), CliError> {
    Err(CliError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
pub(super) fn caller_identity_for_executable(
    executable: &Path,
) -> Result<CallerIdentity, CliError> {
    Ok(linux_caller_identity_for_executable(executable)?)
}

#[cfg(target_os = "macos")]
pub(super) fn caller_identity_for_executable(
    executable: &Path,
) -> Result<CallerIdentity, CliError> {
    Ok(macos_caller_identity_for_executable(executable)?)
}

#[cfg(target_os = "windows")]
pub(super) fn caller_identity_for_executable(
    executable: &Path,
) -> Result<CallerIdentity, CliError> {
    Ok(windows_caller_identity_for_executable(executable)?)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(super) fn caller_identity_for_executable(
    _executable: &Path,
) -> Result<CallerIdentity, CliError> {
    Err(CliError::UnsupportedPlatform)
}
