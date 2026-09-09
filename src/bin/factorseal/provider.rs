//! Factorseal implementation of the SecretSpec external-provider protocol.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factorseal::{
    MAX_PERMISSION_WAIT_MS, PermissionWaitStatus, VaultAction, VaultApplicationContext,
    VaultClient, VaultError, VaultRequest, VaultResponseBody, VaultResponseErrorCode, WireSecret,
};
use secretspec_ipc::error::{ErrorKind, InteractionReference, RpcError};
use secretspec_ipc::protocol::provider::{
    self as wire, Address, CoordinateName, InitializeApplication, Metadata, Persistence,
    ResolveAddressResult,
};
use secretspec_ipc::provider::{ProvidedSecret, ProviderHandler, SecretValue, serve_provider};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};

use super::CliError;

#[path = "provider/address.rs"]
mod address;

const PROVIDER_URI: &str = "factorseal://default";

#[cfg(target_os = "linux")]
struct InputChannelGuard(std::os::unix::net::UnixStream);
#[cfg(target_os = "linux")]
impl Drop for InputChannelGuard {
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

fn check_request_live(context: &RequestContext) -> RpcResult<()> {
    if context.cancellation.is_cancelled() {
        return Err(RpcError::new(ErrorKind::Cancelled));
    }
    if tokio::time::Instant::now() >= context.deadline {
        return Err(RpcError::new(ErrorKind::DeadlineExceeded));
    }
    Ok(())
}

/// One Factorseal process acting as a SecretSpec provider endpoint.
pub(super) struct FactorsealProvider {
    client: Arc<dyn VaultClient>,
    #[cfg(all(test, target_os = "linux"))]
    test_input: bool,
    application: OnceLock<VaultApplicationContext>,
}

impl FactorsealProvider {
    fn new(root: &Path, socket: Option<&Path>) -> Result<Self, CliError> {
        Ok(Self {
            client: Arc::new(super::platform::native_client(root, socket)?),
            #[cfg(all(test, target_os = "linux"))]
            test_input: false,
            application: OnceLock::new(),
        })
    }

    #[cfg(test)]
    fn with_client(client: Arc<dyn VaultClient>) -> Self {
        Self {
            client,
            #[cfg(target_os = "linux")]
            test_input: true,
            application: OnceLock::new(),
        }
    }

    async fn request_once(&self, action: VaultAction) -> RpcResult<VaultResponseBody> {
        let client = Arc::clone(&self.client);
        let application = self
            .application
            .get()
            .cloned()
            .ok_or_else(|| RpcError::new(ErrorKind::Internal))?;
        tokio::task::spawn_blocking(move || request(client.as_ref(), action, application))
            .await
            .map_err(|_| RpcError::new(ErrorKind::Internal))?
    }

    async fn request<F>(&self, context: &RequestContext, action: F) -> RpcResult<VaultResponseBody>
    where
        F: FnMut() -> factorseal::VaultResult<VaultAction>,
    {
        let mut opened_desktop = false;
        let result = self
            .request_inner(context, action, &mut opened_desktop)
            .await;
        #[cfg(target_os = "linux")]
        if opened_desktop {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let connection = zbus::Connection::session().await?;
                let service = zbus::Proxy::new(
                    &connection,
                    "org.freedesktop.secrets",
                    "/org/freedesktop/secrets",
                    "org.freedesktop.Secret.Service",
                )
                .await?;
                service
                    .call::<_, _, ()>("FinishIpcAccess", &(self.request_attributes(context),))
                    .await
            })
            .await;
        }
        result
    }

    async fn request_inner<F>(
        &self,
        context: &RequestContext,
        mut action: F,
        _opened_desktop: &mut bool,
    ) -> RpcResult<VaultResponseBody>
    where
        F: FnMut() -> factorseal::VaultResult<VaultAction>,
    {
        let first = self
            .request_once(action().map_err(|e| map_vault_error(&e))?)
            .await;
        #[cfg(target_os = "linux")]
        let first = if matches!(&first, Err(error) if error.data.kind == ErrorKind::InteractionRequired && error.data.interaction.is_none())
        {
            *_opened_desktop = true;
            self.unlock_desktop(context).await?;
            self.request_once(action().map_err(|error| map_vault_error(&error))?)
                .await
        } else {
            first
        };
        let interaction = match &first {
            Err(error) if error.data.kind == ErrorKind::InteractionRequired => {
                error.data.interaction.clone()
            }
            _ => return first,
        };
        let Some(interaction) = interaction else {
            return first;
        };
        match self.wait_for_permission(context, &interaction.id).await? {
            PermissionWaitStatus::Granted => {
                self.request_once(action().map_err(|e| map_vault_error(&e))?)
                    .await
            }
            PermissionWaitStatus::Denied => Err(RpcError::new(ErrorKind::PermissionDenied)),
            PermissionWaitStatus::Expired => Err(RpcError::new(ErrorKind::DeadlineExceeded)),
            PermissionWaitStatus::Pending => unreachable!("permission wait loops while pending"),
        }
    }

    #[cfg(target_os = "linux")]
    async fn unlock_desktop(&self, context: &RequestContext) -> RpcResult<()> {
        let attributes = self.request_attributes(context);
        let unlock = async {
            let connection = zbus::Connection::session().await?;
            let service = zbus::Proxy::new(
                &connection,
                "org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
            )
            .await?;
            service
                .call::<_, _, ()>("UnlockForIpc", &(attributes,))
                .await
        };
        tokio::select! {
            () = context.cancellation.cancelled() => Err(RpcError::new(ErrorKind::Cancelled)),
            result = tokio::time::timeout_at(context.deadline, unlock) => match result {
                Err(_) => Err(RpcError::new(ErrorKind::DeadlineExceeded)),
                Ok(Ok(())) => Ok(()),
                Ok(Err(zbus::Error::MethodError(name, _, _))) => {
                    let kind = if name.as_str().ends_with(".TimedOut") { ErrorKind::DeadlineExceeded }
                        else if name.as_str().ends_with(".AccessDenied") { ErrorKind::PermissionDenied }
                        else if name.as_str().ends_with(".Cancelled") { ErrorKind::Cancelled }
                        else { return Err(RpcError::interaction_required(None)); };
                    Err(RpcError::new(kind))
                }
                Ok(Err(_)) => Err(RpcError::interaction_required(None)),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn request_attributes(
        &self,
        context: &RequestContext,
    ) -> std::collections::HashMap<String, String> {
        let mut attributes = self.desktop_attributes();
        attributes.insert(
            "factorseal_request_id".to_owned(),
            format!("{:?}", context.request_id),
        );
        attributes
    }

    #[cfg(target_os = "linux")]
    fn desktop_attributes(&self) -> std::collections::HashMap<String, String> {
        let mut attributes = std::collections::HashMap::new();
        if let Some(application) = self.application.get() {
            for (name, value) in [
                ("project", &application.project),
                ("profile", &application.profile),
                ("base_dir", &application.base_dir),
                ("reason", &application.reason),
            ] {
                if let Some(value) = value {
                    attributes.insert(name.to_owned(), value.clone());
                }
            }
        }
        attributes
    }

    #[cfg(target_os = "linux")]
    async fn edit_secret(
        &self,
        context: &RequestContext,
        address: &factorseal::SecretSpecAddress,
        initial: WireSecret,
    ) -> RpcResult<WireSecret> {
        #[cfg(test)]
        if self.test_input {
            return Ok(initial);
        }
        let mut attributes = self.desktop_attributes();
        attributes.insert(
            "secret".to_owned(),
            match address {
                factorseal::SecretSpecAddress::Convention { key, .. } => key.clone(),
                factorseal::SecretSpecAddress::Native { coordinates } => coordinates.item.clone(),
            },
        );
        let (mut local, remote) = std::os::unix::net::UnixStream::pair()
            .map_err(|_| RpcError::new(ErrorKind::Internal))?;
        local
            .set_read_timeout(Some(std::time::Duration::from_mins(2)))
            .map_err(|_| RpcError::new(ErrorKind::Internal))?;
        local
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .map_err(|_| RpcError::new(ErrorKind::Internal))?;
        let _channel_guard = InputChannelGuard(
            local
                .try_clone()
                .map_err(|_| RpcError::new(ErrorKind::Internal))?,
        );
        let exchange = tokio::task::spawn_blocking(move || {
            factorseal::desktop_worker::send(&mut local, &initial)?;
            factorseal::desktop_worker::receive::<WireSecret>(&mut local)
        });
        let input = async {
            let connection = zbus::Connection::session().await?;
            let service = zbus::Proxy::new(
                &connection,
                "org.freedesktop.secrets",
                "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service",
            )
            .await?;
            let fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(remote));
            service
                .call::<_, _, ()>("InputForIpc", &(attributes, fd))
                .await
        };
        let result = tokio::select! {
            () = context.cancellation.cancelled() => Err(RpcError::new(ErrorKind::Cancelled)),
            result = tokio::time::timeout_at(context.deadline, input) => match result {
                Err(_) => Err(RpcError::new(ErrorKind::DeadlineExceeded)),
                Ok(Ok(())) => Ok(()),
                Ok(Err(zbus::Error::MethodError(name, _, _))) if name.as_str().ends_with(".AccessDenied") => Err(RpcError::new(ErrorKind::PermissionDenied)),
                Ok(Err(zbus::Error::MethodError(name, _, _))) if name.as_str().ends_with(".TimedOut") => Err(RpcError::new(ErrorKind::DeadlineExceeded)),
                Ok(Err(zbus::Error::MethodError(name, _, _))) if name.as_str().ends_with(".Cancelled") => Err(RpcError::new(ErrorKind::Cancelled)),
                Ok(Err(_)) => Err(RpcError::interaction_required(None)),
            }
        };
        result?;
        tokio::select! {
            () = context.cancellation.cancelled() => Err(RpcError::new(ErrorKind::Cancelled)),
            result = tokio::time::timeout_at(context.deadline, exchange) => result
                .map_err(|_| RpcError::new(ErrorKind::DeadlineExceeded))?
                .map_err(|_| RpcError::new(ErrorKind::Internal))?
                .map_err(|_| RpcError::new(ErrorKind::OperationFailed)),
        }
    }

    async fn write_secret(
        &self,
        context: &RequestContext,
        address: factorseal::SecretSpecAddress,
        value: SecretValue,
        evict_at: Option<u64>,
    ) -> RpcResult<()> {
        check_request_live(context)?;
        let project = self.project()?.to_owned();
        #[cfg(target_os = "linux")]
        {
            let initial = WireSecret::new(value.expose().as_bytes().to_vec())
                .map_err(|error| map_vault_error(&error))?;
            let value = self.edit_secret(context, &address, initial).await?;
            check_request_live(context)?;
            // The trusted CLI already has manager authority. Each write here is
            // individually confirmed in Desktop; it does not authorize future writes.
            let response = self
                .request_once(VaultAction::WriteCacheFromDialog {
                    project,
                    address,
                    value,
                    evict_at,
                })
                .await?;
            matches!(response, VaultResponseBody::Stored)
                .then_some(())
                .ok_or_else(|| RpcError::new(ErrorKind::OperationFailed))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let response = self
                .request(context, || {
                    Ok(VaultAction::PutCache {
                        project: project.clone(),
                        address: address.clone(),
                        value: WireSecret::new(value.expose().as_bytes().to_vec())?,
                        evict_at,
                    })
                })
                .await?;
            matches!(response, VaultResponseBody::Stored)
                .then_some(())
                .ok_or_else(|| RpcError::new(ErrorKind::OperationFailed))
        }
    }

    async fn wait_for_permission(
        &self,
        context: &RequestContext,
        id: &str,
    ) -> RpcResult<PermissionWaitStatus> {
        loop {
            if context.cancellation.is_cancelled() {
                return Err(RpcError::new(ErrorKind::Cancelled));
            }
            let remaining = context
                .deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or_else(|| RpcError::new(ErrorKind::DeadlineExceeded))?;
            let timeout_ms = u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .clamp(1, MAX_PERMISSION_WAIT_MS);
            match self
                .request_once(VaultAction::WaitPermission {
                    id: id.to_owned(),
                    timeout_ms,
                })
                .await?
            {
                VaultResponseBody::PermissionWait {
                    status: PermissionWaitStatus::Pending,
                } => {}
                VaultResponseBody::PermissionWait { status } => return Ok(status),
                _ => return Err(RpcError::new(ErrorKind::OperationFailed)),
            }
        }
    }

    fn project(&self) -> RpcResult<&str> {
        self.application
            .get()
            .and_then(|application| application.project.as_deref())
            .ok_or_else(|| RpcError::new(ErrorKind::InvalidParams))
    }

    fn wire_address(&self, address: Address) -> RpcResult<factorseal::SecretSpecAddress> {
        let project = self.project()?;
        let address = address::wire_address(address)?;
        if address
            .project()
            .is_some_and(|address_project| address_project != project)
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        Ok(address)
    }
}

#[async_trait]
impl ProviderHandler for FactorsealProvider {
    fn capabilities(&self) -> Vec<String> {
        [
            wire::method::RESOLVE_ADDRESS,
            wire::method::GET,
            wire::method::EXISTS,
            wire::method::SET,
            wire::method::SET_EXPIRING,
            wire::method::DELETE,
            wire::method::CHECK_WRITABLE,
            wire::method::CHECK_DELETABLE,
            wire::method::DESCRIBE_WRITE_TARGET,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    async fn initialize(
        &self,
        _context: &RequestContext,
        application: InitializeApplication,
    ) -> RpcResult<Metadata> {
        if application.scheme != "factorseal"
            || application.uri != PROVIDER_URI
            || !application.credentials.is_empty()
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        let requested_duration_seconds = application
            .context
            .requested_authorization_duration_ms
            .map(|milliseconds| milliseconds.div_ceil(1_000));
        let folder = application
            .context
            .base_dir
            .as_ref()
            .map(std::path::PathBuf::from)
            .map_or_else(std::env::current_dir, Ok)
            .and_then(std::fs::canonicalize)
            .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
        let folder = folder
            .to_str()
            .ok_or_else(|| RpcError::new(ErrorKind::InvalidParams))?
            .to_owned();
        let application_context = VaultApplicationContext::new(
            application.context.project,
            application.context.profile,
            Some(folder),
            application.context.reason,
        )
        .and_then(|context| {
            context.with_requested_permission_duration_seconds(requested_duration_seconds)
        })
        .map_err(|error| map_vault_error(&error))?;
        if application_context.project.is_none() {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        self.application
            .set(application_context)
            .map_err(|_| RpcError::new(ErrorKind::Conflict))?;
        Ok(Metadata {
            name: "factorseal".to_owned(),
            display_uri: PROVIDER_URI.to_owned(),
            supported_coordinates: vec![
                CoordinateName::Field,
                CoordinateName::Vault,
                CoordinateName::Section,
                CoordinateName::Version,
            ],
            generated_value_persistence: Persistence::Persist,
            prompted_value_persistence: Persistence::Persist,
            storage_identity: PROVIDER_URI.to_owned(),
            entry_container_identity: PROVIDER_URI.to_owned(),
            physical_store_path: None,
        })
    }

    async fn resolve_address(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<ResolveAddressResult> {
        Ok(ResolveAddressResult {
            coordinates: address::coordinates(address),
        })
    }

    async fn get(
        &self,
        context: RequestContext,
        address: Address,
    ) -> RpcResult<Option<ProvidedSecret>> {
        let address = self.wire_address(address)?;
        let project = self.project()?.to_owned();
        match self
            .request(&context, || {
                Ok(VaultAction::GetCache {
                    project: project.clone(),
                    address: address.clone(),
                })
            })
            .await?
        {
            VaultResponseBody::Secret { value: Some(value) } => {
                let bytes = value.into_locked();
                let value = std::str::from_utf8(&bytes)
                    .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
                Ok(Some(ProvidedSecret::new(value.to_owned(), None)))
            }
            VaultResponseBody::Secret { value: None } => Ok(None),
            _ => Err(RpcError::new(ErrorKind::OperationFailed)),
        }
    }

    async fn exists(&self, context: RequestContext, address: Address) -> RpcResult<bool> {
        Ok(self.get(context, address).await?.is_some())
    }

    async fn set(
        &self,
        context: RequestContext,
        address: Address,
        value: SecretValue,
    ) -> RpcResult<()> {
        let address = self.wire_address(address)?;
        self.write_secret(&context, address, value, None).await
    }

    async fn set_expiring(
        &self,
        context: RequestContext,
        address: Address,
        value: SecretValue,
        ttl_ms: u64,
    ) -> RpcResult<()> {
        if ttl_ms == 0 {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        let now = unix_time_ms()?;
        let evict_at = now
            .checked_add(ttl_ms)
            .and_then(|expires_at| expires_at.checked_add(999))
            .ok_or_else(|| RpcError::new(ErrorKind::InvalidParams))?
            / 1_000;
        let address = self.wire_address(address)?;
        self.write_secret(&context, address, value, Some(evict_at))
            .await
    }

    async fn delete(&self, context: RequestContext, address: Address) -> RpcResult<bool> {
        let address = self.wire_address(address)?;
        let project = self.project()?.to_owned();
        match self
            .request(&context, || {
                Ok(VaultAction::DeleteCache {
                    project: project.clone(),
                    address: address.clone(),
                })
            })
            .await?
        {
            VaultResponseBody::Deleted { existed } => Ok(existed),
            _ => Err(RpcError::new(ErrorKind::OperationFailed)),
        }
    }

    async fn check_writable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        self.wire_address(address).map(|_| ())
    }

    async fn check_deletable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        self.wire_address(address).map(|_| ())
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<String> {
        self.wire_address(address)?;
        Ok("Factorseal device cache".to_owned())
    }
}

fn request(
    client: &dyn VaultClient,
    action: VaultAction,
    application: VaultApplicationContext,
) -> RpcResult<VaultResponseBody> {
    let request = VaultRequest::new_with_application(action, application)
        .map_err(|error| map_vault_error(&error))?;
    let response = client
        .request(&request)
        .map_err(|error| map_vault_error(&error))?;
    response.result.map_err(|error| match error.code {
        VaultResponseErrorCode::AuthorizationRequired => {
            if let Some(interaction) = error.interaction {
                let expires_at_unix_ms = interaction.expires_at.checked_mul(1_000);
                RpcError::interaction_required(Some(InteractionReference::authorization(
                    interaction.id,
                    expires_at_unix_ms,
                )))
            } else {
                RpcError::new(ErrorKind::PermissionDenied)
            }
        }
        code => RpcError::new(match code {
            VaultResponseErrorCode::Replay | VaultResponseErrorCode::Conflict => {
                ErrorKind::Conflict
            }
            VaultResponseErrorCode::Sealed => {
                return RpcError::interaction_required(None);
            }
            VaultResponseErrorCode::InvalidRequest => ErrorKind::InvalidParams,
            VaultResponseErrorCode::Internal => ErrorKind::OperationFailed,
            VaultResponseErrorCode::AuthorizationRequired => unreachable!("handled above"),
        }),
    })
}

fn map_vault_error(error: &VaultError) -> RpcError {
    RpcError::new(match error {
        VaultError::EmptyAddress { .. } | VaultError::AddressTooLong { .. } => {
            ErrorKind::InvalidParams
        }
        VaultError::AuthorizationRequired | VaultError::ApprovalLimited => {
            ErrorKind::PermissionDenied
        }
        VaultError::Sealed => return RpcError::interaction_required(None),
        // The provider endpoint is intentionally independent of the agent. If
        // the initialized vault has no live worker or listener, SecretSpec can
        // only proceed after the user starts/unseals it through Factorseal's
        // own interaction channel.
        VaultError::WorkerUnavailable | VaultError::AgentUnreachable(_) => {
            return RpcError::interaction_required(None);
        }
        VaultError::Conflict | VaultError::Replay => ErrorKind::Conflict,
        VaultError::Expired
        | VaultError::InvalidData(_)
        | VaultError::Automerge(_)
        | VaultError::Crypto
        | VaultError::Signature
        | VaultError::Random(_)
        | VaultError::Database(_)
        | VaultError::Protocol(_)
        | VaultError::HardwareUnavailable
        | VaultError::HardwarePolicyUnsupported
        | VaultError::NativeAuthorization(_)
        | VaultError::PasswordRejected
        | VaultError::Protection(_) => ErrorKind::OperationFailed,
    })
}

fn unix_time_ms() -> RpcResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?
        .as_millis()
        .try_into()
        .map_err(|_| RpcError::new(ErrorKind::OperationFailed))
}

pub(super) fn serve(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    let provider = FactorsealProvider::new(root, socket)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| CliError::ProviderProtocol(error.to_string()))?;
    runtime
        .block_on(serve_provider(
            tokio::io::stdin(),
            tokio::io::stdout(),
            provider,
            ServerConfig::default(),
        ))
        .map_err(|error| CliError::ProviderProtocol(error.to_string()))
}

#[cfg(test)]
#[path = "provider/tests.rs"]
mod tests;
