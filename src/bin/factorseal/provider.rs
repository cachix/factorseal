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
use zeroize::Zeroizing;

use super::CliError;

#[path = "provider/address.rs"]
mod address;

const PROVIDER_URI: &str = "factorseal://default";

/// One Factorseal process acting as a SecretSpec provider endpoint.
pub(super) struct FactorsealProvider {
    client: Arc<dyn VaultClient>,
    application: OnceLock<VaultApplicationContext>,
}

impl FactorsealProvider {
    fn new(root: &Path, socket: Option<&Path>) -> Result<Self, CliError> {
        Ok(Self {
            client: Arc::new(super::platform::native_client(root, socket)?),
            application: OnceLock::new(),
        })
    }

    #[cfg(test)]
    fn with_client(client: Arc<dyn VaultClient>) -> Self {
        Self {
            client,
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

    async fn request<F>(
        &self,
        context: &RequestContext,
        mut action: F,
    ) -> RpcResult<VaultResponseBody>
    where
        F: FnMut() -> VaultAction,
    {
        let first = self.request_once(action()).await;
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
            PermissionWaitStatus::Granted => self.request_once(action()).await,
            PermissionWaitStatus::Denied => Err(RpcError::new(ErrorKind::PermissionDenied)),
            PermissionWaitStatus::Expired => Err(RpcError::interaction_required(Some(interaction))),
            PermissionWaitStatus::Pending => unreachable!("permission wait loops while pending"),
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
        let application_context = VaultApplicationContext::new(
            application.context.project,
            application.context.profile,
            application.context.base_dir,
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
            .request(&context, || VaultAction::GetCache {
                project: project.clone(),
                address: address.clone(),
            })
            .await?
        {
            VaultResponseBody::Secret { value: Some(value) } => {
                let bytes = Zeroizing::new(value.expose().to_vec());
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
        let project = self.project()?.to_owned();
        let response = self
            .request(&context, || VaultAction::PutCache {
                project: project.clone(),
                address: address.clone(),
                value: WireSecret::new(value.expose().as_bytes().to_vec()),
                evict_at: None,
            })
            .await?;
        matches!(response, VaultResponseBody::Stored)
            .then_some(())
            .ok_or_else(|| RpcError::new(ErrorKind::OperationFailed))
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
        let project = self.project()?.to_owned();
        let response = self
            .request(&context, || VaultAction::PutCache {
                project: project.clone(),
                address: address.clone(),
                value: WireSecret::new(value.expose().as_bytes().to_vec()),
                evict_at: Some(evict_at),
            })
            .await?;
        matches!(response, VaultResponseBody::Stored)
            .then_some(())
            .ok_or_else(|| RpcError::new(ErrorKind::OperationFailed))
    }

    async fn delete(&self, context: RequestContext, address: Address) -> RpcResult<bool> {
        let address = self.wire_address(address)?;
        let project = self.project()?.to_owned();
        match self
            .request(&context, || VaultAction::DeleteCache {
                project: project.clone(),
                address: address.clone(),
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
        VaultError::AuthorizationRequired => ErrorKind::PermissionDenied,
        VaultError::Sealed => return RpcError::interaction_required(None),
        VaultError::WorkerUnavailable | VaultError::AgentUnreachable(_) => ErrorKind::Unavailable,
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
