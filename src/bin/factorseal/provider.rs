//! Factorseal implementation of the SecretSpec external-provider protocol.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factorseal::{
    VaultAction, VaultClient, VaultError, VaultRequest, VaultResponseBody, VaultResponseErrorCode,
    WireSecret,
};
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::provider::{
    self as wire, Address, CoordinateName, InitializeApplication, Metadata, Persistence,
    ResolveAddressResult,
};
use secretspec_ipc::provider::{ProvidedSecret, ProviderHandler, SecretValue, serve_provider};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use zeroize::Zeroizing;

use super::{CliError, SECRETSPEC_CACHE_NAMESPACE};

#[path = "provider/address.rs"]
mod address;

const PROVIDER_URI: &str = "factorseal://default";

/// One Factorseal process acting as a SecretSpec provider endpoint.
pub(super) struct FactorsealProvider {
    client: Arc<dyn VaultClient>,
}

impl FactorsealProvider {
    fn new(root: &Path, socket: Option<&Path>) -> Result<Self, CliError> {
        Ok(Self {
            client: Arc::new(super::platform::native_client(root, socket)?),
        })
    }

    #[cfg(test)]
    fn with_client(client: Arc<dyn VaultClient>) -> Self {
        Self { client }
    }

    async fn request(&self, action: VaultAction) -> RpcResult<VaultResponseBody> {
        let client = Arc::clone(&self.client);
        tokio::task::spawn_blocking(move || request(client.as_ref(), action))
            .await
            .map_err(|_| RpcError::new(ErrorKind::Internal))?
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
        Ok(Metadata {
            name: "factorseal".to_owned(),
            display_uri: PROVIDER_URI.to_owned(),
            supported_coordinates: vec![CoordinateName::Field],
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
            coordinates: address::coordinates(address)?,
        })
    }

    async fn get(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<Option<ProvidedSecret>> {
        match self
            .request(VaultAction::GetCache {
                namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
                address: address::wire_address(address)?,
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
        _context: RequestContext,
        address: Address,
        value: SecretValue,
    ) -> RpcResult<()> {
        let response = self
            .request(VaultAction::PutCache {
                namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
                address: address::wire_address(address)?,
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
        _context: RequestContext,
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
        let response = self
            .request(VaultAction::PutCache {
                namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
                address: address::wire_address(address)?,
                value: WireSecret::new(value.expose().as_bytes().to_vec()),
                evict_at: Some(evict_at),
            })
            .await?;
        matches!(response, VaultResponseBody::Stored)
            .then_some(())
            .ok_or_else(|| RpcError::new(ErrorKind::OperationFailed))
    }

    async fn delete(&self, _context: RequestContext, address: Address) -> RpcResult<bool> {
        match self
            .request(VaultAction::DeleteCache {
                namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
                address: address::wire_address(address)?,
            })
            .await?
        {
            VaultResponseBody::Deleted { existed } => Ok(existed),
            _ => Err(RpcError::new(ErrorKind::OperationFailed)),
        }
    }

    async fn check_writable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        address::wire_address(address).map(|_| ())
    }

    async fn check_deletable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        address::wire_address(address).map(|_| ())
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<String> {
        address::wire_address(address)?;
        Ok("Factorseal device cache".to_owned())
    }
}

fn request(client: &dyn VaultClient, action: VaultAction) -> RpcResult<VaultResponseBody> {
    let request = VaultRequest::new(action).map_err(|error| map_vault_error(&error))?;
    let response = client
        .request(&request)
        .map_err(|error| map_vault_error(&error))?;
    response.result.map_err(|error| {
        RpcError::new(match error.code {
            VaultResponseErrorCode::AuthorizationRequired => ErrorKind::PermissionDenied,
            VaultResponseErrorCode::Replay | VaultResponseErrorCode::Conflict => {
                ErrorKind::Conflict
            }
            VaultResponseErrorCode::Sealed => {
                return RpcError::interaction_required(None);
            }
            VaultResponseErrorCode::InvalidRequest => ErrorKind::InvalidParams,
            VaultResponseErrorCode::Internal => ErrorKind::OperationFailed,
        })
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
