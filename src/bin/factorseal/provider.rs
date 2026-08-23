//! Factorseal implementation of the SecretSpec external-provider protocol.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factorseal::{
    VaultAction, VaultClient, VaultError, VaultRequest, VaultResponseBody, VaultResponseErrorCode,
    WireSecret, WireSecretAddress,
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secretspec_ipc::error::{ErrorKind, RpcError};
use secretspec_ipc::protocol::provider::{
    self as wire, Address, CoordinateName, InitializeApplication, Metadata, Persistence,
    ResolveAddressResult,
};
use secretspec_ipc::provider::{ProviderHandler, SecretValue, serve_provider};
use secretspec_ipc::server::{RequestContext, RpcResult, ServerConfig};
use zeroize::Zeroizing;

use super::{CliError, SECRETSPEC_CACHE_NAMESPACE};

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

    fn coordinates(address: Address) -> RpcResult<wire::Coordinates> {
        let coordinates = match address {
            Address::Convention {
                project,
                profile,
                key,
            } => {
                let encode = |value: &str| utf8_percent_encode(value, NON_ALPHANUMERIC).to_string();
                wire::Coordinates {
                    item: format!(
                        "v1/{}/{}/{}",
                        encode(&project),
                        encode(&profile),
                        encode(&key)
                    ),
                    field: None,
                    vault: None,
                    section: None,
                    version: None,
                }
            }
            Address::Native { coordinates } => coordinates,
        };
        if coordinates.vault.is_some()
            || coordinates.section.is_some()
            || coordinates.version.is_some()
        {
            return Err(RpcError::new(ErrorKind::InvalidParams));
        }
        let address = WireSecretAddress::new(coordinates.item.clone(), coordinates.field.clone());
        address
            .validate()
            .map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
        Ok(coordinates)
    }

    fn address(address: Address) -> RpcResult<WireSecretAddress> {
        let coordinates = Self::coordinates(address)?;
        Ok(WireSecretAddress::new(coordinates.item, coordinates.field))
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
            coordinates: Self::coordinates(address)?,
        })
    }

    async fn get(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<Option<SecretValue>> {
        match self
            .request(VaultAction::GetCache {
                namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
                address: Self::address(address)?,
            })
            .await?
        {
            VaultResponseBody::Secret { value: Some(value) } => {
                let bytes = Zeroizing::new(value.expose().to_vec());
                let value = std::str::from_utf8(&bytes)
                    .map_err(|_| RpcError::new(ErrorKind::OperationFailed))?;
                Ok(Some(SecretValue::new(value.to_owned())))
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
                address: Self::address(address)?,
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
                address: Self::address(address)?,
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
                address: Self::address(address)?,
            })
            .await?
        {
            VaultResponseBody::Deleted { existed } => Ok(existed),
            _ => Err(RpcError::new(ErrorKind::OperationFailed)),
        }
    }

    async fn check_writable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        Self::address(address).map(|_| ())
    }

    async fn check_deletable(&self, _context: RequestContext, address: Address) -> RpcResult<()> {
        Self::address(address).map(|_| ())
    }

    async fn describe_write_target(
        &self,
        _context: RequestContext,
        address: Address,
    ) -> RpcResult<String> {
        Self::address(address)?;
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
            VaultResponseErrorCode::Sealed => ErrorKind::InteractionRequired,
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
        VaultError::Sealed => ErrorKind::InteractionRequired,
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
mod tests {
    use super::*;
    use factorseal::VaultResponse;
    use secretspec_ipc::client::Client;
    use secretspec_ipc::protocol::provider::{
        AddressParams, Coordinates, DeletedResult, GetResult, InitializeApplication,
        InitializedApplication, SetExpiringParams, SetParams, StoredResult,
    };
    use secretspec_ipc::protocol::{
        InitializeParams, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
    };
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Mutex;

    type CacheKey = (String, Option<String>);

    #[derive(Default)]
    struct MemoryVault {
        values: Mutex<HashMap<CacheKey, Vec<u8>>>,
        last_evict_at: Mutex<Option<u64>>,
    }

    impl VaultClient for MemoryVault {
        fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
            let body = match &request.action {
                VaultAction::GetCache { namespace, address } => {
                    assert_eq!(namespace, SECRETSPEC_CACHE_NAMESPACE);
                    VaultResponseBody::Secret {
                        value: self
                            .values
                            .lock()
                            .unwrap()
                            .get(&(address.item.clone(), address.field.clone()))
                            .cloned()
                            .map(WireSecret::new),
                    }
                }
                VaultAction::PutCache {
                    namespace,
                    address,
                    value,
                    evict_at,
                } => {
                    assert_eq!(namespace, SECRETSPEC_CACHE_NAMESPACE);
                    self.values.lock().unwrap().insert(
                        (address.item.clone(), address.field.clone()),
                        value.expose().to_vec(),
                    );
                    *self.last_evict_at.lock().unwrap() = *evict_at;
                    VaultResponseBody::Stored
                }
                VaultAction::DeleteCache { namespace, address } => {
                    assert_eq!(namespace, SECRETSPEC_CACHE_NAMESPACE);
                    let existed = self
                        .values
                        .lock()
                        .unwrap()
                        .remove(&(address.item.clone(), address.field.clone()))
                        .is_some();
                    VaultResponseBody::Deleted { existed }
                }
                _ => {
                    return Err(VaultError::Protocol(
                        "provider used a non-cache vault action".to_owned(),
                    ));
                }
            };
            Ok(VaultResponse::success(request.request_id(), body))
        }
    }

    fn address() -> Address {
        Address::Convention {
            project: "demo".to_owned(),
            profile: "production".to_owned(),
            key: "TOKEN".to_owned(),
        }
    }

    fn deadline() -> u64 {
        unix_time_ms().unwrap() + 2_000
    }

    fn native_address() -> Address {
        Address::Native {
            coordinates: Coordinates {
                item: "database".to_owned(),
                field: Some("password".to_owned()),
                vault: None,
                section: None,
                version: None,
            },
        }
    }

    async fn store(client: &Client, address: Address, value: &str) {
        let stored: StoredResult = client
            .call(
                wire::method::SET,
                &SetParams {
                    address,
                    value: value.to_owned(),
                },
                deadline(),
            )
            .await
            .unwrap();
        assert!(stored.stored);
    }

    async fn get(client: &Client, address: Address) -> GetResult {
        client
            .call(wire::method::GET, &AddressParams { address }, deadline())
            .await
            .unwrap()
    }

    async fn delete(client: &Client, address: Address) {
        let deleted: DeletedResult = client
            .call(wire::method::DELETE, &AddressParams { address }, deadline())
            .await
            .unwrap();
        assert!(deleted.deleted);
    }

    async fn store_expiring(client: &Client, address: Address) {
        let stored: StoredResult = client
            .call(
                wire::method::SET_EXPIRING,
                &SetExpiringParams {
                    address,
                    value: "expiring".to_owned(),
                    ttl_ms: 2_500,
                },
                deadline(),
            )
            .await
            .unwrap();
        assert!(stored.stored);
    }

    #[tokio::test]
    async fn provider_uses_cache_actions_for_crud_and_expiry() {
        let vault = Arc::new(MemoryVault::default());
        let provider = FactorsealProvider::with_client(vault.clone());
        assert!(
            !provider
                .capabilities()
                .contains(&wire::method::CLEAR.to_owned())
        );
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, server_write) = tokio::io::split(server_io);
        let server = tokio::spawn(serve_provider(
            server_read,
            server_write,
            provider,
            ServerConfig::default(),
        ));
        let initialize = InitializeParams {
            protocol: PROVIDER_PROTOCOL.to_owned(),
            versions: vec![PROTOCOL_VERSION],
            client: Product {
                name: "factorseal-provider-test".to_owned(),
                version: "1".to_owned(),
            },
            limits: Limits {
                max_frame_bytes: 32 * 1024,
                max_in_flight: 8,
            },
            client_methods: Vec::new(),
            application: InitializeApplication {
                scheme: "factorseal".to_owned(),
                uri: PROVIDER_URI.to_owned(),
                base_dir: None,
                credentials: BTreeMap::new(),
                reason: Some("test".to_owned()),
            },
        };
        let (client, initialized) = Client::connect::<_, _, _, InitializedApplication>(
            client_read,
            client_write,
            initialize,
            deadline(),
        )
        .await
        .unwrap();
        assert_eq!(initialized.application.provider.name, "factorseal");

        store(&client, address(), "secret").await;
        assert_eq!(
            get(&client, address()).await,
            GetResult::Found {
                value: "secret".to_owned()
            }
        );

        let native = native_address();
        store(&client, native.clone(), "native").await;
        delete(&client, native).await;

        store_expiring(&client, address()).await;
        assert!(vault.last_evict_at.lock().unwrap().is_some());
        client.close(deadline()).await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn convention_addresses_are_versioned_and_unambiguous() {
        let first = FactorsealProvider::coordinates(Address::Convention {
            project: "a/b".to_owned(),
            profile: "c".to_owned(),
            key: "d".to_owned(),
        })
        .unwrap();
        let second = FactorsealProvider::coordinates(Address::Convention {
            project: "a".to_owned(),
            profile: "b/c".to_owned(),
            key: "d".to_owned(),
        })
        .unwrap();

        assert_eq!(first.item, "v1/a%2Fb/c/d");
        assert_eq!(second.item, "v1/a/b%2Fc/d");
        assert_ne!(first.item, second.item);
    }
}
