use super::*;
use factorseal::{
    CallerIdentity, CallerPlatform, HardwareBackend, KeyProtector, KeyProtectorFactory,
    PermissionChange, PermissionState, UnlockCredentials, UnlockFactorKind, UnlockGroup,
    UnlockPolicy, UnsealLeasePolicy, Vault, VaultInteractionReference, VaultPlatform,
    VaultResponse, VaultResponseError, VaultService, WireSecretAddress,
};
use secretspec_ipc::client::Client;
use secretspec_ipc::protocol::provider::{
    AddressParams, ApplicationContext, Coordinates, DeletedResult, GetResult,
    InitializeApplication, InitializedApplication, SetExpiringParams, SetParams, StoredResult,
};
use secretspec_ipc::protocol::{
    InitializeParams, Limits, PROTOCOL_VERSION, PROVIDER_PROTOCOL, Product,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

type CacheKey = (String, Option<String>);

fn application_context() -> VaultApplicationContext {
    VaultApplicationContext::new(
        Some("demo".to_owned()),
        Some("default".to_owned()),
        Some(
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ),
        Some("test".to_owned()),
    )
    .unwrap()
}

#[derive(Default)]
struct MemoryVault {
    values: Mutex<HashMap<CacheKey, Vec<u8>>>,
    last_evict_at: Mutex<Option<u64>>,
}

impl VaultClient for MemoryVault {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        assert_eq!(request.application(), Some(&application_context()));
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
            context: ApplicationContext {
                project: Some("demo".to_owned()),
                profile: Some("default".to_owned()),
                base_dir: application_context().base_dir,
                reason: Some("test".to_owned()),
                requested_authorization_duration_ms: None,
            },
            credentials: BTreeMap::new(),
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
            value: "secret".to_owned(),
            expires_at_unix_ms: None,
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
    let first = address::coordinates(Address::Convention {
        project: "a/b".to_owned(),
        profile: "c".to_owned(),
        key: "d".to_owned(),
    })
    .unwrap();
    let second = address::coordinates(Address::Convention {
        project: "a".to_owned(),
        profile: "b/c".to_owned(),
        key: "d".to_owned(),
    })
    .unwrap();

    assert_eq!(first.item, "v1/a%2Fb/c/d");
    assert_eq!(second.item, "v1/a/b%2Fc/d");
    assert_ne!(first.item, second.item);
}

struct ApprovalVault;

impl VaultClient for ApprovalVault {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        Ok(VaultResponse::failure(
            request.request_id(),
            VaultResponseError {
                code: VaultResponseErrorCode::AuthorizationRequired,
                message: "application authorization is required".to_owned(),
                interaction: Some(VaultInteractionReference {
                    id: "prm_provider_test".to_owned(),
                    expires_at: 1_800_000_000,
                }),
            },
        ))
    }
}

#[test]
fn provider_maps_pending_approval_to_structured_interaction() {
    let error = request(
        &ApprovalVault,
        VaultAction::GetCache {
            namespace: SECRETSPEC_CACHE_NAMESPACE.to_vec(),
            address: WireSecretAddress::new("demo/default/TOKEN", None),
        },
        application_context(),
    )
    .unwrap_err();
    assert_eq!(error.data.kind, ErrorKind::InteractionRequired);
    let interaction = error.data.interaction.unwrap();
    assert_eq!(interaction.id, "prm_provider_test");
    assert_eq!(interaction.expires_at_unix_ms, Some(1_800_000_000_000));
}

struct IntegrationProtector {
    key: u8,
}

impl KeyProtector for IntegrationProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::AndroidTrustedEnvironment
    }

    fn wrap(&self, plaintext: &[u8]) -> factorseal::VaultResult<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.key).collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> factorseal::VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ self.key).collect(),
        ))
    }

    fn delete(&self) -> factorseal::VaultResult<()> {
        Ok(())
    }
}

struct IntegrationProtectorFactory;

impl KeyProtectorFactory for IntegrationProtectorFactory {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        self.open(root, label, biometric)
    }

    fn open(
        &self,
        _root: &Path,
        label: &str,
        _biometric: bool,
    ) -> factorseal::VaultResult<Box<dyn KeyProtector>> {
        let key = if label.contains("-wrap-") { 0x35 } else { 0x97 };
        Ok(Box::new(IntegrationProtector { key }))
    }
}

struct ServiceVaultClient {
    service: Arc<VaultService>,
    caller: CallerIdentity,
    now: AtomicU64,
}

impl VaultClient for ServiceVaultClient {
    fn request(&self, request: &VaultRequest) -> factorseal::VaultResult<VaultResponse> {
        // Exercise the native protocol codec as a transport would, rather than
        // handing the service the provider's in-memory request directly.
        let request = VaultRequest::decode(&request.encode()?)?;
        Ok(self.service.handle(
            &self.caller,
            request,
            self.now.fetch_add(1, Ordering::Relaxed),
        ))
    }
}

struct ApprovalIntegrationFixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    unlock_group: UnlockGroup,
    service: Arc<VaultService>,
    manager: CallerIdentity,
    now: u64,
}

impl ApprovalIntegrationFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unlock_group = UnlockGroup::new([UnlockFactorKind::Biometric]).unwrap();
        let policy = UnlockPolicy::new([unlock_group.clone()]).unwrap();
        let unsealed = Vault::create_with_key_protector_policy(
            &root,
            VaultPlatform::Android,
            &policy,
            UnlockCredentials::none(),
            &IntegrationProtectorFactory,
        )
        .unwrap();
        let now = unix_time_ms().unwrap() / 1_000;
        let service = Arc::new(
            VaultService::open(&root, unsealed, now, UnsealLeasePolicy::default()).unwrap(),
        );
        let manager = CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "dev.factorseal.cli",
            [9; 32],
            None,
        )
        .unwrap();
        service.authorize_permission_manager(&manager, now).unwrap();
        Self {
            _directory: directory,
            root,
            unlock_group,
            service,
            manager,
            now,
        }
    }

    fn provider(&self) -> FactorsealProvider {
        FactorsealProvider::with_client(Arc::new(ServiceVaultClient {
            service: Arc::clone(&self.service),
            caller: CallerIdentity::new(
                CallerPlatform::Linux,
                "uid:1000",
                "dev.factorseal.provider",
                [7; 32],
                None,
            )
            .unwrap(),
            now: AtomicU64::new(self.now + 1),
        }))
    }
}

fn approval_initialize() -> InitializeParams<InitializeApplication> {
    InitializeParams {
        protocol: PROVIDER_PROTOCOL.to_owned(),
        versions: vec![PROTOCOL_VERSION],
        client: Product {
            name: "approval-integration-test".to_owned(),
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
            context: ApplicationContext {
                project: Some("demo".to_owned()),
                profile: Some("production".to_owned()),
                base_dir: None,
                reason: Some("deploy".to_owned()),
                requested_authorization_duration_ms: Some(8 * 60 * 60 * 1_000),
            },
            credentials: BTreeMap::new(),
        },
    }
}

#[tokio::test]
async fn secretspec_request_waits_for_approval_and_completes() {
    let fixture = ApprovalIntegrationFixture::new();
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::split(client_io);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = tokio::spawn(serve_provider(
        server_read,
        server_write,
        fixture.provider(),
        ServerConfig::default(),
    ));
    let (client, _) = Client::connect::<_, _, _, InitializedApplication>(
        client_read,
        client_write,
        approval_initialize(),
        deadline(),
    )
    .await
    .unwrap();

    let request_client = client.clone();
    let pending_request = tokio::spawn(async move {
        request_client
            .call::<_, GetResult>(
                wire::method::GET,
                &AddressParams { address: address() },
                unix_time_ms().unwrap() + 10_000,
            )
            .await
    });
    let service = Arc::clone(&fixture.service);
    let manager = fixture.manager.clone();
    let now = fixture.now;
    let listed = tokio::task::spawn_blocking(move || {
        service.handle(
            &manager,
            VaultRequest::new(VaultAction::WaitPermissions {
                after_revision: 0,
                timeout_ms: 5_000,
            })
            .unwrap(),
            now + 2,
        )
    })
    .await
    .unwrap();
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = listed.result else {
        panic!("expected one pending approval");
    };
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].application.project.as_deref(), Some("demo"));
    assert_eq!(permissions[0].application.reason.as_deref(), Some("deploy"));
    assert_eq!(
        permissions[0]
            .application
            .requested_permission_duration_seconds,
        Some(8 * 60 * 60)
    );

    let unsealed = Vault::unseal_with_key_protector_group(
        &fixture.root,
        &fixture.unlock_group,
        UnlockCredentials::none(),
        &IntegrationProtectorFactory,
    )
    .unwrap();
    let PermissionState::Pending { challenge, .. } = &permissions[0].state else {
        panic!("expected a pending permission");
    };
    let signature = unsealed
        .sign_permission_challenge(&permissions[0].id, challenge, Some(8 * 60 * 60))
        .unwrap();
    let approved = fixture.service.handle(
        &fixture.manager,
        VaultRequest::new(VaultAction::ApprovePermission {
            id: permissions[0].id.clone(),
            signature,
            duration_seconds: Some(8 * 60 * 60),
        })
        .unwrap(),
        fixture.now + 3,
    );
    assert!(matches!(
        approved.result,
        Ok(VaultResponseBody::PermissionChanged {
            status: PermissionChange::Granted
        })
    ));
    assert_eq!(pending_request.await.unwrap().unwrap(), GetResult::Missing);

    client.close(deadline()).await.unwrap();
    server.await.unwrap().unwrap();
}
