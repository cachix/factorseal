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
