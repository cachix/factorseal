//! XDG Secret portal backend backed by the live Factorseal agent.
//!
//! `xdg-desktop-portal` authenticates the sandbox and forwards its application
//! ID to this backend. The backend itself is a D-Bus-activated process and is
//! the only principal that receives Factorseal's native socket capability.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write as _;
use std::sync::{Arc, Mutex};

use factorseal::{
    LINUX_SECRET_PORTAL_NAMESPACE, LinuxVaultClient, VaultAction, VaultClient, VaultError,
    VaultRequest, VaultResponseBody, WireSecret, WireSecretAddress,
};
use zbus::names::BusName;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo, interface};

const BACKEND_BUS_NAME: &str = "org.freedesktop.impl.portal.desktop.factorseal";
const FRONTEND_BUS_NAME: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const SECRET_BYTES: usize = 64;
const RESPONSE_SUCCESS: u32 = 0;
const RESPONSE_CANCELLED: u32 = 1;
const RESPONSE_OTHER: u32 = 2;

type Results = HashMap<String, OwnedValue>;

pub(super) fn serve(client: LinuxVaultClient) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the Secret portal runtime: {error}"))?;
    runtime.block_on(async move {
        let backend = SecretPortal {
            store: PortalStore::new(Arc::new(client)),
        };
        let connection = zbus::connection::Builder::session()
            .map_err(portal_error)?
            .name(BACKEND_BUS_NAME)
            .map_err(portal_error)?
            .serve_at(PORTAL_PATH, backend)
            .map_err(portal_error)?
            .build()
            .await
            .map_err(portal_error)?;
        connection.closed().await;
        Ok(())
    })
}

struct PortalStore {
    client: Arc<dyn VaultClient>,
    /// Serialize get-or-create so concurrent first requests for one app cannot
    /// receive different master secrets.
    mutation: Mutex<()>,
}

impl PortalStore {
    fn new(client: Arc<dyn VaultClient>) -> Arc<Self> {
        Arc::new(Self {
            client,
            mutation: Mutex::new(()),
        })
    }

    fn retrieve(&self, app_id: &str) -> Result<WireSecret, VaultError> {
        let address = application_address(app_id)?;
        let _serialized = self
            .mutation
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;

        match self.call(VaultAction::Get {
            namespace: LINUX_SECRET_PORTAL_NAMESPACE.to_vec(),
            address: address.clone(),
        })? {
            VaultResponseBody::Secret { value: Some(value) } => {
                validate_secret(&value)?;
                Ok(value)
            }
            VaultResponseBody::Secret { value: None } => {
                let mut value = vec![0_u8; SECRET_BYTES];
                getrandom::fill(&mut value)?;
                let value = WireSecret::new(value);
                match self.call(VaultAction::Put {
                    namespace: LINUX_SECRET_PORTAL_NAMESPACE.to_vec(),
                    address,
                    value: WireSecret::new(value.expose().to_vec()),
                    evict_at: None,
                })? {
                    VaultResponseBody::Stored => Ok(value),
                    _ => Err(unexpected_response()),
                }
            }
            _ => Err(unexpected_response()),
        }
    }

    fn call(&self, action: VaultAction) -> Result<VaultResponseBody, VaultError> {
        let request = VaultRequest::new(action)?;
        self.client
            .request(&request)?
            .result
            .map_err(|error| VaultError::Protocol(error.message))
    }
}

struct SecretPortal {
    store: Arc<PortalStore>,
}

#[allow(clippy::too_many_arguments, clippy::unused_self)]
#[interface(name = "org.freedesktop.impl.portal.Secret")]
impl SecretPortal {
    #[zbus(out_args("response", "results"))]
    async fn retrieve_secret(
        &self,
        handle: OwnedObjectPath,
        app_id: String,
        fd: OwnedFd,
        options: HashMap<String, OwnedValue>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &Connection,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(u32, Results)> {
        drop(options);
        require_portal_frontend(connection, &header).await?;

        let request = Arc::new(RequestState::default());
        let inserted = server
            .at(
                handle.clone(),
                PortalRequest {
                    request: Arc::clone(&request),
                },
            )
            .await
            .map_err(failed)?;
        if !inserted {
            return Err(fdo::Error::ObjectPathInUse(handle.to_string()));
        }

        let response = self
            .complete_retrieve(app_id, fd, &request)
            .await
            .unwrap_or_else(|error| {
                eprintln!("factorseal portal: {error}");
                (RESPONSE_OTHER, Results::new())
            });
        server
            .remove::<PortalRequest, _>(handle.as_str())
            .await
            .map_err(failed)?;
        Ok(response)
    }

    #[zbus(property)]
    const fn version(&self) -> u32 {
        1
    }
}

impl SecretPortal {
    async fn complete_retrieve(
        &self,
        app_id: String,
        fd: OwnedFd,
        request: &RequestState,
    ) -> Result<(u32, Results), VaultError> {
        use std::sync::atomic::Ordering;

        if request.cancelled.load(Ordering::Acquire) {
            return Ok((RESPONSE_CANCELLED, Results::new()));
        }
        let store = Arc::clone(&self.store);
        let mut retrieval = tokio::task::spawn_blocking(move || store.retrieve(&app_id));
        let secret = loop {
            match tokio::time::timeout(std::time::Duration::from_millis(50), &mut retrieval).await {
                Ok(result) => {
                    break result.map_err(|error| {
                        VaultError::Protocol(format!(
                            "Secret portal retrieval task failed: {error}"
                        ))
                    })??;
                }
                Err(_) if request.cancelled.load(Ordering::Acquire) => {
                    return Ok((RESPONSE_CANCELLED, Results::new()));
                }
                Err(_) => {}
            }
        };
        if request.cancelled.load(Ordering::Acquire) {
            return Ok((RESPONSE_CANCELLED, Results::new()));
        }

        let owned: std::os::fd::OwnedFd = fd.into();
        let mut output = File::from(owned);
        output
            .write_all(secret.expose())
            .and_then(|()| output.flush())
            .map_err(|error| {
                VaultError::Protocol(format!("could not write portal secret: {error}"))
            })?;
        Ok((RESPONSE_SUCCESS, Results::new()))
    }
}

struct PortalRequest {
    request: Arc<RequestState>,
}

#[derive(Default)]
struct RequestState {
    cancelled: std::sync::atomic::AtomicBool,
}

#[interface(name = "org.freedesktop.impl.portal.Request")]
impl PortalRequest {
    fn close(&self) {
        self.request
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

async fn require_portal_frontend(
    connection: &Connection,
    header: &zbus::message::Header<'_>,
) -> fdo::Result<()> {
    let sender = header
        .sender()
        .ok_or_else(|| fdo::Error::AccessDenied("D-Bus caller has no unique name".to_owned()))?;
    let name = BusName::try_from(FRONTEND_BUS_NAME).map_err(failed)?;
    let owner = fdo::DBusProxy::new(connection)
        .await
        .map_err(failed)?
        .get_name_owner(name)
        .await
        .map_err(failed)?;
    if owner.as_str() != sender.as_str() {
        return Err(fdo::Error::AccessDenied(
            "only xdg-desktop-portal may call the Secret backend".to_owned(),
        ));
    }
    Ok(())
}

fn application_address(app_id: &str) -> Result<WireSecretAddress, VaultError> {
    if app_id.is_empty() || app_id.len() > 4 * 1024 {
        return Err(VaultError::Protocol(
            "portal application ID is empty or too long".to_owned(),
        ));
    }
    let address = WireSecretAddress::new(format!("application/{app_id}"), None);
    address.validate()?;
    Ok(address)
}

fn validate_secret(secret: &WireSecret) -> Result<(), VaultError> {
    if secret.expose().len() != SECRET_BYTES {
        return Err(VaultError::InvalidData(
            "stored Secret portal master key has the wrong length".to_owned(),
        ));
    }
    Ok(())
}

fn unexpected_response() -> VaultError {
    VaultError::Protocol("unexpected Secret portal vault response".to_owned())
}

fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}

fn portal_error(error: impl std::fmt::Display) -> String {
    format!("Secret portal D-Bus error: {error}")
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::os::fd::OwnedFd as StdOwnedFd;
    use std::os::unix::net::UnixStream;

    use factorseal::{VaultResponse, VaultResponseError, VaultResponseErrorCode};
    use zbus::Proxy;

    use super::*;

    #[derive(Default)]
    struct MemoryClient {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl VaultClient for MemoryClient {
        fn request(&self, request: &VaultRequest) -> Result<VaultResponse, VaultError> {
            let body = match &request.action {
                VaultAction::Get { namespace, address } => {
                    assert_eq!(namespace, LINUX_SECRET_PORTAL_NAMESPACE);
                    VaultResponseBody::Secret {
                        value: self
                            .values
                            .lock()
                            .unwrap()
                            .get(&address.item)
                            .cloned()
                            .map(WireSecret::new),
                    }
                }
                VaultAction::Put {
                    namespace,
                    address,
                    value,
                    evict_at,
                } => {
                    assert_eq!(namespace, LINUX_SECRET_PORTAL_NAMESPACE);
                    assert_eq!(*evict_at, None);
                    self.values
                        .lock()
                        .unwrap()
                        .insert(address.item.clone(), value.expose().to_vec());
                    VaultResponseBody::Stored
                }
                action => panic!("unexpected portal action: {action:?}"),
            };
            Ok(VaultResponse::success(request.request_id(), body))
        }
    }

    struct SealedClient;

    impl VaultClient for SealedClient {
        fn request(&self, request: &VaultRequest) -> Result<VaultResponse, VaultError> {
            Ok(VaultResponse::failure(
                request.request_id(),
                VaultResponseError {
                    code: VaultResponseErrorCode::Sealed,
                    message: "the vault is sealed".to_owned(),
                    interaction: None,
                },
            ))
        }
    }

    #[test]
    fn master_secret_is_stable_and_isolated_by_application_id() {
        let store = PortalStore::new(Arc::new(MemoryClient::default()));
        let first = store.retrieve("dev.factorseal.First").unwrap();
        let again = store.retrieve("dev.factorseal.First").unwrap();
        let other = store.retrieve("dev.factorseal.Other").unwrap();

        assert_eq!(first.expose().len(), SECRET_BYTES);
        assert_eq!(first.expose(), again.expose());
        assert_ne!(first.expose(), other.expose());
    }

    #[test]
    fn concurrent_first_retrievals_return_one_master_secret() {
        let store = PortalStore::new(Arc::new(MemoryClient::default()));
        let threads = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    store
                        .retrieve("dev.factorseal.Concurrent")
                        .unwrap()
                        .expose()
                        .to_vec()
                })
            })
            .collect::<Vec<_>>();
        let values = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        assert!(values.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn sealed_agent_does_not_produce_a_fallback_secret() {
        let store = PortalStore::new(Arc::new(SealedClient));
        assert!(store.retrieve("dev.factorseal.Sealed").is_err());
    }

    #[test]
    fn portal_dbus_method_writes_the_stable_secret_to_the_passed_fd() {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let backend = SecretPortal {
                store: PortalStore::new(Arc::new(MemoryClient::default())),
            };
            let _server = zbus::connection::Builder::session()
                .unwrap()
                .name(BACKEND_BUS_NAME)
                .unwrap()
                .serve_at(PORTAL_PATH, backend)
                .unwrap()
                .build()
                .await
                .unwrap();
            let frontend = Connection::session().await.unwrap();
            frontend
                .request_name_with_flags(
                    FRONTEND_BUS_NAME,
                    zbus::fdo::RequestNameFlags::DoNotQueue.into(),
                )
                .await
                .unwrap();
            let proxy = Proxy::new(
                &frontend,
                BACKEND_BUS_NAME,
                PORTAL_PATH,
                "org.freedesktop.impl.portal.Secret",
            )
            .await
            .unwrap();

            let first = retrieve_over_dbus(&proxy, "first").await;
            let second = retrieve_over_dbus(&proxy, "second").await;
            assert_eq!(first, second);
            assert_eq!(first.len(), SECRET_BYTES);
        });
    }

    async fn retrieve_over_dbus(proxy: &Proxy<'_>, suffix: &str) -> Vec<u8> {
        let (mut read, write) = UnixStream::pair().unwrap();
        let raw: StdOwnedFd = write.into();
        let fd = OwnedFd::from(raw);
        let handle = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/portal/desktop/request/factorseal/{suffix}"
        ))
        .unwrap();
        let (response, results): (u32, Results) = proxy
            .call(
                "RetrieveSecret",
                &(
                    handle,
                    "dev.factorseal.PortalTest".to_owned(),
                    fd,
                    Results::new(),
                ),
            )
            .await
            .unwrap();
        assert_eq!(response, RESPONSE_SUCCESS);
        assert!(results.is_empty());

        let mut secret = vec![0_u8; SECRET_BYTES];
        read.read_exact(&mut secret).unwrap();
        secret
    }
}
