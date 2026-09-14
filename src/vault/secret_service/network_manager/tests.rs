use super::*;
use crate::vault::secret_service::{SecretServiceInputRequest, SecretServicePrompter};
use tokio::sync::mpsc;

const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
const PATH: &str = "/org/freedesktop/NetworkManager/Settings/1";

struct Prompter(mpsc::UnboundedSender<SecretServiceInputRequest>);

impl SecretServicePrompter for Prompter {
    fn request_unlock(&self) {}
    fn supports_input(&self) -> bool {
        true
    }
    fn request_input(&self, request: SecretServiceInputRequest) {
        self.0.send(request).unwrap();
    }
}

struct Manager(mpsc::UnboundedSender<(String, String, u32)>);

#[zbus::interface(name = "org.freedesktop.NetworkManager.AgentManager")]
#[allow(clippy::needless_pass_by_value)] // zbus owns the dispatch header.
impl Manager {
    fn register_with_capabilities(
        &self,
        identifier: String,
        capabilities: u32,
        #[zbus(header)] header: Header<'_>,
    ) {
        self.0
            .send((
                header.sender().unwrap().to_string(),
                identifier,
                capabilities,
            ))
            .unwrap();
    }
}

fn wifi(key_management: &str, flags: u32, secret: Option<&str>) -> Settings {
    let mut security = BTreeMap::from([
        ("key-mgmt".into(), string_variant(key_management)),
        ("psk-flags".into(), OwnedValue::from(flags)),
    ]);
    if let Some(secret) = secret {
        security.insert("psk".into(), string_variant(secret));
    }
    BTreeMap::from([
        (
            "connection".into(),
            BTreeMap::from([
                ("uuid".into(), string_variant(UUID)),
                ("id".into(), string_variant("Office Wi-Fi")),
                ("type".into(), string_variant("802-11-wireless")),
            ]),
        ),
        (protocol::WIFI_SECURITY_SETTING.into(), security),
    ])
}

fn enterprise(secret: Option<Vec<u8>>, flags: u32) -> Settings {
    let mut profile = wifi("wpa-eap", 0, None);
    let mut settings = BTreeMap::from([
        (
            "eap".into(),
            OwnedValue::try_from(Value::from(vec!["peap".to_owned()])).unwrap(),
        ),
        ("password-raw-flags".into(), OwnedValue::from(flags)),
        ("private-key-password-flags".into(), OwnedValue::from(1_u32)),
        (
            "private-key-password".into(),
            string_variant("key-password"),
        ),
    ]);
    if let Some(secret) = secret {
        settings.insert(
            "password-raw".into(),
            OwnedValue::try_from(Value::from(secret)).unwrap(),
        );
    }
    profile.insert(protocol::EAP_SETTING.into(), settings);
    profile
}

async fn proxy<'a>(connection: &'a Connection, target: &'a str) -> zbus::Proxy<'a> {
    zbus::Proxy::new(
        connection,
        target,
        protocol::SECRET_AGENT_PATH,
        protocol::SECRET_AGENT_INTERFACE,
    )
    .await
    .unwrap()
}

async fn get(
    connection: &Connection,
    target: &str,
    settings: Settings,
    flags: u32,
) -> Result<Settings, zbus::Error> {
    let setting = if settings.contains_key(protocol::EAP_SETTING) {
        protocol::EAP_SETTING
    } else {
        protocol::WIFI_SECURITY_SETTING
    };
    let hints = if settings.contains_key(protocol::EAP_SETTING) {
        vec!["password-raw"]
    } else {
        vec!["psk"]
    };
    proxy(connection, target)
        .await
        .call(
            "GetSecrets",
            &(
                settings,
                OwnedObjectPath::try_from(PATH).unwrap(),
                setting,
                hints,
                flags,
            ),
        )
        .await
}

async fn save(
    connection: &Connection,
    target: &str,
    settings: Settings,
) -> Result<(), zbus::Error> {
    proxy(connection, target)
        .await
        .call(
            "SaveSecrets",
            &(settings, OwnedObjectPath::try_from(PATH).unwrap()),
        )
        .await
}

fn error_name<T>(result: Result<T, zbus::Error>, suffix: &str) {
    match result {
        Err(zbus::Error::MethodError(name, _, _)) => assert_eq!(
            name.as_str(),
            format!("org.freedesktop.NetworkManager.SecretAgent.{suffix}")
        ),
        _ => panic!("expected a secret-agent D-Bus error"),
    }
}

#[test]
fn network_manager_profile_rejects_invalid_identity_and_preserves_wire_types() {
    let mut settings = wifi("wpa-psk", 1, None);
    settings
        .get_mut("connection")
        .unwrap()
        .insert("uuid".into(), string_variant("../other-network"));
    assert!(Profile::parse(&settings, &[]).is_err());
    let mut settings = wifi("wpa-psk", 1, None);
    settings
        .get_mut(protocol::WIFI_SECURITY_SETTING)
        .unwrap()
        .insert("psk-flags".into(), string_variant("1"));
    assert!(Profile::parse(&settings, &[]).is_err());
    let profile = Profile::parse(
        &enterprise(Some(vec![0xff, 0, 0x80]), 1),
        &["password-raw".into()],
    )
    .unwrap();
    let raw = profile
        .credentials
        .iter()
        .find(|credential| credential.property.is_raw())
        .unwrap();
    assert_eq!(raw.supplied.as_ref().unwrap().expose(), &[0xff, 0, 0x80]);
    assert!(raw.needed);
    let mut tls = enterprise(None, 1);
    tls.get_mut(protocol::EAP_SETTING).unwrap().insert(
        "eap".into(),
        OwnedValue::try_from(Value::from(vec!["tls".to_owned()])).unwrap(),
    );
    let token = Profile::parse(&tls, &["pin".into()]).unwrap();
    assert!(
        token
            .credentials
            .iter()
            .find(|credential| credential.property.name() == "pin")
            .unwrap()
            .needed
    );
    assert!(
        !token
            .credentials
            .iter()
            .find(|credential| credential.property.name() == "private-key-password")
            .unwrap()
            .needed
    );
    assert!(
        !profile
            .credentials
            .iter()
            .find(|credential| credential.property.name() == "password")
            .unwrap()
            .needed
    );
}

#[test]
fn network_manager_namespace_requires_its_own_grant() {
    use crate::vault::GrantPermission;
    let (_directory, service, caller) = super::super::tests::test_service_unprivileged();
    service
        .authorize_namespace(&caller, NAMESPACE, [GrantPermission::Get], None, 100)
        .unwrap();
    let request = || {
        VaultRequest::new(VaultAction::Get {
            namespace: NAMESPACE.to_vec(),
            address: profile::Property::Psk.address(UUID),
        })
        .unwrap()
    };
    assert!(service.handle(&caller, request(), 100).result.is_err());
    service
        .authorize_network_manager_host(&caller, 100)
        .unwrap();
    assert!(matches!(
        service.handle(&caller, request(), 100).result,
        Ok(VaultResponseBody::Secret { value: None })
    ));
}

#[test]
#[allow(clippy::too_many_lines)] // One isolated daemon/vault lifecycle, including owner replacement.
fn network_manager_dbus_vault_lifecycle() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (_directory, service, caller) = super::super::tests::test_service_unprivileged();
            service
                .authorize_network_manager_host(&caller, super::super::unix_time())
                .unwrap();
            let store = Store::in_process(Arc::clone(&service), caller.clone());
            let (inputs, mut input) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(Prompter(inputs))));
            let installed = Arc::new(super::super::agent::Agent::load(store.clone()).unwrap());
            shared.set_agent(Some(Arc::clone(&installed))).unwrap();
            let server = Connection::session().await.unwrap();
            let target = server.unique_name().unwrap().to_string();
            let manager = Connection::session().await.unwrap();
            let (registrations, mut registration) = mpsc::unbounded_channel();
            manager
                .object_server()
                .at(protocol::AGENT_MANAGER_PATH, Manager(registrations.clone()))
                .await
                .unwrap();
            manager.request_name(protocol::BUS_NAME).await.unwrap();
            let requests = Arc::new(Requests::default());
            let host = tokio::spawn(serve_on(server, Arc::clone(&shared), Arc::clone(&requests)));
            assert_eq!(
                registration.recv().await.unwrap(),
                (target.clone(), IDENTIFIER.into(), 0)
            );

            save(
                &manager,
                &target,
                wifi("wpa-psk", 1, Some("first-password")),
            )
            .await
            .unwrap();
            let reply = get(&manager, &target, wifi("wpa-psk", 1, None), 0)
                .await
                .unwrap();
            assert_eq!(
                <&str>::try_from(&reply[protocol::WIFI_SECURITY_SETTING]["psk"]).unwrap(),
                "first-password"
            );
            assert!(input.try_recv().is_err());

            // Authentication covers every method before any vault operation.
            let stranger = Connection::session().await.unwrap();
            error_name(
                get(&stranger, &target, wifi("wpa-psk", 1, None), 0).await,
                "PermissionDenied",
            );
            error_name(
                save(
                    &stranger,
                    &target,
                    wifi("wpa-psk", 1, Some("attacker-password")),
                )
                .await,
                "PermissionDenied",
            );
            for method in ["DeleteSecrets", "CancelGetSecrets"] {
                let proxy = proxy(&stranger, &target).await;
                let result: Result<(), _> = if method == "DeleteSecrets" {
                    proxy
                        .call(
                            method,
                            &(
                                wifi("wpa-psk", 1, None),
                                OwnedObjectPath::try_from(PATH).unwrap(),
                            ),
                        )
                        .await
                } else {
                    proxy
                        .call(
                            method,
                            &(
                                OwnedObjectPath::try_from(PATH).unwrap(),
                                protocol::WIFI_SECURITY_SETTING,
                            ),
                        )
                        .await
                };
                error_name(result, "PermissionDenied");
            }

            // A request for new credentials never silently returns stored ones.
            let pending_manager = manager.clone();
            let pending_target = target.clone();
            let pending = tokio::spawn(async move {
                get(
                    &pending_manager,
                    &pending_target,
                    wifi("wpa-psk", 1, None),
                    2,
                )
                .await
            });
            let mut prompt = input.recv().await.unwrap();
            prompt.save(WireSecret::new(b"new-password".to_vec()).unwrap());
            pending.await.unwrap().unwrap();
            assert_eq!(
                read(store.clone(), profile::Property::Psk.address(UUID))
                    .await
                    .unwrap()
                    .unwrap()
                    .expose(),
                b"new-password"
            );

            // Cancel all pending calls for this path and setting, including UI.
            let mut pending = Vec::new();
            let mut prompts = Vec::new();
            for _ in 0..2 {
                let manager = manager.clone();
                let target = target.clone();
                pending.push(tokio::spawn(async move {
                    get(&manager, &target, wifi("wpa-psk", 1, None), 2).await
                }));
                prompts.push(input.recv().await.unwrap());
            }
            proxy(&manager, &target)
                .await
                .call::<_, _, ()>(
                    "CancelGetSecrets",
                    &(
                        OwnedObjectPath::try_from(PATH).unwrap(),
                        protocol::WIFI_SECURITY_SETTING,
                    ),
                )
                .await
                .unwrap();
            for pending in pending {
                error_name(pending.await.unwrap(), "AgentCanceled");
            }
            assert!(prompts.iter().all(SecretServiceInputRequest::is_expired));
            assert!(requests.pending.lock().unwrap().is_empty());

            // GetSecrets is responsible for persistence itself: NM need not
            // send SaveSecrets after a successful prompt for a one-time value.
            let pending_manager = manager.clone();
            let pending_target = target.clone();
            let pending = tokio::spawn(async move {
                get(
                    &pending_manager,
                    &pending_target,
                    wifi("wpa-psk", 3, None),
                    1,
                )
                .await
            });
            let mut prompt = input.recv().await.unwrap();
            assert_eq!(prompt.context.attributes["secret"], "Wi-Fi password");
            prompt.save(WireSecret::new(b"one-time-password".to_vec()).unwrap());
            let reply = pending.await.unwrap().unwrap();
            assert_eq!(
                <&str>::try_from(&reply[protocol::WIFI_SECURITY_SETTING]["psk"]).unwrap(),
                "one-time-password"
            );
            assert!(
                read(store.clone(), profile::Property::Psk.address(UUID))
                    .await
                    .unwrap()
                    .is_none()
            );

            // A full SaveSecrets snapshot with a removed value clears the old
            // password even when its ownership flag remains agent-owned.
            save(
                &manager,
                &target,
                wifi("wpa-psk", 1, Some("removed-password")),
            )
            .await
            .unwrap();
            save(&manager, &target, wifi("wpa-psk", 1, None))
                .await
                .unwrap();
            assert!(
                read(store.clone(), profile::Property::Psk.address(UUID))
                    .await
                    .unwrap()
                    .is_none()
            );

            // Flags prevent reuse and storage, and SaveSecrets removes stale values.
            error_name(
                get(&manager, &target, wifi("wpa-psk", 3, None), 0).await,
                "NoSecrets",
            );
            save(
                &manager,
                &target,
                wifi("wpa-psk", 3, Some("not-saved-password")),
            )
            .await
            .unwrap();
            assert!(
                read(store.clone(), profile::Property::Psk.address(UUID))
                    .await
                    .unwrap()
                    .is_none()
            );
            save(
                &manager,
                &target,
                wifi("wpa-psk", 0, Some("system-password")),
            )
            .await
            .unwrap();
            assert!(
                read(store.clone(), profile::Property::Psk.address(UUID))
                    .await
                    .unwrap()
                    .is_none()
            );

            // Enterprise replies preserve binary password bytes and TLS secrets.
            save(&manager, &target, enterprise(Some(vec![0xff, 0, 0x80]), 1))
                .await
                .unwrap();
            let reply = get(&manager, &target, enterprise(None, 1), 0)
                .await
                .unwrap();
            let raw = reply[protocol::EAP_SETTING]["password-raw"]
                .try_clone()
                .unwrap();
            assert_eq!(Vec::<u8>::try_from(raw).unwrap(), [0xff, 0, 0x80]);
            assert_eq!(
                <&str>::try_from(&reply[protocol::EAP_SETTING]["private-key-password"]).unwrap(),
                "key-password"
            );

            // Metadata is derived inside the encrypted worker and categorized.
            service
                .authorize_permission_manager(&caller, super::super::unix_time())
                .unwrap();
            let inventory = store
                .backend_request(
                    VaultRequest::new(VaultAction::ListVaultEntries {
                        cursor: None,
                        limit: 8,
                    })
                    .unwrap(),
                )
                .unwrap()
                .result
                .unwrap();
            let VaultResponseBody::VaultEntries { entries, .. } = inventory else {
                panic!("expected inventory")
            };
            let wifi_entries: Vec<_> = entries
                .iter()
                .filter(|entry| entry.document_kind == crate::DocumentKind::NetworkManagerWifi)
                .collect();
            assert_eq!(wifi_entries.len(), 2);
            assert!(
                wifi_entries
                    .iter()
                    .all(|entry| entry.display_name.as_deref() == Some("Office Wi-Fi"))
            );

            // Mixed enterprise ownership must not prompt for, or persist, a
            // system-owned key password supplied by NetworkManager.
            let mut mixed = enterprise(None, 1);
            mixed
                .get_mut(protocol::EAP_SETTING)
                .unwrap()
                .insert("private-key-password-flags".into(), OwnedValue::from(0_u32));
            let reply = get(&manager, &target, mixed, 0).await.unwrap();
            assert_eq!(
                <&str>::try_from(&reply[protocol::EAP_SETTING]["private-key-password"]).unwrap(),
                "key-password"
            );
            assert!(
                read(
                    store.clone(),
                    profile::Property::Eap(protocol::EapSecretProperty::PrivateKeyPassword)
                        .address(UUID)
                )
                .await
                .unwrap()
                .is_none()
            );
            assert!(input.try_recv().is_err());

            shared.set_agent(None).unwrap();
            error_name(
                get(&manager, &target, enterprise(None, 1), 0).await,
                "NoSecrets",
            );
            error_name(
                save(&manager, &target, enterprise(Some(vec![1]), 1)).await,
                "NoSecrets",
            );
            assert!(input.try_recv().is_err());
            shared.set_agent(Some(installed)).unwrap();

            // Re-register with a new owner and reject requests from the old one.
            manager.release_name(protocol::BUS_NAME).await.unwrap();
            let replacement = Connection::session().await.unwrap();
            replacement
                .object_server()
                .at(protocol::AGENT_MANAGER_PATH, Manager(registrations))
                .await
                .unwrap();
            replacement.request_name(protocol::BUS_NAME).await.unwrap();
            registration.recv().await.unwrap();
            error_name(
                get(&manager, &target, enterprise(None, 1), 0).await,
                "PermissionDenied",
            );
            get(&replacement, &target, enterprise(None, 1), 0)
                .await
                .unwrap();
            let pending_manager = replacement.clone();
            let pending_target = target.clone();
            let pending = tokio::spawn(async move {
                get(
                    &pending_manager,
                    &pending_target,
                    wifi("wpa-psk", 1, None),
                    2,
                )
                .await
            });
            let prompt = input.recv().await.unwrap();
            proxy(&replacement, &target)
                .await
                .call::<_, _, ()>(
                    "DeleteSecrets",
                    &(
                        enterprise(None, 1),
                        OwnedObjectPath::try_from(PATH).unwrap(),
                    ),
                )
                .await
                .unwrap();
            error_name(pending.await.unwrap(), "AgentCanceled");
            assert!(prompt.is_expired());
            error_name(
                get(&replacement, &target, enterprise(None, 1), 0).await,
                "NoSecrets",
            );
            assert!(
                read(store, WireSecretAddress::new(UUID, Some(NAME_FIELD.into())))
                    .await
                    .unwrap()
                    .is_none()
            );
            host.abort();
            let _ = host.await;
        })
        .await
        .unwrap();
    });
}
