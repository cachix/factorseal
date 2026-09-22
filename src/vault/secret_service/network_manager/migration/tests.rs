use super::super::{Agent, Error, GetSecretsFlags, Requests, SecretServiceAccessContext};
use super::*;
use crate::vault::secret_service::network_manager::tests::{UUID, enterprise, wifi};
use std::collections::HashMap;
use std::sync::Mutex;

const PATH: &str = "/org/freedesktop/NetworkManager/Settings/42";

fn duplicate(settings: &Settings) -> Settings {
    settings
        .iter()
        .map(|(setting, values)| {
            (
                setting.clone(),
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.try_clone().unwrap()))
                    .collect(),
            )
        })
        .collect()
}

#[allow(clippy::struct_excessive_bools)] // Independent remote failure injection and persistence state.
struct State {
    settings: Settings,
    secrets: Settings,
    version: u64,
    reject: bool,
    deny_read: bool,
    unsaved: bool,
    edit_during_read: bool,
    updates: usize,
}

impl State {
    fn new(mut settings: Settings) -> Self {
        let mut secrets = Settings::new();
        for property in PROPERTIES {
            if let Some(value) = settings
                .get_mut(property.setting())
                .and_then(|values| values.remove(property.name()))
            {
                secrets
                    .entry(property.setting().into())
                    .or_default()
                    .insert(property.name().into(), value);
            }
        }
        Self {
            settings,
            secrets,
            version: 1,
            reject: false,
            deny_read: false,
            unsaved: false,
            edit_during_read: false,
            updates: 0,
        }
    }
}

struct MockConnection {
    state: Arc<Mutex<State>>,
    store: Store,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl MockConnection {
    #[zbus(property)]
    fn version_id(&self) -> u64 {
        eprintln!("migration mock: VersionId");
        self.state.lock().unwrap().version
    }
    #[zbus(property)]
    fn unsaved(&self) -> bool {
        self.state.lock().unwrap().unsaved
    }
    fn get_settings(&self) -> Settings {
        duplicate(&self.state.lock().unwrap().settings)
    }
    fn get_secrets(&self, setting: &str) -> Result<Settings, Error> {
        eprintln!("migration mock: GetSecrets");
        assert!(matches!(
            setting,
            protocol::WIFI_SECURITY_SETTING | protocol::EAP_SETTING
        ));
        let mut state = self.state.lock().unwrap();
        if state.deny_read {
            return Err(Error::PermissionDenied("denied".into()));
        }
        if state.edit_during_read {
            state.version += 1;
            state
                .settings
                .get_mut("connection")
                .unwrap()
                .insert("id".into(), string_variant("Concurrent edit"));
            state.edit_during_read = false;
        }
        if state.secrets.values().all(BTreeMap::is_empty) {
            return Err(Error::no_secrets());
        }
        Ok(duplicate(&state.secrets))
    }
    async fn update2(
        &self,
        settings: Settings,
        flags: u32,
        args: BTreeMap<String, OwnedValue>,
    ) -> fdo::Result<BTreeMap<String, OwnedValue>> {
        eprintln!("migration mock: Update2");
        assert_eq!(flags, 0x41);
        let profile = Profile::parse(&settings, &[]).unwrap();
        // This assertion is inside the remote Update2 handler: source removal
        // must never be attempted before a matching durable vault copy exists.
        for credential in &profile.credentials {
            if credential.flags.agent_may_save()
                && let Some(value) = &credential.supplied
            {
                assert_eq!(
                    read(
                        self.store.clone(),
                        credential.property.address(&profile.uuid)
                    )
                    .await
                    .unwrap()
                    .unwrap()
                    .expose(),
                    value.expose()
                );
            }
        }
        let mut state = self.state.lock().unwrap();
        if state.reject {
            eprintln!("migration mock: reject Update2");
            return Err(fdo::Error::AccessDenied("denied".into()));
        }
        if u64::try_from(&args["version-id"]).unwrap() != state.version {
            return Err(fdo::Error::Failed("concurrent edit".into()));
        }
        let mut updated = State::new(settings);
        // Simulate NM's persistent secret filtering after Update2.
        for property in PROPERTIES {
            let flags = updated
                .settings
                .get(property.setting())
                .and_then(|values| values.get(property.flags_name()))
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0);
            if flags != 0
                && let Some(values) = updated.secrets.get_mut(property.setting())
            {
                values.remove(property.name());
            }
        }
        updated.version = state.version + 1;
        updated.updates = state.updates + 1;
        *state = updated;
        eprintln!("migration mock: updated");
        Ok(BTreeMap::new())
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    shared: Arc<Shared>,
    store: Store,
    server: Connection,
    client: Connection,
    state: Arc<Mutex<State>>,
}

impl Fixture {
    async fn new(settings: Settings) -> Self {
        let (directory, service, caller) =
            crate::vault::secret_service::tests::test_service_unprivileged();
        service
            .authorize_network_manager_host(&caller, crate::vault::secret_service::unix_time())
            .unwrap();
        let store = Store::in_process(service, caller);
        let shared = Arc::new(Shared::new(Arc::new(
            crate::vault::secret_service::NoPrompter,
        )));
        shared
            .set_agent(Some(Arc::new(
                crate::vault::secret_service::agent::Agent::load(store.clone()).unwrap(),
            )))
            .unwrap();
        let server = Connection::session().await.unwrap();
        let client = Connection::session().await.unwrap();
        let state = Arc::new(Mutex::new(State::new(settings)));
        server
            .object_server()
            .at(
                PATH,
                MockConnection {
                    state: Arc::clone(&state),
                    store: store.clone(),
                },
            )
            .await
            .unwrap();
        Self {
            _directory: directory,
            shared,
            store,
            server,
            client,
            state,
        }
    }
    async fn migrate(&self, legacy: Option<&Legacy>) -> WifiMigrationEntry {
        tokio::time::timeout(Duration::from_secs(30), async {
            let proxy = proxy(
                &self.client,
                self.server.unique_name().unwrap().as_str(),
                PATH,
                CONNECTION,
            )
            .await
            .unwrap();
            migrate_connection(&proxy, &self.shared, legacy)
                .await
                .unwrap()
                .unwrap()
        })
        .await
        .expect("NetworkManager migration did not finish within 30 seconds")
    }
    async fn password(&self) -> Option<WireSecret> {
        read(self.store.clone(), Property::Psk.address(UUID))
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn migration_copies_before_update_and_retries_without_losing_source() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let fixture = Fixture::new(wifi("wpa-psk", 0, Some("system-password"))).await;
    fixture.state.lock().unwrap().reject = true;
    assert!(!fixture.migrate(None).await.migrated);
    assert_eq!(
        fixture.password().await.unwrap().expose(),
        b"system-password"
    );
    assert!(
        fixture.state.lock().unwrap().secrets[protocol::WIFI_SECURITY_SETTING].contains_key("psk")
    );
    fixture.state.lock().unwrap().reject = false;
    assert!(fixture.migrate(None).await.migrated);
    assert!(fixture.state.lock().unwrap().secrets[protocol::WIFI_SECURITY_SETTING].is_empty());
    assert_eq!(
        u32::try_from(
            &fixture.state.lock().unwrap().settings[protocol::WIFI_SECURITY_SETTING]["psk-flags"]
        )
        .unwrap(),
        1
    );
    assert!(fixture.migrate(None).await.migrated);
    assert_eq!(
        fixture.password().await.unwrap().expose(),
        b"system-password"
    );
}

#[tokio::test]
async fn migration_refuses_concurrent_edits_conflicts_and_a_sealed_vault() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let fixture = Fixture::new(wifi("wpa-psk", 0, Some("system-password"))).await;
    fixture.state.lock().unwrap().deny_read = true;
    assert!(!fixture.migrate(None).await.migrated);
    assert!(fixture.password().await.is_none());
    fixture.state.lock().unwrap().deny_read = false;
    fixture.state.lock().unwrap().unsaved = true;
    assert!(!fixture.migrate(None).await.migrated);
    assert!(fixture.password().await.is_none());
    fixture.state.lock().unwrap().unsaved = false;
    fixture.state.lock().unwrap().edit_during_read = true;
    assert!(!fixture.migrate(None).await.migrated);
    assert_eq!(
        <&str>::try_from(&fixture.state.lock().unwrap().settings["connection"]["id"]).unwrap(),
        "Concurrent edit"
    );
    assert_eq!(fixture.state.lock().unwrap().updates, 0);
    mutate(
        fixture.store.clone(),
        vec![VaultMutation::Put {
            address: Property::Psk.address(UUID),
            value: WireSecret::new(b"different-password".to_vec()).unwrap(),
            evict_at: None,
        }],
    )
    .await
    .unwrap();
    assert!(!fixture.migrate(None).await.migrated);
    assert_eq!(
        fixture.password().await.unwrap().expose(),
        b"different-password"
    );
    fixture.shared.set_agent(None).unwrap();
    assert!(!fixture.migrate(None).await.migrated);
    assert_eq!(fixture.state.lock().unwrap().updates, 0);
}

#[tokio::test]
async fn migration_preserves_temporary_flags_and_enterprise_binary_values() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let fixture = Fixture::new(wifi("wpa-psk", 2, Some("temporary-password"))).await;
    assert!(fixture.migrate(None).await.migrated);
    assert_eq!(fixture.state.lock().unwrap().updates, 0);
    assert!(fixture.password().await.is_none());

    let mut settings = enterprise(Some(vec![0xff, 0, 0x80]), 0);
    settings.get_mut(protocol::EAP_SETTING).unwrap().extend([
        ("pin-flags".into(), OwnedValue::from(2_u32)),
        ("pin".into(), string_variant("1234")),
        (
            "domain-suffix-match".into(),
            string_variant("radius.example"),
        ),
    ]);
    let fixture = Fixture::new(settings).await;
    assert!(fixture.migrate(None).await.migrated);
    assert_eq!(
        read(
            fixture.store.clone(),
            Property::Eap(protocol::EapSecretProperty::PasswordRaw).address(UUID)
        )
        .await
        .unwrap()
        .unwrap()
        .expose(),
        &[0xff, 0, 0x80]
    );
    assert!(
        read(
            fixture.store.clone(),
            Property::Eap(protocol::EapSecretProperty::Pin).address(UUID)
        )
        .await
        .unwrap()
        .is_none()
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(
        u32::try_from(&state.settings[protocol::EAP_SETTING]["pin-flags"]).unwrap(),
        2
    );
    assert_eq!(
        <&str>::try_from(&state.settings[protocol::EAP_SETTING]["domain-suffix-match"]).unwrap(),
        "radius.example"
    );
}

struct OldKeyring {
    attributes: HashMap<String, String>,
    value: Vec<u8>,
    deleted: bool,
    locked: bool,
    reject_delete: bool,
    nm: Arc<Mutex<State>>,
}
struct OldService(Arc<Mutex<OldKeyring>>);
struct OldItem(Arc<Mutex<OldKeyring>>);
struct OldSession;

struct InputPrompter(
    tokio::sync::mpsc::UnboundedSender<crate::vault::secret_service::SecretServiceInputRequest>,
);

impl crate::vault::secret_service::SecretServicePrompter for InputPrompter {
    fn request_unlock(&self) {}
    fn supports_input(&self) -> bool {
        true
    }
    fn request_input(&self, request: crate::vault::secret_service::SecretServiceInputRequest) {
        self.0.send(request).unwrap();
    }
}

#[tokio::test]
async fn migration_invalidates_an_older_password_prompt() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let fixture = Fixture::new(wifi("wpa-psk", 0, Some("system-password"))).await;
    let (sender, mut inputs) = tokio::sync::mpsc::unbounded_channel();
    let shared = Arc::new(Shared::new(Arc::new(InputPrompter(sender))));
    shared
        .set_agent(Some(fixture.shared.agent().unwrap()))
        .unwrap();
    let agent = Agent {
        shared: Arc::clone(&shared),
        requests: Arc::new(Requests::default()),
    };
    let old = Profile::parse(&wifi("wpa-psk", 0, None), &[]).unwrap();
    let pending = tokio::spawn(async move {
        agent
            .get(
                old,
                GetSecretsFlags::REQUEST_NEW,
                SecretServiceAccessContext::default(),
                0,
            )
            .await
    });
    let mut prompt = inputs.recv().await.unwrap();
    let proxy = proxy(
        &fixture.client,
        fixture.server.unique_name().unwrap().as_str(),
        PATH,
        CONNECTION,
    )
    .await
    .unwrap();
    assert!(
        migrate_connection(&proxy, &shared, None)
            .await
            .unwrap()
            .unwrap()
            .migrated
    );
    prompt.save(WireSecret::new(b"late-password".to_vec()).unwrap());
    assert!(matches!(
        pending.await.unwrap(),
        Err(Error::AgentCanceled(_))
    ));
    assert_eq!(
        fixture.password().await.unwrap().expose(),
        b"system-password"
    );
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
#[allow(clippy::unused_self, clippy::needless_pass_by_value)] // D-Bus dispatch methods.
impl OldService {
    fn open_session(&self, algorithm: &str, input: Value<'_>) -> (OwnedValue, OwnedObjectPath) {
        let _ = input;
        assert_eq!(algorithm, "plain");
        (
            string_variant(""),
            OwnedObjectPath::try_from("/session").unwrap(),
        )
    }
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let state = self.0.lock().unwrap();
        if state.deleted
            || attributes
                .iter()
                .any(|(key, value)| state.attributes.get(key) != Some(value))
        {
            return (Vec::new(), Vec::new());
        }
        let paths = vec![OwnedObjectPath::try_from("/item").unwrap()];
        if state.locked {
            (Vec::new(), paths)
        } else {
            (paths, Vec::new())
        }
    }
}
#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl OldItem {
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        self.0.lock().unwrap().attributes.clone()
    }
    fn get_secret(&self, session: OwnedObjectPath) -> crate::vault::secret_service::Secret {
        (
            session,
            Vec::new(),
            self.0.lock().unwrap().value.clone(),
            "text/plain".into(),
        )
    }
    fn delete(&self) -> fdo::Result<OwnedObjectPath> {
        let mut state = self.0.lock().unwrap();
        assert!(state.nm.lock().unwrap().updates > 0);
        if state.reject_delete {
            return Err(fdo::Error::AccessDenied("denied".into()));
        }
        state.deleted = true;
        Ok(OwnedObjectPath::try_from("/").unwrap())
    }
}
#[zbus::interface(name = "org.freedesktop.Secret.Session")]
#[allow(clippy::unused_self)] // D-Bus dispatch method.
impl OldSession {
    fn close(&self) {}
}

#[tokio::test]
async fn migration_verifies_old_keyring_cleanup_and_can_retry_cleanup_failure() {
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let fixture = Fixture::new(wifi("wpa-psk", 1, None)).await;
    let old = Arc::new(Mutex::new(OldKeyring {
        attributes: HashMap::from([
            ("connection-uuid".into(), UUID.into()),
            (
                "setting-name".into(),
                protocol::WIFI_SECURITY_SETTING.into(),
            ),
            ("setting-key".into(), "psk".into()),
        ]),
        value: b"keyring-password".to_vec(),
        deleted: false,
        locked: true,
        reject_delete: true,
        nm: Arc::clone(&fixture.state),
    }));
    let server = Connection::session().await.unwrap();
    server
        .object_server()
        .at("/org/freedesktop/secrets", OldService(Arc::clone(&old)))
        .await
        .unwrap();
    server
        .object_server()
        .at("/item", OldItem(Arc::clone(&old)))
        .await
        .unwrap();
    server
        .object_server()
        .at("/session", OldSession)
        .await
        .unwrap();
    let legacy = Legacy::connect_on(
        Connection::session().await.unwrap(),
        server.unique_name().unwrap().to_string(),
    )
    .await
    .unwrap();
    assert!(!fixture.migrate(Some(&legacy)).await.migrated);
    assert_eq!(fixture.state.lock().unwrap().updates, 0);
    assert!(fixture.password().await.is_none());
    old.lock().unwrap().locked = false;
    assert!(!fixture.migrate(Some(&legacy)).await.migrated);
    assert_eq!(
        fixture.password().await.unwrap().expose(),
        b"keyring-password"
    );
    assert!(!old.lock().unwrap().deleted);
    old.lock().unwrap().reject_delete = false;
    assert!(fixture.migrate(Some(&legacy)).await.migrated);
    assert!(old.lock().unwrap().deleted);
    legacy.close().await;
}
