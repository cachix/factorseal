use std::collections::{BTreeMap, btree_map};
use std::sync::{Arc, Mutex, PoisonError};

use factorseal::personal::{PersonalSecret, PersonalSecretKind};
use factorseal::vault::CallerPlatform;
use factorseal::{
    DocumentKind, Permission, PermissionOperation, PermissionPrincipal, PermissionState,
    PermissionTarget, SecretAddress, SecretSpecAddress, UnlockFactorKind, UnlockGroup,
    UnlockPolicy, VaultAction, VaultApplicationContext, VaultClient, VaultEntryImportStatus,
    VaultEntryMetadata, VaultMetadata, VaultMutation, VaultRequest, VaultResponse,
    VaultResponseBody, VaultResponseError, VaultResponseErrorCode, VaultResult, WireSecret,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::sync::{Devices, View};
use super::{
    LeasePolicy, PERSONAL_SECRET_NAMESPACE, RuntimeConfig, Snapshot,
    load_vault_contents_from_client, unix_time,
};

const UNAVAILABLE: &str = "This is not available in the browser.";
const SECRET_SERVICE_NAMESPACE: &[u8] = b"factorseal/secret-service/v1";
const WIFI_NAMESPACE: &[u8] = b"factorseal/network-manager/v1";

pub(crate) struct DesktopRuntime {
    events: async_channel::Sender<Snapshot>,
    vault: MemoryVault,
    lease: Mutex<Option<LeasePolicy>>,
    metadata: Mutex<Option<VaultMetadata>>,
    devices: Arc<Devices>,
}

impl DesktopRuntime {
    pub(crate) fn new(_config: RuntimeConfig) -> (Arc<Self>, async_channel::Receiver<Snapshot>) {
        let (events, receiver) = async_channel::bounded(16);
        let runtime = Arc::new(Self {
            events,
            vault: MemoryVault::default(),
            lease: Mutex::new(None),
            metadata: Mutex::new(None),
            devices: Arc::default(),
        });
        if let Ok(metadata) = UnlockGroup::new([UnlockFactorKind::Password])
            .and_then(|group| UnlockPolicy::new([group]))
            .map_err(drop)
            .and_then(|policy| runtime.create(policy))
        {
            runtime.start_lease(metadata);
        }
        (runtime, receiver)
    }

    pub(crate) fn inspect(&self) -> Snapshot {
        let Ok(metadata) = self.metadata() else {
            return Snapshot::Uninitialized { error: None };
        };
        match self.vault.deadlines() {
            Some(deadlines) => self.unsealed(metadata, deadlines),
            None => Snapshot::Sealed {
                metadata,
                error: None,
            },
        }
    }

    pub(crate) fn set_next_lease(&self, lease: LeasePolicy) {
        *self.lease.lock().unwrap_or_else(PoisonError::into_inner) = Some(lease);
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn initialize(
        self: &Arc<Self>,
        policy: UnlockPolicy,
        _password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        let metadata = self
            .create(policy)
            .map_err(|()| "could not create the vault")?;
        self.open(metadata);
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
    pub(crate) fn unlock(
        self: &Arc<Self>,
        metadata: VaultMetadata,
        _group: UnlockGroup,
        _password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        self.open(metadata);
        Ok(())
    }

    pub(crate) fn seal(&self) -> Result<(), String> {
        self.vault.close();
        let _ = self.events.try_send(Snapshot::Sealed {
            metadata: self.metadata()?,
            error: None,
        });
        Ok(())
    }

    pub(crate) fn start_seal(self: &Arc<Self>, _metadata: VaultMetadata) -> Result<(), String> {
        self.seal()
    }

    pub(crate) fn lease_deadlines(&self, _metadata: &VaultMetadata) -> Option<(u64, u64)> {
        self.vault.deadlines()
    }

    pub(super) fn client(&self, _metadata: &VaultMetadata) -> MemoryVault {
        self.vault.clone()
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn sync_view(self: &Arc<Self>) -> Result<View, String> {
        Ok(if self.metadata().is_ok() {
            self.devices.view()
        } else {
            View::default()
        })
    }

    pub(crate) fn sync_manager(self: &Arc<Self>) -> Result<Arc<Devices>, String> {
        self.metadata()?;
        Ok(Arc::clone(&self.devices))
    }

    pub(super) fn metadata(&self) -> Result<VaultMetadata, String> {
        self.metadata
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| "Set up your vault first".to_owned())
    }

    fn create(&self, policy: UnlockPolicy) -> Result<VaultMetadata, ()> {
        let created_at = unix_time().map_err(drop)?;
        let metadata = VaultMetadata::in_memory(policy, created_at).map_err(drop)?;
        *self.metadata.lock().unwrap_or_else(PoisonError::into_inner) = Some(metadata.clone());
        self.vault.fill(
            sample_items(),
            sample_entries(),
            sample_permissions(created_at),
        );
        Ok(metadata)
    }

    fn open(&self, metadata: VaultMetadata) {
        let deadlines = self.start_lease(metadata.clone());
        let _ = self.events.try_send(self.unsealed(metadata, deadlines));
    }

    fn start_lease(&self, metadata: VaultMetadata) -> (u64, u64) {
        let policy = *self.lease.lock().unwrap_or_else(PoisonError::into_inner);
        let (lease, deadlines) = self.vault.open(policy);
        let vault = self.vault.clone();
        let events = self.events.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                match vault.lease_state(lease) {
                    LeaseState::Alive(deadline) => sleep_until(deadline).await,
                    LeaseState::Expired => {
                        let _ = events.try_send(Snapshot::Sealed {
                            metadata,
                            error: None,
                        });
                        break;
                    }
                    LeaseState::Ended => break,
                }
            }
        });
        deadlines
    }

    fn unsealed(&self, metadata: VaultMetadata, (idle, absolute): (u64, u64)) -> Snapshot {
        let (contents, contents_error) = match load_vault_contents_from_client(&self.vault) {
            Ok(contents) => (contents, None),
            Err(error) => (super::VaultContents::default(), Some(error)),
        };
        Snapshot::Unsealed {
            metadata,
            idle_deadline: idle,
            absolute_deadline: absolute,
            owned: true,
            contents,
            contents_error,
            error: None,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct MemoryVault(Arc<Mutex<Store>>);

#[derive(Default)]
struct Store {
    items: BTreeMap<String, Zeroizing<Vec<u8>>>,
    entries: Vec<(VaultEntryMetadata, Zeroizing<Vec<u8>>)>,
    permissions: Vec<Permission>,
    revision: u64,
    leases: u64,
    lease: Option<Lease>,
}

struct Lease {
    id: u64,
    policy: Option<LeasePolicy>,
    idle: u64,
    absolute: u64,
}

impl Lease {
    const fn alive(&self, now: u64) -> bool {
        now < self.idle && now < self.absolute
    }
}

enum LeaseState {
    Alive(u64),
    Expired,
    Ended,
}

impl MemoryVault {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fill(
        &self,
        items: impl IntoIterator<Item = PersonalSecret>,
        entries: Vec<(VaultEntryMetadata, Zeroizing<Vec<u8>>)>,
        permissions: Vec<Permission>,
    ) {
        let mut store = self.store();
        for item in items {
            if let Ok(encoded) = item.encode() {
                store.items.insert(item.id.clone(), encoded);
            }
        }
        store.entries = entries;
        store.permissions = permissions;
    }

    fn open(&self, policy: Option<LeasePolicy>) -> (u64, (u64, u64)) {
        let now = unix_time().unwrap_or_default();
        let (idle, absolute) = policy.map_or((u64::MAX, u64::MAX), |policy| {
            (
                now + policy.idle_timeout.as_secs(),
                now + policy.maximum_lifetime.as_secs(),
            )
        });
        let mut store = self.store();
        store.leases += 1;
        let lease = Lease {
            id: store.leases,
            policy,
            idle,
            absolute,
        };
        let opened = (lease.id, (lease.idle, lease.absolute));
        store.lease = Some(lease);
        opened
    }

    fn close(&self) {
        self.store().lease = None;
    }

    fn deadlines(&self) -> Option<(u64, u64)> {
        let now = unix_time().unwrap_or_default();
        self.store()
            .lease
            .as_ref()
            .filter(|lease| lease.alive(now))
            .map(|lease| (lease.idle, lease.absolute))
    }

    fn lease_state(&self, id: u64) -> LeaseState {
        let mut store = self.store();
        let now = unix_time().unwrap_or_default();
        match &store.lease {
            Some(lease) if lease.id != id => LeaseState::Ended,
            Some(lease) if lease.alive(now) => LeaseState::Alive(lease.idle.min(lease.absolute)),
            Some(_) => {
                store.lease = None;
                LeaseState::Expired
            }
            None => LeaseState::Ended,
        }
    }
}

impl VaultClient for MemoryVault {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        let id = request.request_id();
        Ok(match self.answer(&request.action) {
            Ok(body) => VaultResponse::success(id, body),
            Err((code, message)) => VaultResponse::failure(
                id,
                VaultResponseError {
                    code,
                    message: message.to_owned(),
                    interaction: None,
                },
            ),
        })
    }
}

impl MemoryVault {
    fn answer(
        &self,
        action: &VaultAction,
    ) -> Result<VaultResponseBody, (VaultResponseErrorCode, &'static str)> {
        if self.deadlines().is_none() {
            return Err((VaultResponseErrorCode::Sealed, "The vault is sealed."));
        }
        let mut store = self.store();
        if let Some(lease) = &mut store.lease
            && let Some(policy) = lease.policy
        {
            let now = unix_time().unwrap_or_default();
            lease.idle = (now + policy.idle_timeout.as_secs()).min(lease.absolute);
        }
        match action {
            VaultAction::ListVaultEntries { .. } => Ok(VaultResponseBody::VaultEntries {
                entries: store
                    .items
                    .iter()
                    .filter_map(|(id, value)| entry_metadata(id, value))
                    .chain(store.entries.iter().map(|(entry, _)| entry.clone()))
                    .collect(),
                next_cursor: None,
            }),
            VaultAction::ExportVaultEntry { entry }
                if entry.partition == PERSONAL_SECRET_NAMESPACE =>
            {
                entry
                    .address
                    .as_local()
                    .and_then(|(id, _)| store.items.get(id))
                    .and_then(|value| WireSecret::new(value.to_vec()).ok())
                    .map(|value| VaultResponseBody::VaultEntrySecret {
                        value,
                        evict_at: None,
                    })
                    .ok_or((
                        VaultResponseErrorCode::InvalidRequest,
                        "The item is missing.",
                    ))
            }
            VaultAction::ExportVaultEntry { entry } => store
                .entries
                .iter()
                .find(|(stored, _)| same_entry(stored, entry))
                .map(|(_, value)| value)
                .and_then(|value| WireSecret::new(value.to_vec()).ok())
                .map(|value| VaultResponseBody::VaultEntrySecret {
                    value,
                    evict_at: None,
                })
                .ok_or((
                    VaultResponseErrorCode::InvalidRequest,
                    "The item is missing.",
                )),
            VaultAction::Mutate {
                namespace,
                mutations,
            } if namespace.as_slice() == PERSONAL_SECRET_NAMESPACE => {
                apply(&mut store.items, mutations)
            }
            VaultAction::ExportRevision => Ok(VaultResponseBody::ExportRevision { revision: None }),
            VaultAction::ImportVaultEntry {
                entry,
                value,
                replace_existing,
                ..
            } => Ok(VaultResponseBody::VaultEntryImported {
                status: import(&mut store, entry, value.expose(), *replace_existing)?,
            }),
            VaultAction::ListPermissions => Ok(VaultResponseBody::Permissions {
                revision: store.revision,
                permissions: store.permissions.clone(),
                next_cursor: None,
            }),
            VaultAction::RevokePermission { id } => {
                store.permissions.retain(|permission| permission.id != *id);
                store.revision += 1;
                Ok(VaultResponseBody::Mutated)
            }
            _ => Err((VaultResponseErrorCode::InvalidRequest, UNAVAILABLE)),
        }
    }
}

fn import(
    store: &mut Store,
    entry: &VaultEntryMetadata,
    value: &[u8],
    replace_existing: bool,
) -> Result<VaultEntryImportStatus, (VaultResponseErrorCode, &'static str)> {
    let value = Zeroizing::new(value.to_vec());
    let existing = if entry.partition == PERSONAL_SECRET_NAMESPACE {
        let (id, _) = entry.address.as_local().ok_or((
            VaultResponseErrorCode::InvalidRequest,
            "The item is not valid.",
        ))?;
        match store.items.entry(id.to_owned()) {
            btree_map::Entry::Occupied(slot) => slot.into_mut(),
            btree_map::Entry::Vacant(slot) => {
                slot.insert(value);
                return Ok(VaultEntryImportStatus::Added);
            }
        }
    } else if let Some(index) = store
        .entries
        .iter()
        .position(|(stored, _)| same_entry(stored, entry))
    {
        &mut store.entries[index].1
    } else {
        store.entries.push((entry.clone(), value));
        return Ok(VaultEntryImportStatus::Added);
    };
    if !replace_existing {
        return Ok(VaultEntryImportStatus::KeptExisting);
    }
    *existing = value;
    Ok(VaultEntryImportStatus::Replaced)
}

fn same_entry(stored: &VaultEntryMetadata, entry: &VaultEntryMetadata) -> bool {
    stored.document_kind == entry.document_kind
        && stored.partition == entry.partition
        && stored.address == entry.address
}

async fn sleep_until(deadline: u64) {
    let delay = deadline
        .saturating_sub(unix_time().unwrap_or_default())
        .saturating_add(1)
        .saturating_mul(1000);
    let delay = i32::try_from(delay).unwrap_or(i32::MAX);
    let elapsed = js_sys::Promise::new(&mut |resolve, _| {
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, delay);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(elapsed).await;
}

fn apply(
    items: &mut BTreeMap<String, Zeroizing<Vec<u8>>>,
    mutations: &[VaultMutation],
) -> Result<VaultResponseBody, (VaultResponseErrorCode, &'static str)> {
    let mut next = items.clone();
    for mutation in mutations {
        match mutation {
            VaultMutation::Check {
                address,
                expected_sha256,
            } => {
                let current = next
                    .get(&address.item)
                    .map(|value| <[u8; 32]>::from(Sha256::digest(value)));
                if current != *expected_sha256 {
                    return Err((VaultResponseErrorCode::Conflict, "The item changed."));
                }
            }
            VaultMutation::Put { address, value, .. } => {
                next.insert(
                    address.item.clone(),
                    Zeroizing::new(value.expose().to_vec()),
                );
            }
            VaultMutation::Delete { address } => {
                next.remove(&address.item);
            }
        }
    }
    *items = next;
    Ok(VaultResponseBody::Mutated)
}

fn entry_metadata(id: &str, value: &[u8]) -> Option<VaultEntryMetadata> {
    let item = PersonalSecret::decode_current(value).ok()?;
    Some(VaultEntryMetadata {
        access_project: None,
        display_name: Some(item.title.clone()),
        display_type: Some(item.kind.label().to_owned()),
        display_username: item.username().map(str::to_owned),
        display_website: item.website_host(),
        updated_at: unix_time().ok(),
        favorite: item.favorite,
        document_kind: DocumentKind::LocalKeyring,
        partition: PERSONAL_SECRET_NAMESPACE.to_vec(),
        address: SecretAddress::new(id, None).ok()?,
    })
}

fn sample_items() -> Vec<PersonalSecret> {
    let login = |title: &str, username: &str, password: &str, website: &str| {
        let mut item = PersonalSecret::login(title.to_owned(), website, username);
        item.set_password(password);
        item
    };
    let filled = |kind, title: &str, values: &[(&str, &str)]| {
        let mut item = PersonalSecret::template(kind, title.to_owned());
        for field in &mut item.sections[0].fields {
            if let Some((_, value)) = values.iter().find(|(id, _)| *id == field.id) {
                field.value = (*value).into();
            }
        }
        item
    };
    let mut fastmail = login(
        "Fastmail",
        "john@example.com",
        "vX7#qLm2!pR9sT4w",
        "https://app.fastmail.com",
    );
    fastmail.favorite = true;
    let mut github = login(
        "GitHub",
        "john.doe",
        "Kd8$wq3Lz!mN0rTe",
        "https://github.com",
    );
    github.favorite = true;
    github.set_one_time_password(
        "otpauth://totp/GitHub:john.doe?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    );
    let identity = filled(
        PersonalSecretKind::Identity,
        "John Doe",
        &[
            ("firstName", "John"),
            ("lastName", "Doe"),
            ("email", "john@example.com"),
        ],
    );
    let card = filled(
        PersonalSecretKind::Card,
        "Everyday Visa",
        &[
            ("cardholderName", "John Doe"),
            ("number", "4111111111111111"),
            ("expMonth", "08"),
            ("expYear", "2029"),
            ("code", "123"),
        ],
    );
    let mut wifi = PersonalSecret::new(PersonalSecretKind::SecureNote, "Home Wi-Fi".to_owned());
    wifi.notes = Some("Network: Doe Home\nPassword: correct-horse-battery".to_owned());
    vec![
        fastmail,
        github,
        identity,
        card,
        login(
            "Figma",
            "john@example.com",
            "pQ4!nW8@zR2#kL6m",
            "https://www.figma.com",
        ),
        login(
            "Hetzner Cloud",
            "john.doe",
            "Hz5%tY1&bN7*cV3x",
            "https://console.hetzner.cloud",
        ),
        wifi,
        login(
            "Tailscale",
            "john@example.com",
            "Ts9^gH4!jK2@wE7q",
            "https://login.tailscale.com",
        ),
    ]
}

fn sample_entries() -> Vec<(VaultEntryMetadata, Zeroizing<Vec<u8>>)> {
    let project = |project: &str, profile: &str, key: &str| {
        SecretAddress::secret_spec(SecretSpecAddress::convention(project, profile, key).ok()?).ok()
    };
    let local =
        |item: &str, field: Option<&str>| SecretAddress::new(item, field.map(str::to_owned)).ok();
    [
        (
            DocumentKind::SecretSpecProject,
            b"my-app".as_slice(),
            project("my-app", "default", "DATABASE_URL"),
            None,
            None,
            "postgres://app:local-dev@localhost:5432/app",
        ),
        (
            DocumentKind::SecretSpecProject,
            b"my-app",
            project("my-app", "production", "STRIPE_SECRET_KEY"),
            None,
            None,
            "sk_test_example_51Hx9QeKZ2tYv8Lm3NpR7wDc",
        ),
        (
            DocumentKind::SecretSpecProject,
            b"site",
            project("site", "default", "GITHUB_TOKEN"),
            None,
            None,
            "ghp_9fK2mQ7xL4vT8nB3cR6wY1zH5jD0sA",
        ),
        (
            DocumentKind::SecretSpecProviderCache,
            b"my-app",
            project("my-app", "production", "DATABASE_URL"),
            None,
            None,
            "postgres://app:Xq7v2Lm9@db.internal:5432/app",
        ),
        (
            DocumentKind::LinuxSecretService,
            SECRET_SERVICE_NAMESPACE,
            local("item/06f719e968dea3b34f723f7bfcdb1d5c", None),
            Some("gh:github.com"),
            Some("service/gh:github.com"),
            "gho_16C7e42F292c6912E7710c838347Ae178B4a",
        ),
        (
            DocumentKind::LinuxSecretService,
            SECRET_SERVICE_NAMESPACE,
            local("item/301162742759bac4622546a6fc17b7e9", None),
            Some("Chromium Safe Storage"),
            Some("application/chromium"),
            "q1Fz8VbN3xRk7Lw2Tp9YcM4h",
        ),
        (
            DocumentKind::NetworkManagerWifi,
            WIFI_NAMESPACE,
            local(
                "5f3c9a2e-7d41-4b8e-9c6a-1e2f3a4b5c6d",
                Some("802-11-wireless-security/psk"),
            ),
            Some("Doe Home"),
            None,
            "correct-horse-battery",
        ),
        (
            DocumentKind::LocalKeyring,
            b"atuin",
            local("sync-key", None),
            None,
            None,
            "atuin-6c1f0e9b2d7a4853",
        ),
    ]
    .into_iter()
    .filter_map(
        |(document_kind, partition, address, name, access_project, value)| {
            let entry = VaultEntryMetadata {
                access_project: access_project.map(str::to_owned),
                display_name: name.map(str::to_owned),
                display_type: None,
                display_username: None,
                display_website: None,
                updated_at: None,
                favorite: false,
                document_kind,
                partition: partition.to_vec(),
                address: address?,
            };
            let value = if document_kind == DocumentKind::LinuxSecretService {
                portable_keyring_item(&entry, value)?
            } else {
                value.as_bytes().to_vec()
            };
            Some((entry, Zeroizing::new(value)))
        },
    )
    .collect()
}

fn portable_keyring_item(entry: &VaultEntryMetadata, secret: &str) -> Option<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let (address, _) = entry.address.as_local()?;
    serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "item": {
            "id": address.strip_prefix("item/")?,
            "label": entry.display_name,
            "attributes": {},
            "content_type": "text/plain",
            "created": 0,
            "modified": 0,
        },
        "value": STANDARD.encode(secret),
    }))
    .ok()
}

fn sample_permissions(now: u64) -> Vec<Permission> {
    let grant = |id: &str, application_id: &str, scope, target, project: &str, expires_at| {
        Some(Permission {
            target: Some(Box::new(target)),
            id: id.to_owned(),
            scope: Some(scope),
            operation: PermissionOperation::Get,
            principal: PermissionPrincipal {
                platform: CallerPlatform::Linux,
                user_id: "uid:1000".to_owned(),
                application_id: application_id.to_owned(),
                executable_digest: [0; 32],
                signer_id: None,
            },
            application: VaultApplicationContext::new(Some(project.to_owned()), None, None, None)
                .ok()?,
            state: PermissionState::Granted {
                granted_at: now,
                expires_at,
                single_use: false,
            },
        })
    };
    let Ok(keyring_item) = SecretAddress::new("item/06f719e968dea3b34f723f7bfcdb1d5c", None) else {
        return Vec::new();
    };
    [
        grant(
            "secret-tool",
            "/usr/bin/secret-tool",
            DocumentKind::LinuxSecretService,
            PermissionTarget::ProjectEntry {
                namespace: b"service/gh:github.com".to_vec(),
                address: keyring_item,
                project: "service/gh:github.com".to_owned(),
                base_dir: Some("/home/john/dev/site".to_owned()),
            },
            "service/gh:github.com",
            Some(now + 45 * 60),
        ),
        grant(
            "secretspec",
            "/usr/bin/secretspec",
            DocumentKind::SecretSpecProject,
            PermissionTarget::Project {
                namespace: b"my-app".to_vec(),
                project: "my-app".to_owned(),
                base_dir: Some("/home/john/dev/my-app".to_owned()),
            },
            "my-app",
            None,
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
}

impl RuntimeConfig {
    pub(crate) fn browser() -> Self {
        let settings = crate::settings::DesktopSettings::default();
        Self {
            root: std::path::PathBuf::new(),
            socket: None,
            lease: super::lease_policy(settings.idle_seconds, settings.maximum_seconds)
                .expect("default lease durations are valid"),
            secret_service: false,
        }
    }
}

pub(crate) enum IconManager {}

impl IconManager {
    pub(crate) fn fetch(&self, _host: &str) -> Option<Icon> {
        match *self {}
    }

    pub(crate) fn stop(&self) {
        match *self {}
    }
}

pub(crate) enum Icon {}

impl Icon {
    pub(crate) fn rgba(&self) -> &[u8] {
        match *self {}
    }

    pub(crate) fn width(&self) -> u32 {
        match *self {}
    }

    pub(crate) fn height(&self) -> u32 {
        match *self {}
    }
}

pub(crate) fn open_icon_helper() -> Result<IconManager, String> {
    Err(UNAVAILABLE.to_owned())
}
