use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use factorseal::personal::{PersonalSecret, PersonalSecretKind};
use factorseal::{
    DocumentKind, SecretAddress, UnlockGroup, UnlockPolicy, VaultAction, VaultClient,
    VaultEntryMetadata, VaultMetadata, VaultMutation, VaultRequest, VaultResponse,
    VaultResponseBody, VaultResponseError, VaultResponseErrorCode, VaultResult, WireSecret,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    LeasePolicy, PERSONAL_SECRET_NAMESPACE, RuntimeConfig, Snapshot,
    load_vault_contents_from_client, unix_time,
};

const WRONG_PASSWORD: &str = "The password is not correct.";
const UNAVAILABLE: &str = "This is not available in the browser.";

pub(crate) struct DesktopRuntime {
    events: async_channel::Sender<Snapshot>,
    vault: MemoryVault,
    lease: Mutex<LeasePolicy>,
    setup: Mutex<Option<Setup>>,
}

struct Setup {
    metadata: VaultMetadata,
    password: [u8; 32],
}

impl DesktopRuntime {
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn new(config: RuntimeConfig) -> (Arc<Self>, async_channel::Receiver<Snapshot>) {
        let (events, receiver) = async_channel::bounded(16);
        (
            Arc::new(Self {
                events,
                vault: MemoryVault::default(),
                lease: Mutex::new(config.lease),
                setup: Mutex::new(None),
            }),
            receiver,
        )
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
        *self.lease.lock().unwrap_or_else(PoisonError::into_inner) = lease;
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn initialize(
        self: &Arc<Self>,
        policy: UnlockPolicy,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        let created_at = unix_time().map_err(|_| "could not read the clock")?;
        let metadata = VaultMetadata::in_memory(policy, created_at)
            .map_err(|_| "could not create the vault")?;
        *self.setup.lock().unwrap_or_else(PoisonError::into_inner) = Some(Setup {
            metadata: metadata.clone(),
            password: Sha256::digest(&password).into(),
        });
        self.vault.fill(sample_items());
        self.open(metadata);
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
    pub(crate) fn unlock(
        self: &Arc<Self>,
        metadata: VaultMetadata,
        _group: UnlockGroup,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        let matches = self
            .setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|setup| setup.password == <[u8; 32]>::from(Sha256::digest(&password)));
        if matches {
            self.open(metadata);
        } else {
            let _ = self.events.try_send(Snapshot::Sealed {
                metadata,
                error: Some(WRONG_PASSWORD.to_owned()),
            });
        }
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

    pub(super) fn metadata(&self) -> Result<VaultMetadata, String> {
        self.setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|setup| setup.metadata.clone())
            .ok_or_else(|| "Set up your vault first".to_owned())
    }

    fn open(&self, metadata: VaultMetadata) {
        let lease = *self.lease.lock().unwrap_or_else(PoisonError::into_inner);
        let deadlines = self.vault.open(lease);
        let _ = self.events.try_send(self.unsealed(metadata, deadlines));
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
    lease: Option<Lease>,
}

struct Lease {
    policy: LeasePolicy,
    idle: u64,
    absolute: u64,
}

impl MemoryVault {
    fn store(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fill(&self, items: impl IntoIterator<Item = PersonalSecret>) {
        let mut store = self.store();
        for item in items {
            if let Ok(encoded) = item.encode() {
                store.items.insert(item.id.clone(), encoded);
            }
        }
    }

    fn open(&self, policy: LeasePolicy) -> (u64, u64) {
        let now = unix_time().unwrap_or_default();
        let lease = Lease {
            policy,
            idle: now + policy.idle_timeout.as_secs(),
            absolute: now + policy.maximum_lifetime.as_secs(),
        };
        let deadlines = (lease.idle, lease.absolute);
        self.store().lease = Some(lease);
        deadlines
    }

    fn close(&self) {
        self.store().lease = None;
    }

    fn deadlines(&self) -> Option<(u64, u64)> {
        let mut store = self.store();
        let now = unix_time().unwrap_or_default();
        match &store.lease {
            Some(lease) if now < lease.idle && now < lease.absolute => {
                Some((lease.idle, lease.absolute))
            }
            Some(_) => {
                store.lease = None;
                None
            }
            None => None,
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
        if let Some(lease) = &mut store.lease {
            let now = unix_time().unwrap_or_default();
            lease.idle = (now + lease.policy.idle_timeout.as_secs()).min(lease.absolute);
        }
        match action {
            VaultAction::ListVaultEntries { .. } => Ok(VaultResponseBody::VaultEntries {
                entries: store
                    .items
                    .iter()
                    .filter_map(|(id, value)| entry_metadata(id, value))
                    .collect(),
                next_cursor: None,
            }),
            VaultAction::ExportVaultEntry { entry } => entry
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
                )),
            VaultAction::Mutate {
                namespace,
                mutations,
            } if namespace.as_slice() == PERSONAL_SECRET_NAMESPACE => {
                apply(&mut store.items, mutations)
            }
            VaultAction::ListPermissions => Ok(VaultResponseBody::Permissions {
                revision: 0,
                permissions: Vec::new(),
                next_cursor: None,
            }),
            _ => Err((VaultResponseErrorCode::InvalidRequest, UNAVAILABLE)),
        }
    }
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
