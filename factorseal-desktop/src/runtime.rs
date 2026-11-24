use std::path::{Path, PathBuf};
use std::time::Duration;

use factorseal::{
    DocumentKind, MAX_LIST_PAGE_SIZE, UnlockGroup, VaultAction, VaultArchive, VaultClient,
    VaultEntryMetadata, VaultMetadata, VaultMutation, VaultRequest, VaultResponseBody,
    VaultResponseErrorCode, WireSecret, WireSecretAddress, decrypt_vault_archive,
    encrypt_vault_archive,
};
use sha2::{Digest as _, Sha256};
use web_time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[cfg(target_family = "wasm")]
mod memory;
#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
pub(crate) mod sync;

#[cfg(target_family = "wasm")]
pub(crate) use memory::{DesktopRuntime, Icon, IconManager, open_icon_helper};
#[cfg(not(target_family = "wasm"))]
pub(crate) use native::{DesktopRuntime, explicit_or_default_root, open_icon_helper};

use factorseal::transfer::{PersonalSecret, TransferFormat, export_manager};

#[derive(Clone, Copy)]
pub(crate) enum TransferKey<'a> {
    Passphrase(&'a [u8]),
    HybridFile(&'a Path),
}

impl TransferKey<'_> {
    fn encrypt_cxf(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use factorseal::transfer::cxf;
        match self {
            Self::Passphrase(passphrase) => {
                factorseal::security::validate_new_password(passphrase)?;
                cxf::encrypt(payload, passphrase)
            }
            Self::HybridFile(path) => cxf::read_recipient_file(path)
                .and_then(|recipient| cxf::encrypt_to_recipient(payload, &recipient)),
        }
        .map_err(|error| error.to_string())
    }

    fn decrypt_cxf(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use factorseal::transfer::cxf;
        match self {
            Self::Passphrase(passphrase) => cxf::decrypt(bytes, passphrase),
            Self::HybridFile(path) => cxf::read_identity_file(path)
                .and_then(|identity| cxf::decrypt_with_hybrid_identity(bytes, &identity)),
        }
        .map_err(|error| error.to_string())
    }
}

pub(crate) use factorseal::personal::PERSONAL_SECRET_NAMESPACE;

#[derive(Clone, Copy, Debug)]
pub(crate) struct LeasePolicy {
    pub(crate) idle_timeout: Duration,
    pub(crate) maximum_lifetime: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub(crate) root: PathBuf,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) lease: LeasePolicy,
    /// This Desktop serves `org.freedesktop.secrets` and needs the adapter
    /// grant from every worker it starts.
    pub(crate) secret_service: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct VaultContents {
    pub(crate) entries: Vec<VaultEntryMetadata>,
    pub(crate) permissions: Vec<factorseal::Permission>,
    pub(crate) permissions_loading: bool,
    pub(crate) permissions_error: Option<String>,
    pub(crate) secret_service_error: Option<String>,
}

impl VaultContents {
    pub(crate) fn complete_permissions(
        &mut self,
        result: Result<Vec<factorseal::Permission>, String>,
    ) {
        if !self.permissions_loading {
            return;
        }
        self.permissions_loading = false;
        self.permissions_error = None;
        match result {
            Ok(permissions) => self.permissions = permissions,
            Err(error) => self.permissions_error = Some(error),
        }
    }
}

pub(crate) use factorseal::transfer::import_plan::{
    ImportSummary as TransferSummary, PreparedImport,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ItemVersion([u8; 32]);

impl ItemVersion {
    pub(crate) fn of(value: &[u8]) -> Self {
        Self(Sha256::digest(value).into())
    }
}

pub(crate) enum PersonalWriteError {
    Changed(VaultContents),
    Failed(String),
}

impl From<String> for PersonalWriteError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}

impl std::fmt::Display for PersonalWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Changed(_) => formatter.write_str("the item changed somewhere else"),
            Self::Failed(error) => formatter.write_str(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum UnlockStep {
    #[default]
    Verifying,
    Starting,
    Loading,
}

#[derive(Clone, Debug)]
pub(crate) enum Snapshot {
    Uninitialized {
        error: Option<String>,
    },
    Initializing,
    Sealed {
        metadata: VaultMetadata,
        error: Option<String>,
    },
    Unlocking {
        metadata: VaultMetadata,
        group: UnlockGroup,
        step: UnlockStep,
    },
    Sealing {
        metadata: VaultMetadata,
    },
    Unsealed {
        metadata: VaultMetadata,
        idle_deadline: u64,
        absolute_deadline: u64,
        owned: bool,
        contents: VaultContents,
        contents_error: Option<String>,
        error: Option<String>,
    },
    Error(String),
}

impl Snapshot {
    pub(crate) fn metadata(&self) -> Option<&VaultMetadata> {
        match self {
            Self::Sealed { metadata, .. }
            | Self::Unlocking { metadata, .. }
            | Self::Sealing { metadata }
            | Self::Unsealed { metadata, .. } => Some(metadata),
            Self::Uninitialized { .. } | Self::Initializing | Self::Error(_) => None,
        }
    }
}

impl DesktopRuntime {
    pub(crate) fn keep_unsealed(&self, metadata: &VaultMetadata) -> Result<(), String> {
        let request = VaultRequest::new(VaultAction::ListVaultEntries {
            cursor: None,
            limit: 1,
        })
        .map_err(|error| error.to_string())?;
        self.request_live(metadata, &request).map(drop)
    }

    pub(crate) fn read_personal_item(
        &self,
        metadata: &VaultMetadata,
        entry: &VaultEntryMetadata,
    ) -> Result<(PersonalSecret, ItemVersion), String> {
        if !is_personal_entry(entry) {
            return Err("This is not a personal item.".into());
        }
        let request = VaultRequest::new(VaultAction::ExportVaultEntry {
            entry: entry.clone(),
        })
        .map_err(|error| error.to_string())?;
        match self.request_live(metadata, &request)? {
            VaultResponseBody::VaultEntrySecret { value, .. } => {
                let item = PersonalSecret::decode_current(value.expose())
                    .map_err(|error| error.to_string())?;
                Ok((item, ItemVersion::of(value.expose())))
            }
            _ => Err("Could not read the personal item.".into()),
        }
    }

    pub(crate) fn put_personal_secret(
        &self,
        secret: &PersonalSecret,
        expected: Option<ItemVersion>,
    ) -> Result<(ItemVersion, VaultContents), PersonalWriteError> {
        let encoded = secret.encode().map_err(|error| error.to_string())?;
        let mutation = VaultMutation::Put {
            address: WireSecretAddress::new(secret.id.clone(), None),
            value: WireSecret::new(encoded.to_vec()).map_err(|error| error.to_string())?,
            evict_at: None,
        };
        let contents = self.change_personal_secret(&secret.id, expected, mutation)?;
        Ok((ItemVersion::of(&encoded), contents))
    }

    pub(crate) fn delete_personal_secret(
        &self,
        id: &str,
        expected: Option<ItemVersion>,
    ) -> Result<VaultContents, PersonalWriteError> {
        let mutation = VaultMutation::Delete {
            address: WireSecretAddress::new(id, None),
        };
        self.change_personal_secret(id, expected, mutation)
    }

    fn change_personal_secret(
        &self,
        id: &str,
        expected: Option<ItemVersion>,
        mutation: VaultMutation,
    ) -> Result<VaultContents, PersonalWriteError> {
        let metadata = self.metadata()?;
        let request = VaultRequest::new(VaultAction::Mutate {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            mutations: vec![
                VaultMutation::Check {
                    address: WireSecretAddress::new(id, None),
                    expected_sha256: expected.map(|version| version.0),
                },
                mutation,
            ],
        })
        .map_err(|error| error.to_string())?;
        let response = self
            .client(&metadata)
            .request(&request)
            .map_err(|error| error.to_string())?;
        match response.result {
            Ok(VaultResponseBody::Mutated) => Ok(self.load_live_contents(&metadata)?),
            Err(error) if error.code == VaultResponseErrorCode::Conflict => Err(
                PersonalWriteError::Changed(self.load_live_contents(&metadata)?),
            ),
            Err(error) => Err(error.message.into()),
            Ok(_) => Err("vault returned an unexpected personal-secret response"
                .to_owned()
                .into()),
        }
    }

    pub(crate) fn export_native_archive(
        &self,
        metadata: &VaultMetadata,
        passphrase: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let archived = factorseal::read_vault_export(&self.client(metadata), |_| true)
            .map_err(|error| error.to_string())?;
        let archive = VaultArchive::new(unix_time()?, archived);
        encrypt_vault_archive(&archive, passphrase).map_err(|error| error.to_string())
    }

    pub(crate) fn prepare_import(
        bytes: &[u8],
        format: TransferFormat,
        key: TransferKey<'_>,
    ) -> Result<PreparedImport, String> {
        if format.is_native() {
            let TransferKey::Passphrase(passphrase) = key else {
                return Err("Native archives require a passphrase".into());
            };
            let archive =
                decrypt_vault_archive(bytes, passphrase).map_err(|error| error.to_string())?;
            return PreparedImport::archive(archive, unix_time()?)
                .map_err(|error| error.to_string());
        }
        let decrypted;
        let bytes = if format == TransferFormat::CxfAge {
            decrypted = key.decrypt_cxf(bytes)?;
            &decrypted
        } else {
            bytes
        };
        PreparedImport::manager(format, bytes).map_err(|error| error.to_string())
    }

    pub(crate) fn export_password_manager(
        &self,
        metadata: &VaultMetadata,
        format: TransferFormat,
        key: TransferKey<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let secrets = self.read_personal_secrets(metadata)?;
        let payload = export_manager(format, &secrets).map_err(|error| error.to_string())?;
        if format == TransferFormat::CxfAge {
            key.encrypt_cxf(&payload)
        } else {
            Ok(payload)
        }
    }

    #[cfg(feature = "apple-credential-exchange")]
    pub(crate) fn export_system_credentials(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let secrets = self.read_personal_secrets(metadata)?;
        factorseal::transfer::cxf::export_json(&secrets).map_err(|error| error.to_string())
    }

    pub(crate) fn commit_import(
        &self,
        metadata: &VaultMetadata,
        prepared: PreparedImport,
        replace_existing: bool,
    ) -> Result<(TransferSummary, VaultContents), String> {
        let summary = prepared
            .commit(&self.client(metadata), replace_existing)
            .map_err(|error| error.to_string())?;
        let contents = self.load_live_contents(metadata).map_err(|error| {
            format!(
                "Import completed for {} items, but refreshing the vault failed: {error}",
                summary.processed()
            )
        })?;
        Ok((summary, contents))
    }

    fn read_personal_secrets(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Vec<PersonalSecret>, String> {
        factorseal::read_vault_export(&self.client(metadata), is_personal_entry)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|entry| {
                let title = entry
                    .metadata
                    .address
                    .as_local()
                    .ok_or("invalid personal-secret address")?
                    .0;
                let value = entry.value;
                PersonalSecret::decode(title, value.expose()).map_err(|error| error.to_string())
            })
            .collect()
    }

    fn load_live_contents(&self, metadata: &VaultMetadata) -> Result<VaultContents, String> {
        load_vault_contents_from_client(&self.client(metadata))
    }

    pub(crate) fn load_permissions(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Vec<factorseal::Permission>, String> {
        load_permissions(|action| {
            let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
            self.request_live(metadata, &request)
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn watch_permissions(
        &self,
        metadata: &VaultMetadata,
        after_revision: Option<u64>,
    ) -> Result<(u64, Vec<factorseal::Permission>), String> {
        read_permissions(
            |action| {
                let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
                self.request_live(metadata, &request)
            },
            after_revision,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn deny_permission(
        &self,
        metadata: &VaultMetadata,
        id: String,
    ) -> Result<(), String> {
        self.request_live(
            metadata,
            &VaultRequest::new(factorseal::VaultAction::DenyPermission { id })
                .map_err(|error| error.to_string())?,
        )
        .map(|_| ())
    }

    pub(crate) fn revoke_permission(
        &self,
        metadata: &VaultMetadata,
        id: String,
    ) -> Result<(), String> {
        self.request_live(
            metadata,
            &VaultRequest::new(factorseal::VaultAction::RevokePermission { id })
                .map_err(|error| error.to_string())?,
        )
        .map(|_| ())
    }

    fn request_live(
        &self,
        metadata: &VaultMetadata,
        request: &VaultRequest,
    ) -> Result<VaultResponseBody, String> {
        self.client(metadata)
            .request(request)
            .map_err(|error| error.to_string())?
            .result
            .map_err(|error| error.message)
    }
}

fn is_personal_entry(entry: &VaultEntryMetadata) -> bool {
    entry.document_kind == DocumentKind::LocalKeyring
        && entry.partition == PERSONAL_SECRET_NAMESPACE
}

fn load_vault_contents_from_client(client: &impl VaultClient) -> Result<VaultContents, String> {
    load_vault_contents(|action| request_contents(client, action))
}

fn request_contents(
    client: &impl VaultClient,
    action: VaultAction,
) -> Result<VaultResponseBody, String> {
    let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
    client
        .request(&request)
        .map_err(|error| error.to_string())?
        .result
        .map_err(|error| error.message)
}

fn load_vault_contents(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<VaultContents, String> {
    let mut contents = load_vault_entries(&mut request)?;
    contents.complete_permissions(Ok(load_permissions(request)?));
    Ok(contents)
}

fn load_vault_entries(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<VaultContents, String> {
    let mut entries = Vec::new();
    let mut cursor = None;
    loop {
        let response = crate::timing::result("desktop_inventory", "list_entries_page", || {
            request(VaultAction::ListVaultEntries {
                cursor: cursor.clone(),
                limit: MAX_LIST_PAGE_SIZE,
            })
        })?;
        let VaultResponseBody::VaultEntries {
            entries: page,
            next_cursor,
        } = response
        else {
            return Err("vault returned an unexpected inventory response".to_owned());
        };
        entries.extend(page);
        if next_cursor.is_none() {
            break;
        }
        if next_cursor == cursor {
            return Err("vault returned a repeated inventory cursor".to_owned());
        }
        cursor = next_cursor;
    }

    Ok(VaultContents {
        entries,
        permissions_loading: true,
        secret_service_error: {
            let started = web_time::Instant::now();
            let error = secret_service_error();
            crate::timing::record("desktop_inventory", "probe_secret_service", started, "ok");
            error
        },
        ..VaultContents::default()
    })
}

fn load_permissions(
    request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<Vec<factorseal::Permission>, String> {
    read_permissions(request, None).map(|(_, permissions)| permissions)
}

fn read_permissions(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
    after_revision: Option<u64>,
) -> Result<(u64, Vec<factorseal::Permission>), String> {
    factorseal::read_permission_pages(
        |action| request(action).map_err(factorseal::VaultError::Protocol),
        after_revision,
    )
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn secret_service_error() -> Option<String> {
    zbus::block_on(secret_service_error_async())
}

#[cfg(target_os = "linux")]
async fn secret_service_error_async() -> Option<String> {
    use zbus::{Proxy, connection::Builder};

    const BUS_NAME: &str = "org.freedesktop.secrets";
    const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";

    let connection = match Builder::session()
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
    {
        Ok(connection) => connection,
        Err(error) => {
            return Some(format!(
                "System keyring integration cannot connect to the session D-Bus: {error}. FactorSeal's vault is still available."
            ));
        }
    };
    let owner = Proxy::new(
        &connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )
    .await;
    let owner = match owner {
        Ok(bus) => bus.call::<_, _, bool>("NameHasOwner", &(BUS_NAME,)).await,
        Err(error) => Err(error),
    };
    match owner {
        Ok(false) => return None,
        Ok(true) => {}
        Err(error) => {
            return Some(format!(
                "System keyring integration could not inspect the session D-Bus: {error}. FactorSeal's vault is still available."
            ));
        }
    }

    let collections: Result<Vec<zbus::OwnedObjectPath>, zbus::Error> =
        match Proxy::new(&connection, BUS_NAME, SERVICE_PATH, SERVICE_INTERFACE).await {
            Ok(service) => service.get_property("Collections").await,
            Err(error) => Err(error),
        };
    match collections {
        Ok(collections) if factorseal_secret_service(&collections) => None,
        Ok(_) => Some(
            "System keyring integration is unavailable because another application owns org.freedesktop.secrets. FactorSeal's vault is still available. Disable the other Secret Service provider and restart FactorSeal."
                .to_owned(),
        ),
        Err(error) => Some(format!(
            "System keyring integration could not inspect the active Secret Service provider: {error}. FactorSeal's vault is still available."
        )),
    }
}

#[cfg(target_os = "linux")]
fn factorseal_secret_service(collections: &[zbus::OwnedObjectPath]) -> bool {
    collections
        .iter()
        .any(|path| path.as_str() == "/org/freedesktop/secrets/collection/factorseal")
}

#[cfg(not(target_os = "linux"))]
const fn secret_service_error() -> Option<String> {
    None
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

pub(crate) fn lease_policy(idle_seconds: u64, maximum_seconds: u64) -> Result<LeasePolicy, String> {
    if idle_seconds == 0 || maximum_seconds == 0 || idle_seconds > maximum_seconds {
        return Err(
            "idle and maximum lease durations must be positive, and idle must not exceed maximum"
                .to_owned(),
        );
    }
    Ok(LeasePolicy {
        idle_timeout: Duration::from_secs(idle_seconds),
        maximum_lifetime: Duration::from_secs(maximum_seconds),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use factorseal::{
        DocumentKind, SecretAddress, SecretSpecAddress, VaultEntryMetadata, VaultResponseBody,
    };

    #[cfg(target_os = "linux")]
    use super::factorseal_secret_service;
    use super::load_vault_contents;

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_factorseal_as_the_secret_service_provider() {
        let factorseal =
            zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/factorseal")
                .unwrap();
        let other =
            zbus::OwnedObjectPath::try_from("/org/freedesktop/secrets/collection/login").unwrap();

        assert!(factorseal_secret_service(&[factorseal]));
        assert!(!factorseal_secret_service(&[other]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn keyring_probe_and_activation_use_the_session_bus() {
        use super::secret_service_error;
        use std::time::Duration;

        struct Keyring(bool);
        #[zbus::interface(name = "org.freedesktop.Secret.Service")]
        impl Keyring {
            #[zbus(property)]
            fn collections(&self) -> Vec<zbus::OwnedObjectPath> {
                vec![
                    zbus::OwnedObjectPath::try_from(if self.0 {
                        "/org/freedesktop/secrets/collection/factorseal"
                    } else {
                        "/org/freedesktop/secrets/collection/login"
                    })
                    .unwrap(),
                ]
            }
        }
        if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
            return;
        }
        assert!(secret_service_error().is_none());
        assert!(crate::wait_for_secret_service(Duration::ZERO).is_err());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        for factorseal in [true, false] {
            let service = runtime
                .block_on(
                    zbus::connection::Builder::session()
                        .name("org.freedesktop.secrets")
                        .serve_at("/org/freedesktop/secrets", Keyring(factorseal))
                        .build(),
                )
                .unwrap();
            assert!(crate::wait_for_secret_service(Duration::ZERO).is_ok());
            assert_eq!(secret_service_error().is_none(), factorseal);
            runtime
                .block_on(service.release_name("org.freedesktop.secrets"))
                .unwrap();
        }
    }

    #[test]
    fn vault_contents_follow_every_inventory_page() {
        let first = SecretSpecAddress::convention("alpha", "default", "TOKEN").unwrap();
        let second = SecretSpecAddress::convention("beta", "production", "DATABASE_URL").unwrap();
        let first = VaultEntryMetadata {
            access_project: None,
            display_name: None,
            display_type: None,
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"alpha".to_vec(),
            address: SecretAddress::secret_spec(first).unwrap(),
        };
        let second = VaultEntryMetadata {
            access_project: None,
            display_name: None,
            display_type: None,
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"beta".to_vec(),
            address: SecretAddress::secret_spec(second).unwrap(),
        };
        let mut responses = VecDeque::from([
            VaultResponseBody::VaultEntries {
                entries: vec![first.clone()],
                next_cursor: Some("first-page".to_owned()),
            },
            VaultResponseBody::VaultEntries {
                entries: vec![second.clone()],
                next_cursor: None,
            },
            VaultResponseBody::Permissions {
                revision: 0,
                permissions: Vec::new(),
                next_cursor: None,
            },
        ]);

        let contents = load_vault_contents(|_| {
            responses
                .pop_front()
                .ok_or_else(|| "unexpected request".to_owned())
        })
        .unwrap();

        assert!(responses.is_empty());
        assert_eq!(contents.entries, vec![first, second]);
        assert_eq!(contents.permissions, [] as [factorseal::Permission; 0]);
        assert!(!contents.permissions_loading);
    }

    #[test]
    fn initial_inventory_does_not_wait_for_permissions() {
        let entry = VaultEntryMetadata {
            access_project: None,
            display_name: None,
            display_type: None,
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"project".to_vec(),
            address: SecretAddress::secret_spec(
                SecretSpecAddress::convention("project", "default", "TOKEN").unwrap(),
            )
            .unwrap(),
        };
        let mut contents = super::load_vault_entries(|action| {
            assert!(matches!(
                action,
                factorseal::VaultAction::ListVaultEntries { .. }
            ));
            Ok(VaultResponseBody::VaultEntries {
                entries: vec![entry.clone()],
                next_cursor: None,
            })
        })
        .unwrap();
        assert_eq!(contents.entries, vec![entry.clone()]);
        assert!(contents.permissions_loading);
        assert_eq!(contents.permissions, [] as [factorseal::Permission; 0]);

        // An unsuccessful follow-up must leave the visible inventory intact.
        contents.complete_permissions(Err("permission request failed".to_owned()));
        assert_eq!(contents.entries, vec![entry]);
        assert!(!contents.permissions_loading);
        assert_eq!(
            contents.permissions_error.as_deref(),
            Some("permission request failed")
        );
    }

    #[test]
    fn deferred_permissions_do_not_replace_already_refreshed_contents() {
        let mut contents = super::VaultContents {
            permissions_loading: true,
            ..super::VaultContents::default()
        };
        contents.complete_permissions(Ok(Vec::new()));
        assert!(!contents.permissions_loading);
        contents.complete_permissions(Err("stale response".to_owned()));
        assert!(contents.permissions_error.is_none());
    }

    #[test]
    fn permission_watch_lists_once_then_waits_for_the_last_revision() {
        for after_revision in [None, Some(42)] {
            let mut calls = 0;
            let (revision, permissions) = super::read_permissions(
                |action| {
                    calls += 1;
                    match after_revision {
                        None => assert!(matches!(action, factorseal::VaultAction::ListPermissions)),
                        Some(expected) => assert!(matches!(
                            action,
                            factorseal::VaultAction::WaitPermissions {
                                after_revision,
                                timeout_ms: factorseal::MAX_PERMISSION_WAIT_MS,
                            } if after_revision == expected
                        )),
                    }
                    Ok(VaultResponseBody::Permissions {
                        revision: 42,
                        permissions: Vec::new(),
                        next_cursor: None,
                    })
                },
                after_revision,
            )
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(revision, 42);
            assert_eq!(permissions.len(), 0);
        }
    }
}
