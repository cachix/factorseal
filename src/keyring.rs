use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keyring_core::api::{CredentialApi, CredentialPersistence, CredentialStoreApi};
use keyring_core::{Credential, Entry, Error, Result};

use crate::vault::validate_specifiers;
use crate::{CredentialOptions, Error as VaultError, UnlockedVault};

/// Keyring attribute containing a credential's Unix eviction timestamp.
pub const EVICT_AT_ATTRIBUTE: &str = "evict_at";
/// Keyring creation modifier specifying retention from each successful write.
pub const RETENTION_SECONDS_MODIFIER: &str = "retention_seconds";

/// Runtime options for the FactorSeal keyring adapter.
#[derive(Clone, Debug, Default)]
pub struct FactorSealStoreOptions {
    /// Default retention applied to credentials created without modifiers.
    pub default_retention: Option<Duration>,
}

/// A `keyring-core` credential store backed by one unlocked FactorSeal vault.
pub struct FactorSealStore {
    vault: Arc<UnlockedVault>,
    id: String,
    options: FactorSealStoreOptions,
}

impl FactorSealStore {
    #[must_use]
    pub fn new(vault: UnlockedVault) -> Arc<Self> {
        Self::with_options(vault, FactorSealStoreOptions::default())
    }

    #[must_use]
    pub fn with_options(vault: UnlockedVault, options: FactorSealStoreOptions) -> Arc<Self> {
        Self::from_shared_vault_with_options(Arc::new(vault), options)
    }

    #[must_use]
    pub fn from_shared_vault(vault: Arc<UnlockedVault>) -> Arc<Self> {
        Self::from_shared_vault_with_options(vault, FactorSealStoreOptions::default())
    }

    #[must_use]
    pub fn from_shared_vault_with_options(
        vault: Arc<UnlockedVault>,
        options: FactorSealStoreOptions,
    ) -> Arc<Self> {
        let id = format!(
            "factorseal-keyring-{}-{}",
            env!("CARGO_PKG_VERSION"),
            vault.vault_id()
        );
        Arc::new(Self { vault, id, options })
    }

    #[must_use]
    pub fn vault(&self) -> &Arc<UnlockedVault> {
        &self.vault
    }
}

impl std::fmt::Debug for FactorSealStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FactorSealStore")
            .field("vault", &self.vault)
            .field("id", &self.id)
            .field("options", &self.options)
            .finish()
    }
}

impl CredentialStoreApi for FactorSealStore {
    fn vendor(&self) -> String {
        "FactorSeal, https://github.com/factorseal/factorseal".to_owned()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        validate_specifiers(service, user).map_err(map_vault_error)?;
        let eviction = parse_eviction_policy(modifiers, self.options.default_retention)?;

        let credential = Arc::new(FactorSealCredential {
            vault: Arc::clone(&self.vault),
            service: service.to_owned(),
            account: user.to_owned(),
            eviction,
        });
        Ok(Entry::new_with_credential(credential))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }
}

struct FactorSealCredential {
    vault: Arc<UnlockedVault>,
    service: String,
    account: String,
    eviction: EvictionPolicy,
}

impl std::fmt::Debug for FactorSealCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FactorSealCredential")
            .field("service", &self.service)
            .field("account", &self.account)
            .field("eviction", &self.eviction)
            .finish_non_exhaustive()
    }
}

impl CredentialApi for FactorSealCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        match self.eviction.resolve()? {
            EvictionUpdate::Preserve => self.vault.set(&self.service, &self.account, secret),
            EvictionUpdate::Set(evict_at) => self.vault.set_with_options(
                &self.service,
                &self.account,
                secret,
                CredentialOptions { evict_at },
            ),
        }
        .map_err(map_vault_error)
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        let plaintext = self
            .vault
            .get(&self.service, &self.account)
            .map_err(map_vault_error)?;
        Ok(plaintext.to_vec())
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        let metadata = self
            .vault
            .metadata(&self.service, &self.account)
            .map_err(map_vault_error)?;
        let mut attributes = HashMap::from([
            ("service".to_owned(), self.service.clone()),
            ("user".to_owned(), self.account.clone()),
            ("store".to_owned(), "factorseal".to_owned()),
        ]);
        if let Some(evict_at) = metadata.evict_at {
            attributes.insert(EVICT_AT_ATTRIBUTE.to_owned(), evict_at.to_string());
        }
        Ok(attributes)
    }

    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        let policy = parse_eviction_policy(Some(attributes), None)?;
        let EvictionUpdate::Set(evict_at) = policy.resolve()? else {
            return Ok(());
        };
        self.vault
            .update_eviction(&self.service, &self.account, evict_at)
            .map_err(map_vault_error)
    }

    fn delete_credential(&self) -> Result<()> {
        self.vault
            .delete(&self.service, &self.account)
            .map_err(map_vault_error)
    }

    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        if !self
            .vault
            .contains(&self.service, &self.account)
            .map_err(map_vault_error)?
        {
            return Err(Error::NoEntry);
        }
        Ok(None)
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.account.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Clone, Copy, Debug)]
enum EvictionPolicy {
    Preserve,
    At(Option<u64>),
    After(Duration),
}

enum EvictionUpdate {
    Preserve,
    Set(Option<u64>),
}

impl EvictionPolicy {
    fn resolve(self) -> Result<EvictionUpdate> {
        match self {
            Self::Preserve => Ok(EvictionUpdate::Preserve),
            Self::At(evict_at) => Ok(EvictionUpdate::Set(evict_at)),
            Self::After(retention) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| {
                        Error::Invalid(
                            RETENTION_SECONDS_MODIFIER.to_owned(),
                            "system clock is before the Unix epoch".to_owned(),
                        )
                    })?
                    .as_secs();
                let evict_at = now.checked_add(retention.as_secs()).ok_or_else(|| {
                    Error::Invalid(
                        RETENTION_SECONDS_MODIFIER.to_owned(),
                        "retention deadline is outside the supported range".to_owned(),
                    )
                })?;
                Ok(EvictionUpdate::Set(Some(evict_at)))
            }
        }
    }
}

fn parse_eviction_policy(
    modifiers: Option<&HashMap<&str, &str>>,
    default_retention: Option<Duration>,
) -> Result<EvictionPolicy> {
    let Some(modifiers) = modifiers.filter(|values| !values.is_empty()) else {
        return Ok(default_retention.map_or(EvictionPolicy::Preserve, EvictionPolicy::After));
    };
    if let Some(name) = modifiers
        .keys()
        .find(|name| **name != EVICT_AT_ATTRIBUTE && **name != RETENTION_SECONDS_MODIFIER)
    {
        return Err(Error::NotSupportedByStore(format!(
            "FactorSeal does not support the `{name}` entry modifier"
        )));
    }
    let evict_at = modifiers.get(EVICT_AT_ATTRIBUTE);
    let retention = modifiers.get(RETENTION_SECONDS_MODIFIER);
    if evict_at.is_some() && retention.is_some() {
        return Err(Error::Invalid(
            EVICT_AT_ATTRIBUTE.to_owned(),
            format!("cannot be combined with `{RETENTION_SECONDS_MODIFIER}`"),
        ));
    }
    if let Some(value) = evict_at {
        if value.eq_ignore_ascii_case("never") {
            return Ok(EvictionPolicy::At(None));
        }
        return value
            .parse()
            .map(|deadline| EvictionPolicy::At(Some(deadline)))
            .map_err(|_| {
                Error::Invalid(
                    EVICT_AT_ATTRIBUTE.to_owned(),
                    "must be a Unix timestamp or `never`".to_owned(),
                )
            });
    }
    if let Some(value) = retention {
        return value
            .parse()
            .map(Duration::from_secs)
            .map(EvictionPolicy::After)
            .map_err(|_| {
                Error::Invalid(
                    RETENTION_SECONDS_MODIFIER.to_owned(),
                    "must be a non-negative number of seconds".to_owned(),
                )
            });
    }
    Ok(EvictionPolicy::Preserve)
}

fn map_vault_error(error: VaultError) -> Error {
    match error {
        VaultError::NoEntry => Error::NoEntry,
        locked @ (VaultError::VaultLocked | VaultError::VaultStatePoisoned) => {
            Error::NoStorageAccess(Box::new(locked))
        }
        VaultError::EmptyService => {
            Error::Invalid("service".to_owned(), "must not be empty".to_owned())
        }
        VaultError::EmptyAccount => {
            Error::Invalid("user".to_owned(), "must not be empty".to_owned())
        }
        VaultError::CredentialNameTooLong { field, maximum } => Error::Invalid(
            if field == "account" { "user" } else { field }.to_owned(),
            format!("must not be longer than {maximum} bytes"),
        ),
        other => Error::PlatformFailure(Box::new(other)),
    }
}

#[cfg(all(test, feature = "hardware"))]
mod tests {
    use super::*;
    use crate::Vault;

    #[test]
    fn keyring_entry_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);
        let entry = store.build("example", "DATABASE_URL", None).unwrap();

        entry.set_secret(b"postgres://localhost").unwrap();
        assert_eq!(entry.get_secret().unwrap(), b"postgres://localhost");
        assert_eq!(
            entry.get_attributes().unwrap().get("store").unwrap(),
            "factorseal"
        );

        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
    }

    #[test]
    fn rejects_entry_modifiers() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);
        let modifiers = HashMap::from([("policy", "weaker")]);

        assert!(matches!(
            store.build("service", "user", Some(&modifiers)),
            Err(Error::NotSupportedByStore(_))
        ));
    }

    #[test]
    fn retention_modifier_sets_an_eviction_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);
        let modifiers = HashMap::from([(RETENTION_SECONDS_MODIFIER, "60")]);
        let entry = store.build("service", "user", Some(&modifiers)).unwrap();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        entry.set_secret(b"secret").unwrap();

        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let deadline: u64 = entry
            .get_attributes()
            .unwrap()
            .get(EVICT_AT_ATTRIBUTE)
            .unwrap()
            .parse()
            .unwrap();
        assert!(deadline >= before + 60);
        assert!(deadline <= after + 60);
    }

    #[test]
    fn expired_keyring_credentials_behave_as_missing() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);
        let modifiers = HashMap::from([(EVICT_AT_ATTRIBUTE, "0")]);
        let entry = store.build("service", "user", Some(&modifiers)).unwrap();

        entry.set_secret(b"secret").unwrap();

        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
        assert!(matches!(entry.get_attributes(), Err(Error::NoEntry)));
    }

    #[test]
    fn eviction_deadline_can_be_updated_or_cleared() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);
        let entry = store.build("service", "user", None).unwrap();
        entry.set_secret(b"secret").unwrap();

        entry
            .update_attributes(&HashMap::from([(
                EVICT_AT_ATTRIBUTE,
                "18446744073709551615",
            )]))
            .unwrap();
        assert_eq!(
            entry
                .get_attributes()
                .unwrap()
                .get(EVICT_AT_ATTRIBUTE)
                .map(String::as_str),
            Some("18446744073709551615")
        );

        entry
            .update_attributes(&HashMap::from([(EVICT_AT_ATTRIBUTE, "never")]))
            .unwrap();
        assert!(
            !entry
                .get_attributes()
                .unwrap()
                .contains_key(EVICT_AT_ATTRIBUTE)
        );
    }

    #[test]
    fn store_default_retention_applies_to_generic_entries() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::with_options(
            vault,
            FactorSealStoreOptions {
                default_retention: Some(Duration::ZERO),
            },
        );
        let entry = store.build("service", "user", None).unwrap();

        entry.set_secret(b"secret").unwrap();

        assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
    }

    #[test]
    fn rejects_invalid_specifiers_when_building_an_entry() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let store = FactorSealStore::new(vault);

        assert!(matches!(
            store.build("", "user", None),
            Err(Error::Invalid(field, _)) if field == "service"
        ));
        assert!(matches!(
            store.build("service", "", None),
            Err(Error::Invalid(field, _)) if field == "user"
        ));
        assert!(matches!(
            store.build("service", &"x".repeat(1025), None),
            Err(Error::Invalid(field, _)) if field == "user"
        ));
    }
}
