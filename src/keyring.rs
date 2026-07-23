use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use keyring_core::api::{CredentialApi, CredentialPersistence, CredentialStoreApi};
use keyring_core::{Credential, Entry, Error, Result};

use crate::{Error as VaultError, UnlockedVault};

/// A `keyring-core` credential store backed by one unlocked FactorSeal vault.
pub struct FactorSealStore {
    vault: Arc<UnlockedVault>,
    id: String,
}

impl FactorSealStore {
    #[must_use]
    pub fn new(vault: UnlockedVault) -> Arc<Self> {
        let id = format!(
            "factorseal-keyring-{}-{}",
            env!("CARGO_PKG_VERSION"),
            vault.vault_id()
        );
        Arc::new(Self {
            vault: Arc::new(vault),
            id,
        })
    }

    #[must_use]
    pub fn from_shared_vault(vault: Arc<UnlockedVault>) -> Arc<Self> {
        let id = format!(
            "factorseal-keyring-{}-{}",
            env!("CARGO_PKG_VERSION"),
            vault.vault_id()
        );
        Arc::new(Self { vault, id })
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
        validate_specifier("service", service)?;
        validate_specifier("user", user)?;
        if modifiers.is_some_and(|values| !values.is_empty()) {
            return Err(Error::NotSupportedByStore(
                "FactorSeal does not use per-entry keyring modifiers".to_owned(),
            ));
        }

        let credential = Arc::new(FactorSealCredential {
            vault: Arc::clone(&self.vault),
            service: service.to_owned(),
            account: user.to_owned(),
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
}

impl std::fmt::Debug for FactorSealCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FactorSealCredential")
            .field("service", &self.service)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl CredentialApi for FactorSealCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.vault
            .set(&self.service, &self.account, secret)
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
        if !self
            .vault
            .contains(&self.service, &self.account)
            .map_err(map_vault_error)?
        {
            return Err(Error::NoEntry);
        }
        Ok(HashMap::from([
            ("service".to_owned(), self.service.clone()),
            ("user".to_owned(), self.account.clone()),
            ("store".to_owned(), "factorseal".to_owned()),
        ]))
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

fn validate_specifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::Invalid(
            name.to_owned(),
            "must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn map_vault_error(error: VaultError) -> Error {
    match error {
        VaultError::NoEntry => Error::NoEntry,
        VaultError::EmptyService => {
            Error::Invalid("service".to_owned(), "must not be empty".to_owned())
        }
        VaultError::EmptyAccount => {
            Error::Invalid("user".to_owned(), "must not be empty".to_owned())
        }
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
}
