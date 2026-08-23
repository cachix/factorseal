use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{SecretAddress, VaultError, VaultResult};

const ENTRIES_KEY: &str = "entries";
const RECORD_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRecord {
    version: u8,
    item: String,
    field: Option<String>,
    value: Vec<u8>,
    evict_at: Option<u64>,
}

pub(crate) enum SecretRead {
    Missing,
    Value(Vec<u8>),
    Conflict,
    Expired,
}

pub(crate) struct DocumentMutation {
    pub(crate) snapshot: Vec<u8>,
    pub(crate) changes: Vec<Change>,
    pub(crate) heads: Vec<ChangeHash>,
}

/// One ordered mutation applied to a secret document as part of one durable
/// generation. Values retain zeroizing ownership until the worker commits or
/// drops the enclosing command.
pub(crate) enum DocumentOperation {
    Put {
        address: SecretAddress,
        value: Zeroizing<Vec<u8>>,
        evict_at: Option<u64>,
    },
    Delete {
        address: SecretAddress,
    },
}

/// Domain wrapper around Automerge for secret records.
pub(crate) struct SecretDocument {
    document: AutoCommit,
    entries: ObjId,
    persisted_heads: Vec<ChangeHash>,
}

impl SecretDocument {
    pub(crate) fn new(actor_id: &[u8]) -> VaultResult<Self> {
        let mut document = AutoCommit::new().with_actor(ActorId::from(actor_id));
        let entries = document
            .put_object(ROOT, ENTRIES_KEY, ObjType::Map)
            .map_err(automerge_error)?;
        Ok(Self {
            document,
            entries,
            persisted_heads: Vec::new(),
        })
    }

    pub(crate) fn load(snapshot: &[u8], actor_id: &[u8]) -> VaultResult<Self> {
        let mut document = AutoCommit::load(snapshot).map_err(automerge_error)?;
        document.set_actor(ActorId::from(actor_id));
        let Some((value, entries)) = document.get(ROOT, ENTRIES_KEY).map_err(automerge_error)?
        else {
            return Err(VaultError::InvalidData(
                "secret document has no entries map".to_owned(),
            ));
        };
        if value != automerge::Value::Object(ObjType::Map) {
            return Err(VaultError::InvalidData(
                "secret document entries value is not a map".to_owned(),
            ));
        }
        let persisted_heads = document.get_heads();
        Ok(Self {
            document,
            entries,
            persisted_heads,
        })
    }

    pub(crate) fn get(&self, address: &SecretAddress, now: u64) -> VaultResult<SecretRead> {
        let values = self
            .document
            .get_all(&self.entries, address.storage_key())
            .map_err(automerge_error)?;
        if values.is_empty() {
            return Ok(SecretRead::Missing);
        }

        let mut records = Vec::with_capacity(values.len());
        for (value, _) in values {
            let bytes = value.into_bytes().map_err(|_| {
                VaultError::InvalidData("secret document record is not bytes".to_owned())
            })?;
            let record: SecretRecord = serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            validate_record(&record, address)?;
            records.push(record);
        }

        if records
            .iter()
            .any(|record| record.evict_at.is_some_and(|deadline| deadline <= now))
        {
            return Ok(SecretRead::Expired);
        }
        let first = &records[0].value;
        if records.iter().skip(1).any(|record| record.value != *first) {
            return Ok(SecretRead::Conflict);
        }
        Ok(SecretRead::Value(first.clone()))
    }

    pub(crate) fn put(
        &mut self,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<DocumentMutation> {
        self.put_uncommitted(address, value, evict_at)?;
        Ok(self.finish_mutation())
    }

    /// Apply an ordered group of mutations as one Automerge change set and
    /// therefore one signed, encrypted document generation. An error before
    /// this method returns leaves the altered in-memory document unpersisted.
    pub(crate) fn apply(
        &mut self,
        operations: &[DocumentOperation],
    ) -> VaultResult<Option<DocumentMutation>> {
        let mut changed = false;
        for operation in operations {
            match operation {
                DocumentOperation::Put {
                    address,
                    value,
                    evict_at,
                } => {
                    self.put_uncommitted(address, value, *evict_at)?;
                    changed = true;
                }
                DocumentOperation::Delete { address } => {
                    changed |= self.delete_uncommitted(address)?;
                }
            }
        }
        Ok(changed.then(|| self.finish_mutation()))
    }

    fn put_uncommitted(
        &mut self,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<()> {
        let record = SecretRecord {
            version: RECORD_VERSION,
            item: address.item().to_owned(),
            field: address.field().map(ToOwned::to_owned),
            value: value.to_vec(),
            evict_at,
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        self.document
            .put(&self.entries, address.storage_key(), bytes)
            .map_err(automerge_error)
    }

    pub(crate) fn delete(
        &mut self,
        address: &SecretAddress,
    ) -> VaultResult<Option<DocumentMutation>> {
        if !self.delete_uncommitted(address)? {
            return Ok(None);
        }
        Ok(Some(self.finish_mutation()))
    }

    fn delete_uncommitted(&mut self, address: &SecretAddress) -> VaultResult<bool> {
        let key = address.storage_key();
        if self
            .document
            .get_all(&self.entries, &key)
            .map_err(automerge_error)?
            .is_empty()
        {
            return Ok(false);
        }
        self.document
            .delete(&self.entries, key)
            .map_err(automerge_error)?;
        Ok(true)
    }

    pub(crate) fn purge_expired(&mut self, now: u64) -> VaultResult<Option<DocumentMutation>> {
        let keys: Vec<String> = self.document.keys(&self.entries).collect();
        let mut expired = Vec::new();
        for key in keys {
            let values = self
                .document
                .get_all(&self.entries, &key)
                .map_err(automerge_error)?;
            let mut should_delete = false;
            for (value, _) in values {
                let bytes = value.into_bytes().map_err(|_| {
                    VaultError::InvalidData("secret document record is not bytes".to_owned())
                })?;
                let record: SecretRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| VaultError::InvalidData(error.to_string()))?;
                if record.evict_at.is_some_and(|deadline| deadline <= now) {
                    should_delete = true;
                    break;
                }
            }
            if should_delete {
                expired.push(key);
            }
        }
        if expired.is_empty() {
            return Ok(None);
        }

        for key in expired {
            self.document
                .delete(&self.entries, key)
                .map_err(automerge_error)?;
        }
        Ok(Some(self.finish_mutation()))
    }

    pub(crate) fn clear(&mut self) -> VaultResult<Option<(usize, DocumentMutation)>> {
        let keys: Vec<String> = self.document.keys(&self.entries).collect();
        if keys.is_empty() {
            return Ok(None);
        }
        let count = keys.len();
        for key in keys {
            self.document
                .delete(&self.entries, key)
                .map_err(automerge_error)?;
        }
        Ok(Some((count, self.finish_mutation())))
    }

    #[cfg(test)]
    pub(crate) fn save(&mut self) -> Vec<u8> {
        self.document.save()
    }

    fn finish_mutation(&mut self) -> DocumentMutation {
        let changes = self.document.get_changes(&self.persisted_heads);
        let heads = self.document.get_heads();
        let snapshot = self.document.save();
        self.persisted_heads.clone_from(&heads);
        DocumentMutation {
            snapshot,
            changes,
            heads,
        }
    }
}

fn validate_record(record: &SecretRecord, address: &SecretAddress) -> VaultResult<()> {
    if record.version != RECORD_VERSION
        || record.item != address.item()
        || record.field.as_deref() != address.field()
    {
        return Err(VaultError::InvalidData(
            "secret document record does not match its authenticated address".to_owned(),
        ));
    }
    Ok(())
}

fn automerge_error(error: impl std::fmt::Display) -> VaultError {
    VaultError::Automerge(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SecretAddress {
        SecretAddress::new("project/default/API_TOKEN", Some("value".to_owned())).unwrap()
    }

    #[test]
    fn document_round_trips_secret_and_expiry() {
        let mut document = SecretDocument::new(b"device-a").unwrap();
        document.put(&address(), b"classified", Some(100)).unwrap();
        let snapshot = document.save();

        let loaded = SecretDocument::load(&snapshot, b"device-a").unwrap();
        assert!(matches!(
            loaded.get(&address(), 99).unwrap(),
            SecretRead::Value(value) if value == b"classified"
        ));
        assert!(matches!(
            loaded.get(&address(), 100).unwrap(),
            SecretRead::Expired
        ));
    }

    #[test]
    fn delete_is_idempotent() {
        let mut document = SecretDocument::new(b"device-a").unwrap();
        assert!(document.delete(&address()).unwrap().is_none());
        document.put(&address(), b"value", None).unwrap();
        assert!(document.delete(&address()).unwrap().is_some());
        assert!(document.delete(&address()).unwrap().is_none());
    }

    #[test]
    fn purge_removes_entries_at_deadline() {
        let mut document = SecretDocument::new(b"device-a").unwrap();
        document.put(&address(), b"value", Some(5)).unwrap();

        assert!(document.purge_expired(4).unwrap().is_none());
        assert!(document.purge_expired(5).unwrap().is_some());
        assert!(matches!(
            document.get(&address(), 5).unwrap(),
            SecretRead::Missing
        ));
    }

    #[test]
    fn clear_reports_and_removes_every_entry() {
        let mut document = SecretDocument::new(b"device-a").unwrap();
        document.put(&address(), b"value", None).unwrap();
        let second = SecretAddress::new("another", None).unwrap();
        document.put(&second, b"value", None).unwrap();

        assert_eq!(document.clear().unwrap().unwrap().0, 2);
        assert!(document.clear().unwrap().is_none());
    }
}
