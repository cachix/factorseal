use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, Change, ChangeHash, ObjId, ObjType, ROOT, ReadDoc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{DocumentKind, SecretAddress, VaultError, VaultResult};

const ENTRIES_KEY: &str = "entries";
const FORMAT_KEY: &str = "format";
const FORMAT_VERSION_KEY: &str = "format-version";
const PARTITION_KEY: &str = "partition";
const FORMAT_VERSION: u64 = 1;
const RECORD_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRecord {
    version: u8,
    address: SecretAddress,
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
    partition: Vec<u8>,
    persisted_heads: Vec<ChangeHash>,
}

impl SecretDocument {
    pub(crate) fn new(actor_id: &[u8], kind: DocumentKind, partition: &[u8]) -> VaultResult<Self> {
        let mut document = AutoCommit::new().with_actor(ActorId::from(actor_id));
        document
            .put(ROOT, FORMAT_KEY, kind.as_str())
            .map_err(automerge_error)?;
        document
            .put(ROOT, FORMAT_VERSION_KEY, FORMAT_VERSION)
            .map_err(automerge_error)?;
        document
            .put(ROOT, PARTITION_KEY, partition.to_vec())
            .map_err(automerge_error)?;
        let entries = document
            .put_object(ROOT, ENTRIES_KEY, ObjType::Map)
            .map_err(automerge_error)?;
        Ok(Self {
            document,
            entries,
            partition: partition.to_vec(),
            persisted_heads: Vec::new(),
        })
    }

    pub(crate) fn load(
        snapshot: &[u8],
        actor_id: &[u8],
        kind: DocumentKind,
        expected_partition: Option<&[u8]>,
    ) -> VaultResult<Self> {
        let mut document = AutoCommit::load(snapshot).map_err(automerge_error)?;
        document.set_actor(ActorId::from(actor_id));
        let format = document
            .get(ROOT, FORMAT_KEY)
            .map_err(automerge_error)?
            .and_then(|(value, _)| value.to_str().map(str::to_owned));
        let version = document
            .get(ROOT, FORMAT_VERSION_KEY)
            .map_err(automerge_error)?
            .and_then(|(value, _)| value.to_u64());
        let partition = document
            .get(ROOT, PARTITION_KEY)
            .map_err(automerge_error)?
            .and_then(|(value, _)| value.into_bytes().ok());
        let Some(partition) = partition else {
            return Err(VaultError::InvalidData(
                "Automerge document metadata does not match its protected descriptor".to_owned(),
            ));
        };
        if format.as_deref() != Some(kind.as_str())
            || version != Some(FORMAT_VERSION)
            || expected_partition.is_some_and(|expected| partition != expected)
        {
            return Err(VaultError::InvalidData(
                "Automerge document metadata does not match its protected descriptor".to_owned(),
            ));
        }
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
            partition,
            persisted_heads,
        })
    }

    pub(crate) fn partition(&self) -> &[u8] {
        &self.partition
    }

    /// Enumerate authenticated address metadata without returning values.
    /// Concurrent secret values for one address collapse to one list entry;
    /// conflicting addresses under the same digest fail closed.
    pub(crate) fn addresses(&self) -> VaultResult<Vec<(String, SecretAddress)>> {
        let mut keys: Vec<String> = self.document.keys(&self.entries).collect();
        keys.sort_unstable();
        let mut addresses = Vec::with_capacity(keys.len());
        for key in keys {
            let values = self
                .document
                .get_all(&self.entries, &key)
                .map_err(automerge_error)?;
            let mut address = None;
            for (value, _) in values {
                let bytes = value.into_bytes().map_err(|_| {
                    VaultError::InvalidData("secret document record is not bytes".to_owned())
                })?;
                let record: SecretRecord = serde_json::from_slice(&bytes)
                    .map_err(|error| VaultError::InvalidData(error.to_string()))?;
                validate_record_key(&record, &key)?;
                if address
                    .as_ref()
                    .is_some_and(|visible| visible != &record.address)
                {
                    return Err(VaultError::Conflict);
                }
                address = Some(record.address);
            }
            let address = address.ok_or_else(|| {
                VaultError::InvalidData("secret document entry has no visible record".to_owned())
            })?;
            addresses.push((key, address));
        }
        Ok(addresses)
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
            address: address.clone(),
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
                validate_record_key(&record, &key)?;
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
    if record.version != RECORD_VERSION || record.address != *address {
        return Err(VaultError::InvalidData(
            "secret document record does not match its authenticated address".to_owned(),
        ));
    }
    Ok(())
}

fn validate_record_key(record: &SecretRecord, storage_key: &str) -> VaultResult<()> {
    if record.version != RECORD_VERSION || record.address.storage_key() != storage_key {
        return Err(VaultError::InvalidData(
            "secret document record does not match its authenticated index".to_owned(),
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
    use crate::vault::{SecretSpecAddress, SecretSpecCoordinates};

    fn new_document() -> SecretDocument {
        SecretDocument::new(b"device-a", DocumentKind::LocalKeyring, b"test").unwrap()
    }

    #[test]
    fn project_document_preserves_the_complete_secretspec_address() {
        let address = SecretAddress::secret_spec(
            SecretSpecAddress::native(SecretSpecCoordinates {
                item: "database".to_owned(),
                field: Some("password".to_owned()),
                vault: Some("Production".to_owned()),
                section: Some("credentials".to_owned()),
                version: Some("3".to_owned()),
            })
            .unwrap(),
        )
        .unwrap();
        let mut document = SecretDocument::new(
            b"device-a",
            DocumentKind::SecretSpecProject,
            b"payments-api",
        )
        .unwrap();
        document.put(&address, b"secret", None).unwrap();
        let snapshot = document.save();
        let loaded = SecretDocument::load(
            &snapshot,
            b"device-a",
            DocumentKind::SecretSpecProject,
            Some(b"payments-api"),
        )
        .unwrap();
        assert!(matches!(
            loaded.get(&address, 1).unwrap(),
            SecretRead::Value(value) if value == b"secret"
        ));
        assert!(
            SecretDocument::load(
                &snapshot,
                b"device-a",
                DocumentKind::SecretSpecProject,
                Some(b"another-project"),
            )
            .is_err()
        );
    }

    #[test]
    fn address_listing_collapses_concurrent_values_without_exposing_them() {
        let address = SecretAddress::secret_spec(
            SecretSpecAddress::convention("demo", "default", "API_TOKEN").unwrap(),
        )
        .unwrap();
        let base = SecretDocument::new(b"base", DocumentKind::SecretSpecProject, b"demo")
            .unwrap()
            .save();
        let mut left = SecretDocument::load(
            &base,
            b"left",
            DocumentKind::SecretSpecProject,
            Some(b"demo"),
        )
        .unwrap();
        let mut right = SecretDocument::load(
            &base,
            b"right",
            DocumentKind::SecretSpecProject,
            Some(b"demo"),
        )
        .unwrap();
        left.put(&address, b"left-secret", None).unwrap();
        right.put(&address, b"right-secret", None).unwrap();
        left.document.merge(&mut right.document).unwrap();

        assert!(matches!(
            left.get(&address, 1).unwrap(),
            SecretRead::Conflict
        ));
        let listed = left.addresses().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, address);
    }

    fn address() -> SecretAddress {
        SecretAddress::new("project/default/API_TOKEN", Some("value".to_owned())).unwrap()
    }

    #[test]
    fn document_round_trips_secret_and_expiry() {
        let mut document = new_document();
        document.put(&address(), b"classified", Some(100)).unwrap();
        let snapshot = document.save();

        let loaded = SecretDocument::load(
            &snapshot,
            b"device-a",
            DocumentKind::LocalKeyring,
            Some(b"test"),
        )
        .unwrap();
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
        let mut document = new_document();
        assert!(document.delete(&address()).unwrap().is_none());
        document.put(&address(), b"value", None).unwrap();
        assert!(document.delete(&address()).unwrap().is_some());
        assert!(document.delete(&address()).unwrap().is_none());
    }

    #[test]
    fn purge_removes_entries_at_deadline() {
        let mut document = new_document();
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
        let mut document = new_document();
        document.put(&address(), b"value", None).unwrap();
        let second = SecretAddress::new("another", None).unwrap();
        document.put(&second, b"value", None).unwrap();

        assert_eq!(document.clear().unwrap().unwrap().0, 2);
        assert!(document.clear().unwrap().is_none());
    }
}
