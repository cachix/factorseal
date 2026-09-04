use automerge::transaction::Transactable;
use automerge::{ActorId, AutoCommit, ObjId, ObjType, ROOT, ReadDoc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::encoding::base64_bytes;
use super::history::{HistoryOperation, PendingHistory, Provenance, VersionId};
use super::{DeviceKeyId, DocumentKind, SecretAddress, VaultError, VaultResult};

const ENTRIES_KEY: &str = "entries";
const FORMAT_KEY: &str = "format";
const FORMAT_VERSION_KEY: &str = "format-version";
const PARTITION_KEY: &str = "partition";
// Version 3 holds only current records; history lives in its own log beside
// the document. Version 2 added per-record value versions.
const FORMAT_VERSION: u64 = 3;
const RECORD_VERSION: u8 = 2;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretRecord {
    version: u8,
    address: SecretAddress,
    #[serde(with = "base64_bytes")]
    value: Zeroizing<Vec<u8>>,
    evict_at: Option<u64>,
    version_id: VersionId,
    created_at: u64,
    updated_at: u64,
}

pub(crate) enum SecretRead {
    Missing,
    Value(Zeroizing<Vec<u8>>),
    Conflict,
    Expired,
}

/// Plaintext of one generation, zeroized once the worker has encrypted it,
/// with the changes that generation makes for the history log.
pub(crate) struct DocumentMutation {
    pub(crate) snapshot: Zeroizing<Vec<u8>>,
    pub(crate) partition: Vec<u8>,
    pub(crate) history: Vec<PendingHistory>,
    /// Earliest eviction deadline among the records this generation keeps,
    /// so the eviction sweep knows when the document next needs a look.
    pub(crate) next_eviction: Option<u64>,
}

/// The one record field the projection reads while copying records verbatim.
#[derive(Deserialize)]
struct RecordDeadline {
    evict_at: Option<u64>,
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

/// Who a mutation is for and when it happens, as recorded in history.
#[derive(Clone, Copy)]
pub(crate) struct MutationContext<'a> {
    pub(crate) now: u64,
    pub(crate) provenance: &'a Provenance,
    pub(crate) device_key_id: DeviceKeyId,
}

/// Domain wrapper around Automerge for secret records.
///
/// The persisted form is always a fresh-genesis projection of the current
/// records. Automerge's own operation history is deliberately not carried
/// across generations, so a deleted or overwritten value never survives in a
/// snapshot; what survives is the history entry that describes the change,
/// kept in the log beside the document.
pub(crate) struct SecretDocument {
    document: AutoCommit,
    entries: ObjId,
    kind: DocumentKind,
    partition: Vec<u8>,
    pending: Vec<PendingHistory>,
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
            kind,
            partition: partition.to_vec(),
            pending: Vec::new(),
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
            return Err(descriptor_mismatch());
        };
        if format.as_deref() != Some(kind.as_str())
            || version != Some(FORMAT_VERSION)
            || expected_partition.is_some_and(|expected| partition != expected)
        {
            return Err(descriptor_mismatch());
        }
        let entries = root_object(&document, ENTRIES_KEY, ObjType::Map)?;
        Ok(Self {
            document,
            entries,
            kind,
            partition,
            pending: Vec::new(),
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
            let mut address = None;
            for record in self.records(&key)? {
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
        self.get_with_deadline(address, now).map(|(read, _)| read)
    }

    pub(crate) fn get_with_deadline(
        &self,
        address: &SecretAddress,
        now: u64,
    ) -> VaultResult<(SecretRead, Option<u64>)> {
        let records = self.records(&address.storage_key())?;
        if records.is_empty() {
            return Ok((SecretRead::Missing, None));
        }
        for record in &records {
            validate_record(record, address)?;
        }
        if records
            .iter()
            .any(|record| record.evict_at.is_some_and(|deadline| deadline <= now))
        {
            return Ok((SecretRead::Expired, None));
        }
        let first = &records[0].value;
        if records
            .iter()
            .skip(1)
            .any(|record| record.value.as_slice() != first.as_slice())
        {
            return Ok((SecretRead::Conflict, None));
        }
        let deadline = records.iter().filter_map(|record| record.evict_at).min();
        Ok((SecretRead::Value(first.clone()), deadline))
    }

    pub(crate) fn put(
        &mut self,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
        context: &MutationContext<'_>,
    ) -> VaultResult<DocumentMutation> {
        self.mutate(|document| {
            document.put_uncommitted(address, value, evict_at, context)?;
            document.finish_mutation()
        })
    }

    /// Apply an ordered group of mutations as one Automerge change set and
    /// therefore one signed, encrypted document generation.
    pub(crate) fn apply(
        &mut self,
        operations: &[DocumentOperation],
        context: &MutationContext<'_>,
    ) -> VaultResult<Option<DocumentMutation>> {
        self.mutate(|document| {
            let mut changed = false;
            for operation in operations {
                match operation {
                    DocumentOperation::Put {
                        address,
                        value,
                        evict_at,
                    } => {
                        document.put_uncommitted(address, value, *evict_at, context)?;
                        changed = true;
                    }
                    DocumentOperation::Delete { address } => {
                        changed |=
                            document.delete_uncommitted(address, HistoryOperation::Delete)?;
                    }
                }
            }
            if !changed {
                return Ok(None);
            }
            document.finish_mutation().map(Some)
        })
    }

    /// Run one mutation and, if any step of it fails, discard everything it
    /// changed in memory: the open Automerge change set and the history it
    /// queued. A rejected write must not ride along with the next successful
    /// one, so after an error the document is exactly what was last loaded or
    /// projected.
    fn mutate<T>(&mut self, operation: impl FnOnce(&mut Self) -> VaultResult<T>) -> VaultResult<T> {
        // A document that was only just created still holds its genesis in
        // an open change set. Close it so a rollback can undo exactly this
        // mutation and nothing older. A loaded or projected document has no
        // open change set, so this is a no-op for it, and the persisted form
        // is always the projection, which is unaffected either way.
        self.document.commit();
        let result = operation(self);
        if result.is_err() {
            self.document.rollback();
            self.pending.clear();
        }
        result
    }

    fn put_uncommitted(
        &mut self,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
        context: &MutationContext<'_>,
    ) -> VaultResult<()> {
        let key = address.storage_key();
        let existing = self.records(&key)?.into_iter().next();
        let changed = existing
            .as_ref()
            .is_none_or(|record| record.value.as_slice() != value || record.evict_at != evict_at);
        let version_id = match (&existing, changed) {
            (Some(record), false) => record.version_id,
            _ => VersionId::random()?,
        };
        let record = SecretRecord {
            version: RECORD_VERSION,
            address: address.clone(),
            value: Zeroizing::new(value.to_vec()),
            evict_at,
            version_id,
            created_at: existing
                .as_ref()
                .map_or(context.now, |record| record.created_at),
            updated_at: context.now,
        };
        // The serialized record carries the base64 value, so the vault-owned
        // buffer is wiped on drop. Automerge keeps its own copy, which is the
        // storage a loaded document already exposes.
        let bytes = Zeroizing::new(
            serde_json::to_vec(&record)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?,
        );
        self.document
            .put(&self.entries, key, bytes.to_vec())
            .map_err(automerge_error)?;
        if changed || self.kind.history_retention().record_unchanged {
            self.pending.push(PendingHistory {
                operation: HistoryOperation::Put { changed },
                address: address.clone(),
                version_id: Some(version_id),
                previous_version_id: existing.map(|record| record.version_id),
                evict_at,
            });
        }
        Ok(())
    }

    pub(crate) fn delete(
        &mut self,
        address: &SecretAddress,
    ) -> VaultResult<Option<DocumentMutation>> {
        self.remove(address, HistoryOperation::Delete)
    }

    /// Remove a record whose eviction deadline has passed.
    pub(crate) fn expire(
        &mut self,
        address: &SecretAddress,
    ) -> VaultResult<Option<DocumentMutation>> {
        self.remove(address, HistoryOperation::Expire)
    }

    fn remove(
        &mut self,
        address: &SecretAddress,
        operation: HistoryOperation,
    ) -> VaultResult<Option<DocumentMutation>> {
        self.mutate(|document| {
            if !document.delete_uncommitted(address, operation)? {
                return Ok(None);
            }
            document.finish_mutation().map(Some)
        })
    }

    fn delete_uncommitted(
        &mut self,
        address: &SecretAddress,
        operation: HistoryOperation,
    ) -> VaultResult<bool> {
        let key = address.storage_key();
        let records = self.records(&key)?;
        let Some(existing) = records.into_iter().next() else {
            return Ok(false);
        };
        self.document
            .delete(&self.entries, key)
            .map_err(automerge_error)?;
        self.pending.push(PendingHistory {
            operation,
            address: address.clone(),
            version_id: None,
            previous_version_id: Some(existing.version_id),
            evict_at: existing.evict_at,
        });
        Ok(true)
    }

    /// Remove every record whose eviction deadline has passed at `now`.
    pub(crate) fn purge_expired(&mut self, now: u64) -> VaultResult<Option<DocumentMutation>> {
        self.mutate(|document| {
            let keys: Vec<String> = document.document.keys(&document.entries).collect();
            let mut expired = Vec::new();
            for key in keys {
                for record in document.records(&key)? {
                    validate_record_key(&record, &key)?;
                    if record.evict_at.is_some_and(|deadline| deadline <= now) {
                        expired.push(record.address);
                        break;
                    }
                }
            }
            if expired.is_empty() {
                return Ok(None);
            }
            for address in expired {
                document.delete_uncommitted(&address, HistoryOperation::Expire)?;
            }
            document.finish_mutation().map(Some)
        })
    }

    pub(crate) fn clear(&mut self) -> VaultResult<Option<(usize, DocumentMutation)>> {
        self.mutate(|document| {
            let keys: Vec<String> = document.document.keys(&document.entries).collect();
            if keys.is_empty() {
                return Ok(None);
            }
            let count = keys.len();
            for key in keys {
                let Some(record) = document.records(&key)?.into_iter().next() else {
                    continue;
                };
                document.delete_uncommitted(&record.address, HistoryOperation::Clear)?;
            }
            Ok(Some((count, document.finish_mutation()?)))
        })
    }

    #[cfg(test)]
    pub(crate) fn save(&mut self) -> Vec<u8> {
        self.document.save()
    }

    /// Every visible record for one storage key.
    fn records(&self, key: &str) -> VaultResult<Vec<SecretRecord>> {
        let values = self
            .document
            .get_all(&self.entries, key)
            .map_err(automerge_error)?;
        let mut records = Vec::with_capacity(values.len());
        for (value, _) in values {
            let bytes = record_bytes(value)?;
            let record: SecretRecord = serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            records.push(record);
        }
        Ok(records)
    }

    /// Replace the working document with a fresh-genesis projection of its
    /// current records, serialize that projection, and hand over the queued
    /// history for the log.
    fn finish_mutation(&mut self) -> VaultResult<DocumentMutation> {
        let (projection, next_eviction) = self.project()?;
        let history = std::mem::take(&mut self.pending);
        *self = projection;
        let snapshot = Zeroizing::new(self.document.save());
        Ok(DocumentMutation {
            snapshot,
            partition: self.partition.clone(),
            history,
            next_eviction,
        })
    }

    /// Build a new document containing exactly the visible records, and
    /// report the earliest eviction deadline among them.
    ///
    /// A fresh genesis cannot express concurrent values, so an unresolved
    /// conflict fails closed here: it must be resolved by writing or deleting
    /// the conflicting address before any other change can be persisted.
    fn project(&self) -> VaultResult<(Self, Option<u64>)> {
        let actor_id = self.document.get_actor().to_bytes().to_vec();
        let mut projection = Self::new(&actor_id, self.kind, &self.partition)?;
        let mut next_eviction: Option<u64> = None;
        let mut keys: Vec<String> = self.document.keys(&self.entries).collect();
        keys.sort_unstable();
        for key in keys {
            let values = self
                .document
                .get_all(&self.entries, &key)
                .map_err(automerge_error)?;
            let mut visible: Option<Zeroizing<Vec<u8>>> = None;
            for (value, _) in values {
                let bytes = record_bytes(value)?;
                if visible
                    .as_ref()
                    .is_some_and(|current| current.as_slice() != bytes.as_slice())
                {
                    return Err(VaultError::Conflict);
                }
                visible = Some(bytes);
            }
            let bytes = visible.ok_or_else(|| {
                VaultError::InvalidData("secret document entry has no visible record".to_owned())
            })?;
            let deadline: RecordDeadline = serde_json::from_slice(&bytes)
                .map_err(|error| VaultError::InvalidData(error.to_string()))?;
            if let Some(deadline) = deadline.evict_at {
                next_eviction =
                    Some(next_eviction.map_or(deadline, |current| current.min(deadline)));
            }
            projection
                .document
                .put(&projection.entries, key, bytes.to_vec())
                .map_err(automerge_error)?;
        }
        Ok((projection, next_eviction))
    }
}

fn root_object(document: &AutoCommit, key: &str, expected: ObjType) -> VaultResult<ObjId> {
    let Some((value, object)) = document.get(ROOT, key).map_err(automerge_error)? else {
        return Err(VaultError::InvalidData(format!(
            "secret document has no `{key}` object"
        )));
    };
    if value != automerge::Value::Object(expected) {
        return Err(VaultError::InvalidData(format!(
            "secret document `{key}` value has the wrong type"
        )));
    }
    Ok(object)
}

/// Take a record's bytes out of an Automerge value into a buffer that is
/// wiped on drop; the record carries the base64 secret value.
fn record_bytes(value: automerge::Value<'_>) -> VaultResult<Zeroizing<Vec<u8>>> {
    value
        .into_bytes()
        .map(Zeroizing::new)
        .map_err(|_| VaultError::InvalidData("secret document record is not bytes".to_owned()))
}

fn descriptor_mismatch() -> VaultError {
    VaultError::InvalidData(
        "Automerge document metadata does not match its protected descriptor".to_owned(),
    )
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
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;
    use crate::vault::history::{HistoryLog, ServiceReason};
    use crate::vault::{
        CallerIdentity, CallerPlatform, PermissionPrincipal, SecretSpecAddress,
        SecretSpecCoordinates,
    };

    const DEVICE: DeviceKeyId = DeviceKeyId::from_bytes([9; 32]);

    fn caller() -> CallerIdentity {
        CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "/usr/bin/app",
            [1; 32],
            None,
        )
        .unwrap()
    }

    fn provenance() -> Provenance {
        Provenance::caller(&caller(), None)
    }

    fn context(provenance: &Provenance, now: u64) -> MutationContext<'_> {
        MutationContext {
            now,
            provenance,
            device_key_id: DEVICE,
        }
    }

    fn new_document() -> SecretDocument {
        SecretDocument::new(b"device-a", DocumentKind::LocalKeyring, b"test").unwrap()
    }

    fn new_log() -> HistoryLog {
        HistoryLog::new(DocumentKind::LocalKeyring, b"test")
    }

    fn address() -> SecretAddress {
        SecretAddress::new("project/default/API_TOKEN", Some("value".to_owned())).unwrap()
    }

    /// Record one generation's changes the way the store worker does.
    fn record(log: &mut HistoryLog, mutation: DocumentMutation, context: &MutationContext<'_>) {
        log.record(
            mutation.history,
            context.now,
            context.provenance,
            context.device_key_id,
        )
        .unwrap();
    }

    /// Serialized history must never carry a value in any encoding a record
    /// could use.
    fn history_mentions(log: &HistoryLog, needle: &[u8]) -> bool {
        let bytes = log.serialize().unwrap();
        let encoded = STANDARD.encode(needle);
        bytes.windows(needle.len()).any(|window| window == needle)
            || bytes
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes())
    }

    #[test]
    fn project_document_preserves_the_complete_secretspec_address() {
        let provenance = provenance();
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
        document
            .put(&address, b"secret", None, &context(&provenance, 1))
            .unwrap();
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
            SecretRead::Value(value) if *value == b"secret"
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
        let provenance = provenance();
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
        // Replicas diverge within one generation. Persisting projects to a
        // fresh genesis, so the merge has to happen before either side does.
        left.put_uncommitted(&address, b"left-secret", None, &context(&provenance, 1))
            .unwrap();
        right
            .put_uncommitted(&address, b"right-secret", None, &context(&provenance, 1))
            .unwrap();
        left.document.merge(&mut right.document).unwrap();

        assert!(matches!(
            left.get(&address, 1).unwrap(),
            SecretRead::Conflict
        ));
        let listed = left.addresses().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, address);
    }

    #[test]
    fn document_round_trips_secret_and_expiry() {
        let provenance = provenance();
        let mut document = new_document();
        document
            .put(
                &address(),
                b"classified",
                Some(100),
                &context(&provenance, 1),
            )
            .unwrap();
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
            SecretRead::Value(value) if *value == b"classified"
        ));
        assert!(matches!(
            loaded.get(&address(), 100).unwrap(),
            SecretRead::Expired
        ));
    }

    /// Automerge keeps every operation in a saved document, so the projection
    /// is the only thing standing between a deleted secret and the ciphertext
    /// at rest. Values are base64 inside a record, so both the raw bytes and
    /// that encoding are checked, against an uncompressed re-save so that
    /// Automerge's column compression cannot hide a value from the search.
    #[test]
    fn superseded_values_do_not_survive_a_persisted_snapshot() {
        fn contains(snapshot: &[u8], needle: &[u8]) -> bool {
            let raw = AutoCommit::load(snapshot).unwrap().save_nocompress();
            let encoded = STANDARD.encode(needle);
            raw.windows(needle.len()).any(|window| window == needle)
                || raw
                    .windows(encoded.len())
                    .any(|window| window == encoded.as_bytes())
        }

        let provenance = provenance();
        let mut document = new_document();
        let first = document
            .put(
                &address(),
                b"first-secret-value",
                None,
                &context(&provenance, 1),
            )
            .unwrap();
        assert!(contains(&first.snapshot, b"first-secret-value"));

        let second = document
            .put(
                &address(),
                b"second-secret-value",
                None,
                &context(&provenance, 2),
            )
            .unwrap();
        assert!(!contains(&second.snapshot, b"first-secret-value"));
        assert!(contains(&second.snapshot, b"second-secret-value"));

        let deleted = document.delete(&address()).unwrap().unwrap();
        assert!(!contains(&deleted.snapshot, b"first-secret-value"));
        assert!(!contains(&deleted.snapshot, b"second-secret-value"));

        let mut reloaded = AutoCommit::load(&deleted.snapshot).unwrap();
        assert_eq!(reloaded.get_changes(&[]).len(), 1);
    }

    #[test]
    fn unresolved_conflicts_block_unrelated_writes_until_resolved() {
        let provenance = provenance();
        let conflicted = SecretAddress::secret_spec(
            SecretSpecAddress::convention("demo", "default", "API_TOKEN").unwrap(),
        )
        .unwrap();
        let other = SecretAddress::secret_spec(
            SecretSpecAddress::convention("demo", "default", "OTHER").unwrap(),
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
        left.put_uncommitted(&conflicted, b"left-secret", None, &context(&provenance, 1))
            .unwrap();
        right
            .put_uncommitted(&conflicted, b"right-secret", None, &context(&provenance, 1))
            .unwrap();
        left.document.merge(&mut right.document).unwrap();

        assert!(matches!(
            left.put(&other, b"unrelated", None, &context(&provenance, 2)),
            Err(VaultError::Conflict)
        ));
        // The rejected write is gone from memory, not merely unpersisted.
        assert!(matches!(left.get(&other, 2).unwrap(), SecretRead::Missing));
        let resolved = left
            .put(&conflicted, b"resolved", None, &context(&provenance, 3))
            .unwrap();
        assert!(matches!(
            left.get(&conflicted, 1).unwrap(),
            SecretRead::Value(value) if *value == b"resolved"
        ));
        assert!(matches!(left.get(&other, 3).unwrap(), SecretRead::Missing));
        assert!(
            resolved
                .history
                .iter()
                .all(|entry| entry.address == conflicted),
            "the rejected write left a history entry behind"
        );
        left.put(&other, b"unrelated", None, &context(&provenance, 4))
            .unwrap();
    }

    #[test]
    fn delete_is_idempotent() {
        let provenance = provenance();
        let mut document = new_document();
        assert!(document.delete(&address()).unwrap().is_none());
        document
            .put(&address(), b"value", None, &context(&provenance, 2))
            .unwrap();
        assert!(document.delete(&address()).unwrap().is_some());
        assert!(document.delete(&address()).unwrap().is_none());
    }

    #[test]
    fn purge_removes_entries_at_deadline() {
        let provenance = provenance();
        let expiry = Provenance::service(ServiceReason::Expiry);
        let mut document = new_document();
        let mut log = new_log();
        let put = document
            .put(&address(), b"value", Some(5), &context(&provenance, 1))
            .unwrap();
        record(&mut log, put, &context(&provenance, 1));

        assert!(document.purge_expired(4).unwrap().is_none());
        let purged = document.purge_expired(5).unwrap().unwrap();
        record(&mut log, purged, &context(&expiry, 5));
        assert!(matches!(
            document.get(&address(), 5).unwrap(),
            SecretRead::Missing
        ));
        let history = log.entries();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].operation, HistoryOperation::Expire);
        assert_eq!(history[1].evict_at, Some(5));
        assert_eq!(history[1].provenance, expiry);
    }

    #[test]
    fn clear_reports_and_removes_every_entry_but_keeps_history() {
        let provenance = provenance();
        let mut document = new_document();
        let mut log = new_log();
        let first = document
            .put(&address(), b"value", None, &context(&provenance, 1))
            .unwrap();
        record(&mut log, first, &context(&provenance, 1));
        let second = SecretAddress::new("another", None).unwrap();
        let put = document
            .put(&second, b"value", None, &context(&provenance, 2))
            .unwrap();
        record(&mut log, put, &context(&provenance, 2));

        let (count, cleared) = document.clear().unwrap().unwrap();
        assert_eq!(count, 2);
        record(&mut log, cleared, &context(&provenance, 3));
        assert!(document.clear().unwrap().is_none());
        assert!(document.addresses().unwrap().is_empty());

        let history = log.entries();
        assert_eq!(history.len(), 4);
        assert!(
            history[2..]
                .iter()
                .all(|entry| entry.operation == HistoryOperation::Clear && entry.at == 3)
        );
        let cleared: Vec<_> = history[2..].iter().map(|entry| &entry.address).collect();
        assert!(cleared.contains(&&address()));
        assert!(cleared.contains(&&second));
    }

    #[test]
    fn history_records_operations_versions_and_provenance_without_values() {
        let provenance = provenance();
        let expiry = Provenance::service(ServiceReason::Expiry);
        let mut document = new_document();
        let mut log = new_log();
        for (now, value, evict_at) in [
            (10, b"needle-one".as_slice(), None),
            (11, b"needle-one", None),
            (12, b"needle-two", Some(50)),
        ] {
            let put = document
                .put(&address(), value, evict_at, &context(&provenance, now))
                .unwrap();
            record(&mut log, put, &context(&provenance, now));
        }
        let expired = document.expire(&address()).unwrap().unwrap();
        record(&mut log, expired, &context(&expiry, 50));

        let bytes = log.serialize().unwrap();
        let loaded = HistoryLog::load(&bytes, DocumentKind::LocalKeyring, Some(b"test")).unwrap();
        let history = loaded.entries();
        assert_eq!(history.len(), 4);
        assert_eq!(
            history.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(
            history.iter().map(|entry| entry.at).collect::<Vec<_>>(),
            [10, 11, 12, 50]
        );

        assert_eq!(
            history[0].operation,
            HistoryOperation::Put { changed: true }
        );
        let first_version = history[0].version_id.unwrap();
        assert!(history[0].previous_version_id.is_none());

        assert_eq!(
            history[1].operation,
            HistoryOperation::Put { changed: false }
        );
        assert_eq!(history[1].version_id, Some(first_version));
        assert_eq!(history[1].previous_version_id, Some(first_version));

        assert_eq!(
            history[2].operation,
            HistoryOperation::Put { changed: true }
        );
        let second_version = history[2].version_id.unwrap();
        assert_ne!(second_version, first_version);
        assert_eq!(history[2].previous_version_id, Some(first_version));
        assert_eq!(history[2].evict_at, Some(50));

        assert_eq!(history[3].operation, HistoryOperation::Expire);
        assert!(history[3].version_id.is_none());
        assert_eq!(history[3].previous_version_id, Some(second_version));
        assert_eq!(history[3].provenance, expiry);

        assert!(history[..3].iter().all(|entry| {
            entry.address == address()
                && entry.device_key_id == DEVICE
                && entry.provenance
                    == Provenance::Caller {
                        principal: PermissionPrincipal::from(&caller()),
                        application: None,
                    }
        }));
        assert!(!history_mentions(&loaded, b"needle-one"));
        assert!(!history_mentions(&loaded, b"needle-two"));
        assert!(!history_mentions(&loaded, b"needle"));

        // The sequence continues after a reload rather than restarting.
        let mut loaded = loaded;
        let put = document
            .put(&address(), b"needle-three", None, &context(&provenance, 60))
            .unwrap();
        record(&mut loaded, put, &context(&provenance, 60));
        assert_eq!(loaded.entries().last().unwrap().seq, 4);
    }

    #[test]
    fn unchanged_cache_writes_are_not_recorded() {
        let provenance = provenance();
        let mut document =
            SecretDocument::new(b"device-a", DocumentKind::SecretSpecProviderCache, b"cache")
                .unwrap();
        let mut log = HistoryLog::new(DocumentKind::SecretSpecProviderCache, b"cache");
        for (now, evict_at) in [(1, Some(100)), (2, Some(100)), (3, Some(101))] {
            let put = document
                .put(&address(), b"token", evict_at, &context(&provenance, now))
                .unwrap();
            record(&mut log, put, &context(&provenance, now));
        }

        let history = log.entries();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].at, 1);
        assert_eq!(history[1].at, 3);
        assert_eq!(
            history[1].operation,
            HistoryOperation::Put { changed: true }
        );
    }
}
