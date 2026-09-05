//! Change history recorded beside every encrypted document.
//!
//! History describes what changed, when, and on whose behalf. It never
//! contains a secret value. Entries are explicit data kept in a bounded log
//! that is persisted next to the record document, under the same key and in
//! the same signed generation, so Automerge's own operation history is not
//! the history mechanism and a superseded value does not survive because
//! history does. A read that never lists history does not decrypt the log.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "vault-store", test))]
use super::VaultError;
use super::protocol::{CallerIdentity, PermissionPrincipal, VaultApplicationContext};
use super::{DeviceKeyId, DocumentKind, SecretAddress, VaultResult};

const HISTORY_ENTRY_VERSION: u8 = 1;
#[cfg(any(feature = "vault-store", test))]
const HISTORY_LOG_VERSION: u8 = 1;
const VERSION_ID_BYTES: usize = 16;
/// Longest declared application field retained in a history entry. Declared
/// context is display metadata, and bounding it keeps a page of history
/// inside the wire limit.
const MAX_DECLARED_FIELD_BYTES: usize = 512;

/// Random identifier of one stored value version.
///
/// A put that stores a new value or deadline assigns a fresh identifier; a
/// put that changes nothing keeps the current one.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionId([u8; VERSION_ID_BYTES]);

impl VersionId {
    pub fn random() -> VaultResult<Self> {
        let mut bytes = [0_u8; VERSION_ID_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; VERSION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VERSION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for VersionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VersionId")
            .field(&URL_SAFE_NO_PAD.encode(self.0))
            .finish()
    }
}

impl fmt::Display for VersionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// What one history entry records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HistoryOperation {
    /// A write. `changed` is false when the value and deadline already matched.
    Put { changed: bool },
    /// An explicit delete of one address.
    Delete,
    /// Removal as part of clearing the whole document.
    Clear,
    /// Removal because the record's eviction deadline passed.
    Expire,
}

/// Why the vault itself, rather than an authenticated caller, wrote.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ServiceReason {
    /// A grant was stored by the installation's own authorization path.
    GrantStorage,
    /// A record's eviction deadline passed.
    Expiry,
}

/// Caller-declared application context as it was presented with a request,
/// truncated to a bounded summary. This is display and audit metadata only
/// and never grant authority.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredApplication {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&VaultApplicationContext> for DeclaredApplication {
    fn from(context: &VaultApplicationContext) -> Self {
        Self {
            project: context.project.as_deref().map(bounded),
            profile: context.profile.as_deref().map(bounded),
            base_dir: context.base_dir.as_deref().map(bounded),
            reason: context.reason.as_deref().map(bounded),
        }
    }
}

/// Who a mutation was performed for.
// A caller variant carries the full principal by value so history entries
// and wire pages can use it directly; provenance is cloned once per request.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Provenance {
    /// A transport-authenticated caller, with the context it declared.
    Caller {
        principal: PermissionPrincipal,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        application: Option<DeclaredApplication>,
    },
    /// The vault service acting on its own behalf.
    Service { reason: ServiceReason },
    /// A transport-authenticated caller other than the one reading the
    /// history. A persisted entry always names its caller; this is what a
    /// reader without the `manage-permissions` grant is shown instead of
    /// another application's identity and declared context.
    Redacted,
}

impl Provenance {
    #[must_use]
    pub fn caller(
        identity: &CallerIdentity,
        application: Option<&VaultApplicationContext>,
    ) -> Self {
        Self::Caller {
            principal: PermissionPrincipal::from(identity),
            application: application.map(DeclaredApplication::from),
        }
    }

    #[must_use]
    pub const fn service(reason: ServiceReason) -> Self {
        Self::Service { reason }
    }
}

/// One recorded change to one address. It carries no secret value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    /// Entry format version; always [`Self::CURRENT_VERSION`] when written.
    pub version: u8,
    /// Monotonic per document. Trimming old entries never reuses a number.
    pub seq: u64,
    /// Service clock, in whole seconds since the Unix epoch.
    pub at: u64,
    pub operation: HistoryOperation,
    pub address: SecretAddress,
    /// The value version a put created or kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<VersionId>,
    /// The value version this operation replaced or removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version_id: Option<VersionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict_at: Option<u64>,
    pub provenance: Provenance,
    /// Device that authored the change; the local device until replication.
    pub device_key_id: DeviceKeyId,
}

/// Fields of a history entry that a mutation supplies. The sequence number
/// is assigned when the document is projected.
#[cfg(any(feature = "vault-store", test))]
pub(crate) struct PendingHistory {
    pub(crate) operation: HistoryOperation,
    pub(crate) address: SecretAddress,
    pub(crate) version_id: Option<VersionId>,
    pub(crate) previous_version_id: Option<VersionId>,
    pub(crate) evict_at: Option<u64>,
}

impl HistoryEntry {
    /// Format version written by this build.
    pub const CURRENT_VERSION: u8 = HISTORY_ENTRY_VERSION;

    #[cfg(any(feature = "vault-store", test))]
    pub(crate) fn new(
        seq: u64,
        at: u64,
        pending: PendingHistory,
        provenance: Provenance,
        device_key_id: DeviceKeyId,
    ) -> Self {
        Self {
            version: HISTORY_ENTRY_VERSION,
            seq,
            at,
            operation: pending.operation,
            address: pending.address,
            version_id: pending.version_id,
            previous_version_id: pending.previous_version_id,
            evict_at: pending.evict_at,
            provenance,
            device_key_id,
        }
    }

    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.version == HISTORY_ENTRY_VERSION
    }
}

/// The bounded history of one document as it is persisted.
///
/// The log lives beside the record document in the same encrypted envelope,
/// so it shares the document's key, generation, and signed commit, but a read
/// of the records never has to decrypt or parse it and a write appends to it
/// rather than rebuilding it inside Automerge.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(feature = "vault-store", test))]
pub(crate) struct HistoryLog {
    version: u8,
    kind: DocumentKind,
    partition: Vec<u8>,
    /// Next sequence number to assign. Trimming never reuses one.
    next_seq: u64,
    entries: Vec<HistoryEntry>,
}

#[cfg(any(feature = "vault-store", test))]
impl HistoryLog {
    pub(crate) fn new(kind: DocumentKind, partition: &[u8]) -> Self {
        Self {
            version: HISTORY_LOG_VERSION,
            kind,
            partition: partition.to_vec(),
            next_seq: 0,
            entries: Vec::new(),
        }
    }

    /// Parse a persisted log and check that it belongs to the document it was
    /// loaded for and is well formed: every entry supported, sequence numbers
    /// strictly increasing and below the next one to assign.
    pub(crate) fn load(
        bytes: &[u8],
        kind: DocumentKind,
        expected_partition: Option<&[u8]>,
    ) -> VaultResult<Self> {
        let log: Self = serde_json::from_slice(bytes)
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        log.validate(kind, expected_partition)?;
        Ok(log)
    }

    /// Convert the value-free history embedded by document format 2 into the
    /// independently encrypted log used by current snapshots.
    pub(crate) fn from_legacy_document(
        kind: DocumentKind,
        partition: &[u8],
        next_seq: u64,
        entries: Vec<HistoryEntry>,
    ) -> VaultResult<Self> {
        let log = Self {
            version: HISTORY_LOG_VERSION,
            kind,
            partition: partition.to_vec(),
            next_seq,
            entries,
        };
        log.validate(kind, Some(partition))?;
        Ok(log)
    }

    fn validate(&self, kind: DocumentKind, expected_partition: Option<&[u8]>) -> VaultResult<()> {
        if self.version != HISTORY_LOG_VERSION {
            return Err(VaultError::InvalidData(
                "unsupported secret document history version".to_owned(),
            ));
        }
        if self.kind != kind
            || expected_partition.is_some_and(|expected| self.partition != expected)
        {
            return Err(VaultError::InvalidData(
                "secret document history does not match its document".to_owned(),
            ));
        }
        if self.entries.iter().any(|entry| !entry.is_supported()) {
            return Err(VaultError::InvalidData(
                "unsupported secret document history entry".to_owned(),
            ));
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].seq >= pair[1].seq)
            || self
                .entries
                .last()
                .is_some_and(|last| last.seq >= self.next_seq)
        {
            return Err(VaultError::InvalidData(
                "secret document history is not strictly ordered".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn serialize(&self) -> VaultResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|error| VaultError::InvalidData(error.to_string()))
    }

    /// Recorded changes, oldest first.
    pub(crate) fn entries(&self) -> &[HistoryEntry] {
        &self.entries
    }

    /// Append the changes of one generation, in order, then trim the oldest
    /// entries down to the kind's retention.
    pub(crate) fn record(
        &mut self,
        pending: Vec<PendingHistory>,
        at: u64,
        provenance: &Provenance,
        device_key_id: DeviceKeyId,
    ) -> VaultResult<()> {
        for pending in pending {
            let seq = self.next_seq;
            self.next_seq = seq.checked_add(1).ok_or_else(|| {
                VaultError::InvalidData("secret document history sequence is exhausted".to_owned())
            })?;
            self.entries.push(HistoryEntry::new(
                seq,
                at,
                pending,
                provenance.clone(),
                device_key_id,
            ));
        }
        let retention = self.kind.history_retention();
        let sizes = self
            .entries
            .iter()
            .map(|entry| serde_json::to_vec(entry).map(|bytes| bytes.len()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| VaultError::InvalidData(error.to_string()))?;
        let mut total: usize = sizes.iter().sum();
        let mut start = 0;
        while start < self.entries.len()
            && (self.entries.len() - start > retention.max_entries || total > retention.max_bytes)
        {
            total -= sizes[start];
            start += 1;
        }
        self.entries.drain(..start);
        Ok(())
    }
}

/// Bound applied to a document's history whenever it is projected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryRetention {
    /// Oldest entries are dropped past this count.
    pub max_entries: usize,
    /// Oldest entries are dropped once serialized entries exceed this size.
    pub max_bytes: usize,
    /// Whether a put that changed nothing is recorded at all.
    pub record_unchanged: bool,
}

impl DocumentKind {
    /// Retention policy for this kind. Cache documents are written on every
    /// refresh and their history is least valuable, so they keep the least.
    #[must_use]
    pub const fn history_retention(self) -> HistoryRetention {
        match self {
            Self::SecretSpecProject => HistoryRetention {
                max_entries: 2048,
                max_bytes: 1024 * 1024,
                record_unchanged: true,
            },
            Self::Authorization | Self::LinuxSecretService | Self::LocalKeyring => {
                HistoryRetention {
                    max_entries: 1024,
                    max_bytes: 512 * 1024,
                    record_unchanged: true,
                }
            }
            Self::SecretSpecProviderCache => HistoryRetention {
                max_entries: 64,
                max_bytes: 64 * 1024,
                record_unchanged: false,
            },
        }
    }
}

fn bounded(value: &str) -> String {
    if value.len() <= MAX_DECLARED_FIELD_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_DECLARED_FIELD_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_context_is_truncated_on_a_character_boundary() {
        let long = "é".repeat(MAX_DECLARED_FIELD_BYTES);
        // An absolute path on every platform, since the context validates it.
        let base_dir = std::env::temp_dir().display().to_string();
        let context = VaultApplicationContext::new(
            Some("demo".to_owned()),
            None,
            Some(base_dir.clone()),
            Some(long.clone()),
        )
        .unwrap();
        let declared = DeclaredApplication::from(&context);

        assert_eq!(declared.project.as_deref(), Some("demo"));
        assert_eq!(declared.base_dir.as_deref(), Some(base_dir.as_str()));
        let reason = declared.reason.unwrap();
        assert!(reason.len() <= MAX_DECLARED_FIELD_BYTES);
        assert!(long.starts_with(&reason));
        assert_eq!(reason.len() % 2, 0);
    }

    fn pending(index: usize) -> PendingHistory {
        PendingHistory {
            operation: HistoryOperation::Put { changed: true },
            address: SecretAddress::new(format!("entry-{index}"), None).unwrap(),
            version_id: Some(VersionId::from_bytes([1; 16])),
            previous_version_id: None,
            evict_at: None,
        }
    }

    #[test]
    fn log_round_trips_and_continues_its_sequence() {
        let expiry = Provenance::service(ServiceReason::Expiry);
        let mut log = HistoryLog::new(DocumentKind::LocalKeyring, b"test");
        log.record(
            vec![pending(0), pending(1)],
            10,
            &expiry,
            DeviceKeyId::from_bytes([2; 32]),
        )
        .unwrap();
        let bytes = log.serialize().unwrap();

        let mut loaded =
            HistoryLog::load(&bytes, DocumentKind::LocalKeyring, Some(b"test")).unwrap();
        assert_eq!(
            loaded
                .entries()
                .iter()
                .map(|entry| entry.seq)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        loaded
            .record(
                vec![pending(2)],
                11,
                &expiry,
                DeviceKeyId::from_bytes([2; 32]),
            )
            .unwrap();
        assert_eq!(loaded.entries().last().unwrap().seq, 2);

        assert!(HistoryLog::load(&bytes, DocumentKind::Authorization, Some(b"test")).is_err());
        assert!(HistoryLog::load(&bytes, DocumentKind::LocalKeyring, Some(b"other")).is_err());
        let mut reordered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        reordered["entries"][1]["seq"] = serde_json::Value::from(0);
        assert!(
            HistoryLog::load(
                &serde_json::to_vec(&reordered).unwrap(),
                DocumentKind::LocalKeyring,
                Some(b"test"),
            )
            .is_err()
        );
    }

    #[test]
    fn log_is_bounded_per_kind_and_keeps_its_sequence_after_trimming() {
        let expiry = Provenance::service(ServiceReason::Expiry);
        let kind = DocumentKind::SecretSpecProviderCache;
        let retention = kind.history_retention();
        let mut log = HistoryLog::new(kind, b"cache");
        let writes = retention.max_entries + 6;
        for index in 0..writes {
            log.record(
                vec![pending(index)],
                index as u64,
                &expiry,
                DeviceKeyId::from_bytes([2; 32]),
            )
            .unwrap();
        }

        let entries = log.entries();
        assert_eq!(entries.len(), retention.max_entries);
        assert_eq!(entries[0].seq, 6);
        assert_eq!(entries.last().unwrap().seq, writes as u64 - 1);
        assert!(
            entries
                .windows(2)
                .all(|pair| pair[1].seq == pair[0].seq + 1)
        );
    }

    #[test]
    fn unknown_history_versions_are_detected() {
        let entry = HistoryEntry::new(
            0,
            1,
            PendingHistory {
                operation: HistoryOperation::Delete,
                address: SecretAddress::new("item", None).unwrap(),
                version_id: None,
                previous_version_id: Some(VersionId::from_bytes([1; 16])),
                evict_at: None,
            },
            Provenance::service(ServiceReason::Expiry),
            DeviceKeyId::from_bytes([2; 32]),
        );
        assert!(entry.is_supported());
        let mut json = serde_json::to_value(&entry).unwrap();
        json["version"] = serde_json::Value::from(HISTORY_ENTRY_VERSION + 1);
        let unsupported: HistoryEntry = serde_json::from_value(json).unwrap();
        assert!(!unsupported.is_supported());
    }
}
