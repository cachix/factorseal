//! Fully prepared imports with resumable, independently committed vault records.

use anyhow::bail;

use crate::{
    DocumentKind, SecretAddress, VaultAction, VaultArchive, VaultArchiveEntry, VaultClient,
    VaultEntryImportStatus, VaultEntryMetadata, VaultRequest, VaultResponseBody, WireSecret,
};

use super::{TransferFormat, import_manager, preserved_only_items};

/// Counts contain no credential values and may be displayed before vault writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportSummary {
    pub added: usize,
    pub replaced: usize,
    pub kept_existing: usize,
    pub preserved_only: usize,
}

impl ImportSummary {
    #[must_use]
    pub const fn processed(self) -> usize {
        self.added + self.replaced + self.kept_existing
    }
}

/// Secret buffers remain in memory and use `WireSecret`'s redaction and erasure.
/// Preparing or dropping a plan performs no vault requests.
pub struct PreparedImport {
    entries: Vec<VaultArchiveEntry>,
    preserved_only: usize,
}

impl PreparedImport {
    /// CXF input must already be completely authenticated and decrypted.
    pub fn manager(format: TransferFormat, bytes: &[u8]) -> anyhow::Result<Self> {
        let secrets = import_manager(format, bytes)?;
        let preserved_only = preserved_only_items(&secrets);
        let mut entries = Vec::with_capacity(secrets.len());
        for secret in secrets {
            entries.push(VaultArchiveEntry {
                metadata: VaultEntryMetadata {
                    display_name: None,
                    display_type: None,
                    updated_at: None,
                    document_kind: DocumentKind::LocalKeyring,
                    partition: crate::personal::PERSONAL_SECRET_NAMESPACE.to_vec(),
                    address: SecretAddress::new(secret.id.clone(), None)?,
                },
                value: WireSecret::new(secret.encode()?.to_vec())?,
                evict_at: None,
            });
        }
        Ok(Self {
            entries,
            preserved_only,
        })
    }

    pub fn archive(mut archive: VaultArchive, now: u64) -> anyhow::Result<Self> {
        archive.validate()?;
        if archive
            .entries
            .iter()
            .any(|entry| entry.evict_at.is_some_and(|deadline| deadline < now))
        {
            bail!("archive contains an entry that has already expired");
        }
        let mut preserved_only = 0;
        for entry in &mut archive.entries {
            if entry.metadata.document_kind == DocumentKind::LocalKeyring
                && entry.metadata.partition == crate::personal::PERSONAL_SECRET_NAMESPACE
            {
                let (title, field) = entry
                    .metadata
                    .address
                    .as_local()
                    .ok_or_else(|| anyhow::anyhow!("invalid personal address"))?;
                if field.is_some() || entry.evict_at.is_some() {
                    bail!("personal items cannot have fields or expiry");
                }
                let item = crate::personal::PersonalSecret::decode(title, entry.value.expose())?;
                preserved_only += preserved_only_items(std::slice::from_ref(&item));
                entry.metadata.address = SecretAddress::new(item.id.clone(), None)?;
                entry.value = WireSecret::new(item.encode()?.to_vec())?;
            }
        }
        Ok(Self {
            entries: archive.entries,
            preserved_only,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub const fn preserved_only(&self) -> usize {
        self.preserved_only
    }

    /// Records commit independently. Retrying the same input with replacement
    /// disabled keeps completed records, including a write whose reply was lost.
    pub fn commit(
        self,
        client: &dyn VaultClient,
        replace_existing: bool,
    ) -> anyhow::Result<ImportSummary> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if self
            .entries
            .iter()
            .any(|entry| entry.evict_at.is_some_and(|deadline| deadline < now))
        {
            bail!("an archive entry expired while awaiting import; no items were written");
        }
        let mut summary = ImportSummary {
            preserved_only: self.preserved_only,
            ..ImportSummary::default()
        };
        for entry in self.entries {
            let result = (|| -> anyhow::Result<_> {
                let request = VaultRequest::new(VaultAction::ImportVaultEntry {
                    entry: entry.metadata,
                    value: entry.value,
                    evict_at: entry.evict_at,
                    replace_existing,
                })?;
                let response = client.request(&request)?;
                let body = response
                    .result
                    .map_err(|error| anyhow::anyhow!("{}", error.message))?;
                let VaultResponseBody::VaultEntryImported { status } = body else {
                    bail!("vault returned an unexpected import response");
                };
                Ok(status)
            })();
            let status = result.map_err(|error| anyhow::anyhow!(
                "Import interrupted after {} confirmed items ({} added, {} replaced, {} kept). The last write may also have committed. Retry the same input with replacement disabled to keep completed items. Cause: {error}",
                summary.processed(), summary.added, summary.replaced, summary.kept_existing,
            ))?;
            match status {
                VaultEntryImportStatus::Added => summary.added += 1,
                VaultEntryImportStatus::Replaced => summary.replaced += 1,
                VaultEntryImportStatus::KeptExisting => summary.kept_existing += 1,
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::*;
    use crate::{VaultError, VaultResponse, VaultResult};

    #[derive(Default)]
    struct InterruptedVault(Mutex<(HashSet<String>, bool)>);

    impl VaultClient for InterruptedVault {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            let VaultAction::ImportVaultEntry {
                entry,
                replace_existing,
                ..
            } = &request.action
            else {
                panic!("unexpected import action");
            };
            assert!(!replace_existing);
            let id = entry.address.as_local().unwrap().0.to_owned();
            let mut state = self.0.lock().unwrap();
            let added = state.0.insert(id);
            if state.0.len() == 2 && !state.1 {
                state.1 = true;
                // The write persisted, but the client never received its reply.
                return Err(VaultError::Protocol("synthetic lost reply".into()));
            }
            Ok(VaultResponse::success(
                request.request_id(),
                VaultResponseBody::VaultEntryImported {
                    status: if added {
                        VaultEntryImportStatus::Added
                    } else {
                        VaultEntryImportStatus::KeptExisting
                    },
                },
            ))
        }
    }

    #[test]
    fn preview_is_read_only_and_retry_keeps_a_write_whose_reply_was_lost() {
        let source = br#"{"items":[{"id":"first","type":1,"name":"One","login":{"password":"synthetic secret"}},{"id":"second","type":1,"name":"Two"},{"id":"third","type":1,"name":"Three"}]}"#;
        let client = InterruptedVault::default();
        let prepared = PreparedImport::manager(TransferFormat::BitwardenJson, source).unwrap();
        assert_eq!(prepared.len(), 3);
        assert!(!prepared.is_empty());
        assert!(client.0.lock().unwrap().0.is_empty());
        let error = prepared.commit(&client, false).unwrap_err().to_string();
        assert!(error.contains("1 confirmed items"));
        assert!(error.contains("last write may also have committed"));
        assert!(error.contains("synthetic lost reply"));
        assert!(!error.contains("synthetic secret"));
        let summary = PreparedImport::manager(TransferFormat::BitwardenJson, source)
            .unwrap()
            .commit(&client, false)
            .unwrap();
        assert_eq!(summary.added, 1);
        assert_eq!(summary.kept_existing, 2);
        assert_eq!(client.0.lock().unwrap().0.len(), 3);
    }

    #[test]
    fn archive_preview_rejects_invalid_personal_payloads() {
        let entry = VaultArchiveEntry {
            metadata: VaultEntryMetadata {
                display_name: None,
                display_type: None,
                updated_at: None,
                document_kind: DocumentKind::LocalKeyring,
                partition: crate::personal::PERSONAL_SECRET_NAMESPACE.to_vec(),
                address: SecretAddress::new("synthetic-id", None).unwrap(),
            },
            value: WireSecret::new(
                br#"{"format":"factorseal-personal-secret","version":2}"#.to_vec(),
            )
            .unwrap(),
            evict_at: None,
        };
        assert!(PreparedImport::archive(VaultArchive::new(0, vec![entry]), 0).is_err());
    }

    #[test]
    fn expiry_is_rechecked_after_preview_before_any_writes() {
        let entry = VaultArchiveEntry {
            metadata: VaultEntryMetadata {
                display_name: None,
                display_type: None,
                updated_at: None,
                document_kind: DocumentKind::LocalKeyring,
                partition: b"synthetic".to_vec(),
                address: SecretAddress::new("synthetic-id", None).unwrap(),
            },
            value: WireSecret::new(b"synthetic secret".to_vec()).unwrap(),
            evict_at: Some(1),
        };
        let plan = PreparedImport::archive(VaultArchive::new(0, vec![entry]), 0).unwrap();
        let client = InterruptedVault::default();
        assert!(
            plan.commit(&client, false)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert!(client.0.lock().unwrap().0.is_empty());
    }
}
