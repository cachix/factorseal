//! Fully prepared imports with resumable, independently committed vault records.

use anyhow::bail;

use crate::{
    DocumentKind, SecretAddress, VaultAction, VaultArchive, VaultArchiveEntry, VaultClient,
    VaultEntryImportStatus, VaultEntryMetadata, VaultRequest, VaultResponseBody, WireSecret,
};

use super::{TransferFormat, UnusableData, import_manager, unusable_data};

#[path = "import_review.rs"]
mod review;
pub use review::{ImportChange, ImportComparison, ImportValue, ReviewItem, ReviewedImport};

/// Counts contain no credential values and may be displayed before vault writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ImportSummary {
    pub added: usize,
    pub replaced: usize,
    pub kept_existing: usize,
    pub skipped: usize,
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
    items: Vec<ImportItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportItem {
    pub metadata: VaultEntryMetadata,
    pub unusable: Vec<UnusableData>,
}

impl ImportItem {
    fn personal(metadata: &VaultEntryMetadata, item: &crate::personal::PersonalSecret) -> Self {
        Self {
            metadata: VaultEntryMetadata {
                display_name: Some(item.title.clone()),
                display_type: Some(item.kind.label().to_owned()),
                display_username: item.username().map(str::to_owned),
                display_website: item.website_host(),
                favorite: item.favorite,
                ..metadata.clone()
            },
            unusable: unusable_data(item),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportChoice {
    Skip,
    Add,
    Replace,
}

impl PreparedImport {
    /// CXF input must already be completely authenticated and decrypted.
    pub fn manager(format: TransferFormat, bytes: &[u8]) -> anyhow::Result<Self> {
        let secrets = import_manager(format, bytes)?;
        let mut entries = Vec::with_capacity(secrets.len());
        let mut items = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let entry = VaultArchiveEntry {
                metadata: VaultEntryMetadata {
                    access_project: None,
                    display_name: None,
                    display_type: None,
                    display_username: None,
                    display_website: None,
                    updated_at: None,
                    favorite: false,
                    document_kind: DocumentKind::LocalKeyring,
                    partition: crate::personal::PERSONAL_SECRET_NAMESPACE.to_vec(),
                    address: SecretAddress::new(secret.id.clone(), None)?,
                },
                value: WireSecret::new(secret.encode()?.to_vec())?,
                evict_at: None,
            };
            items.push(ImportItem::personal(&entry.metadata, &secret));
            entries.push(entry);
        }
        Ok(Self { entries, items })
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
        let mut items = Vec::with_capacity(archive.entries.len());
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
                entry.metadata.address = SecretAddress::new(item.id.clone(), None)?;
                entry.value = WireSecret::new(item.encode()?.to_vec())?;
                items.push(ImportItem::personal(&entry.metadata, &item));
            } else {
                items.push(ImportItem {
                    metadata: entry.metadata.clone(),
                    unusable: Vec::new(),
                });
            }
        }
        Ok(Self {
            entries: archive.entries,
            items,
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
    pub fn preserved_only(&self) -> usize {
        self.items
            .iter()
            .filter(|item| !item.unusable.is_empty())
            .count()
    }

    #[must_use]
    pub fn items(&self) -> &[ImportItem] {
        &self.items
    }

    /// Records commit independently. Retrying the same input with replacement
    /// disabled keeps completed records, including a write whose reply was lost.
    pub fn commit(
        self,
        client: &dyn VaultClient,
        replace_existing: bool,
    ) -> anyhow::Result<ImportSummary> {
        let choice = if replace_existing {
            ImportChoice::Replace
        } else {
            ImportChoice::Add
        };
        let choices = vec![choice; self.len()];
        self.commit_selected(client, &choices)
    }

    pub fn commit_selected(
        self,
        client: &dyn VaultClient,
        choices: &[ImportChoice],
    ) -> anyhow::Result<ImportSummary> {
        let versions = vec![None; self.len()];
        self.commit_checked(client, choices, &versions)
    }

    fn commit_checked(
        self,
        client: &dyn VaultClient,
        choices: &[ImportChoice],
        versions: &[Option<[u8; 32]>],
    ) -> anyhow::Result<ImportSummary> {
        if choices.len() != self.len() {
            bail!("import choices do not match the prepared items");
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        if self.entries.iter().zip(choices).any(|(entry, choice)| {
            *choice != ImportChoice::Skip && entry.evict_at.is_some_and(|deadline| deadline < now)
        }) {
            bail!("an archive entry expired while awaiting import; no items were written");
        }
        let mut summary = ImportSummary::default();
        for (index, entry) in self.entries.into_iter().enumerate() {
            if choices[index] == ImportChoice::Skip {
                summary.skipped += 1;
                continue;
            }
            let result = (|| -> anyhow::Result<_> {
                let request = VaultRequest::new(VaultAction::ImportVaultEntry {
                    entry: entry.metadata,
                    value: entry.value,
                    evict_at: entry.evict_at,
                    replace_existing: choices[index] == ImportChoice::Replace,
                    expected_version: if choices[index] == ImportChoice::Replace {
                        versions[index]
                    } else {
                        None
                    },
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
            if status != VaultEntryImportStatus::KeptExisting
                && !self.items[index].unusable.is_empty()
            {
                summary.preserved_only += 1;
            }
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

    #[derive(Default)]
    struct RecordingVault(Mutex<Vec<bool>>);

    impl VaultClient for RecordingVault {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            let VaultAction::ImportVaultEntry {
                replace_existing, ..
            } = &request.action
            else {
                panic!("unexpected import action");
            };
            self.0.lock().unwrap().push(*replace_existing);
            Ok(VaultResponse::success(
                request.request_id(),
                VaultResponseBody::VaultEntryImported {
                    status: if *replace_existing {
                        VaultEntryImportStatus::Replaced
                    } else {
                        VaultEntryImportStatus::KeptExisting
                    },
                },
            ))
        }
    }

    #[test]
    fn commit_replaces_only_the_chosen_items() {
        let source = br#"{"items":[{"id":"first","type":1,"name":"One"},{"id":"second","type":1,"name":"Two"},{"id":"third","type":1,"name":"Three"}]}"#;
        let client = RecordingVault::default();
        let summary = PreparedImport::manager(TransferFormat::BitwardenJson, source)
            .unwrap()
            .commit_selected(
                &client,
                &[ImportChoice::Add, ImportChoice::Replace, ImportChoice::Add],
            )
            .unwrap();
        assert_eq!(*client.0.lock().unwrap(), [false, true, false]);
        assert_eq!(summary.replaced, 1);
        assert_eq!(summary.kept_existing, 2);
    }

    #[test]
    fn skipped_items_never_reach_the_vault_or_preserved_count() {
        let source = br#"{"items":[{"id":"skip","type":1,"name":"Skip","login":{"fido2Credentials":[{"keyValue":"secret"}]}},{"id":"keep","type":1,"name":"Keep"}]}"#;
        let client = RecordingVault::default();
        let plan = PreparedImport::manager(TransferFormat::BitwardenJson, source).unwrap();
        let summary = plan
            .commit_selected(&client, &[ImportChoice::Skip, ImportChoice::Add])
            .unwrap();
        assert_eq!(*client.0.lock().unwrap(), [false]);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.preserved_only, 0);
        let plan = PreparedImport::manager(TransferFormat::BitwardenJson, source).unwrap();
        let summary = plan
            .commit_selected(&client, &[ImportChoice::Skip, ImportChoice::Skip])
            .unwrap();
        assert_eq!(summary.skipped, 2);
        assert_eq!(*client.0.lock().unwrap(), [false]);
    }

    #[test]
    fn invalid_choices_are_rejected_before_any_writes() {
        let source = br#"{"items":[{"id":"one","type":1,"name":"One"}]}"#;
        let client = RecordingVault::default();
        assert!(
            PreparedImport::manager(TransferFormat::BitwardenJson, source)
                .unwrap()
                .commit_selected(&client, &[])
                .is_err()
        );
        assert!(client.0.lock().unwrap().is_empty());
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
    fn prepared_items_describe_entries_without_secret_values() {
        let source = br#"{"items":[
            {"id":"login","type":1,"name":"Login","login":{"username":"ada","password":"synthetic secret","uris":[{"uri":"https://example.com/sign-in"}]}},
            {"id":"passkey","type":1,"name":"Passkey","login":{"fido2Credentials":[{"keyValue":"synthetic key"}]}}
        ]}"#;
        let prepared = PreparedImport::manager(TransferFormat::BitwardenJson, source).unwrap();
        let items = prepared.items();
        assert_eq!(items[0].metadata.display_name.as_deref(), Some("Login"));
        assert_eq!(items[0].metadata.display_type.as_deref(), Some("Login"));
        assert_eq!(items[0].metadata.display_username.as_deref(), Some("ada"));
        assert_eq!(
            items[0].metadata.display_website.as_deref(),
            Some("example.com")
        );
        assert_eq!(items[0].unusable, []);
        assert_eq!(items[1].unusable, [UnusableData::Passkeys]);
        assert_eq!(prepared.preserved_only(), 1);
        assert!(!format!("{items:?}").contains("synthetic"));
        assert!(prepared.entries[0].metadata.display_name.is_none());
    }

    #[test]
    fn archive_preview_rejects_invalid_personal_payloads() {
        let entry = VaultArchiveEntry {
            metadata: VaultEntryMetadata {
                access_project: None,
                display_name: None,
                display_type: None,
                display_username: None,
                display_website: None,
                updated_at: None,
                favorite: false,
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
                access_project: None,
                display_name: None,
                display_type: None,
                display_username: None,
                display_website: None,
                updated_at: None,
                favorite: false,
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
