use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{ImportChoice, ImportItem, ImportSummary, PreparedImport};
use crate::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret};
use crate::{DocumentKind, SecretAddress, VaultArchiveEntry, VaultClient, VaultEntryMetadata};

#[path = "import_comparison.rs"]
mod comparison;
pub use comparison::{ImportComparison, ImportValue};

type EntryKey = (DocumentKind, Vec<u8>, SecretAddress);

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(tag = "type", content = "field", rename_all = "kebab-case")]
pub enum ImportChange {
    Title,
    Kind,
    Notes,
    Folder,
    Tags,
    Favorite,
    Archived,
    Source,
    Field(String),
    OtherFields,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewItem {
    pub item: ImportItem,
    pub existing: bool,
    pub changes: Vec<ImportChange>,
}

pub struct ReviewedImport {
    prepared: PreparedImport,
    items: Vec<ReviewItem>,
    versions: Vec<Option<[u8; 32]>>,
    stored: Vec<Option<Arc<VaultArchiveEntry>>>,
}

fn key(metadata: &VaultEntryMetadata) -> EntryKey {
    (
        metadata.document_kind,
        metadata.partition.clone(),
        metadata.address.clone(),
    )
}

fn version(entry: &VaultArchiveEntry) -> [u8; 32] {
    VaultArchiveEntry::version_of(entry.value.expose(), entry.evict_at)
}

fn personal(entry: &VaultArchiveEntry) -> anyhow::Result<Option<PersonalSecret>> {
    if entry.metadata.document_kind != DocumentKind::LocalKeyring
        || entry.metadata.partition != PERSONAL_SECRET_NAMESPACE
    {
        return Ok(None);
    }
    let (id, _) = entry
        .metadata
        .address
        .as_local()
        .ok_or_else(|| anyhow::anyhow!("invalid personal address"))?;
    PersonalSecret::decode(id, entry.value.expose()).map(Some)
}

fn changes(
    incoming: &VaultArchiveEntry,
    stored: &VaultArchiveEntry,
) -> anyhow::Result<Vec<ImportChange>> {
    Ok(comparison::comparisons(incoming, stored, &[])?
        .into_iter()
        .map(|row| row.change)
        .collect())
}

impl PreparedImport {
    pub fn review(self, client: &dyn VaultClient) -> anyhow::Result<ReviewedImport> {
        let keys: HashSet<_> = self.items.iter().map(|item| key(&item.metadata)).collect();
        let stored: HashMap<_, _> =
            crate::read_vault_export(client, |entry| keys.contains(&key(entry)))?
                .into_iter()
                .map(|entry| (key(&entry.metadata), Arc::new(entry)))
                .collect();
        let mut items = Vec::with_capacity(self.len());
        let mut versions = Vec::with_capacity(self.len());
        let mut originals = Vec::with_capacity(self.len());
        for (entry, item) in self.entries.iter().zip(&self.items) {
            let existing = stored.get(&key(&entry.metadata)).cloned();
            items.push(ReviewItem {
                item: item.clone(),
                existing: existing.is_some(),
                changes: existing
                    .as_ref()
                    .map(|stored| changes(entry, stored))
                    .transpose()?
                    .unwrap_or_default(),
            });
            versions.push(existing.as_deref().map(version));
            originals.push(existing);
        }
        Ok(ReviewedImport {
            prepared: self,
            items,
            versions,
            stored: originals,
        })
    }
}

impl ReviewedImport {
    #[must_use]
    pub fn items(&self) -> &[ReviewItem] {
        &self.items
    }

    pub fn comparisons(
        &self,
        index: usize,
        revealed: &[usize],
    ) -> anyhow::Result<Vec<ImportComparison>> {
        let incoming = self
            .prepared
            .entries
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("invalid import item"))?;
        let Some(stored) = self.stored.get(index).and_then(Option::as_ref) else {
            return Ok(Vec::new());
        };
        comparison::comparisons(incoming, stored, revealed)
    }

    pub fn commit(
        self,
        client: &dyn VaultClient,
        choices: &[ImportChoice],
    ) -> anyhow::Result<ImportSummary> {
        if choices.len() != self.items.len() {
            anyhow::bail!("import choices do not match the prepared items");
        }
        let choices: Vec<_> = self
            .items
            .iter()
            .zip(choices)
            .map(|(item, choice)| {
                if item.existing && item.changes.is_empty() {
                    ImportChoice::Skip
                } else {
                    *choice
                }
            })
            .collect();
        let replacing: HashSet<_> = self
            .items
            .iter()
            .zip(&choices)
            .filter(|(_, choice)| **choice == ImportChoice::Replace)
            .map(|(item, _)| key(&item.item.metadata))
            .collect();
        if !replacing.is_empty() {
            let current: HashMap<_, _> =
                crate::read_vault_export(client, |entry| replacing.contains(&key(entry)))?
                    .into_iter()
                    .map(|entry| (key(&entry.metadata), version(&entry)))
                    .collect();
            for ((item, choice), expected) in self.items.iter().zip(&choices).zip(&self.versions) {
                if *choice == ImportChoice::Replace
                    && (expected.is_none()
                        || current.get(&key(&item.item.metadata)) != expected.as_ref())
                {
                    return Err(crate::VaultError::Conflict.into());
                }
            }
        }
        self.prepared
            .commit_checked(client, &choices, &self.versions)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::transfer::TransferFormat;
    use crate::{
        VaultAction, VaultEntryImportStatus, VaultRequest, VaultResponse, VaultResponseBody,
        VaultResult, WireSecret,
    };

    #[derive(Default)]
    struct MemoryVault {
        entries: Mutex<Vec<VaultArchiveEntry>>,
        writes: Mutex<usize>,
    }

    impl VaultClient for MemoryVault {
        fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
            let mut entries = self.entries.lock().unwrap();
            let response = match &request.action {
                VaultAction::ExportRevision => VaultResponseBody::ExportRevision {
                    revision: Some([0; 32]),
                },
                VaultAction::ListVaultEntries { .. } => VaultResponseBody::VaultEntries {
                    entries: entries.iter().map(|entry| entry.metadata.clone()).collect(),
                    next_cursor: None,
                },
                VaultAction::ExportVaultEntry { entry } => {
                    let current = entries
                        .iter()
                        .find(|current| key(&current.metadata) == key(entry))
                        .unwrap();
                    VaultResponseBody::VaultEntrySecret {
                        value: WireSecret::new(current.value.expose().to_vec()).unwrap(),
                        evict_at: current.evict_at,
                    }
                }
                VaultAction::ImportVaultEntry {
                    entry,
                    value,
                    evict_at,
                    replace_existing,
                    expected_version,
                } => {
                    *self.writes.lock().unwrap() += 1;
                    let existing = entries
                        .iter()
                        .position(|current| key(&current.metadata) == key(entry));
                    if let Some(expected) = expected_version
                        && existing.map(|index| version(&entries[index])) != Some(*expected)
                    {
                        return Err(crate::VaultError::Conflict);
                    }
                    let status = match existing {
                        Some(_) if !replace_existing => VaultEntryImportStatus::KeptExisting,
                        Some(index) => {
                            entries.remove(index);
                            VaultEntryImportStatus::Replaced
                        }
                        None => VaultEntryImportStatus::Added,
                    };
                    if status != VaultEntryImportStatus::KeptExisting {
                        entries.push(VaultArchiveEntry {
                            metadata: entry.clone(),
                            value: WireSecret::new(value.expose().to_vec()).unwrap(),
                            evict_at: *evict_at,
                        });
                    }
                    VaultResponseBody::VaultEntryImported { status }
                }
                _ => panic!("unexpected review request"),
            };
            Ok(VaultResponse::success(request.request_id(), response))
        }
    }

    fn plan(password: &str) -> PreparedImport {
        let source = serde_json::json!({"items":[{"id":"one","type":1,"name":"Example","login":{"username":"ada","password":password}},{"id":"two","type":1,"name":"Skip me"}]});
        PreparedImport::manager(
            TransferFormat::BitwardenJson,
            &serde_json::to_vec(&source).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn review_exposes_changed_field_names_without_secret_values() {
        let vault = MemoryVault::default();
        plan("old-secret")
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let review = plan("new-secret").review(&vault).unwrap();
        assert!(review.items()[0].existing);
        assert!(!review.items()[1].existing);
        assert_eq!(review.items()[0].changes.len(), 1);
        assert!(
            matches!(&review.items()[0].changes[0], ImportChange::Field(label) if label.to_lowercase().contains("password"))
        );
        assert!(!format!("{:?}", review.items()).contains("secret"));
        assert_eq!(*vault.writes.lock().unwrap(), 1);
        let summary = review
            .commit(&vault, &[ImportChoice::Replace, ImportChoice::Skip])
            .unwrap();
        assert_eq!(summary.replaced, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(vault.entries.lock().unwrap().len(), 1);
    }

    #[test]
    fn comparison_values_stay_hidden_until_explicitly_revealed() {
        let vault = MemoryVault::default();
        plan("old-secret")
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let review = plan("new-secret").review(&vault).unwrap();
        let hidden = review.comparisons(0, &[]).unwrap();
        assert_eq!(hidden.len(), 1);
        assert!(hidden[0].current.concealed && hidden[0].current.filled);
        assert!(hidden[0].incoming.concealed && hidden[0].incoming.filled);
        assert!(hidden[0].current.value.is_none());
        assert!(hidden[0].incoming.value.is_none());
        let shown = review.comparisons(0, &[0]).unwrap();
        assert_eq!(
            shown[0].current.value.as_ref().unwrap().expose(),
            b"old-secret"
        );
        assert_eq!(
            shown[0].incoming.value.as_ref().unwrap().expose(),
            b"new-secret"
        );
        assert!(!format!("{shown:?}").contains("old-secret"));
        assert!(!format!("{shown:?}").contains("new-secret"));
        assert!(review.comparisons(1, &[]).unwrap().is_empty());
        assert!(review.comparisons(usize::MAX, &[]).is_err());
        assert_eq!(*vault.writes.lock().unwrap(), 1);
    }

    #[test]
    fn unchanged_items_are_skipped_even_if_a_client_requests_replacement() {
        let vault = MemoryVault::default();
        plan("same")
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let review = plan("same").review(&vault).unwrap();
        assert_eq!(review.items()[0].changes, []);
        assert!(review.comparisons(0, &[]).unwrap().is_empty());
        let result = review
            .commit(&vault, &[ImportChoice::Replace, ImportChoice::Skip])
            .unwrap();
        assert_eq!(result.replaced, 0);
        assert_eq!(result.skipped, 2);
        assert_eq!(*vault.writes.lock().unwrap(), 1);
    }

    #[test]
    fn comparisons_distinguish_removed_fields_and_hide_notes_and_source_data() {
        let vault = MemoryVault::default();
        let prepare = |notes: &str, fields: serde_json::Value, passkey: &str| {
            PreparedImport::manager(
                TransferFormat::BitwardenJson,
                &serde_json::to_vec(&serde_json::json!({
                    "items": [{"id":"one", "name":"Example", "type":1, "notes":notes,
                        "fields":fields, "login":{"fido2Credentials":[{"credentialId":passkey}]}}]
                }))
                .unwrap(),
            )
            .unwrap()
        };
        prepare("old-note", serde_json::json!([{"name":"Recovery", "value":"before", "type":1}, {"name":"Recovery", "value":"removed", "type":1}]), "old-passkey").commit_selected(&vault, &[ImportChoice::Add]).unwrap();
        let review = prepare(
            "new-note",
            serde_json::json!([{"name":"Recovery", "value":"after", "type":1}]),
            "new-passkey",
        )
        .review(&vault)
        .unwrap();
        let hidden = review.comparisons(0, &[]).unwrap();
        assert!(
            hidden
                .iter()
                .all(|row| row.current.value.is_none() && row.incoming.value.is_none())
        );
        let removed = hidden
            .iter()
            .position(|row| row.current.filled && !row.incoming.filled)
            .unwrap();
        let shown = review.comparisons(0, &[removed]).unwrap();
        assert_eq!(
            shown[removed].current.value.as_ref().unwrap().expose(),
            b"removed"
        );
        assert!(shown[removed].incoming.value.is_none());
        assert!(
            shown
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != removed)
                .all(|(_, row)| row.current.value.is_none() && row.incoming.value.is_none())
        );
        assert!(hidden.iter().any(|row| row.change == ImportChange::Notes));
        assert!(hidden.iter().any(|row| row.change == ImportChange::Source));
    }

    #[test]
    fn comparisons_preserve_tag_boundaries_and_detect_field_order_and_expiry() {
        let vault = MemoryVault::default();
        let mut original = plan("same-password");
        let mut item = personal(&original.entries[0]).unwrap().unwrap();
        item.tags = vec!["alpha, beta".to_owned()];
        original.entries[0].value =
            crate::WireSecret::new(item.encode().unwrap().to_vec()).unwrap();
        original
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let mut incoming = plan("same-password");
        item.tags = vec!["alpha".to_owned(), "beta".to_owned()];
        item.sections[0].fields.reverse();
        incoming.entries[0].value =
            crate::WireSecret::new(item.encode().unwrap().to_vec()).unwrap();
        incoming.entries[0].evict_at = Some(12345);
        let review = incoming.review(&vault).unwrap();
        let details = review.comparisons(0, &[]).unwrap();
        let tags = details
            .iter()
            .find(|row| row.change == ImportChange::Tags)
            .unwrap();
        assert_ne!(
            tags.current.value.as_ref().unwrap().expose(),
            tags.incoming.value.as_ref().unwrap().expose()
        );
        assert_eq!(
            details
                .iter()
                .filter(|row| row.change == ImportChange::OtherFields)
                .count(),
            2
        );
        assert!(!format!("{details:?}").contains("same-password"));
        assert!(details.iter().any(|row| {
            row.current.value.is_none()
                && row
                    .incoming
                    .value
                    .as_ref()
                    .is_some_and(|value| value.expose() == b"12345")
        }));
    }

    #[test]
    fn a_changed_vault_requires_another_review_before_replacing() {
        let vault = MemoryVault::default();
        plan("original")
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let review = plan("incoming").review(&vault).unwrap();
        plan("edited-while-reviewing")
            .commit_selected(&vault, &[ImportChoice::Replace, ImportChoice::Skip])
            .unwrap();
        let error = review
            .commit(&vault, &[ImportChoice::Replace, ImportChoice::Add])
            .unwrap_err();
        assert!(matches!(
            error.downcast_ref::<crate::VaultError>(),
            Some(crate::VaultError::Conflict)
        ));
        assert_eq!(*vault.writes.lock().unwrap(), 2);
        assert_eq!(vault.entries.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_change_between_preflight_and_write_does_not_get_overwritten() {
        struct RacingVault(MemoryVault);
        impl VaultClient for RacingVault {
            fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
                if matches!(request.action, VaultAction::ImportVaultEntry { .. }) {
                    plan("concurrent-edit")
                        .commit_selected(&self.0, &[ImportChoice::Replace, ImportChoice::Skip])
                        .unwrap();
                }
                self.0.request(request)
            }
        }
        let vault = RacingVault(MemoryVault::default());
        plan("original")
            .commit_selected(&vault.0, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let review = plan("incoming").review(&vault).unwrap();
        assert!(
            review
                .commit(&vault, &[ImportChoice::Replace, ImportChoice::Skip])
                .is_err()
        );
        let entries = vault.0.entries.lock().unwrap();
        let item = personal(&entries[0]).unwrap().unwrap();
        assert_eq!(
            item.sections
                .iter()
                .flat_map(|section| &section.fields)
                .find(|field| field.id == "password")
                .unwrap()
                .value
                .as_str(),
            Some("concurrent-edit")
        );
    }

    #[test]
    fn a_new_item_never_overwrites_a_later_arrival() {
        let vault = MemoryVault::default();
        let review = plan("incoming").review(&vault).unwrap();
        plan("arrived-later")
            .commit_selected(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        let summary = review
            .commit(&vault, &[ImportChoice::Add, ImportChoice::Skip])
            .unwrap();
        assert_eq!(summary.kept_existing, 1);
        assert_eq!(summary.added, 0);
        assert_eq!(summary.replaced, 0);
    }
}
