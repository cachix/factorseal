//! Personal-item identity migration and validation inside the storage boundary.
use std::collections::HashSet;

use super::{
    DocumentKind, DocumentMutation, ROOT, ReadDoc, SecretAddress, SecretDocument, SecretRead,
    Transactable, VaultError, VaultResult, Zeroizing, automerge_error, descriptor_mismatch,
};
use crate::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret};

const PERSONAL_LAYOUT: &str = "personal-layout";
const PERSONAL_ALIASES: &str = "personal-legacy-addresses";

impl SecretDocument {
    pub(super) fn ensure_personal_unconflicted(&self, address: &SecretAddress) -> VaultResult<()> {
        if self.is_personal()
            && let Some((id, _)) = address.as_local()
            && let Some(replica) = self
                .personal_replicas()?
                .load(id, self.document.get_actor().to_bytes())?
            && replica.values()?.len() > 1
        {
            return Err(VaultError::Conflict);
        }
        Ok(())
    }

    pub(super) fn is_personal(&self) -> bool {
        self.kind == DocumentKind::LocalKeyring && self.partition == PERSONAL_SECRET_NAMESPACE
    }

    pub(super) fn validate_personal_put(
        &mut self,
        address: &SecretAddress,
        value: &[u8],
        evict_at: Option<u64>,
    ) -> VaultResult<()> {
        if !self.is_personal() {
            return Ok(());
        }
        let item = PersonalSecret::decode_current(value)
            .map_err(|_| VaultError::Protocol("invalid personal item".into()))?;
        if address.as_local() != Some((item.id.as_str(), None)) || evict_at.is_some() {
            return Err(VaultError::Protocol(
                "personal items must be addressed by ID and cannot expire".into(),
            ));
        }
        self.document
            .put(ROOT, PERSONAL_LAYOUT, 1_u64)
            .map_err(automerge_error)?;
        Ok(())
    }

    pub(crate) fn personal_title(
        &self,
        address: &SecretAddress,
        _now: u64,
    ) -> VaultResult<Option<String>> {
        if !self.is_personal() {
            return Ok(None);
        }
        // Titles remain available when the replicated register is conflicted.
        let read = self
            .records(&address.storage_key())?
            .into_iter()
            .next()
            .map_or(SecretRead::Missing, |record| {
                SecretRead::Value(record.value)
            });
        match read {
            SecretRead::Value(value) => {
                let item = PersonalSecret::decode_current(&value)
                    .map_err(|_| VaultError::InvalidData("invalid personal item".into()))?;
                let mut title = item.title.clone();
                if title.len() > 1024 {
                    let mut end = 1024;
                    while !title.is_char_boundary(end) {
                        end -= 1;
                    }
                    title.truncate(end);
                }
                Ok(Some(title))
            }
            SecretRead::Missing | SecretRead::Expired => Ok(None),
            SecretRead::Conflict => Err(VaultError::Conflict),
        }
    }

    /// Rewrite the existing document in one generation, retaining record versions,
    /// dates, deadlines, and an encrypted mapping back to old history addresses.
    pub(crate) fn migrate_personal(&mut self) -> VaultResult<Option<DocumentMutation>> {
        if !self.is_personal() {
            return Ok(None);
        }
        if let Some((value, _)) = self
            .document
            .get(ROOT, PERSONAL_LAYOUT)
            .map_err(automerge_error)?
        {
            if value.as_u64() == Some(1) {
                return Ok(None);
            }
            return Err(VaultError::InvalidData(
                "unsupported personal layout".into(),
            ));
        }
        self.mutate(|document| {
            let mut records = Vec::new();
            for (key, _) in document.addresses()? {
                let mut visible = document.records(&key)?;
                if visible.len() != 1 {
                    return Err(VaultError::Conflict);
                }
                let record = visible.pop().expect("one record");
                let (title, _) = record.address.as_local().ok_or_else(descriptor_mismatch)?;
                let item = PersonalSecret::decode(title, &record.value)
                    .map_err(|_| VaultError::InvalidData("invalid legacy personal item".into()))?;
                records.push((key, record, item));
            }
            let mut reserved: HashSet<String> =
                records.iter().map(|(_, _, item)| item.id.clone()).collect();
            let mut seen = HashSet::new();
            let mut aliases = Vec::new();
            let mut address_migrations = Vec::new();
            let mut replicas = super::replicas::ReplicaCatalog::default();
            for (key, _, _) in &records {
                document
                    .document
                    .delete(&document.entries, key)
                    .map_err(automerge_error)?;
            }
            for (_, mut record, mut item) in records {
                if !seen.insert(item.id.clone()) || !item.has_storage_id() {
                    loop {
                        item.id = uuid::Uuid::new_v4().to_string();
                        if reserved.insert(item.id.clone()) {
                            break;
                        }
                    }
                }
                aliases.push((item.id.clone(), record.address.clone()));
                let new_address = SecretAddress::new(item.id.clone(), None)?;
                address_migrations.push((record.address.clone(), new_address.clone()));
                record.address = new_address;
                let mut replica = crate::personal::replica::PersonalReplica::new(
                    &item.id,
                    document.document.get_actor().to_bytes(),
                )?;
                replica.set(Some(&item), None)?;
                replicas.store(&item.id, &mut replica, true)?;
                record.value = item.encode().map_err(|_| {
                    VaultError::InvalidData("invalid migrated personal item".into())
                })?;
                let bytes = Zeroizing::new(
                    serde_json::to_vec(&record)
                        .map_err(|e| VaultError::InvalidData(e.to_string()))?,
                );
                document
                    .document
                    .put(
                        &document.entries,
                        record.address.storage_key(),
                        bytes.to_vec(),
                    )
                    .map_err(automerge_error)?;
            }
            document.save_personal_replicas(&replicas)?;
            let aliases = Zeroizing::new(
                serde_json::to_vec(&aliases).map_err(|e| VaultError::InvalidData(e.to_string()))?,
            );
            document
                .document
                .put(ROOT, PERSONAL_ALIASES, aliases.to_vec())
                .map_err(automerge_error)?;
            document
                .document
                .put(ROOT, PERSONAL_LAYOUT, 1_u64)
                .map_err(automerge_error)?;
            let mut mutation = document.finish_mutation()?;
            mutation.address_migrations = address_migrations;
            Ok(Some(mutation))
        })
    }

    pub(super) fn project_personal_metadata(&self, projection: &mut Self) -> VaultResult<()> {
        if self.is_personal() {
            for key in [
                PERSONAL_LAYOUT,
                PERSONAL_ALIASES,
                "personal-automerge-v1",
                "personal-sync-v1",
            ] {
                if let Some((value, _)) = self.document.get(ROOT, key).map_err(automerge_error)? {
                    let automerge::Value::Scalar(value) = value else {
                        return Err(descriptor_mismatch());
                    };
                    projection
                        .document
                        .put(ROOT, key, value.into_owned())
                        .map_err(automerge_error)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::PARTITION_KEY;
    use super::*;
    use crate::vault::{DeviceKeyId, DocumentOperation, MutationContext, Provenance};

    fn context() -> MutationContext<'static> {
        static PROVENANCE: Provenance = Provenance::Redacted;
        MutationContext {
            now: 10,
            provenance: &PROVENANCE,
            device_key_id: DeviceKeyId::from_bytes([7; 32]),
        }
    }

    fn legacy(entries: &[(&str, &[u8])]) -> SecretDocument {
        let mut document =
            SecretDocument::new(b"fixture", DocumentKind::LocalKeyring, b"fixture").unwrap();
        for (title, value) in entries {
            document
                .put(
                    &SecretAddress::new(*title, None).unwrap(),
                    value,
                    None,
                    &context(),
                )
                .unwrap();
        }
        document.partition = PERSONAL_SECRET_NAMESPACE.to_vec();
        document
            .document
            .put(ROOT, PARTITION_KEY, PERSONAL_SECRET_NAMESPACE.to_vec())
            .unwrap();
        document
    }

    #[test]
    fn migration_preserves_duplicate_ids_and_old_history_coordinates() {
        let item = PersonalSecret::generic("Same title".into(), "secret".into());
        let encoded = item.encode().unwrap();
        let mut document = legacy(&[("first", &encoded), ("second", &encoded)]);
        let mutation = document.migrate_personal().unwrap().unwrap();
        assert_eq!(mutation.address_migrations.len(), 2);
        let addresses = document.addresses().unwrap();
        assert_eq!(addresses.len(), 2);
        assert_ne!(addresses[0].1, addresses[1].1);
        for (_, address) in addresses {
            assert_eq!(
                document.personal_title(&address, 10).unwrap().as_deref(),
                Some("Same title")
            );
            let SecretRead::Value(value) = document.get(&address, 10).unwrap() else {
                panic!()
            };
            let item = PersonalSecret::decode_current(&value).unwrap();
            assert_eq!(address.as_local(), Some((item.id.as_str(), None)));
            assert_eq!(item.sections[0].fields[0].text(), Some("secret"));
        }
        let mut loaded = SecretDocument::load(
            &mutation.snapshot,
            b"reader",
            DocumentKind::LocalKeyring,
            Some(PERSONAL_SECRET_NAMESPACE),
        )
        .unwrap();
        assert!(loaded.migrate_personal().unwrap().is_none());
        assert_eq!(loaded.personal_replicas().unwrap().pending.len(), 2);
    }

    #[test]
    fn rename_preserves_identity_and_same_titles_do_not_collide() {
        let mut document = SecretDocument::new(
            b"writer",
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
        )
        .unwrap();
        let mut first = PersonalSecret::generic("Original".into(), "first".into());
        let address = SecretAddress::new(first.id.clone(), None).unwrap();
        document
            .put(&address, &first.encode().unwrap(), None, &context())
            .unwrap();
        document
            .put(&address, &first.encode().unwrap(), None, &context())
            .unwrap();
        assert_eq!(
            document.personal_replicas().unwrap().replicas.len(),
            1,
            "unchanged puts do not create revisions"
        );
        first.title = "Renamed".into();
        document
            .put(&address, &first.encode().unwrap(), None, &context())
            .unwrap();
        let second = PersonalSecret::generic("Renamed".into(), "second".into());
        document
            .put(
                &SecretAddress::new(second.id.clone(), None).unwrap(),
                &second.encode().unwrap(),
                None,
                &context(),
            )
            .unwrap();
        assert_eq!(document.addresses().unwrap().len(), 2);
        assert_eq!(
            document.personal_title(&address, 10).unwrap().as_deref(),
            Some("Renamed")
        );
        assert!(document.delete(&address).unwrap().is_some());
        assert_eq!(document.addresses().unwrap().len(), 1);
        let replicas = document.personal_replicas().unwrap();
        assert_eq!(replicas.pending.len(), 2);
        assert_eq!(
            replicas
                .load(&first.id, b"reader")
                .unwrap()
                .unwrap()
                .values()
                .unwrap(),
            vec![None]
        );
        let snapshot = document.save();
        let loaded = SecretDocument::load(
            &snapshot,
            b"restarted",
            DocumentKind::LocalKeyring,
            Some(PERSONAL_SECRET_NAMESPACE),
        )
        .unwrap();
        assert_eq!(
            &loaded.personal_replicas().unwrap().replicas,
            &replicas.replicas
        );
    }

    #[test]
    fn invalid_personal_batch_rolls_back_and_other_namespaces_remain_opaque() {
        let mut document = SecretDocument::new(
            b"writer",
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
        )
        .unwrap();
        let item = PersonalSecret::generic("Title".into(), "secret".into());
        let address = SecretAddress::new(item.id.clone(), None).unwrap();
        let invalid = SecretAddress::new("wrong-id", None).unwrap();
        let encoded = item.encode().unwrap();
        assert!(
            document
                .apply(
                    &[
                        DocumentOperation::Put {
                            address: address.clone(),
                            value: encoded.clone(),
                            evict_at: None
                        },
                        DocumentOperation::Put {
                            address: invalid.clone(),
                            value: encoded.clone(),
                            evict_at: None
                        },
                    ],
                    &context()
                )
                .is_err()
        );
        assert!(document.addresses().unwrap().is_empty());
        assert!(
            document.personal_replicas().unwrap().replicas.is_empty(),
            "rejected batches must roll back the outbox too"
        );
        assert!(
            document
                .put(&address, &encoded, Some(20), &context())
                .is_err()
        );
        assert!(
            document
                .put(&address, b"plaintext", None, &context())
                .is_err()
        );
        let mut other =
            SecretDocument::new(b"writer", DocumentKind::LocalKeyring, b"device-only").unwrap();
        other
            .put(&invalid, b"plaintext", Some(20), &context())
            .unwrap();
        assert!(other.migrate_personal().unwrap().is_none());
    }
}
