//! Personal Automerge histories are encrypted inside the local snapshot, apart
//! from local keys/membership. Projection preserves these histories verbatim.
use super::{
    DocumentMutation, ROOT, ReadDoc, SecretAddress, SecretDocument, Transactable, VaultError,
    VaultResult, Zeroizing, automerge_error, descriptor_mismatch,
};
use crate::personal::{PersonalSecret, replica::PersonalReplica};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const REPLICAS: &str = "personal-automerge-v1";
const MAX_CATALOG_BYTES: usize = 32 * 1024 * 1024;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplicaCatalog {
    pub replicas: BTreeMap<String, Vec<u8>>,
    pub pending: BTreeSet<String>,
}
impl ReplicaCatalog {
    pub fn load(&self, id: &str, actor: &[u8]) -> VaultResult<Option<PersonalReplica>> {
        self.replicas
            .get(id)
            .map(|bytes| PersonalReplica::load(id, bytes, actor))
            .transpose()
    }
    pub fn store(
        &mut self,
        id: &str,
        replica: &mut PersonalReplica,
        pending: bool,
    ) -> VaultResult<()> {
        if !self.replicas.contains_key(id) && self.replicas.len() >= 4096 {
            return Err(VaultError::Protocol(
                "personal replica catalog is full".into(),
            ));
        }
        self.replicas
            .insert(id.to_owned(), replica.save()?.to_vec());
        if pending {
            self.pending.insert(id.to_owned());
        }
        Ok(())
    }
}
impl Drop for ReplicaCatalog {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for value in self.replicas.values_mut() {
            value.zeroize();
        }
    }
}
impl SecretDocument {
    pub(super) fn personal_replicas(&self) -> VaultResult<ReplicaCatalog> {
        if !self.is_personal() {
            return Err(descriptor_mismatch());
        }
        match self.document.get(ROOT, REPLICAS).map_err(automerge_error)? {
            Some((value, _)) => {
                let bytes = Zeroizing::new(value.into_bytes().map_err(|_| descriptor_mismatch())?);
                if bytes.len() > MAX_CATALOG_BYTES {
                    return Err(descriptor_mismatch());
                }
                let catalog: ReplicaCatalog =
                    serde_json::from_slice(&bytes).map_err(|_| descriptor_mismatch())?;
                if catalog.replicas.len() > 4096
                    || !catalog
                        .pending
                        .iter()
                        .all(|id| catalog.replicas.contains_key(id))
                {
                    return Err(descriptor_mismatch());
                }
                Ok(catalog)
            }
            None => Ok(ReplicaCatalog::default()),
        }
    }
    pub(super) fn save_personal_replicas(&mut self, replicas: &ReplicaCatalog) -> VaultResult<()> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(replicas).map_err(|_| descriptor_mismatch())?);
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(VaultError::Protocol(
                "personal replica catalog is full".into(),
            ));
        }
        self.document
            .put(ROOT, REPLICAS, bytes.to_vec())
            .map_err(automerge_error)?;
        Ok(())
    }
    pub(super) fn record_personal_change(
        &mut self,
        address: &SecretAddress,
        deleted: bool,
    ) -> VaultResult<()> {
        if !self.is_personal() {
            return Ok(());
        }
        let (id, field) = address.as_local().ok_or_else(descriptor_mismatch)?;
        if field.is_some() {
            return Err(descriptor_mismatch());
        }
        let mut catalog = self.personal_replicas()?;
        let actor = self.document.get_actor().to_bytes();
        let mut replica = catalog
            .load(id, actor)?
            .unwrap_or(PersonalReplica::new(id, actor)?);
        let item = if deleted {
            None
        } else {
            let record = self
                .records(&address.storage_key())?
                .into_iter()
                .next()
                .ok_or_else(descriptor_mismatch)?;
            Some(PersonalSecret::decode_current(&record.value).map_err(|_| descriptor_mismatch())?)
        };
        replica.set(item.as_ref(), None)?;
        catalog.store(id, &mut replica, true)?;
        self.save_personal_replicas(&catalog)
    }
    /// Upgrade projected v4 records once. Old causal IDs are not translated into
    /// another graph: Automerge starts from the surviving value or tombstone.
    pub(crate) fn migrate_personal_replicas(&mut self) -> VaultResult<Option<DocumentMutation>> {
        if !self.is_personal()
            || self
                .document
                .get(ROOT, REPLICAS)
                .map_err(automerge_error)?
                .is_some()
        {
            return Ok(None);
        }
        self.mutate(|document| {
            let mut catalog = ReplicaCatalog::default();
            let actor = document.document.get_actor().to_bytes();
            for (key, address) in document.addresses()? {
                let (id, _) = address.as_local().ok_or_else(descriptor_mismatch)?;
                let record = document
                    .records(&key)?
                    .into_iter()
                    .next()
                    .ok_or_else(descriptor_mismatch)?;
                let item = PersonalSecret::decode_current(&record.value)
                    .map_err(|_| descriptor_mismatch())?;
                let mut replica = PersonalReplica::new(id, actor)?;
                replica.set(Some(&item), None)?;
                catalog.store(id, &mut replica, true)?;
            }
            if let Some((value, _)) = document
                .document
                .get(ROOT, "personal-revisions-v1")
                .map_err(automerge_error)?
            {
                let bytes = value.into_bytes().map_err(|_| descriptor_mismatch())?;
                for id in crate::personal::legacy_revision::tombstones(&bytes)? {
                    if catalog.replicas.contains_key(&id) {
                        return Err(descriptor_mismatch());
                    }
                    let mut replica = PersonalReplica::new(&id, actor)?;
                    replica.set(None, None)?;
                    catalog.store(&id, &mut replica, true)?;
                }
            }
            document.save_personal_replicas(&catalog)?;
            document.finish_mutation().map(Some)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personal::PERSONAL_SECRET_NAMESPACE;
    use crate::vault::{DeviceKeyId, DocumentKind, MutationContext, Provenance};

    #[test]
    fn legacy_journal_tombstones_migrate_once_without_resurrecting_values() {
        let mut document = SecretDocument::new(
            b"writer",
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
        )
        .unwrap();
        let live = PersonalSecret::generic("Live".into(), "value".into());
        let deleted = PersonalSecret::generic("Deleted".into(), "old password".into());
        let context = MutationContext {
            now: 10,
            provenance: &Provenance::Redacted,
            device_key_id: DeviceKeyId::from_bytes([7; 32]),
        };
        document
            .put(
                &SecretAddress::new(&live.id, None).unwrap(),
                &live.encode().unwrap(),
                None,
                &context,
            )
            .unwrap();
        // Recreate the previously committed v4 format and value-free journal.
        document.document.delete(ROOT, REPLICAS).unwrap();
        document
            .document
            .put(ROOT, "format-version", 4_u64)
            .unwrap();
        let journal = serde_json::json!({"revisions":[{"id":vec![1_u8;16],"item_id":deleted.id,"parent":null,"deleted":true}],"pending":[vec![1_u8;16]]});
        document
            .document
            .put(
                ROOT,
                "personal-revisions-v1",
                serde_json::to_vec(&journal).unwrap(),
            )
            .unwrap();
        let mutation = document.migrate_personal_replicas().unwrap().unwrap();
        let mut loaded = SecretDocument::load(
            &mutation.snapshot,
            b"restart",
            DocumentKind::LocalKeyring,
            Some(PERSONAL_SECRET_NAMESPACE),
        )
        .unwrap();
        let replicas = loaded.personal_replicas().unwrap();
        assert_eq!(replicas.pending.len(), 2);
        assert_eq!(
            replicas
                .load(&deleted.id, b"reader")
                .unwrap()
                .unwrap()
                .values()
                .unwrap(),
            vec![None]
        );
        assert_eq!(
            replicas
                .load(&live.id, b"reader")
                .unwrap()
                .unwrap()
                .values()
                .unwrap(),
            vec![Some(live)]
        );
        assert!(loaded.migrate_personal_replicas().unwrap().is_none());
        assert!(
            loaded
                .document
                .get(ROOT, "personal-revisions-v1")
                .unwrap()
                .is_none()
        );
    }
}
