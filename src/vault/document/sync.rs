//! Local sync bookkeeping is separate from the replicated Automerge histories.
use super::{
    DocumentMutation, HistoryOperation, MutationContext, ROOT, ReadDoc, SecretAddress,
    SecretDocument, Transactable, VaultError, VaultResult, Zeroizing, automerge_error,
    descriptor_mismatch,
};
use crate::personal::{
    PersonalSecret,
    replica::{PersonalReplica, ReplicaHeads},
    sync::{Membership, PacketId, PersonalConflict, PersonalUpdate, ReceiveOutcome},
};
use crate::vault::keys::WrappedReaderIdentity;
use serde::{Deserialize, Serialize};
const STATE_KEY: &str = "personal-sync-v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedPublication {
    pub item_id: String,
    pub heads: ReplicaHeads,
    pub packet: Vec<u8>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersonalSyncState {
    pub reader: Option<WrappedReaderIdentity>,
    #[serde(default)]
    pub pairing: crate::personal::sync::pairing::PairingState,
    pub membership: Option<Membership>,
    pub prepared: Option<PreparedPublication>,
    pub receipts: Vec<ReceivedPacket>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceivedPacket {
    pub packet: PacketId,
    pub item_id: String,
    pub heads: ReplicaHeads,
}
impl SecretDocument {
    pub(crate) fn sync_state(&self) -> VaultResult<PersonalSyncState> {
        if !self.is_personal() {
            return Err(descriptor_mismatch());
        }
        match self
            .document
            .get(ROOT, STATE_KEY)
            .map_err(automerge_error)?
        {
            Some((value, _)) => {
                let bytes = Zeroizing::new(value.into_bytes().map_err(|_| descriptor_mismatch())?);
                if bytes.len() > 16 * 1024 * 1024 {
                    return Err(descriptor_mismatch());
                }
                serde_json::from_slice(&bytes).map_err(|_| descriptor_mismatch())
            }
            None => Ok(PersonalSyncState::default()),
        }
    }
    fn save_sync_state(&mut self, state: &PersonalSyncState) -> VaultResult<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(state).map_err(|_| descriptor_mismatch())?);
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(VaultError::Protocol("personal sync state is full".into()));
        }
        self.document
            .put(ROOT, "personal-layout", 1_u64)
            .map_err(automerge_error)?;
        self.document
            .put(ROOT, STATE_KEY, bytes.to_vec())
            .map_err(automerge_error)?;
        Ok(())
    }
    pub(crate) fn update_sync_state(
        &mut self,
        state: &PersonalSyncState,
        replicas: &super::replicas::ReplicaCatalog,
    ) -> VaultResult<DocumentMutation> {
        self.mutate(|document| {
            document.save_sync_state(state)?;
            document.save_personal_replicas(replicas)?;
            document.finish_mutation()
        })
    }
    pub(crate) fn sync_replicas(&self) -> VaultResult<super::replicas::ReplicaCatalog> {
        self.personal_replicas()
    }
    pub(crate) fn sync_replica(&self, id: &str) -> VaultResult<PersonalReplica> {
        self.personal_replicas()?
            .load(id, self.document.get_actor().to_bytes())?
            .ok_or_else(descriptor_mismatch)
    }
    pub(crate) fn sync_conflicts(&self, id: &str) -> VaultResult<PersonalConflict> {
        let mut replica = self.sync_replica(id)?;
        let values = replica.values()?;
        Ok(PersonalConflict {
            heads: replica.heads(),
            values,
        })
    }
    fn materialize_sync_value(
        &mut self,
        id: &str,
        values: &[Option<PersonalSecret>],
        context: &MutationContext<'_>,
    ) -> VaultResult<()> {
        let address = SecretAddress::new(id, None)?;
        match values.iter().find_map(Option::as_ref) {
            Some(item) => self.put_value_uncommitted(
                &address,
                &item.encode().map_err(|_| descriptor_mismatch())?,
                None,
                context,
                false,
            ),
            None => self
                .delete_value_uncommitted(&address, HistoryOperation::Delete, false)
                .map(|_| ()),
        }
    }
    pub(crate) fn receive_personal(
        &mut self,
        packet: PacketId,
        update: &PersonalUpdate,
        context: &MutationContext<'_>,
    ) -> VaultResult<(ReceiveOutcome, Option<DocumentMutation>)> {
        let mut state = self.sync_state()?;
        if state
            .receipts
            .iter()
            .any(|receipt| receipt.packet == packet)
        {
            return Ok((ReceiveOutcome::Duplicate, None));
        }
        if state.receipts.len() >= 4096 {
            return Err(VaultError::Protocol(
                "personal sync receipts are full".into(),
            ));
        }
        let id = update.item_id();
        let actor = self.document.get_actor().to_bytes();
        let mut catalog = self.personal_replicas()?;
        let mut replica = catalog
            .load(id, actor)?
            .unwrap_or(PersonalReplica::new(id, actor)?);
        let changed = replica.merge(update)?;
        let values = replica.values()?;
        let outcome = if !changed {
            ReceiveOutcome::Duplicate
        } else if values.len() > 1 {
            ReceiveOutcome::Conflict
        } else {
            ReceiveOutcome::Applied
        };
        let mut incoming = update.replica()?;
        state.receipts.push(ReceivedPacket {
            packet,
            item_id: id.to_owned(),
            heads: incoming.heads(),
        });
        // If a remote change incorporates an unpublished local edit, forwarding
        // the incoming packet already carries that history. Otherwise keep the
        // local pending marker: it will publish the merged document's heads.
        if replica.heads() == incoming.heads() {
            catalog.pending.remove(id);
        }
        catalog.store(id, &mut replica, false)?;
        let mutation = self.mutate(|document| {
            if changed {
                document.materialize_sync_value(id, &values, context)?;
            }
            document.save_sync_state(&state)?;
            document.save_personal_replicas(&catalog)?;
            document.finish_mutation()
        })?;
        Ok((outcome, Some(mutation)))
    }
    pub(crate) fn resolve_personal(
        &mut self,
        id: &str,
        expected: &ReplicaHeads,
        item: Option<&PersonalSecret>,
        context: &MutationContext<'_>,
    ) -> VaultResult<DocumentMutation> {
        let mut replica = self.sync_replica(id)?;
        if replica.values()?.len() < 2 {
            return Err(VaultError::Conflict);
        }
        replica.set(item, Some(expected))?;
        let mut catalog = self.personal_replicas()?;
        let values = replica.values()?;
        catalog.store(id, &mut replica, true)?;
        self.mutate(|document| {
            document.materialize_sync_value(id, &values, context)?;
            document.save_personal_replicas(&catalog)?;
            document.finish_mutation()
        })
    }
}
