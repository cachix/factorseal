//! Lease-bound personal sync work; no transport credentials or spool ownership.
use super::{
    DocumentKind, Provenance, SecretDocument, ServiceReason, StoreWorker, VaultError, VaultResult,
    unix_time,
};
use crate::personal::{
    PERSONAL_SECRET_NAMESPACE, PersonalSecret,
    replica::ReplicaHeads,
    sync::{
        MemberPublicKeys, Membership, PacketId, ReaderIdentity, ReceiveOutcome, SyncStatus,
        VerifiedPacket,
    },
};
use crate::vault::document::PreparedPublication;
mod pairing;
use crate::personal::sync::{PairingInvitation, PairingRequest, VerifiedGroup};
pub(crate) use pairing::PairingCommand;

pub(crate) enum SyncCommand {
    Identity,
    Group,
    PairingStatus,
    Pairing(PairingCommand),
    Membership,
    Configure(Membership),
    Prepare,
    Stored(PacketId),
    Receive(Vec<u8>),
    Status,
    Conflicts(String),
    Resolve {
        id: String,
        expected: ReplicaHeads,
        item: Option<Box<PersonalSecret>>,
    },
}

pub(crate) enum SyncReply {
    Identity(MemberPublicKeys),
    Group(VerifiedGroup),
    PairingStatus(Box<crate::personal::sync::PairingStatus>),
    Invitation(PairingInvitation),
    PairingRequest(PairingRequest),
    Membership(Membership),
    Prepared(Option<(Vec<u8>, Membership)>),
    Received(ReceiveOutcome),
    Status(SyncStatus),
    Conflicts(crate::personal::sync::PersonalConflict),
    Done,
}

impl StoreWorker {
    #[allow(clippy::too_many_lines)]
    pub(super) async fn personal_sync(&mut self, command: SyncCommand) -> VaultResult<SyncReply> {
        let scope = DocumentKind::LocalKeyring;
        let partition = PERSONAL_SECRET_NAMESPACE;
        let id = self.document_id(scope, partition);
        let (mut document, head) = match self.load_document(id, scope, Some(partition)).await? {
            Some(loaded) => (loaded.document, Some(loaded.head)),
            None => (
                SecretDocument::new(self.device.actor_id(), scope, partition)?,
                None,
            ),
        };
        let mut state = document.sync_state()?;
        if let Some(pinned) = &state.pairing.group {
            let group = pinned.verified()?;
            if state.membership.as_ref().map(Membership::digest)
                != Some(group.membership().digest())
            {
                return Err(not_configured());
            }
        }
        let mut replicas = document.sync_replicas()?;
        let provenance = Provenance::service(ServiceReason::PersonalSync);
        let context = self.context(&provenance, unix_time()?);
        let installation = self.device.installation_id();
        let vault = self.device.device_vault_id();
        let reply = match command {
            SyncCommand::PairingStatus => {
                return Ok(SyncReply::PairingStatus(Box::new(
                    crate::personal::sync::PairingStatus {
                        target: state
                            .pairing
                            .joining
                            .as_ref()
                            .map(|(_, _, pinned)| pinned.verified())
                            .transpose()?,
                        introduction: state
                            .pairing
                            .introduction
                            .as_ref()
                            .map(crate::personal::sync::pairing::PinnedGroup::verified)
                            .transpose()?,
                        invitation: state.pairing.invitation.clone().or_else(|| {
                            state
                                .pairing
                                .joining
                                .as_ref()
                                .map(|(invitation, _, _)| invitation.clone())
                        }),
                        request: state
                            .pairing
                            .joining
                            .as_ref()
                            .map(|(_, request, _)| request.clone())
                            .or_else(|| state.pairing.staged.clone()),
                        joining: state.pairing.joining.is_some(),
                    },
                )));
            }
            SyncCommand::Group => {
                return state
                    .pairing
                    .group
                    .as_ref()
                    .ok_or_else(not_configured)?
                    .verified()
                    .map(SyncReply::Group);
            }
            SyncCommand::Pairing(command) => {
                if state.reader.is_none() {
                    let identity = ReaderIdentity::generate()?;
                    state.reader = Some(self.secrets.protect_reader(
                        installation,
                        vault,
                        &identity,
                    )?);
                }
                let identity = self.secrets.open_reader(
                    installation,
                    vault,
                    state.reader.as_ref().expect("created reader"),
                )?;
                let previous = state.membership.as_ref().map(Membership::digest);
                let reply = pairing::handle(&mut state, &identity, command, unix_time()?)?;
                if previous != state.membership.as_ref().map(Membership::digest) {
                    state.prepared = None;
                    replicas.pending = replicas.replicas.keys().cloned().collect();
                }
                reply
            }
            SyncCommand::Membership => {
                return state
                    .membership
                    .ok_or_else(not_configured)
                    .map(SyncReply::Membership);
            }
            SyncCommand::Identity => {
                if let Some(wrapped) = &state.reader {
                    let identity = self.secrets.open_reader(installation, vault, wrapped)?;
                    return Ok(SyncReply::Identity(identity.public_keys().clone()));
                }
                if state.reader.is_none() {
                    let identity = ReaderIdentity::generate()?;
                    state.reader = Some(self.secrets.protect_reader(
                        installation,
                        vault,
                        &identity,
                    )?);
                }
                let identity = self.secrets.open_reader(
                    installation,
                    vault,
                    state.reader.as_ref().expect("created reader"),
                )?;
                SyncReply::Identity(identity.public_keys().clone())
            }
            SyncCommand::Configure(membership) => {
                if state.pairing.group.is_some()
                    || state.pairing.joining.is_some()
                    || state.pairing.introduction.is_some()
                {
                    return Err(VaultError::Protocol(
                        "signed membership is pinned; raw configuration is disabled".into(),
                    ));
                }
                let wrapped = state.reader.as_ref().ok_or_else(not_configured)?;
                let identity = self.secrets.open_reader(installation, vault, wrapped)?;
                if !membership.members().contains(identity.public_keys()) {
                    return Err(not_configured());
                }
                if let Some(current) = &state.membership {
                    if current.digest() == membership.digest() {
                        return Ok(SyncReply::Done);
                    }
                    if current.group() != membership.group()
                        || current.epoch() >= membership.epoch()
                    {
                        return Err(VaultError::Protocol(
                            "personal sync membership cannot roll back or change groups".into(),
                        ));
                    }
                }
                state.membership = Some(membership);
                state.prepared = None;
                replicas.pending = replicas.replicas.keys().cloned().collect();
                SyncReply::Done
            }
            SyncCommand::Prepare => {
                let membership = state.membership.as_ref().ok_or_else(not_configured)?;
                if let Some(prepared) = &state.prepared {
                    // The exact previously committed bytes survive edits and restarts.
                    VerifiedPacket::verify(&prepared.packet, membership)?;
                    return Ok(SyncReply::Prepared(Some((
                        prepared.packet.clone(),
                        membership.clone(),
                    ))));
                }
                let Some(item_id) = replicas.pending.iter().next().cloned() else {
                    return Ok(SyncReply::Prepared(None));
                };
                let identity = self.secrets.open_reader(
                    installation,
                    vault,
                    state.reader.as_ref().ok_or_else(not_configured)?,
                )?;
                let mut replica = document.sync_replica(&item_id)?;
                let heads = replica.heads();
                let update = replica.update()?;
                let packet = identity.seal_update(&update, membership)?;
                state.prepared = Some(PreparedPublication {
                    item_id,
                    heads,
                    packet: packet.as_bytes().to_vec(),
                });
                SyncReply::Prepared(Some((packet.as_bytes().to_vec(), membership.clone())))
            }
            SyncCommand::Stored(packet_id) => {
                let prepared = state.prepared.as_ref().ok_or_else(not_configured)?;
                let membership = state.membership.as_ref().ok_or_else(not_configured)?;
                if VerifiedPacket::verify(&prepared.packet, membership)?.id() != packet_id {
                    return Err(VaultError::Protocol(
                        "unexpected personal publication receipt".into(),
                    ));
                }
                if document.sync_replica(&prepared.item_id)?.heads() == prepared.heads {
                    replicas.pending.remove(&prepared.item_id);
                }
                state.prepared = None;
                SyncReply::Done
            }
            SyncCommand::Receive(bytes) => {
                let membership = state.membership.as_ref().ok_or_else(not_configured)?;
                // Untrusted packet failures must not trigger the local integrity
                // failure latch and seal a healthy vault.
                let packet = VerifiedPacket::verify(&bytes, membership).map_err(rejected_packet)?;
                let identity = self.secrets.open_reader(
                    installation,
                    vault,
                    state.reader.as_ref().ok_or_else(not_configured)?,
                )?;
                let update = packet
                    .open(&identity, membership)
                    .map_err(rejected_packet)?;
                let (outcome, mutation) =
                    document.receive_personal(packet.id(), &update, &context)?;
                if let Some(mutation) = mutation {
                    self.commit_mutation(id, scope, head, mutation, &context)
                        .await?;
                }
                return Ok(SyncReply::Received(outcome));
            }
            SyncCommand::Status => {
                let mut conflicts = std::collections::BTreeMap::new();
                for item_id in replicas.replicas.keys() {
                    let mut replica = replicas
                        .load(item_id, self.device.actor_id())?
                        .ok_or_else(not_configured)?;
                    if replica.values()?.len() > 1 {
                        conflicts.insert(item_id.clone(), replica.heads());
                    }
                }
                let conflict_packets = state
                    .receipts
                    .iter()
                    .filter(|receipt| {
                        conflicts.get(&receipt.item_id).is_some_and(|heads| {
                            receipt.heads.iter().any(|head| heads.contains(head))
                        })
                    })
                    .count();
                return Ok(SyncReply::Status(SyncStatus {
                    applied_packets: state.receipts.len() - conflict_packets,
                    conflict_packets,
                    readers: state
                        .membership
                        .as_ref()
                        .map_or(0, |membership| membership.members().len()),
                    pending_publications: replicas.pending.len(),
                    prepared_packet: state
                        .prepared
                        .as_ref()
                        .map(|prepared| {
                            VerifiedPacket::verify(
                                &prepared.packet,
                                state.membership.as_ref().ok_or_else(not_configured)?,
                            )
                            .map(|packet| packet.id())
                        })
                        .transpose()?,
                    conflicted_items: conflicts.len(),
                }));
            }
            SyncCommand::Conflicts(id) => {
                return document.sync_conflicts(&id).map(SyncReply::Conflicts);
            }
            SyncCommand::Resolve {
                id: item_id,
                expected,
                item,
            } => {
                let mutation =
                    document.resolve_personal(&item_id, &expected, item.as_deref(), &context)?;
                self.commit_mutation(id, scope, head, mutation, &context)
                    .await?;
                return Ok(SyncReply::Done);
            }
        };
        let mutation = document.update_sync_state(&state, &replicas)?;
        self.commit_mutation(id, scope, head, mutation, &context)
            .await?;
        Ok(reply)
    }
}

fn not_configured() -> VaultError {
    VaultError::Protocol("personal sync reader or membership is not configured".into())
}
#[allow(clippy::needless_pass_by_value)]
fn rejected_packet(_: VaultError) -> VaultError {
    VaultError::Protocol("personal sync packet was rejected".into())
}

#[cfg(all(test, feature = "hardware"))]
mod tests;
