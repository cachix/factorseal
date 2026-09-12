//! Trusted host-management entry points. These are deliberately absent from
//! application IPC: exposing enrollment or conflict values there would require
//! explicit management authorization and replay protection.
use super::{Instant, VaultError, VaultResult, VaultService};
use crate::personal::{
    PersonalSecret,
    replica::ReplicaHeads,
    sync::{
        CiphertextSpool, MemberPublicKeys, Membership, PacketId, PairingInvitation, PairingRequest,
        PairingStatus, PersonalConflict, ReceiveOutcome, SyncApplyPage, SyncStatus, VerifiedGroup,
    },
};
use crate::vault::store::{PairingCommand, SyncCommand, SyncReply};

impl VaultService {
    /// Create/load the reader identity without exporting its secret seeds.
    pub fn personal_sync_identity(&self) -> VaultResult<MemberPublicKeys> {
        match self.sync_command(SyncCommand::Identity)? {
            SyncReply::Identity(keys) => Ok(keys),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }

    /// Trusted host management only: the caller must authenticate membership
    /// through enrollment before invoking this. Never accept a network peer's
    /// proposed keys as authorization. Enforces a monotonic same-group epoch.
    pub fn configure_personal_sync(&self, membership: Membership) -> VaultResult<()> {
        self.sync_command(SyncCommand::Configure(membership))
            .map(|_| ())
    }

    pub fn personal_sync_status(&self) -> VaultResult<SyncStatus> {
        match self.sync_command(SyncCommand::Status)? {
            SyncReply::Status(status) => Ok(status),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }

    /// Publish up to `limit` pending heads. Each packet is committed in the
    /// encrypted vault first, then synced to the separate spool, then marked
    /// published. Any interruption is recoverable by retrying this method.
    /// This is local durable possession, never a peer's applied acknowledgement.
    pub fn publish_personal_sync(
        &self,
        spool: &mut CiphertextSpool,
        limit: usize,
    ) -> VaultResult<usize> {
        if limit == 0 || limit > 128 {
            return Err(VaultError::Protocol(
                "invalid publication batch limit".into(),
            ));
        }
        let mut count = 0;
        while count < limit {
            let SyncReply::Prepared(prepared) = self.sync_command(SyncCommand::Prepare)? else {
                return Err(VaultError::WorkerUnavailable);
            };
            let Some((bytes, membership)) = prepared else {
                break;
            };
            let id = spool.put(&bytes, &membership)?;
            self.sync_command(SyncCommand::Stored(id))?;
            count += 1;
        }
        Ok(count)
    }

    /// Reverify and apply one received ciphertext while the vault is unsealed.
    /// Returns only after any changed value, tombstone or conflict is durable.
    /// The caller retains the packet in its spool for further forwarding.
    pub fn receive_personal_sync(&self, packet: &[u8]) -> VaultResult<ReceiveOutcome> {
        if packet.len() > 2 * 1024 * 1024 {
            return Err(VaultError::Protocol(
                "personal sync packet is too large".into(),
            ));
        }
        match self.sync_command(SyncCommand::Receive(packet.to_vec()))? {
            SyncReply::Received(outcome) => Ok(outcome),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }

    /// Apply one page of ciphertext after unlock. The host resumes with `next`,
    /// and begins a new pass at None after reconnect/unlock. Repeated passes are
    /// safe: durable receipt and revision tracking makes replay idempotent.
    pub fn apply_personal_sync(
        &self,
        spool: &CiphertextSpool,
        after: Option<PacketId>,
        limit: usize,
    ) -> VaultResult<SyncApplyPage> {
        let SyncReply::Membership(membership) = self.sync_command(SyncCommand::Membership)? else {
            return Err(VaultError::WorkerUnavailable);
        };
        let ids = spool.inventory(after, limit)?;
        let mut page = SyncApplyPage::default();
        if ids.len() == limit {
            page.next = ids.last().copied();
        }
        for id in ids {
            let packet = match spool.get(id, &membership) {
                Ok(packet) => packet,
                Err(VaultError::Signature | VaultError::Crypto | VaultError::Protocol(_)) => {
                    page.rejected += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match self.receive_personal_sync(packet.as_bytes()) {
                Ok(ReceiveOutcome::Applied) => page.applied += 1,
                Ok(ReceiveOutcome::Duplicate) => page.duplicates += 1,
                Ok(ReceiveOutcome::Conflict) => page.conflicts += 1,
                // Protocol rejection includes malformed authorized payloads and
                // changed membership. Disk/lease failures abort the batch.
                Err(VaultError::Protocol(_)) => page.rejected += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(page)
    }

    /// Trusted host management only. Reveals competing personal values for an
    /// explicit user resolution; not an application IPC read bypass.
    pub fn personal_sync_conflicts(&self, id: &str) -> VaultResult<PersonalConflict> {
        match self.sync_command(SyncCommand::Conflicts(id.to_owned()))? {
            SyncReply::Conflicts(values) => Ok(values),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }

    /// Trusted host management only. The chosen value (or deletion) must follow
    /// an explicit user decision. `expected` is the sorted set of all observed
    /// head revision IDs; a newly arrived concurrent head rejects this decision.
    pub fn resolve_personal_sync(
        &self,
        id: &str,
        expected: &ReplicaHeads,
        item: Option<PersonalSecret>,
    ) -> VaultResult<()> {
        self.sync_command(SyncCommand::Resolve {
            id: id.to_owned(),
            expected: expected.clone(),
            item: item.map(Box::new),
        })
        .map(|_| ())
    }

    fn sync_command(&self, command: SyncCommand) -> VaultResult<SyncReply> {
        // Host operations share the live lease. Background sync activity does
        // not refresh it, and lifecycle sealing is independent of this mutex.
        let state = self.state.lock_live(Instant::now())?;
        state.store().personal_sync(command)
    }
}

impl VaultService {
    /// Create the first signed group. Transport credentials stay with the host.
    pub fn initialize_personal_sync(
        &self,
        endpoint: [u8; 32],
        name: String,
    ) -> VaultResult<VerifiedGroup> {
        self.pairing_group(PairingCommand::Initialize { endpoint, name })
    }
    /// Load the durably pinned public chain; never refreshes the unseal lease.
    pub fn personal_sync_group(&self) -> VaultResult<VerifiedGroup> {
        match self.sync_command(SyncCommand::Group)? {
            SyncReply::Group(group) => Ok(group),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Create an introduction without changing active membership.
    pub fn offer_personal_sync_connection(
        &self,
        endpoint: [u8; 32],
        name: String,
    ) -> VaultResult<PairingInvitation> {
        match self.sync_command(SyncCommand::Pairing(PairingCommand::Offer {
            endpoint,
            name,
        }))? {
            SyncReply::Invitation(invitation) => Ok(invitation),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Create/retrieve a five-minute invitation, persisted before display.
    pub fn invite_personal_sync_device(&self) -> VaultResult<PairingInvitation> {
        match self.sync_command(SyncCommand::Pairing(PairingCommand::Invite))? {
            SyncReply::Invitation(invitation) => Ok(invitation),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Call after scanning the ticket and fetching the chain from its pinned
    /// endpoint. This persists the joining transcript before sending it.
    pub fn request_personal_sync_pairing(
        &self,
        invitation: PairingInvitation,
        group: VerifiedGroup,
        endpoint: [u8; 32],
        name: String,
    ) -> VaultResult<PairingRequest> {
        match self.sync_command(SyncCommand::Pairing(PairingCommand::Join {
            invitation,
            group,
            endpoint,
            name,
        }))? {
            SyncReply::PairingRequest(request) => Ok(request),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Stage an incoming request for user review; this grants no membership.
    /// The host must pass the authenticated iroh peer identity, not a wire claim.
    pub fn stage_personal_sync_pairing(
        &self,
        request: PairingRequest,
        peer: [u8; 32],
    ) -> VaultResult<PairingRequest> {
        if request.endpoint() != peer {
            return Err(VaultError::Protocol("pairing endpoint mismatch".into()));
        }
        match self.sync_command(SyncCommand::Pairing(PairingCommand::Stage(request)))? {
            SyncReply::PairingRequest(request) => Ok(request),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Approve the joining group's exact, reviewed merge transcript.
    pub fn approve_personal_sync_join(&self, expected: [u8; 32]) -> VaultResult<PairingRequest> {
        match self.sync_command(SyncCommand::Pairing(PairingCommand::ApproveJoin(expected)))? {
            SyncReply::PairingRequest(request) => Ok(request),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Explicit user approval only, after comparing verification codes on both
    /// devices. Names the full reviewed request ID, never just a short code.
    pub fn approve_personal_sync_pairing(&self, expected: [u8; 32]) -> VaultResult<VerifiedGroup> {
        self.pairing_group(PairingCommand::Approve(expected))
    }
    /// Accept the approved joining response or extend an existing pinned chain.
    /// Unknown initial controllers and unsigned membership are never accepted.
    pub fn accept_personal_sync_group(&self, group: VerifiedGroup) -> VaultResult<VerifiedGroup> {
        self.pairing_group(PairingCommand::Accept(group))
    }
    pub fn cancel_personal_sync_pairing(&self) -> VaultResult<()> {
        self.sync_command(SyncCommand::Pairing(PairingCommand::Cancel))
            .map(|_| ())
    }
    fn pairing_group(&self, command: PairingCommand) -> VaultResult<VerifiedGroup> {
        match self.sync_command(SyncCommand::Pairing(command))? {
            SyncReply::Group(group) => Ok(group),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
}

impl VaultService {
    pub fn personal_sync_pairing_status(&self) -> VaultResult<PairingStatus> {
        match self.sync_command(SyncCommand::PairingStatus)? {
            SyncReply::PairingStatus(status) => Ok(*status),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
}

impl VaultService {
    /// Trusted inherited-pipe host only: persist exact bytes before returning.
    /// Confirm only after the independent ciphertext spool has fsynced them.
    pub fn prepare_personal_sync_publication(&self) -> VaultResult<Option<Vec<u8>>> {
        match self.sync_command(SyncCommand::Prepare)? {
            SyncReply::Prepared(packet) => Ok(packet.map(|(bytes, _)| bytes)),
            _ => Err(VaultError::WorkerUnavailable),
        }
    }
    /// Trusted host durable-storage receipt, never a network acknowledgement.
    pub fn confirm_personal_sync_publication(&self, id: PacketId) -> VaultResult<()> {
        self.sync_command(SyncCommand::Stored(id)).map(|_| ())
    }
}
