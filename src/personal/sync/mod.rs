//! Experimental portable personal updates and ciphertext storage.
//!
//! Membership passed to this module must already be authenticated by pairing or
//! a trusted membership controller. Validation of public keys alone does not
//! establish that a device belongs to the user. No transport credential is a
//! reader/writer identity. Network discovery and enrollment are separate layers.
mod authority;
mod identity;
pub use authority::{GroupCertificate, TransportBinding, VerifiedGroup};
#[cfg(feature = "personal-sync-network")]
pub mod network;
mod packet;
mod spool;

pub use crate::personal::replica::{PersonalUpdate, ReplicaHeads};
pub use identity::{MemberId, MemberPublicKeys, Membership, ReaderIdentity};
pub use packet::{PacketId, VerifiedPacket};
pub use spool::CiphertextSpool;

/// Result returned only after the receiving vault transaction is durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Applied,
    Duplicate,
    Conflict,
}

/// Local publication/application status. It does not assert peer application.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncStatus {
    /// Received ciphertext packets durably incorporated, including ancestors
    /// superseded by a newer value or explicit resolution. Not peer receipts.
    pub applied_packets: usize,
    /// Received packets whose current values still require a user decision.
    pub conflict_packets: usize,
    pub readers: usize,
    pub pending_publications: usize,
    pub prepared_packet: Option<PacketId>,
    pub conflicted_items: usize,
}

/// One bounded pass over stored ciphertext. Rejected includes stale-epoch
/// packets; they remain stored, and never count as applied.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncApplyPage {
    pub applied: usize,
    pub duplicates: usize,
    pub conflicts: usize,
    pub rejected: usize,
    pub next: Option<PacketId>,
}

#[cfg(feature = "fuzzing")]
pub(crate) use packet::{fuzz, fuzz_seeds};

use crate::vault::{VaultError, VaultResult};

fn invalid() -> VaultError {
    VaultError::Protocol("invalid personal sync object".into())
}

fn encode(value: &impl serde::Serialize) -> VaultResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

mod bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        STANDARD.decode(value).map_err(serde::de::Error::custom)
    }
}

/// Competing Automerge register values and the heads a resolution must name.
/// Contains plaintext; available only to the unlocked trusted management host.
pub struct PersonalConflict {
    pub heads: ReplicaHeads,
    pub values: Vec<Option<crate::personal::PersonalSecret>>,
}
impl std::fmt::Debug for PersonalConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonalConflict([REDACTED])")
    }
}
