//! Experimental portable personal updates and ciphertext storage.
//!
//! Membership passed to this module must already be authenticated by pairing or
//! a trusted membership controller. Validation of public keys alone does not
//! establish that a device belongs to the user. No transport credential is a
//! reader/writer identity. Network discovery and enrollment are separate layers.
mod identity;
mod packet;
mod spool;

pub use identity::{MemberId, MemberPublicKeys, Membership, ReaderIdentity};
pub use packet::{PacketId, PersonalUpdate, VerifiedPacket};
pub use spool::CiphertextSpool;

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
