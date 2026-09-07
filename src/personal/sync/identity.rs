use hpke::{Deserializable, Kem as _, Serializable, kem::MlKem768};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{encode, invalid};
use crate::security::memory::LockedKey;
use crate::vault::{VaultResult, signature};

pub(super) type KemPrivate = <MlKem768 as hpke::Kem>::PrivateKey;
pub(super) type KemPublic = <MlKem768 as hpke::Kem>::PublicKey;
pub(super) const MAX_MEMBERS: usize = 16;

/// Fingerprint of both reader and writer public keys.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct MemberId(pub(super) [u8; 32]);

/// Public reader/writer identity; contains no transport credentials or secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberPublicKeys {
    #[serde(with = "super::bytes")]
    pub(super) encryption: Vec<u8>,
    #[serde(with = "super::bytes")]
    pub(super) signing: Vec<u8>,
}

impl MemberPublicKeys {
    #[must_use]
    pub fn id(&self) -> MemberId {
        let mut hash = Sha256::new();
        hash.update(b"factorseal/sync/member/v1\0");
        hash.update((self.encryption.len() as u64).to_be_bytes());
        hash.update(&self.encryption);
        hash.update((self.signing.len() as u64).to_be_bytes());
        hash.update(&self.signing);
        MemberId(hash.finalize().into())
    }

    pub(super) fn validate(&self) -> VaultResult<()> {
        KemPublic::from_bytes(&self.encryption).map_err(|_| invalid())?;
        signature::PreparedVerifyingKey::new(&self.signing)?;
        Ok(())
    }
}

/// Unlocked content authority. Seeds remain in locked, guarded allocations;
/// expanded cryptographic keys are temporary library-owned values.
pub struct ReaderIdentity {
    pub(crate) encryption_seed: LockedKey<64>,
    pub(crate) signing_seed: LockedKey<32>,
    public: MemberPublicKeys,
}

impl std::fmt::Debug for ReaderIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReaderIdentity([REDACTED])")
    }
}

impl ReaderIdentity {
    pub fn generate() -> VaultResult<Self> {
        let mut encryption_seed = LockedKey::zeroed()?;
        let mut signing_seed = LockedKey::zeroed()?;
        getrandom::fill(&mut encryption_seed[..])?;
        getrandom::fill(&mut signing_seed[..])?;
        Self::from_seeds(encryption_seed, signing_seed)
    }

    pub(crate) fn from_seeds(
        encryption_seed: LockedKey<64>,
        signing_seed: LockedKey<32>,
    ) -> VaultResult<Self> {
        let private = KemPrivate::from_bytes(&encryption_seed[..]).map_err(|_| invalid())?;
        let public = MemberPublicKeys {
            encryption: MlKem768::sk_to_pk(&private).to_bytes().to_vec(),
            signing: signature::public_key_for_seed(&signing_seed),
        };
        Ok(Self {
            encryption_seed,
            signing_seed,
            public,
        })
    }

    #[must_use]
    pub const fn public_keys(&self) -> &MemberPublicKeys {
        &self.public
    }

    #[cfg(feature = "fuzzing")]
    pub(super) fn synthetic() -> Self {
        Self::from_seeds(
            LockedKey::from_slice(&[3; 64]).unwrap(),
            LockedKey::from_slice(&[5; 32]).unwrap(),
        )
        .unwrap()
    }
}

/// A caller-authenticated membership epoch. `new` checks its structure, not its
/// authority: callers must authenticate enrollment before trusting these keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "MembershipWire", into = "MembershipWire")]
pub struct Membership {
    pub(super) group: [u8; 16],
    pub(super) epoch: u64,
    pub(super) members: Vec<MemberPublicKeys>,
    pub(super) digest: [u8; 32],
}

impl Membership {
    pub fn new(
        group: [u8; 16],
        epoch: u64,
        mut members: Vec<MemberPublicKeys>,
    ) -> VaultResult<Self> {
        if group == [0; 16] || epoch == 0 || members.is_empty() || members.len() > MAX_MEMBERS {
            return Err(invalid());
        }
        for member in &members {
            member.validate()?;
        }
        members.sort_by_key(MemberPublicKeys::id);
        if members.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        hash.update(b"factorseal/sync/membership/v1\0");
        hash.update(group);
        hash.update(epoch.to_be_bytes());
        hash.update(encode(&members)?);
        Ok(Self {
            group,
            epoch,
            members,
            digest: hash.finalize().into(),
        })
    }

    pub(super) fn member(&self, id: MemberId) -> VaultResult<&MemberPublicKeys> {
        self.members
            .iter()
            .find(|member| member.id() == id)
            .ok_or_else(invalid)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipWire {
    group: [u8; 16],
    epoch: u64,
    members: Vec<MemberPublicKeys>,
}
impl From<Membership> for MembershipWire {
    fn from(value: Membership) -> Self {
        Self {
            group: value.group,
            epoch: value.epoch,
            members: value.members,
        }
    }
}
impl TryFrom<MembershipWire> for Membership {
    type Error = crate::vault::VaultError;
    fn try_from(value: MembershipWire) -> Result<Self, Self::Error> {
        Self::new(value.group, value.epoch, value.members)
    }
}
impl Membership {
    #[must_use]
    pub const fn group(&self) -> [u8; 16] {
        self.group
    }
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    #[must_use]
    pub fn members(&self) -> &[MemberPublicKeys] {
        &self.members
    }
    #[must_use]
    pub(crate) const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}
