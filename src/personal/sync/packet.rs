use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::{AeadTag, AesGcm256},
    inout::InOutBuf,
    kdf::HkdfSha256,
    kem::MlKem768,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    MemberId, Membership, ReaderIdentity, encode,
    identity::{KemPrivate, KemPublic, MAX_MEMBERS},
    invalid,
};
use crate::{
    EncryptionAlgorithm, crypto,
    personal::replica::PersonalUpdate,
    security::memory::{LockedKey, serialize_locked},
    vault::{VaultError, VaultResult, signature},
};

pub(super) const MAX_PACKET_BYTES: usize = 2 * 1024 * 1024;
const MAX_UPDATE_BYTES: usize = 1024 * 1024;
const SUITE: &str = "automerge-mlkem768-hkdfsha256-aes256gcm-mldsa65-v1";
const PACKET_DOMAIN: &[u8] = b"factorseal/sync/packet/v1\0";
const WRAP_DOMAIN: &[u8] = b"factorseal/sync/recipient-key/v1\0";

/// Ciphertext content address; never a hash of a password or plaintext item.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PacketId(pub(super) [u8; 32]);

impl std::fmt::Display for PacketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    suite: String,
    group: [u8; 16],
    epoch: u64,
    membership: [u8; 32],
    author: MemberId,
    operation: [u8; 16],
    recipients: Vec<MemberId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientKey {
    recipient: MemberId,
    #[serde(with = "super::bytes")]
    encapsulated: Vec<u8>,
    #[serde(with = "super::bytes")]
    wrapped: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    context: Context,
    nonce: [u8; 12],
    #[serde(with = "super::bytes")]
    ciphertext: Vec<u8>,
    keys: Vec<RecipientKey>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    body: Body,
    #[serde(with = "super::bytes")]
    signature: Vec<u8>,
}

/// Immutable, signature-checked ciphertext. This proves authenticity against
/// the supplied membership, not validity/application of the encrypted update.
pub struct VerifiedPacket {
    packet: Packet,
    bytes: Vec<u8>,
    id: PacketId,
}

impl std::fmt::Debug for VerifiedPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VerifiedPacket").field(&self.id).finish()
    }
}

impl VerifiedPacket {
    /// Validate public structure, exact recipient set, signature, and canonical
    /// encoding without any secret key. Recheck with the current membership on
    /// every trust-boundary crossing; a cached old verification is not revocation.
    pub fn verify(bytes: &[u8], membership: &Membership) -> VaultResult<Self> {
        if bytes.len() > MAX_PACKET_BYTES {
            return Err(invalid());
        }
        let packet: Packet = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        packet.validate(membership)?;
        if encode(&packet)? != bytes {
            return Err(invalid());
        }
        let author = membership.member(packet.body.context.author)?;
        signature::verify(&author.signing, &packet.signed_bytes()?, &packet.signature)?;
        Ok(Self {
            packet,
            bytes: bytes.to_vec(),
            id: PacketId(Sha256::digest(bytes).into()),
        })
    }

    #[must_use]
    pub const fn id(&self) -> PacketId {
        self.id
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Decrypt only after checking the caller's current membership again. This
    /// method does not apply revisions or acknowledge them in the local vault.
    pub fn open(
        &self,
        identity: &ReaderIdentity,
        membership: &Membership,
    ) -> VaultResult<PersonalUpdate> {
        self.packet.validate(membership)?;
        let recipient = identity.public_keys().id();
        membership.member(recipient)?;
        let wrapped = self
            .packet
            .body
            .keys
            .iter()
            .find(|key| key.recipient == recipient)
            .ok_or_else(invalid)?;
        let private =
            KemPrivate::from_bytes(&identity.encryption_seed[..]).map_err(|_| invalid())?;
        let encapsulated = <MlKem768 as hpke::Kem>::EncappedKey::from_bytes(&wrapped.encapsulated)
            .map_err(|_| invalid())?;
        let mut dek = LockedKey::<32>::zeroed()?;
        dek.copy_from_slice(&wrapped.wrapped[..32]);
        let tag =
            AeadTag::<AesGcm256>::from_bytes(&wrapped.wrapped[32..]).map_err(|_| invalid())?;
        let wrap_context = self.packet.body.wrap_context(recipient)?;
        hpke::single_shot_open_inout_detached::<AesGcm256, HkdfSha256, MlKem768>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            WRAP_DOMAIN,
            InOutBuf::from(&mut dek[..]),
            &wrap_context,
            &tag,
        )
        .map_err(|_| VaultError::Crypto)?;
        let plaintext = crypto::decrypt(
            EncryptionAlgorithm::Aes256Gcm,
            &dek,
            &self.packet.body.nonce,
            &encode(&self.packet.body.context)?,
            &self.packet.body.ciphertext,
        )
        .map_err(|_| VaultError::Crypto)?;
        if plaintext.len() > MAX_UPDATE_BYTES {
            return Err(invalid());
        }
        let update: PersonalUpdate = serde_json::from_slice(&plaintext).map_err(|_| invalid())?;
        update.validate()?;
        Ok(update)
    }
}

impl ReaderIdentity {
    pub fn seal_update(
        &self,
        update: &PersonalUpdate,
        membership: &Membership,
    ) -> VaultResult<VerifiedPacket> {
        update.validate()?;
        let author = self.public_keys().id();
        membership.member(author)?;
        let plaintext = serialize_locked(update, MAX_UPDATE_BYTES)?;
        let mut dek = LockedKey::<32>::zeroed()?;
        getrandom::fill(&mut dek[..])?;
        let mut operation = [0; 16];
        getrandom::fill(&mut operation)?;
        let context = Context {
            suite: SUITE.into(),
            group: membership.group,
            epoch: membership.epoch,
            membership: membership.digest,
            author,
            operation,
            recipients: membership
                .members
                .iter()
                .map(super::MemberPublicKeys::id)
                .collect(),
        };
        let encrypted = crypto::encrypt(&dek, &encode(&context)?, plaintext.as_slice())
            .map_err(|_| VaultError::Crypto)?;
        let mut body = Body {
            context,
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            keys: Vec::new(),
        };
        for member in &membership.members {
            let public = KemPublic::from_bytes(&member.encryption).map_err(|_| invalid())?;
            let (encapsulated, wrapped) =
                hpke::single_shot_seal::<AesGcm256, HkdfSha256, MlKem768>(
                    &OpModeS::Base,
                    &public,
                    WRAP_DOMAIN,
                    &dek[..],
                    &body.wrap_context(member.id())?,
                )
                .map_err(|_| VaultError::Crypto)?;
            body.keys.push(RecipientKey {
                recipient: member.id(),
                encapsulated: encapsulated.to_bytes().to_vec(),
                wrapped,
            });
        }
        let mut packet = Packet {
            body,
            signature: Vec::new(),
        };
        packet.signature = signature::sign(&self.signing_seed, &packet.signed_bytes()?)?;
        VerifiedPacket::verify(&encode(&packet)?, membership)
    }
}

impl Body {
    fn wrap_context(&self, recipient: MemberId) -> VaultResult<Vec<u8>> {
        let mut context = encode(&self.context)?;
        context.extend_from_slice(&recipient.0);
        context.extend_from_slice(&self.nonce);
        context.extend_from_slice(&Sha256::digest(&self.ciphertext));
        Ok(context)
    }
}

impl Packet {
    fn signed_bytes(&self) -> VaultResult<Vec<u8>> {
        let mut bytes = PACKET_DOMAIN.to_vec();
        bytes.extend_from_slice(&encode(&self.body)?);
        Ok(bytes)
    }

    fn validate(&self, membership: &Membership) -> VaultResult<()> {
        let context = &self.body.context;
        if context.suite != SUITE
            || context.group != membership.group
            || context.epoch != membership.epoch
            || context.membership != membership.digest
            || context.recipients
                != membership
                    .members
                    .iter()
                    .map(super::MemberPublicKeys::id)
                    .collect::<Vec<_>>()
            || self.body.keys.len() != context.recipients.len()
            || self.body.keys.len() > MAX_MEMBERS
            || self.body.ciphertext.len() < 16
            || self.body.ciphertext.len() > MAX_UPDATE_BYTES + 16
            || self.signature.len() > 8192
        {
            return Err(invalid());
        }
        membership.member(context.author)?;
        for (key, recipient) in self.body.keys.iter().zip(&context.recipients) {
            if key.recipient != *recipient || key.wrapped.len() != 48 {
                return Err(invalid());
            }
            <MlKem768 as hpke::Kem>::EncappedKey::from_bytes(&key.encapsulated)
                .map_err(|_| invalid())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz(bytes: &[u8]) {
    static MEMBERSHIP: std::sync::OnceLock<Membership> = std::sync::OnceLock::new();
    if bytes.len() > MAX_PACKET_BYTES {
        return;
    }
    let group = MEMBERSHIP.get_or_init(|| {
        Membership::new(
            [7; 16],
            1,
            vec![ReaderIdentity::synthetic().public_keys().clone()],
        )
        .unwrap()
    });
    if let Ok(packet) = VerifiedPacket::verify(bytes, group) {
        assert_eq!(packet.as_bytes(), bytes);
        let _ = packet.open(&ReaderIdentity::synthetic(), group);
    }
    if bytes.len() <= MAX_UPDATE_BYTES
        && let Ok(update) = serde_json::from_slice::<PersonalUpdate>(bytes)
    {
        let _ = update.validate();
    }
    if bytes.len() <= 8192
        && let Ok(member) = serde_json::from_slice::<super::MemberPublicKeys>(bytes)
    {
        let _ = Membership::new([7; 16], 1, vec![member]);
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_seeds() -> Vec<Vec<u8>> {
    let identity = ReaderIdentity::synthetic();
    let group = Membership::new([7; 16], 1, vec![identity.public_keys().clone()]).unwrap();
    let item =
        crate::personal::PersonalSecret::generic("Synthetic".into(), "synthetic-value".into());
    let mut replica =
        crate::personal::replica::PersonalReplica::new(&item.id, b"synthetic").unwrap();
    replica.set(Some(&item), None).unwrap();
    let update = replica.update().unwrap();
    vec![
        identity
            .seal_update(&update, &group)
            .unwrap()
            .as_bytes()
            .to_vec(),
        encode(&update).unwrap(),
        encode(identity.public_keys()).unwrap(),
    ]
}
