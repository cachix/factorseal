//! Controller-signed membership and transport authorization. Trust in the first
//! controller fingerprint must come from explicit local enrollment, never a peer.
use super::{MemberId, MemberPublicKeys, Membership, ReaderIdentity, encode, invalid};
use crate::vault::{VaultResult, signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const DOMAIN: &[u8] = b"factorseal/sync/group-certificate/v1\0";
const MAX_EPOCHS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBinding {
    pub endpoint: [u8; 32],
    /// None grants storage/forwarding only; it adds no content recipient.
    pub reader: Option<MemberId>,
    pub name: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    version: u8,
    controller: MemberId,
    membership: Membership,
    previous: Option<[u8; 32]>,
    transports: Vec<TransportBinding>,
    enrollment: Option<[u8; 32]>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupCertificate {
    body: Body,
    #[serde(with = "super::bytes")]
    signature: Vec<u8>,
}
impl GroupCertificate {
    fn digest(&self) -> VaultResult<[u8; 32]> {
        Ok(Sha256::digest(encode(self)?).into())
    }
    fn payload(&self) -> VaultResult<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(encode(&self.body)?);
        Ok(bytes)
    }
}
/// Immutable verified chain. Serialization transports certificates, not trust.
#[derive(Clone)]
pub struct VerifiedGroup {
    chain: Vec<GroupCertificate>,
}
impl std::fmt::Debug for VerifiedGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedGroup")
            .field("epoch", &self.membership().epoch())
            .finish()
    }
}
impl VerifiedGroup {
    pub fn verify(chain: Vec<GroupCertificate>, trusted_controller: MemberId) -> VaultResult<Self> {
        if chain.is_empty() || chain.len() > MAX_EPOCHS || encode(&chain)?.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        let first = &chain[0].body;
        if first.controller != trusted_controller {
            return Err(invalid());
        }
        let controller = first.membership.member(trusted_controller)?;
        let mut previous = None;
        for (index, certificate) in chain.iter().enumerate() {
            let body = &certificate.body;
            if body.version != 1
                || body.controller != trusted_controller
                || body.previous != previous
                || body.membership.group() != first.membership.group()
                || body.membership.epoch() != index as u64 + 1
                || body.membership.member(trusted_controller)? != controller
            {
                return Err(invalid());
            }
            validate_transports(&body.membership, &body.transports)?;
            signature::verify(
                &controller.signing,
                &certificate.payload()?,
                &certificate.signature,
            )?;
            previous = Some(certificate.digest()?);
        }
        Ok(Self { chain })
    }
    pub fn decode(bytes: &[u8], trusted_controller: MemberId) -> VaultResult<Self> {
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        Self::verify(
            serde_json::from_slice(bytes).map_err(|_| invalid())?,
            trusted_controller,
        )
    }
    pub fn encode(&self) -> VaultResult<Vec<u8>> {
        encode(&self.chain)
    }
    #[must_use]
    pub fn membership(&self) -> &Membership {
        &self.current().body.membership
    }
    #[must_use]
    pub fn controller(&self) -> MemberId {
        self.current().body.controller
    }
    #[must_use]
    pub fn transports(&self) -> &[TransportBinding] {
        &self.current().body.transports
    }
    pub fn digest(&self) -> VaultResult<[u8; 32]> {
        self.current().digest()
    }
    #[must_use]
    pub fn enrollment(&self) -> Option<[u8; 32]> {
        self.current().body.enrollment
    }
    #[must_use]
    pub fn permits(&self, endpoint: &[u8; 32]) -> bool {
        self.transports()
            .iter()
            .any(|binding| &binding.endpoint == endpoint)
    }
    /// A successor must extend our pinned chain. Even a controller-signed fork
    /// at the same epoch is rejected rather than selected by arrival order.
    pub fn accept_extension(&self, incoming: &Self) -> VaultResult<()> {
        if incoming.controller() != self.controller()
            || incoming.chain.len() < self.chain.len()
            || incoming.chain[self.chain.len() - 1].digest()? != self.digest()?
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn current(&self) -> &GroupCertificate {
        self.chain.last().expect("verified nonempty chain")
    }
}
impl ReaderIdentity {
    pub fn create_group(&self, endpoint: [u8; 32], name: String) -> VaultResult<VerifiedGroup> {
        let mut group = [0; 16];
        getrandom::fill(&mut group)?;
        let membership = Membership::new(group, 1, vec![self.public_keys().clone()])?;
        let body = Body {
            version: 1,
            controller: self.public_keys().id(),
            membership,
            previous: None,
            transports: vec![TransportBinding {
                endpoint,
                reader: Some(self.public_keys().id()),
                name,
            }],
            enrollment: None,
        };
        let certificate = self.sign_group(body)?;
        VerifiedGroup::verify(vec![certificate], self.public_keys().id())
    }
    pub fn advance_group(
        &self,
        current: &VerifiedGroup,
        members: Vec<MemberPublicKeys>,
        mut transports: Vec<TransportBinding>,
        enrollment: Option<[u8; 32]>,
    ) -> VaultResult<VerifiedGroup> {
        if current.controller() != self.public_keys().id() {
            return Err(invalid());
        }
        transports.sort_by_key(|binding| binding.endpoint);
        let body = Body {
            version: 1,
            controller: current.controller(),
            membership: Membership::new(
                current.membership().group(),
                current
                    .membership()
                    .epoch()
                    .checked_add(1)
                    .ok_or_else(invalid)?,
                members,
            )?,
            previous: Some(current.digest()?),
            transports,
            enrollment,
        };
        let mut chain = current.chain.clone();
        chain.push(self.sign_group(body)?);
        VerifiedGroup::verify(chain, current.controller())
    }
    fn sign_group(&self, body: Body) -> VaultResult<GroupCertificate> {
        validate_transports(&body.membership, &body.transports)?;
        let mut certificate = GroupCertificate {
            body,
            signature: Vec::new(),
        };
        certificate.signature = signature::sign(&self.signing_seed, &certificate.payload()?)?;
        Ok(certificate)
    }
}
fn validate_transports(
    membership: &Membership,
    transports: &[TransportBinding],
) -> VaultResult<()> {
    let mut endpoints = std::collections::BTreeSet::new();
    let mut readers = std::collections::BTreeSet::new();
    if transports.is_empty() || transports.len() > 32 {
        return Err(invalid());
    }
    for binding in transports {
        if binding.endpoint == [0; 32]
            || !endpoints.insert(binding.endpoint)
            || binding.name.is_empty()
            || binding.name.len() > 80
            || binding.name.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        if let Some(reader) = binding.reader {
            membership.member(reader)?;
            if !readers.insert(reader) {
                return Err(invalid());
            }
        }
    }
    if readers.len() != membership.members().len() {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn anchored_chain_rejects_tampering_rollback_and_signed_forks() {
        let controller = ReaderIdentity::generate().unwrap();
        let outsider = ReaderIdentity::generate().unwrap();
        let first = controller.create_group([1; 32], "Laptop".into()).unwrap();
        let bytes = first.encode().unwrap();
        assert!(VerifiedGroup::decode(&bytes, outsider.public_keys().id()).is_err());
        let restored = VerifiedGroup::decode(&bytes, controller.public_keys().id()).unwrap();
        let next = controller
            .advance_group(
                &first,
                first.membership().members().to_vec(),
                first.transports().to_vec(),
                Some([2; 32]),
            )
            .unwrap();
        restored.accept_extension(&next).unwrap();
        assert!(next.accept_extension(&first).is_err());
        let fork = controller
            .advance_group(
                &first,
                first.membership().members().to_vec(),
                first.transports().to_vec(),
                Some([3; 32]),
            )
            .unwrap();
        assert!(next.accept_extension(&fork).is_err());
        let mut tampered = next.chain.clone();
        tampered[1].body.transports[0].name = "Attacker".into();
        assert!(VerifiedGroup::verify(tampered, controller.public_keys().id()).is_err());
        assert!(
            outsider
                .advance_group(
                    &first,
                    first.membership().members().to_vec(),
                    first.transports().to_vec(),
                    None
                )
                .is_err()
        );
    }
    #[test]
    fn storage_binding_adds_no_reader_and_every_reader_needs_one_endpoint() {
        let controller = ReaderIdentity::generate().unwrap();
        let first = controller.create_group([1; 32], "Laptop".into()).unwrap();
        let mut transports = first.transports().to_vec();
        transports.push(TransportBinding {
            endpoint: [2; 32],
            reader: None,
            name: "Server".into(),
        });
        let next = controller
            .advance_group(
                &first,
                first.membership().members().to_vec(),
                transports.clone(),
                None,
            )
            .unwrap();
        assert_eq!(next.membership().members().len(), 1);
        assert!(next.permits(&[2; 32]));
        transports[1].reader = Some(controller.public_keys().id());
        assert!(
            controller
                .advance_group(
                    &first,
                    first.membership().members().to_vec(),
                    transports,
                    None
                )
                .is_err()
        );
        assert!(controller.create_group([0; 32], "Laptop".into()).is_err());
    }
}
