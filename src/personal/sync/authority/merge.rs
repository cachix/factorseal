//! Bilateral approval for combining exact membership heads.
use super::*;
const MERGE_DOMAIN: &[u8] = b"factorseal/sync/merge-approval/v1\0";

/// Public, signed consent. Creating one requires explicit local approval.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeApproval {
    source_controller: MemberId,
    #[serde(with = "super::super::bytes")]
    source: Vec<u8>,
    target: [u8; 32],
    signer: MemberId,
    #[serde(with = "super::super::bytes")]
    signature: Vec<u8>,
}
impl MergeApproval {
    pub(crate) fn source_group(&self, target: &VerifiedGroup) -> VaultResult<VerifiedGroup> {
        self.verify(target, 0)
    }
    fn payload(&self) -> VaultResult<Vec<u8>> {
        let mut payload = MERGE_DOMAIN.to_vec();
        payload.extend(encode(&(
            self.source_controller,
            Sha256::digest(&self.source).to_vec(),
            self.target,
            self.signer,
        ))?);
        Ok(payload)
    }
    pub(super) fn source_at_depth(&self, depth: usize) -> VaultResult<VerifiedGroup> {
        if self.source.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        VerifiedGroup::verify_at_depth(
            serde_json::from_slice(&self.source).map_err(|_| invalid())?,
            self.source_controller,
            depth,
        )
    }
    pub(super) fn verify(
        &self,
        target: &VerifiedGroup,
        depth: usize,
    ) -> VaultResult<VerifiedGroup> {
        let source = self.source_at_depth(depth)?;
        if self.target != target.digest()? || self.signature.len() > 4096 {
            return Err(invalid());
        }
        let signer = source.membership().member(self.signer)?;
        signature::verify(&signer.signing, &self.payload()?, &self.signature)?;
        union(target, &source)?;
        Ok(source)
    }
}
impl ReaderIdentity {
    /// Approve sharing both groups' personal secrets with their combined readers.
    /// Consent binds both exact heads; a membership change requires fresh review.
    pub fn approve_group_merge(
        &self,
        source: &VerifiedGroup,
        target: &VerifiedGroup,
    ) -> VaultResult<MergeApproval> {
        source.membership().member(self.public_keys().id())?;
        union(target, source)?;
        let mut approval = MergeApproval {
            source_controller: source.controller(),
            source: source.encode()?,
            target: target.digest()?,
            signer: self.public_keys().id(),
            signature: Vec::new(),
        };
        approval.signature = signature::sign(&self.signing_seed, &approval.payload()?)?;
        Ok(approval)
    }
    /// Commit the target side's explicit approval and include the source's proof.
    pub fn merge_group(
        &self,
        target: &VerifiedGroup,
        approval: MergeApproval,
        enrollment: [u8; 32],
    ) -> VaultResult<VerifiedGroup> {
        target.membership().member(self.public_keys().id())?;
        let source = approval.verify(target, 1)?;
        let (members, transports) = union(target, &source)?;
        let body = Body {
            version: 2,
            controller: target.controller(),
            membership: Membership::new(
                target.membership().group(),
                target
                    .membership()
                    .epoch()
                    .checked_add(1)
                    .ok_or_else(invalid)?,
                members,
            )?,
            previous: Some(target.digest()?),
            transports,
            enrollment: Some(enrollment),
            signer: Some(self.public_keys().id()),
            merge: Some(approval),
        };
        let mut chain = target.chain.clone();
        chain.push(self.sign_group(body)?);
        VerifiedGroup::verify(chain, target.controller())
    }
}
pub(super) fn union(
    target: &VerifiedGroup,
    source: &VerifiedGroup,
) -> VaultResult<(Vec<MemberPublicKeys>, Vec<TransportBinding>)> {
    // Overlapping/forked groups need reconciliation, never silent selection.
    if target.membership().group() == source.membership().group() {
        return Err(invalid());
    }
    let mut members = target.membership().members().to_vec();
    for member in source.membership().members() {
        if members.iter().any(|old| old.id() == member.id()) {
            return Err(invalid());
        }
        members.push(member.clone());
    }
    let membership = Membership::new(target.membership().group(), 1, members)?;
    let mut transports = target.transports().to_vec();
    transports.extend_from_slice(source.transports());
    transports.sort_by_key(|binding| binding.endpoint);
    validate_transports(&membership, &transports)?;
    Ok((membership.members().to_vec(), transports))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_requires_both_signers_and_preserves_both_ancestries() {
        let a = ReaderIdentity::generate().unwrap();
        let b = ReaderIdentity::generate().unwrap();
        let c = ReaderIdentity::generate().unwrap();
        let ga = a.create_group([1; 32], "A".into()).unwrap();
        let gb = b.create_group([2; 32], "B".into()).unwrap();
        let gb = b
            .advance_group(
                &gb,
                gb.membership().members().to_vec(),
                gb.transports().to_vec(),
                Some([9; 32]),
            )
            .unwrap();
        let consent = b.approve_group_merge(&gb, &ga).unwrap();
        assert!(c.approve_group_merge(&gb, &ga).is_err());
        assert!(c.merge_group(&ga, consent.clone(), [7; 32]).is_err());
        let merged = a.merge_group(&ga, consent.clone(), [7; 32]).unwrap();
        ga.accept_extension(&merged).unwrap();
        gb.accept_extension(&merged).unwrap();
        assert!(merged.accept_extension(&ga).is_err());
        assert!(merged.accept_extension(&gb).is_err());
        assert!(merged.contains_enrollment([9; 32]));
        assert_eq!(merged.transports().len(), 2);
        let decoded = VerifiedGroup::decode(&merged.encode().unwrap(), ga.controller()).unwrap();
        gb.accept_extension(&decoded).unwrap();
        let mut forged = consent;
        forged.signature[0] ^= 1;
        assert!(a.merge_group(&ga, forged, [7; 32]).is_err());
        // A reader from the other former group can approve subsequent membership.
        let next = b
            .advance_group(
                &merged,
                merged.membership().members().to_vec(),
                merged.transports().to_vec(),
                None,
            )
            .unwrap();
        ga.accept_extension(&next).unwrap();
        gb.accept_extension(&next).unwrap();
    }
    #[test]
    fn stale_heads_forks_and_unrelated_groups_do_not_gain_trust() {
        let a = ReaderIdentity::generate().unwrap();
        let b = ReaderIdentity::generate().unwrap();
        let c = ReaderIdentity::generate().unwrap();
        let ga = a.create_group([1; 32], "A".into()).unwrap();
        let gb = b.create_group([2; 32], "B".into()).unwrap();
        let gc = c.create_group([3; 32], "C".into()).unwrap();
        let consent = b.approve_group_merge(&gb, &ga).unwrap();
        let newer_a = a
            .advance_group(
                &ga,
                ga.membership().members().to_vec(),
                ga.transports().to_vec(),
                None,
            )
            .unwrap();
        assert!(a.merge_group(&newer_a, consent.clone(), [1; 32]).is_err());
        let merged = a.merge_group(&ga, consent, [1; 32]).unwrap();
        assert!(newer_a.accept_extension(&merged).is_err());
        assert!(gc.accept_extension(&merged).is_err());
        let fork_b = b
            .advance_group(
                &gb,
                gb.membership().members().to_vec(),
                gb.transports().to_vec(),
                None,
            )
            .unwrap();
        assert!(fork_b.accept_extension(&merged).is_err());
        assert!(a.approve_group_merge(&ga, &ga).is_err());
        let mut tampered = merged.chain.clone();
        tampered.last_mut().unwrap().body.transports[0].name = "Changed after consent".into();
        assert!(VerifiedGroup::verify(tampered, ga.controller()).is_err());
    }
}
