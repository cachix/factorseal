//! Short-lived pairing capabilities and signed, explicitly approved transcripts.
use super::{MemberId, MemberPublicKeys, ReaderIdentity, VerifiedGroup, encode, invalid};
use crate::vault::{VaultResult, signature};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};
const DOMAIN: &[u8] = b"factorseal/sync/pairing/v1\0";
const PREFIX: &str = "factorseal-sync:1:";

/// A bearer invitation. Display only on the inviting device, never in logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingInvitation {
    endpoint: [u8; 32],
    controller: MemberId,
    group: [u8; 32],
    expires: u64,
    secret: [u8; 32],
}
impl Drop for PairingInvitation {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl std::fmt::Debug for PairingInvitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingInvitation([REDACTED])")
    }
}
impl PairingInvitation {
    pub(crate) fn new(group: &VerifiedGroup, now: u64) -> VaultResult<Self> {
        let endpoint = group
            .transports()
            .iter()
            .find(|binding| binding.reader == Some(group.controller()))
            .ok_or_else(invalid)?
            .endpoint;
        let mut secret = [0; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self {
            endpoint,
            controller: group.controller(),
            group: group.digest()?,
            expires: now.checked_add(300).ok_or_else(invalid)?,
            secret,
        })
    }
    /// Compact QR/copy-paste ticket; public reader keys are exchanged separately.
    pub fn ticket(&self) -> VaultResult<Zeroizing<String>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(136));
        bytes.extend(self.endpoint);
        bytes.extend(self.controller.0);
        bytes.extend(self.group);
        bytes.extend(self.expires.to_be_bytes());
        bytes.extend(self.secret);
        Ok(Zeroizing::new(format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(&*bytes)
        )))
    }
    pub fn from_ticket(ticket: &str) -> VaultResult<Self> {
        if ticket.len() > 256 {
            return Err(invalid());
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(ticket.strip_prefix(PREFIX).ok_or_else(invalid)?)
                .map_err(|_| invalid())?,
        );
        if bytes.len() != 136 {
            return Err(invalid());
        }
        let array = |start: usize| -> VaultResult<[u8; 32]> {
            bytes[start..start + 32].try_into().map_err(|_| invalid())
        };
        Ok(Self {
            endpoint: array(0)?,
            controller: MemberId(array(32)?),
            group: array(64)?,
            expires: u64::from_be_bytes(bytes[96..104].try_into().map_err(|_| invalid())?),
            secret: array(104)?,
        })
    }
    #[must_use]
    pub fn endpoint(&self) -> [u8; 32] {
        self.endpoint
    }
    #[must_use]
    pub fn controller(&self) -> MemberId {
        self.controller
    }
    pub(crate) fn check(&self, group: &VerifiedGroup, now: u64) -> VaultResult<()> {
        if now >= self.expires
            || self.expires.saturating_sub(now) > 300
            || self.controller != group.controller()
            || self.group != group.digest()?
            || !group.transports().iter().any(|binding| {
                binding.endpoint == self.endpoint && binding.reader == Some(self.controller)
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn digest(&self) -> VaultResult<[u8; 32]> {
        Ok(Sha256::digest(Zeroizing::new(encode(self)?).as_slice()).into())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    invitation: [u8; 32],
    endpoint: [u8; 32],
    reader: MemberPublicKeys,
    name: String,
}
/// Contains public keys, a capability proof and a reader signature; no secrets.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    body: RequestBody,
    proof: [u8; 32],
    #[serde(with = "super::bytes")]
    signature: Vec<u8>,
}
impl std::fmt::Debug for PairingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingRequest")
            .field("name", &self.body.name)
            .finish_non_exhaustive()
    }
}
impl PairingRequest {
    pub fn decode(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() > 16 * 1024 {
            return Err(invalid());
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        request.validate()?;
        Ok(request)
    }
    pub fn encode(&self) -> VaultResult<Vec<u8>> {
        encode(self)
    }
    pub fn id(&self) -> VaultResult<[u8; 32]> {
        Ok(Sha256::digest(encode(self)?).into())
    }
    /// Compare on both devices before approving this exact request ID.
    pub fn verification_code(&self) -> VaultResult<String> {
        use std::fmt::Write as _;
        let mut code = String::with_capacity(12);
        for byte in &self.id()?[..6] {
            write!(&mut code, "{byte:02X}").map_err(|_| invalid())?;
        }
        Ok(code)
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.body.name
    }
    #[must_use]
    pub fn endpoint(&self) -> [u8; 32] {
        self.body.endpoint
    }
    pub(crate) fn reader(&self) -> &MemberPublicKeys {
        &self.body.reader
    }
    fn payload(&self) -> VaultResult<Vec<u8>> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(encode(&self.body)?);
        Ok(bytes)
    }
    fn signed_payload(&self) -> VaultResult<Vec<u8>> {
        let mut bytes = self.payload()?;
        bytes.extend(self.proof);
        Ok(bytes)
    }
    fn validate(&self) -> VaultResult<()> {
        if self.body.endpoint == [0; 32]
            || self.body.name.is_empty()
            || self.body.name.len() > 80
            || self.body.name.chars().any(char::is_control)
            || self.signature.len() > 4096
        {
            return Err(invalid());
        }
        self.body.reader.validate()?;
        signature::verify(
            &self.body.reader.signing,
            &self.signed_payload()?,
            &self.signature,
        )
        .map_err(|_| invalid())
    }
    pub(crate) fn verify(
        &self,
        invitation: &PairingInvitation,
        group: &VerifiedGroup,
        now: u64,
    ) -> VaultResult<()> {
        invitation.check(group, now)?;
        if self.body.invitation != invitation.digest()? {
            return Err(invalid());
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(&invitation.secret).map_err(|_| invalid())?;
        mac.update(&self.payload()?);
        mac.verify_slice(&self.proof).map_err(|_| invalid())?;
        self.validate()
    }
}
impl ReaderIdentity {
    pub(crate) fn request_pairing(
        &self,
        invitation: &PairingInvitation,
        group: &VerifiedGroup,
        endpoint: [u8; 32],
        name: String,
        now: u64,
    ) -> VaultResult<PairingRequest> {
        invitation.check(group, now)?;
        let mut request = PairingRequest {
            body: RequestBody {
                invitation: invitation.digest()?,
                endpoint,
                reader: self.public_keys().clone(),
                name,
            },
            proof: [0; 32],
            signature: Vec::new(),
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&invitation.secret).map_err(|_| invalid())?;
        mac.update(&request.payload()?);
        request.proof = mac.finalize().into_bytes().into();
        request.signature = signature::sign(&self.signing_seed, &request.signed_payload()?)?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinnedGroup {
    controller: MemberId,
    #[serde(with = "super::bytes")]
    bytes: Vec<u8>,
}
impl PinnedGroup {
    pub(crate) fn new(group: &VerifiedGroup) -> VaultResult<Self> {
        Ok(Self {
            controller: group.controller(),
            bytes: group.encode()?,
        })
    }
    pub(crate) fn verified(&self) -> VaultResult<VerifiedGroup> {
        VerifiedGroup::decode(&self.bytes, self.controller)
    }
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairingState {
    pub group: Option<PinnedGroup>,
    pub invitation: Option<PairingInvitation>,
    pub staged: Option<PairingRequest>,
    pub joining: Option<(PairingInvitation, PairingRequest, PinnedGroup)>,
    pub approved: Option<[u8; 32]>,
}

#[cfg(feature = "personal-sync-network")]
impl PairingInvitation {
    /// Sensitive SVG for local display. Do not publish or log invitation QRs.
    pub fn qr_svg(&self) -> VaultResult<Zeroizing<String>> {
        let ticket = self.ticket()?;
        let code = qrcode::QrCode::new(ticket.as_bytes()).map_err(|_| invalid())?;
        Ok(Zeroizing::new(
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(256, 256)
                .build(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invitation_expiry_binding_and_signed_request() {
        let a = ReaderIdentity::generate().unwrap();
        let b = ReaderIdentity::generate().unwrap();
        let group = a.create_group([1; 32], "Laptop".into()).unwrap();
        let invitation = PairingInvitation::new(&group, 100).unwrap();
        let ticket = invitation.ticket().unwrap();
        assert!(ticket.len() < 256);
        let restored = PairingInvitation::from_ticket(&ticket).unwrap();
        let request = b
            .request_pairing(&restored, &group, [2; 32], "Phone".into(), 101)
            .unwrap();
        request.verify(&invitation, &group, 399).unwrap();
        assert!(request.verify(&invitation, &group, 400).is_err());
        assert!(request.verify(&invitation, &group, 99).is_err());
        let decoded = PairingRequest::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(
            decoded.verification_code().unwrap(),
            request.verification_code().unwrap()
        );
        let mut changed = request.clone();
        changed.body.endpoint = [3; 32];
        assert!(changed.verify(&invitation, &group, 101).is_err());
        let other = PairingInvitation::new(&group, 100).unwrap();
        assert!(request.verify(&other, &group, 101).is_err());
        let next = a
            .advance_group(
                &group,
                group.membership().members().to_vec(),
                group.transports().to_vec(),
                None,
            )
            .unwrap();
        assert!(request.verify(&invitation, &next, 101).is_err());
        assert!(PairingInvitation::from_ticket(&"x".repeat(257)).is_err());
        #[cfg(feature = "personal-sync-network")]
        assert!(invitation.qr_svg().unwrap().contains("<svg"));
    }
}

/// Trusted management view of a pending pairing, available only while unlocked.
#[derive(Debug)]
pub struct PairingStatus {
    pub invitation: Option<PairingInvitation>,
    pub request: Option<PairingRequest>,
    pub joining: bool,
}
