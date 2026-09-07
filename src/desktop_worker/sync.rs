//! Management frames for inherited Desktop pipes only. Never application IPC.
use crate::personal::sync::{MemberId, PacketId, PairingInvitation, PairingRequest, VerifiedGroup};
use crate::{VaultError, VaultResult, VaultService};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
const MAX_FRAME: usize = 12 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicGroup {
    pub controller: MemberId,
    #[serde(with = "crate::personal::sync::bytes")]
    pub bytes: Vec<u8>,
}
impl PublicGroup {
    pub fn new(group: &VerifiedGroup) -> VaultResult<Self> {
        Ok(Self {
            controller: group.controller(),
            bytes: group.encode()?,
        })
    }
    pub fn verified(&self) -> VaultResult<VerifiedGroup> {
        VerifiedGroup::decode(&self.bytes, self.controller)
    }
}
#[derive(Serialize, Deserialize)]
pub enum Command {
    State,
    Initialize {
        endpoint: [u8; 32],
        name: String,
    },
    Invite,
    Offer {
        endpoint: [u8; 32],
        name: String,
    },
    Join {
        invitation: PairingInvitation,
        group: PublicGroup,
        endpoint: [u8; 32],
        name: String,
    },
    Stage {
        request: PairingRequest,
        peer: [u8; 32],
    },
    Approve([u8; 32]),
    ApproveJoin([u8; 32]),
    Accept(PublicGroup),
    Cancel,
    Prepare,
    Stored(PacketId),
    Receive(Vec<u8>),
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub group: Option<PublicGroup>,
    pub introduction: Option<PublicGroup>,
    pub target: Option<PublicGroup>,
    pub invitation: Option<PairingInvitation>,
    pub request: Option<PairingRequest>,
    pub joining: bool,
    pub pending: usize,
    pub conflicts: usize,
    pub readers: usize,
}
#[derive(Serialize, Deserialize)]
pub enum Reply {
    State(Box<State>),
    Group(PublicGroup),
    Packet(Option<Vec<u8>>),
    Done,
}
impl Command {
    pub fn execute(self, service: &VaultService) -> VaultResult<Reply> {
        let group = match self {
            Self::State => {
                let status = service.personal_sync_status()?;
                let pairing = service.personal_sync_pairing_status()?;
                return Ok(Reply::State(Box::new(State {
                    group: service
                        .personal_sync_group()
                        .ok()
                        .as_ref()
                        .map(PublicGroup::new)
                        .transpose()?,
                    target: pairing.target.as_ref().map(PublicGroup::new).transpose()?,
                    introduction: pairing
                        .introduction
                        .as_ref()
                        .map(PublicGroup::new)
                        .transpose()?,
                    invitation: pairing.invitation,
                    request: pairing.request,
                    joining: pairing.joining,
                    pending: status.pending_publications,
                    conflicts: status.conflicted_items,
                    readers: status.readers,
                })));
            }
            Self::Initialize { endpoint, name } => {
                service.initialize_personal_sync(endpoint, name)?
            }
            Self::Offer { endpoint, name } => {
                service.offer_personal_sync_connection(endpoint, name)?;
                return Self::State.execute(service);
            }
            Self::Invite => {
                service.invite_personal_sync_device()?;
                return Self::State.execute(service);
            }
            Self::Join {
                invitation,
                group,
                endpoint,
                name,
            } => {
                if service.personal_sync_group().is_err()
                    && service
                        .personal_sync_pairing_status()?
                        .introduction
                        .is_none()
                {
                    service.offer_personal_sync_connection(endpoint, name.clone())?;
                }
                service.request_personal_sync_pairing(
                    invitation,
                    group.verified()?,
                    endpoint,
                    name,
                )?;
                return Self::State.execute(service);
            }
            Self::Stage { request, peer } => {
                service.stage_personal_sync_pairing(request, peer)?;
                return Ok(Reply::Done);
            }
            Self::ApproveJoin(id) => {
                service.approve_personal_sync_join(id)?;
                return Self::State.execute(service);
            }
            Self::Approve(id) => service.approve_personal_sync_pairing(id)?,
            Self::Accept(group) => service.accept_personal_sync_group(group.verified()?)?,
            Self::Cancel => {
                service.cancel_personal_sync_pairing()?;
                return Ok(Reply::Done);
            }
            Self::Prepare => {
                return service
                    .prepare_personal_sync_publication()
                    .map(Reply::Packet);
            }
            Self::Stored(id) => {
                service.confirm_personal_sync_publication(id)?;
                return Ok(Reply::Done);
            }
            Self::Receive(bytes) => {
                service.receive_personal_sync(&bytes)?;
                return Ok(Reply::Done);
            }
        };
        Ok(Reply::Group(PublicGroup::new(&group)?))
    }
}
pub fn send(writer: &mut impl Write, value: &impl Serialize) -> std::io::Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    if bytes.len() > MAX_FRAME {
        return Err(std::io::Error::other("sync frame too large"));
    }
    writer.write_all(
        &u32::try_from(bytes.len())
            .map_err(std::io::Error::other)?
            .to_be_bytes(),
    )?;
    writer.write_all(&bytes)?;
    writer.flush()
}
pub fn receive<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> std::io::Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(std::io::Error::other("invalid sync frame"));
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}
#[must_use]
pub fn unavailable() -> VaultError {
    VaultError::Protocol("unlock the vault in this Desktop to manage devices".into())
}

#[cfg(feature = "personal-sync-network")]
pub mod network;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn management_frames_are_bounded_and_preserve_message_boundaries() {
        let mut bytes = Vec::new();
        send(&mut bytes, &Command::State).unwrap();
        send(&mut bytes, &Command::Cancel).unwrap();
        let mut input = bytes.as_slice();
        assert!(matches!(
            receive::<Command>(&mut input).unwrap(),
            Command::State
        ));
        assert!(matches!(
            receive::<Command>(&mut input).unwrap(),
            Command::Cancel
        ));
        assert!(receive::<Command>(&mut &u32::MAX.to_be_bytes()[..]).is_err());
        assert!(receive::<Command>(&mut &[0, 0, 0, 1, b'{'][..]).is_err());
    }
}
