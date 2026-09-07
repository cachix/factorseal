use super::{ReaderIdentity, SyncReply, VaultResult, not_configured};
use crate::personal::sync::{
    PairingInvitation, PairingRequest, TransportBinding, VerifiedGroup, pairing::PinnedGroup,
};
use crate::vault::document::PersonalSyncState;

pub(crate) enum PairingCommand {
    Offer {
        endpoint: [u8; 32],
        name: String,
    },
    Initialize {
        endpoint: [u8; 32],
        name: String,
    },
    Invite,
    Join {
        invitation: PairingInvitation,
        group: VerifiedGroup,
        endpoint: [u8; 32],
        name: String,
    },
    Stage(PairingRequest),
    Approve([u8; 32]),
    ApproveJoin([u8; 32]),
    Accept(VerifiedGroup),
    Cancel,
}
#[allow(clippy::too_many_lines)]
pub(super) fn handle(
    state: &mut PersonalSyncState,
    identity: &ReaderIdentity,
    command: PairingCommand,
    now: u64,
) -> VaultResult<SyncReply> {
    let current = state
        .pairing
        .group
        .as_ref()
        .or(state.pairing.introduction.as_ref())
        .map(PinnedGroup::verified)
        .transpose()?;
    match command {
        PairingCommand::Offer { endpoint, name } => {
            let group = if let Some(group) = current {
                group
            } else {
                let group = identity.create_group(endpoint, name)?;
                state.pairing.introduction = Some(PinnedGroup::new(&group)?);
                group
            };
            let invitation =
                PairingInvitation::for_reader(&group, identity.public_keys().id(), now)?;
            state.pairing.invitation = Some(invitation.clone());
            state.pairing.staged = None;
            Ok(SyncReply::Invitation(invitation))
        }
        PairingCommand::Initialize { endpoint, name } => {
            if state.membership.is_some() || state.pairing.joining.is_some() {
                return Err(not_configured());
            }
            let group = identity.create_group(endpoint, name)?;
            install(state, &group)?;
            Ok(SyncReply::Group(group))
        }
        PairingCommand::Invite => {
            let group = current.ok_or_else(not_configured)?;
            if !group
                .membership()
                .members()
                .contains(identity.public_keys())
            {
                return Err(not_configured());
            }
            if let Some(invitation) = &state.pairing.invitation
                && invitation.check(&group, now).is_ok()
            {
                return Ok(SyncReply::Invitation(invitation.clone()));
            }
            let invitation =
                PairingInvitation::for_reader(&group, identity.public_keys().id(), now)?;
            state.pairing.invitation = Some(invitation.clone());
            state.pairing.staged = None;
            Ok(SyncReply::Invitation(invitation))
        }
        PairingCommand::Join {
            invitation,
            group,
            endpoint,
            name,
        } => {
            // Retrying does not generate a new randomized signature/transcript.
            if let Some((old, request, pinned)) = &state.pairing.joining {
                if old.ticket()? != invitation.ticket()?
                    || request.endpoint() != endpoint
                    || request.name() != name
                    || pinned.verified()?.digest()? != group.digest()?
                {
                    return Err(not_configured());
                }
                invitation.check(&group, now)?;
                return Ok(SyncReply::PairingRequest(request.clone()));
            }
            let request = if let Some(source) = &current {
                if source.accept_extension(&group).is_ok() || group.accept_extension(source).is_ok()
                {
                    return Err(crate::VaultError::Protocol(
                        "These devices are already connected".into(),
                    ));
                }
                identity.request_group_pairing(&invitation, &group, source, endpoint, name, now)?
            } else {
                identity.request_pairing(&invitation, &group, endpoint, name, now)?
            };
            state.pairing.invitation = None;
            state.pairing.staged = None;
            state.pairing.joining = Some((invitation, request.clone(), PinnedGroup::new(&group)?));
            Ok(SyncReply::PairingRequest(request))
        }
        PairingCommand::Stage(request) => {
            let group = current.ok_or_else(not_configured)?;
            request.verify(
                state
                    .pairing
                    .invitation
                    .as_ref()
                    .ok_or_else(not_configured)?,
                &group,
                now,
            )?;
            if !group
                .membership()
                .members()
                .contains(identity.public_keys())
                || group.permits(&request.endpoint())
                || group.membership().members().contains(request.reader())
            {
                return Err(not_configured());
            }
            if let Some(staged) = &state.pairing.staged
                && staged.id()? != request.id()?
            {
                return Err(not_configured());
            }
            state.pairing.staged = Some(request.clone());
            Ok(SyncReply::PairingRequest(request))
        }
        PairingCommand::Approve(expected) => {
            let group = current.ok_or_else(not_configured)?;
            if state.pairing.approved == Some(expected) {
                return Ok(SyncReply::Group(group));
            }
            let request = state.pairing.staged.as_ref().ok_or_else(not_configured)?;
            if request.id()? != expected {
                return Err(not_configured());
            }
            request.verify(
                state
                    .pairing
                    .invitation
                    .as_ref()
                    .ok_or_else(not_configured)?,
                &group,
                now,
            )?;
            let mut members = group.membership().members().to_vec();
            members.push(request.reader().clone());
            let mut transports = group.transports().to_vec();
            transports.push(TransportBinding {
                endpoint: request.endpoint(),
                reader: Some(request.reader().id()),
                name: request.name().into(),
            });
            let next = if let Some(approval) = request.merge_approval(&group)? {
                identity.merge_group(&group, approval, expected)?
            } else {
                identity.advance_group(&group, members, transports, Some(expected))?
            };
            install(state, &next)?;
            state.pairing.invitation = None;
            state.pairing.staged = None;
            state.pairing.approved = Some(expected);
            Ok(SyncReply::Group(next))
        }
        PairingCommand::ApproveJoin(expected) => {
            let (invitation, request, target) =
                state.pairing.joining.as_mut().ok_or_else(not_configured)?;
            let target = target.verified()?;
            invitation.check(&target, now)?;
            if request.id()? != expected {
                return Err(not_configured());
            }
            let source = current.ok_or_else(not_configured)?;
            if request.origin()?.ok_or_else(not_configured)?.digest()? != source.digest()? {
                return Err(not_configured());
            }
            identity.approve_pairing_merge(request, &target)?;
            Ok(SyncReply::PairingRequest(request.clone()))
        }
        PairingCommand::Accept(group) => {
            if let Some(current) = current {
                current.accept_extension(&group)?;
                if current.digest()? == group.digest()? {
                    return Ok(SyncReply::Group(group));
                }
            } else {
                let (_, request, pinned) =
                    state.pairing.joining.as_ref().ok_or_else(not_configured)?;
                pinned.verified()?.accept_extension(&group)?;
                if !group.contains_enrollment(request.id()?)
                    || !group.transports().iter().any(|binding| {
                        binding.endpoint == request.endpoint()
                            && binding.reader == Some(identity.public_keys().id())
                    })
                {
                    return Err(not_configured());
                }
            }
            if !group
                .membership()
                .members()
                .contains(identity.public_keys())
            {
                return Err(not_configured());
            }
            install(state, &group)?;
            state.pairing.joining = None;
            state.pairing.invitation = None;
            state.pairing.staged = None;
            Ok(SyncReply::Group(group))
        }
        PairingCommand::Cancel => {
            state.pairing.invitation = None;
            state.pairing.staged = None;
            state.pairing.joining = None;
            state.pairing.introduction = None;
            Ok(SyncReply::Done)
        }
    }
}
fn install(state: &mut PersonalSyncState, group: &VerifiedGroup) -> VaultResult<()> {
    state.pairing.group = Some(PinnedGroup::new(group)?);
    state.pairing.introduction = None;
    state.membership = Some(group.membership().clone());
    Ok(())
}
