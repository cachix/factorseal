//! Bounded, in-memory project approval lifecycle.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::vault::{DocumentKind, Provenance, VaultError, VaultResult, VaultStore};

use super::super::grant::{GrantTarget, promote_permission};
use super::super::{
    CallerIdentity, GrantPermission, Permission, PermissionOperation, PermissionPrincipal,
    PermissionState, PermissionWaitStatus, VaultAction, VaultApplicationContext,
    VaultInteractionReference,
};
use crate::vault::signature::{permission_payload, verify};

const APPROVAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_PENDING_APPROVALS: usize = 128;
const MAX_PENDING_PER_CALLER: usize = 16;
const APPROVAL_RATE_WINDOW: Duration = Duration::from_mins(1);
const MAX_NEW_APPROVALS_PER_CALLER: usize = 8;
const MAX_NEW_APPROVALS: usize = 128;

pub(super) const PERMISSION_CONTROL_NAMESPACE: &[u8] = b"factorseal/permissions/v1";

pub(super) struct ApprovalCandidate {
    caller: CallerIdentity,
    application: VaultApplicationContext,
    scope: DocumentKind,
    namespace: Vec<u8>,
    permission: GrantPermission,
    operation: PermissionOperation,
}

struct ApprovalRecord {
    summary: Permission,
    caller: CallerIdentity,
    scope: DocumentKind,
    namespace: Vec<u8>,
    permission: GrantPermission,
}

struct ResolvedRecord {
    id: String,
    caller_fingerprint: [u8; 32],
    status: PermissionWaitStatus,
    retain_until: u64,
}

#[derive(Default)]
pub(super) struct PendingApprovals {
    records: VecDeque<ApprovalRecord>,
    resolved: VecDeque<ResolvedRecord>,
    revision: u64,
    // Successful creations only, retained across denial/approval. The global
    // rate cap bounds this queue even if callers continually change identity.
    recent_creations: VecDeque<(Instant, [u8; 32])>,
}

impl ApprovalCandidate {
    pub(super) fn for_request(
        caller: &CallerIdentity,
        application: Option<&VaultApplicationContext>,
        action: &VaultAction,
    ) -> Option<Self> {
        let application = application?.clone();
        let project = application.project.as_deref()?;
        let (scope, namespace, permission, operation) = match action {
            VaultAction::GetCache {
                project: requested,
                address,
            } if requested == project
                && address
                    .project()
                    .is_none_or(|address_project| address_project == project) =>
            {
                (
                    DocumentKind::SecretSpecProviderCache,
                    requested.as_bytes(),
                    GrantPermission::Get,
                    PermissionOperation::Get,
                )
            }
            VaultAction::PutCache {
                project: requested,
                address,
                ..
            } if requested == project
                && address
                    .project()
                    .is_none_or(|address_project| address_project == project) =>
            {
                (
                    DocumentKind::SecretSpecProviderCache,
                    requested.as_bytes(),
                    GrantPermission::Put,
                    PermissionOperation::Put,
                )
            }
            VaultAction::DeleteCache {
                project: requested,
                address,
            } if requested == project
                && address
                    .project()
                    .is_none_or(|address_project| address_project == project) =>
            {
                (
                    DocumentKind::SecretSpecProviderCache,
                    requested.as_bytes(),
                    GrantPermission::Delete,
                    PermissionOperation::Delete,
                )
            }
            // A namespace clear cannot be constrained to one project's
            // address prefix, so it and all non-CRUD actions are ineligible.
            _ => return None,
        };
        Some(Self {
            caller: caller.clone(),
            application,
            scope,
            namespace: namespace.to_vec(),
            permission,
            operation,
        })
    }
}

impl PendingApprovals {
    pub(super) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    fn purge_expired(&mut self, now: u64) {
        let before = self.records.len();
        let mut expired = Vec::new();
        self.records.retain(|record| match record.summary.state {
            PermissionState::Pending { expires_at, .. } if expires_at <= now => {
                expired.push((
                    record.summary.id.clone(),
                    record.caller.fingerprint(),
                    expires_at,
                ));
                false
            }
            PermissionState::Pending { .. } => true,
            PermissionState::Granted { .. } => false,
        });
        for (id, caller_fingerprint, expires_at) in expired {
            self.push_resolved(
                id,
                caller_fingerprint,
                PermissionWaitStatus::Expired,
                expires_at.saturating_add(APPROVAL_TTL_SECONDS),
            );
        }
        self.resolved.retain(|record| record.retain_until > now);
        if self.records.len() != before {
            self.revision = self.revision.wrapping_add(1);
        }
    }

    fn push_resolved(
        &mut self,
        id: String,
        caller_fingerprint: [u8; 32],
        status: PermissionWaitStatus,
        retain_until: u64,
    ) {
        if self.resolved.len() == MAX_PENDING_APPROVALS {
            self.resolved.pop_front();
        }
        self.resolved.push_back(ResolvedRecord {
            id,
            caller_fingerprint,
            status,
            retain_until,
        });
    }

    pub(super) fn create(
        &mut self,
        candidate: ApprovalCandidate,
        now: u64,
    ) -> VaultResult<VaultInteractionReference> {
        self.create_at(candidate, now, Instant::now())
    }

    fn create_at(
        &mut self,
        candidate: ApprovalCandidate,
        now: u64,
        monotonic_now: Instant,
    ) -> VaultResult<VaultInteractionReference> {
        self.purge_expired(now);
        let expires_at = now
            .checked_add(APPROVAL_TTL_SECONDS)
            .ok_or(VaultError::Expired)?;
        let fingerprint = candidate.caller.fingerprint();
        if let Some(existing) = self.records.iter().find(|record| {
            record.caller.fingerprint() == fingerprint
                && record.summary.application == candidate.application
                && record.namespace == candidate.namespace
                && record.permission == candidate.permission
        }) {
            let PermissionState::Pending { expires_at, .. } = existing.summary.state else {
                unreachable!("queue stores only pending records");
            };
            return Ok(VaultInteractionReference {
                id: existing.summary.id.clone(),
                expires_at,
            });
        }
        self.recent_creations.retain(|(created, _)| {
            monotonic_now.saturating_duration_since(*created) < APPROVAL_RATE_WINDOW
        });
        if self.records.len() >= MAX_PENDING_APPROVALS
            || self
                .records
                .iter()
                .filter(|record| record.caller.fingerprint() == fingerprint)
                .count()
                >= MAX_PENDING_PER_CALLER
            || self.recent_creations.len() >= MAX_NEW_APPROVALS
            || self
                .recent_creations
                .iter()
                .filter(|(_, caller)| *caller == fingerprint)
                .count()
                >= MAX_NEW_APPROVALS_PER_CALLER
        {
            return Err(VaultError::ApprovalLimited);
        }
        let mut id_bytes = [0_u8; 16];
        let mut challenge = [0_u8; 32];
        getrandom::fill(&mut id_bytes)?;
        getrandom::fill(&mut challenge)?;
        let id = format!("prm_{}", URL_SAFE_NO_PAD.encode(id_bytes));
        let summary = Permission {
            id: id.clone(),
            operation: candidate.operation,
            principal: PermissionPrincipal::from(&candidate.caller),
            application: candidate.application,
            state: PermissionState::Pending {
                created_at: now,
                expires_at,
                challenge,
            },
        };
        self.records.push_back(ApprovalRecord {
            summary,
            caller: candidate.caller,
            scope: candidate.scope,
            namespace: candidate.namespace,
            permission: candidate.permission,
        });
        self.recent_creations
            .push_back((monotonic_now, fingerprint));
        self.revision = self.revision.wrapping_add(1);
        Ok(VaultInteractionReference { id, expires_at })
    }

    pub(super) fn list(&mut self, now: u64) -> (u64, Vec<Permission>) {
        self.purge_expired(now);
        (
            self.revision,
            self.records
                .iter()
                .map(|record| record.summary.clone())
                .collect(),
        )
    }

    pub(super) fn deny(&mut self, id: &str, now: u64) -> VaultResult<()> {
        self.purge_expired(now);
        let index = self
            .records
            .iter()
            .position(|record| record.summary.id == id)
            .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
        let record = self.records.remove(index).expect("located above");
        let expires_at = match record.summary.state {
            PermissionState::Pending { expires_at, .. } => expires_at,
            PermissionState::Granted { .. } => unreachable!("queue stores only pending records"),
        };
        self.push_resolved(
            id.to_owned(),
            record.caller.fingerprint(),
            PermissionWaitStatus::Denied,
            expires_at.saturating_add(APPROVAL_TTL_SECONDS),
        );
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    pub(super) fn status(
        &mut self,
        caller: &CallerIdentity,
        id: &str,
        now: u64,
    ) -> Option<PermissionWaitStatus> {
        self.purge_expired(now);
        let fingerprint = caller.fingerprint();
        if self
            .records
            .iter()
            .any(|record| record.summary.id == id && record.caller.fingerprint() == fingerprint)
        {
            return Some(PermissionWaitStatus::Pending);
        }
        self.resolved
            .iter()
            .find(|record| record.id == id && record.caller_fingerprint == fingerprint)
            .map(|record| record.status)
    }

    pub(super) fn approve(
        &mut self,
        store: &VaultStore,
        id: &str,
        signature: &[u8],
        grant_duration_seconds: Option<u64>,
        now: u64,
        provenance: &Provenance,
    ) -> VaultResult<()> {
        self.purge_expired(now);
        let index = self
            .records
            .iter()
            .position(|record| record.summary.id == id)
            .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
        let record = &self.records[index];
        let PermissionState::Pending { challenge, .. } = record.summary.state else {
            return Err(VaultError::Protocol("permission is not pending".to_owned()));
        };
        verify(
            store.device().public_signing_key(),
            &permission_payload(&record.summary.id, &challenge, grant_duration_seconds),
            signature,
        )?;
        let grant_expires_at = grant_duration_seconds
            .map(|duration| now.checked_add(duration).ok_or(VaultError::Expired))
            .transpose()?;
        let project = record
            .summary
            .application
            .project
            .as_deref()
            .ok_or_else(|| VaultError::Protocol("permission has no project".to_owned()))?;
        let mut permission = record.summary.clone();
        permission.state = PermissionState::Granted {
            granted_at: now,
            expires_at: grant_expires_at,
        };
        promote_permission(
            store,
            &record.caller,
            GrantTarget::Project {
                scope: record.scope,
                namespace: &record.namespace,
                project,
            },
            record.permission,
            permission,
            now,
            provenance,
        )?;
        let caller_fingerprint = record.caller.fingerprint();
        self.records.remove(index);
        self.push_resolved(
            id.to_owned(),
            caller_fingerprint,
            PermissionWaitStatus::Granted,
            now.saturating_add(APPROVAL_TTL_SECONDS),
        );
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::CallerPlatform;

    fn candidate(caller: u8, project: usize) -> ApprovalCandidate {
        let project = format!("project-{project}");
        ApprovalCandidate {
            caller: CallerIdentity::new(
                CallerPlatform::Linux,
                "uid:1000",
                format!("app-{caller}"),
                [caller; 32],
                None,
            )
            .unwrap(),
            application: VaultApplicationContext::new(Some(project.clone()), None, None, None)
                .unwrap(),
            scope: DocumentKind::SecretSpecProviderCache,
            namespace: project.into_bytes(),
            permission: GrantPermission::Get,
            operation: PermissionOperation::Get,
        }
    }

    #[test]
    fn duplicate_approvals_do_not_refresh_expiry_or_revision_even_at_capacity() {
        let mut approvals = PendingApprovals::default();
        let instant = Instant::now();
        let original = approvals.create_at(candidate(0, 0), 100, instant).unwrap();
        for project in 1..MAX_NEW_APPROVALS_PER_CALLER {
            approvals
                .create_at(candidate(0, project), 100, instant)
                .unwrap();
        }
        let revision = approvals.revision();
        let repeated = approvals.create_at(candidate(0, 0), 200, instant).unwrap();
        assert_eq!(original.id, repeated.id);
        assert_eq!(original.expires_at, repeated.expires_at);
        assert_eq!(revision, approvals.revision());
        assert!(matches!(
            approvals.create_at(candidate(0, 99), 200, instant),
            Err(VaultError::ApprovalLimited)
        ));
    }

    #[test]
    fn approval_rate_survives_denial_and_wall_clock_changes() {
        let mut approvals = PendingApprovals::default();
        let instant = Instant::now();
        for project in 0..MAX_NEW_APPROVALS_PER_CALLER {
            let request = approvals
                .create_at(candidate(0, project), 100, instant)
                .unwrap();
            approvals.deny(&request.id, 100).unwrap();
        }
        for wall in [0, 100, 1_000_000] {
            assert!(matches!(
                approvals.create_at(candidate(0, 99), wall, instant),
                Err(VaultError::ApprovalLimited)
            ));
        }
        // Another caller still has a budget; advancing only the monotonic
        // clock replenishes the original caller's creation budget.
        approvals.create_at(candidate(1, 99), 100, instant).unwrap();
        approvals
            .create_at(candidate(0, 99), 100, instant + APPROVAL_RATE_WINDOW)
            .unwrap();
    }

    #[test]
    fn pending_quota_preserves_other_callers_and_existing_requests() {
        let mut approvals = PendingApprovals::default();
        let instant = Instant::now();
        for project in 0..MAX_PENDING_PER_CALLER {
            let batch = u32::try_from(project / MAX_NEW_APPROVALS_PER_CALLER).unwrap();
            approvals
                .create_at(
                    candidate(0, project),
                    100,
                    instant + APPROVAL_RATE_WINDOW * batch,
                )
                .unwrap();
        }
        let later = instant + APPROVAL_RATE_WINDOW * 3;
        let original_ids: Vec<_> = approvals
            .records
            .iter()
            .map(|record| record.summary.id.clone())
            .collect();
        assert!(matches!(
            approvals.create_at(candidate(0, 99), 100, later),
            Err(VaultError::ApprovalLimited)
        ));
        approvals.create_at(candidate(1, 99), 100, later).unwrap();
        for id in original_ids {
            assert_eq!(
                approvals.status(&candidate(0, 0).caller, &id, 100),
                Some(PermissionWaitStatus::Pending)
            );
        }
    }

    #[test]
    fn global_capacity_rejects_new_requests_without_evicting_pending_approvals() {
        let mut approvals = PendingApprovals::default();
        let instant = Instant::now();
        for index in 0..MAX_PENDING_APPROVALS {
            let caller = u8::try_from(index / MAX_NEW_APPROVALS_PER_CALLER).unwrap();
            approvals
                .create_at(candidate(caller, index), 100, instant)
                .unwrap();
        }
        let before: Vec<_> = approvals
            .records
            .iter()
            .map(|record| record.summary.id.clone())
            .collect();
        let revision = approvals.revision();
        assert!(matches!(
            approvals.create_at(candidate(99, 99), 100, instant + APPROVAL_RATE_WINDOW),
            Err(VaultError::ApprovalLimited)
        ));
        assert_eq!(
            before,
            approvals
                .records
                .iter()
                .map(|record| record.summary.id.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(revision, approvals.revision());
        // Expiration frees capacity.
        approvals
            .create_at(
                candidate(99, 99),
                100 + APPROVAL_TTL_SECONDS,
                instant + APPROVAL_RATE_WINDOW,
            )
            .unwrap();
    }

    #[test]
    fn global_rate_is_bounded_even_when_callers_rotate_and_requests_are_resolved() {
        let mut approvals = PendingApprovals::default();
        let instant = Instant::now();
        for index in 0..MAX_NEW_APPROVALS {
            let caller = u8::try_from(index / MAX_NEW_APPROVALS_PER_CALLER).unwrap();
            let request = approvals
                .create_at(candidate(caller, index), 100, instant)
                .unwrap();
            approvals.deny(&request.id, 100).unwrap();
        }
        assert!(matches!(
            approvals.create_at(candidate(99, 99), 100, instant),
            Err(VaultError::ApprovalLimited)
        ));
        approvals
            .create_at(candidate(99, 99), 100, instant + APPROVAL_RATE_WINDOW)
            .unwrap();
    }
}
