//! Bounded, in-memory project approval lifecycle.

use std::collections::VecDeque;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::vault::{DocumentKind, VaultError, VaultResult, VaultStore};

use super::super::grant::{GrantTarget, promote_permission};
use super::super::{
    CallerIdentity, GrantPermission, Permission, PermissionOperation, PermissionPrincipal,
    PermissionState, PermissionWaitStatus, VaultAction, VaultApplicationContext,
    VaultInteractionReference,
};
use crate::vault::signature::{permission_payload, verify};

const APPROVAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_PENDING_APPROVALS: usize = 128;

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
        self.purge_expired(now);
        let expires_at = now
            .checked_add(APPROVAL_TTL_SECONDS)
            .ok_or(VaultError::Expired)?;
        if let Some(existing) = self.records.iter_mut().find(|record| {
            record.caller.fingerprint() == candidate.caller.fingerprint()
                && record.summary.application == candidate.application
                && record.namespace == candidate.namespace
                && record.permission == candidate.permission
        }) {
            if let PermissionState::Pending {
                expires_at: current,
                ..
            } = &mut existing.summary.state
            {
                *current = expires_at;
            }
            self.revision = self.revision.wrapping_add(1);
            return Ok(VaultInteractionReference {
                id: existing.summary.id.clone(),
                expires_at,
            });
        }
        if self.records.len() == MAX_PENDING_APPROVALS {
            self.records.pop_front();
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
            grant_expires_at,
            now,
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
