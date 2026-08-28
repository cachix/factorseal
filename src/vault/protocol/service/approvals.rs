//! Bounded, in-memory project approval lifecycle.

use std::collections::VecDeque;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::vault::{DocumentScope, VaultError, VaultResult, VaultStore};

use super::super::grant::{GrantTarget, promote_permission};
use super::super::{
    CallerIdentity, GrantPermission, Permission, PermissionOperation, PermissionPrincipal,
    PermissionState, VaultAction, VaultApplicationContext, VaultInteractionReference,
};
use crate::vault::signature::{permission_payload, verify};

const APPROVAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_PENDING_APPROVALS: usize = 128;

pub(super) const PERMISSION_CONTROL_NAMESPACE: &[u8] = b"factorseal/permissions/v1";

pub(super) struct ApprovalCandidate {
    caller: CallerIdentity,
    application: VaultApplicationContext,
    scope: DocumentScope,
    namespace: Vec<u8>,
    permission: GrantPermission,
    operation: PermissionOperation,
}

struct ApprovalRecord {
    summary: Permission,
    caller: CallerIdentity,
    scope: DocumentScope,
    namespace: Vec<u8>,
    permission: GrantPermission,
}

#[derive(Default)]
pub(super) struct PendingApprovals {
    records: VecDeque<ApprovalRecord>,
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
            VaultAction::GetCache { namespace, address }
                if address.is_scoped_to_project(project) =>
            {
                (
                    DocumentScope::DeviceCache,
                    namespace,
                    GrantPermission::Get,
                    PermissionOperation::Get,
                )
            }
            VaultAction::PutCache {
                namespace, address, ..
            } if address.is_scoped_to_project(project) => (
                DocumentScope::DeviceCache,
                namespace,
                GrantPermission::Put,
                PermissionOperation::Put,
            ),
            VaultAction::DeleteCache { namespace, address }
                if address.is_scoped_to_project(project) =>
            {
                (
                    DocumentScope::DeviceCache,
                    namespace,
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
            namespace: namespace.clone(),
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
        self.records.retain(|record| {
            matches!(
                record.summary.state,
                PermissionState::Pending { expires_at, .. } if expires_at > now
            )
        });
        if self.records.len() != before {
            self.revision = self.revision.wrapping_add(1);
        }
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
        self.records.remove(index);
        self.revision = self.revision.wrapping_add(1);
        Ok(())
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
        self.records.remove(index);
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
}
