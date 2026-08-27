//! Bounded, in-memory project approval lifecycle.

use std::collections::VecDeque;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::vault::{DocumentScope, VaultError, VaultResult, VaultStore};

use super::super::grant::{GrantTarget, store_grant};
use super::super::{
    ApprovalOperation, CallerIdentity, GrantPermission, PendingApproval, VaultAction,
    VaultApplicationContext, VaultInteractionReference,
};
use crate::vault::signature::{approval_payload, verify};

const APPROVAL_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_PENDING_APPROVALS: usize = 128;

pub(super) const APPROVAL_CONTROL_NAMESPACE: &[u8] = b"factorseal/approvals/v1";

pub(super) struct ApprovalCandidate {
    caller: CallerIdentity,
    application: VaultApplicationContext,
    scope: DocumentScope,
    namespace: Vec<u8>,
    permission: GrantPermission,
    operation: ApprovalOperation,
}

struct ApprovalRecord {
    summary: PendingApproval,
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
        application.project.as_ref()?;
        let (scope, namespace, permission, operation) = match action {
            VaultAction::GetCache { namespace, .. } => (
                DocumentScope::DeviceCache,
                namespace,
                GrantPermission::Get,
                ApprovalOperation::Get,
            ),
            VaultAction::PutCache { namespace, .. } => (
                DocumentScope::DeviceCache,
                namespace,
                GrantPermission::Put,
                ApprovalOperation::Put,
            ),
            VaultAction::DeleteCache { namespace, .. } => (
                DocumentScope::DeviceCache,
                namespace,
                GrantPermission::Delete,
                ApprovalOperation::Delete,
            ),
            VaultAction::ClearCache { namespace } => (
                DocumentScope::DeviceCache,
                namespace,
                GrantPermission::Clear,
                ApprovalOperation::Clear,
            ),
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
    fn purge_expired(&mut self, now: u64) {
        let before = self.records.len();
        self.records
            .retain(|record| record.summary.expires_at > now);
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
            existing.summary.expires_at = expires_at;
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
        let id = format!("apr_{}", URL_SAFE_NO_PAD.encode(id_bytes));
        let summary = PendingApproval {
            id: id.clone(),
            created_at: now,
            expires_at,
            operation: candidate.operation,
            application: candidate.application,
            challenge,
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

    pub(super) fn list(&mut self, now: u64) -> (u64, Vec<PendingApproval>) {
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
            .ok_or_else(|| VaultError::Protocol("approval is missing or expired".to_owned()))?;
        self.records.remove(index);
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }

    pub(super) fn approve(
        &mut self,
        store: &VaultStore,
        id: &str,
        signature: &[u8],
        now: u64,
    ) -> VaultResult<()> {
        self.purge_expired(now);
        let index = self
            .records
            .iter()
            .position(|record| record.summary.id == id)
            .ok_or_else(|| VaultError::Protocol("approval is missing or expired".to_owned()))?;
        let record = &self.records[index];
        verify(
            store.device().public_signing_key(),
            &approval_payload(&record.summary.id, &record.summary.challenge),
            signature,
        )?;
        let project = record
            .summary
            .application
            .project
            .as_deref()
            .ok_or_else(|| VaultError::Protocol("approval has no project".to_owned()))?;
        store_grant(
            store,
            &record.caller,
            GrantTarget::Project {
                scope: record.scope,
                namespace: &record.namespace,
                project,
            },
            [record.permission],
            None,
            now,
        )?;
        self.records.remove(index);
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
}
