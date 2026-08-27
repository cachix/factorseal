//! Synchronized replay, lease, purge, and fail-closed sealing state.

use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use crate::vault::{VaultError, VaultResult, VaultStore};

use super::super::lease::{ReplayWindow, UnsealLease};
use super::super::{PendingApproval, VaultInteractionReference};
use super::super::{RequestId, UnsealLeasePolicy};
use super::approvals::{ApprovalCandidate, PendingApprovals};

pub(super) struct ServiceState {
    live: Mutex<LiveState>,
    // Kept outside `live` so lifecycle events can seal even after a request
    // panics while holding and poisoning the state mutex.
    seal_handle: VaultStore,
}

struct LiveState {
    store: VaultStore,
    lease: UnsealLease,
    replay: ReplayWindow,
    approvals: PendingApprovals,
    /// Whole second the storage eviction sweep last ran in. The sweep
    /// decrypts, verifies, and re-parses every cached document, while platform
    /// event loops poll expiration about ten times a second.
    last_purge_at: u64,
    #[cfg(all(test, feature = "hardware"))]
    purges: usize,
}

pub(super) struct LiveStateGuard<'a>(MutexGuard<'a, LiveState>);

impl ServiceState {
    pub(super) fn new(store: VaultStore, now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        let seal_handle = store.clone();
        Ok(Self {
            live: Mutex::new(LiveState {
                store,
                lease: UnsealLease::new(now, policy)?,
                replay: ReplayWindow::new(),
                approvals: PendingApprovals::default(),
                // Opening the store already swept this second.
                last_purge_at: now,
                #[cfg(all(test, feature = "hardware"))]
                purges: 0,
            }),
            seal_handle,
        })
    }

    pub(super) fn is_sealed(&self) -> bool {
        self.seal_handle.is_sealed()
    }

    pub(super) fn seal(&self) {
        self.seal_handle.seal();
    }

    pub(super) fn lock_live(&self, now: Instant) -> VaultResult<LiveStateGuard<'_>> {
        if self.seal_handle.is_sealed() {
            return Err(VaultError::Sealed);
        }
        let live = self
            .live
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        if live.store.is_sealed() || live.lease.is_expired(now) {
            live.store.seal();
            return Err(VaultError::Sealed);
        }
        Ok(LiveStateGuard(live))
    }

    pub(super) fn expire_if_needed(&self, now: u64, monotonic_now: Instant) -> VaultResult<bool> {
        if self.seal_handle.is_sealed() {
            return Ok(true);
        }
        let mut live = self
            .live
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?;
        if live.store.is_sealed() {
            return Ok(true);
        }
        if live.lease.is_expired(monotonic_now) {
            live.store.seal();
            return Ok(true);
        }
        if live.last_purge_at != now {
            live.store.purge_expired_at(now)?;
            live.last_purge_at = now;
            #[cfg(all(test, feature = "hardware"))]
            {
                live.purges += 1;
            }
        }
        Ok(false)
    }

    #[cfg(all(test, feature = "hardware"))]
    pub(super) fn purge_count(&self) -> usize {
        self.live.lock().unwrap().purges
    }

    #[cfg(all(test, feature = "hardware"))]
    pub(super) fn idle_expires_at(&self) -> Instant {
        self.live.lock().unwrap().lease.idle_expires_at
    }

    /// Panic while holding the state mutex, the way a panicking request does.
    /// Callers wrap this in `catch_unwind`.
    #[cfg(all(test, feature = "hardware"))]
    pub(super) fn poison_for_test(&self) {
        let _state = self.live.lock().unwrap();
        panic!("poison request state");
    }
}

impl LiveStateGuard<'_> {
    pub(super) fn store(&self) -> &VaultStore {
        &self.0.store
    }

    pub(super) fn create_approval(
        &mut self,
        candidate: ApprovalCandidate,
        now: u64,
    ) -> VaultResult<VaultInteractionReference> {
        self.0.approvals.create(candidate, now)
    }

    pub(super) fn list_approvals(&mut self, now: u64) -> (u64, Vec<PendingApproval>) {
        self.0.approvals.list(now)
    }

    pub(super) fn deny_approval(&mut self, id: &str, now: u64) -> VaultResult<()> {
        self.0.approvals.deny(id, now)
    }

    pub(super) fn approve(
        &mut self,
        id: &str,
        signature: &[u8],
        grant_duration_seconds: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        let live = &mut *self.0;
        live.approvals
            .approve(&live.store, id, signature, grant_duration_seconds, now)
    }

    pub(super) fn consume(&mut self, request_id: RequestId) -> VaultResult<()> {
        self.0.replay.consume(request_id)
    }

    pub(super) fn lease_deadlines(&self) -> (u64, u64) {
        (self.0.lease.idle_deadline, self.0.lease.absolute_deadline)
    }

    pub(super) fn touch(&mut self, now: u64, monotonic_now: Instant) -> VaultResult<()> {
        self.0.lease.touch(now, monotonic_now)
    }
}
