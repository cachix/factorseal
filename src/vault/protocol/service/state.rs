//! Synchronized replay, lease, purge, and fail-closed sealing state.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::vault::{VaultError, VaultResult, VaultStore};

use super::super::grant::{list_granted_permissions, revoke_permission};
use super::super::lease::{ReplayWindow, UnsealLease};
use super::super::{Permission, VaultInteractionReference};
use super::super::{RequestId, UnsealLeasePolicy};
use super::approvals::{ApprovalCandidate, PendingApprovals};

pub(super) struct ServiceState {
    live: Mutex<LiveState>,
    approval_changed: Condvar,
    // Kept outside `live` so lifecycle events can seal even after a request
    // panics while holding and poisoning the state mutex.
    seal_handle: VaultStore,
}

struct LiveState {
    store: VaultStore,
    lease: UnsealLease,
    replay: ReplayWindow,
    approvals: PendingApprovals,
    granted_permissions: Vec<Permission>,
    /// Whole second the storage eviction sweep last ran in. The sweep
    /// decrypts, verifies, and re-parses every cached document, while platform
    /// event loops poll expiration about ten times a second.
    last_purge_at: u64,
    #[cfg(all(test, feature = "hardware"))]
    purges: usize,
}

pub(super) struct LiveStateGuard<'a> {
    live: MutexGuard<'a, LiveState>,
    approval_changed: &'a Condvar,
}

impl ServiceState {
    pub(super) fn new(store: VaultStore, now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        let seal_handle = store.clone();
        Ok(Self {
            live: Mutex::new(LiveState {
                store,
                lease: UnsealLease::new(now, policy)?,
                replay: ReplayWindow::new(),
                approvals: PendingApprovals::default(),
                granted_permissions: Vec::new(),
                // Opening the store already swept this second.
                last_purge_at: now,
                #[cfg(all(test, feature = "hardware"))]
                purges: 0,
            }),
            approval_changed: Condvar::new(),
            seal_handle,
        })
    }

    pub(super) fn is_sealed(&self) -> bool {
        self.seal_handle.is_sealed()
    }

    pub(super) fn seal(&self) {
        self.seal_handle.seal();
        self.approval_changed.notify_all();
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
        Ok(LiveStateGuard {
            live,
            approval_changed: &self.approval_changed,
        })
    }

    pub(super) fn expire_if_needed(&self, now: u64, monotonic_now: Instant) -> VaultResult<bool> {
        if self.seal_handle.is_sealed() {
            self.approval_changed.notify_all();
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
            self.approval_changed.notify_all();
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
        &self.live.store
    }

    pub(super) fn create_approval(
        &mut self,
        candidate: ApprovalCandidate,
        now: u64,
    ) -> VaultResult<VaultInteractionReference> {
        let interaction = self.live.approvals.create(candidate, now)?;
        self.approval_changed.notify_all();
        Ok(interaction)
    }

    pub(super) fn list_permissions(&mut self, now: u64) -> VaultResult<(u64, Vec<Permission>)> {
        let (_, mut permissions) = self.live.approvals.list(now);
        let mut granted = list_granted_permissions(&self.live.store, now)?;
        granted.sort_by(|left, right| left.id.cmp(&right.id));
        if granted != self.live.granted_permissions {
            self.live.granted_permissions.clone_from(&granted);
            self.live.approvals.changed();
        }
        permissions.extend(granted);
        permissions.sort_by(|left, right| left.id.cmp(&right.id));
        Ok((self.live.approvals.revision(), permissions))
    }

    pub(super) fn deny_approval(&mut self, id: &str, now: u64) -> VaultResult<()> {
        self.live.approvals.deny(id, now)?;
        self.approval_changed.notify_all();
        Ok(())
    }

    pub(super) fn revoke_permission(&mut self, id: &str, now: u64) -> VaultResult<()> {
        revoke_permission(&self.live.store, id, now)?;
        self.live.approvals.changed();
        self.approval_changed.notify_all();
        Ok(())
    }

    pub(super) fn approve(
        &mut self,
        id: &str,
        signature: &[u8],
        grant_duration_seconds: Option<u64>,
        now: u64,
    ) -> VaultResult<()> {
        let LiveState {
            store, approvals, ..
        } = &mut *self.live;
        approvals.approve(store, id, signature, grant_duration_seconds, now)?;
        self.approval_changed.notify_all();
        Ok(())
    }

    pub(super) fn consume(&mut self, request_id: RequestId) -> VaultResult<()> {
        self.live.replay.consume(request_id)
    }

    pub(super) fn lease_deadlines(&self) -> (u64, u64) {
        (
            self.live.lease.idle_deadline,
            self.live.lease.absolute_deadline,
        )
    }

    pub(super) fn touch(&mut self, now: u64, monotonic_now: Instant) -> VaultResult<()> {
        self.live.lease.touch(now, monotonic_now)
    }
}

impl LiveStateGuard<'_> {
    pub(super) fn wait_for_approvals(
        mut self,
        after_revision: u64,
        timeout: Duration,
        now: u64,
    ) -> VaultResult<(u64, Vec<Permission>)> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| VaultError::Protocol("permission wait timeout overflows".to_owned()))?;
        loop {
            if self.live.store.is_sealed() || self.live.lease.is_expired(Instant::now()) {
                self.live.store.seal();
                return Err(VaultError::Sealed);
            }
            let current = self.list_permissions(now)?;
            if current.0 != after_revision {
                return Ok(current);
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(current);
            };
            let (live, result) = self
                .approval_changed
                .wait_timeout(self.live, remaining)
                .map_err(|_| VaultError::WorkerUnavailable)?;
            self.live = live;
            if result.timed_out() {
                return self.list_permissions(now);
            }
        }
    }
}
