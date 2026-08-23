use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::vault::{VaultError, VaultResult};

use super::RequestId;

const MAX_REPLAY_IDS: usize = 4096;

/// Bounded lifetime for one hardware-unsealed vault session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsealLeasePolicy {
    pub idle_timeout: Duration,
    pub maximum_lifetime: Duration,
}

impl Default for UnsealLeasePolicy {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_mins(5),
            maximum_lifetime: Duration::from_hours(8),
        }
    }
}

impl UnsealLeasePolicy {
    fn validate(self) -> VaultResult<()> {
        if self.idle_timeout.is_zero()
            || self.maximum_lifetime.is_zero()
            || self.idle_timeout > self.maximum_lifetime
        {
            return Err(VaultError::Protocol(
                "unseal lease timeouts are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

pub(super) struct UnsealLease {
    idle_timeout: Duration,
    pub(super) idle_deadline: u64,
    pub(super) absolute_deadline: u64,
    pub(super) idle_expires_at: Instant,
    absolute_expires_at: Instant,
}

impl UnsealLease {
    pub(super) fn new(now: u64, policy: UnsealLeasePolicy) -> VaultResult<Self> {
        Self::new_at(now, Instant::now(), policy)
    }

    pub(super) fn new_at(
        now: u64,
        monotonic_now: Instant,
        policy: UnsealLeasePolicy,
    ) -> VaultResult<Self> {
        policy.validate()?;
        let idle_timeout_seconds = policy.idle_timeout.as_secs();
        let absolute_deadline = now
            .checked_add(policy.maximum_lifetime.as_secs())
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?;
        let idle_deadline = now
            .checked_add(idle_timeout_seconds)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(absolute_deadline);
        let absolute_expires_at = monotonic_now
            .checked_add(policy.maximum_lifetime)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?;
        let idle_expires_at = monotonic_now
            .checked_add(policy.idle_timeout)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(absolute_expires_at);
        Ok(Self {
            idle_timeout: policy.idle_timeout,
            idle_deadline,
            absolute_deadline,
            idle_expires_at,
            absolute_expires_at,
        })
    }

    pub(super) fn is_expired(&self, monotonic_now: Instant) -> bool {
        monotonic_now >= self.idle_expires_at || monotonic_now >= self.absolute_expires_at
    }

    pub(super) fn touch(&mut self, now: u64, monotonic_now: Instant) -> VaultResult<()> {
        self.idle_deadline = now
            .checked_add(self.idle_timeout.as_secs())
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(self.absolute_deadline);
        self.idle_expires_at = monotonic_now
            .checked_add(self.idle_timeout)
            .ok_or_else(|| VaultError::Protocol("unseal lease overflows time".to_owned()))?
            .min(self.absolute_expires_at);
        Ok(())
    }
}

pub(super) struct ReplayWindow {
    set: HashSet<RequestId>,
    order: VecDeque<RequestId>,
}

impl ReplayWindow {
    pub(super) fn new() -> Self {
        Self {
            set: HashSet::with_capacity(MAX_REPLAY_IDS),
            order: VecDeque::with_capacity(MAX_REPLAY_IDS),
        }
    }

    pub(super) fn consume(&mut self, request_id: RequestId) -> VaultResult<()> {
        if !self.set.insert(request_id) {
            return Err(VaultError::Replay);
        }
        self.order.push_back(request_id);
        if self.order.len() > MAX_REPLAY_IDS
            && let Some(expired) = self.order.pop_front()
        {
            self.set.remove(&expired);
        }
        Ok(())
    }
}
