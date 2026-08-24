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

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id(value: u128) -> RequestId {
        RequestId::from_bytes(value.to_be_bytes())
    }

    #[test]
    fn replay_window_rejects_duplicates_but_evicts_the_oldest_ids() {
        let mut window = ReplayWindow::new();
        window.consume(request_id(0)).unwrap();
        assert!(matches!(
            window.consume(request_id(0)),
            Err(VaultError::Replay)
        ));

        for value in 1..=MAX_REPLAY_IDS {
            window.consume(request_id(value as u128)).unwrap();
        }

        // The window stays bounded, so the first identifier is eventually
        // forgotten while recently consumed identifiers remain protected.
        window.consume(request_id(0)).unwrap();
        assert!(matches!(
            window.consume(request_id(MAX_REPLAY_IDS as u128)),
            Err(VaultError::Replay)
        ));
    }

    #[test]
    fn lease_touch_never_extends_past_the_absolute_deadline() {
        let start = Instant::now();
        let policy = UnsealLeasePolicy {
            idle_timeout: Duration::from_secs(5),
            maximum_lifetime: Duration::from_secs(10),
        };
        let mut lease = UnsealLease::new_at(100, start, policy).unwrap();

        lease.touch(107, start + Duration::from_secs(7)).unwrap();
        assert_eq!(lease.idle_deadline, 110);
        assert!(lease.is_expired(start + Duration::from_secs(10)));
    }

    #[test]
    fn lease_rejects_invalid_policies_and_clock_overflow() {
        let start = Instant::now();
        assert!(
            UnsealLease::new_at(
                100,
                start,
                UnsealLeasePolicy {
                    idle_timeout: Duration::ZERO,
                    maximum_lifetime: Duration::from_secs(1),
                },
            )
            .is_err()
        );
        assert!(
            UnsealLease::new_at(
                u64::MAX,
                start,
                UnsealLeasePolicy {
                    idle_timeout: Duration::from_secs(1),
                    maximum_lifetime: Duration::from_secs(1),
                },
            )
            .is_err()
        );
    }
}
