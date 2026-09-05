//! A trusted caller's wall-clock sample advances while a request waits or runs.

use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy)]
pub(super) struct RequestTime {
    wall: u64,
    monotonic: Instant,
    started: Instant,
    system_started: SystemTime,
    wall_fraction: Duration,
}

impl RequestTime {
    pub(super) fn new(wall: u64, monotonic: Instant) -> Self {
        let system_started = SystemTime::now();
        let wall_fraction = Duration::from_nanos(u64::from(
            system_started
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos(),
        ));
        Self {
            wall,
            monotonic,
            started: Instant::now(),
            system_started,
            wall_fraction,
        }
    }

    pub(super) fn sample(self) -> (u64, Instant) {
        self.sample_at(Instant::now(), SystemTime::now())
    }

    fn sample_at(self, monotonic_now: Instant, system_now: SystemTime) -> (u64, Instant) {
        let elapsed = monotonic_now.saturating_duration_since(self.started);
        // A backwards wall-clock adjustment cannot extend an operation's
        // authorization. Forward adjustments do expire it immediately.
        let wall_elapsed = system_now
            .duration_since(self.system_started)
            .unwrap_or(Duration::ZERO)
            .max(elapsed);
        (
            self.wall
                .saturating_add(wall_elapsed.saturating_add(self.wall_fraction).as_secs()),
            self.monotonic
                .checked_add(elapsed)
                .unwrap_or_else(Instant::now),
        )
    }

    pub(super) fn wall(self) -> u64 {
        self.sample().0
    }

    pub(super) fn deadline(self, wall: u64) -> Instant {
        self.deadline_at(wall, Instant::now(), SystemTime::now())
    }

    fn deadline_at(self, wall: u64, now: Instant, system_now: SystemTime) -> Instant {
        let elapsed = system_now
            .duration_since(self.system_started)
            .unwrap_or_default()
            .max(now.saturating_duration_since(self.started));
        let remaining = Duration::from_secs(wall.saturating_sub(self.wall))
            .saturating_sub(self.wall_fraction)
            .saturating_sub(elapsed);
        now.checked_add(remaining).unwrap_or(now)
    }

    pub(super) fn check(self, deadline: Option<u64>) -> crate::vault::VaultResult<()> {
        if deadline.is_some_and(|deadline| self.wall() >= deadline) {
            return Err(crate::vault::VaultError::Expired);
        }
        Ok(())
    }
}

pub(super) fn tighten(target: &std::cell::Cell<Option<u64>>, deadline: Option<u64>) {
    if let Some(deadline) = deadline {
        target.set(Some(target.get().map_or(deadline, |old| old.min(deadline))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_time_advances_and_wall_rollback_does_not_extend_authority() {
        let mut clock = RequestTime::new(100, Instant::now());
        clock.wall_fraction = Duration::ZERO;
        let later = clock.started + Duration::from_secs(10);
        let (wall, monotonic) =
            clock.sample_at(later, clock.system_started - Duration::from_mins(1));
        assert_eq!(wall, 110);
        assert_eq!(monotonic, clock.monotonic + Duration::from_secs(10));
        assert_eq!(
            clock
                .sample_at(later, clock.system_started + Duration::from_secs(100))
                .0,
            200
        );
        assert_eq!(
            clock.deadline_at(110, clock.started, clock.system_started),
            clock.started + Duration::from_secs(10)
        );
        // A forward adjustment that does not yet expire the grant must still
        // shorten its subsequent monotonic delivery budget.
        assert_eq!(
            clock.deadline_at(150, later, clock.system_started + Duration::from_secs(30)),
            later + Duration::from_secs(20)
        );
    }

    #[test]
    fn independent_authorities_only_tighten_a_delivery_deadline() {
        let deadline = std::cell::Cell::new(None);
        for value in [Some(200), None, Some(150), Some(300)] {
            tighten(&deadline, value);
        }
        assert_eq!(deadline.get(), Some(150));
    }
}
