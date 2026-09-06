//! Bounded, value-free security events. Recording uses only saturating atomic
//! counters: no strings, caller IDs, timestamps, allocation, locks, or disk I/O.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    AuthorizationDenied,
    ApprovalLimited,
    ApprovalCreated,
    ApprovalDenied,
    ApprovalGranted,
    ReplayRejected,
    MalformedRequest,
    IntegrityFailure,
    VaultSealed,
    MemoryProtectionFailed,
}

const KINDS: [Kind; 10] = [
    Kind::AuthorizationDenied,
    Kind::ApprovalLimited,
    Kind::ApprovalCreated,
    Kind::ApprovalDenied,
    Kind::ApprovalGranted,
    Kind::ReplayRejected,
    Kind::MalformedRequest,
    Kind::IntegrityFailure,
    Kind::VaultSealed,
    Kind::MemoryProtectionFailed,
];
static COUNTS: [AtomicU64; 10] = [const { AtomicU64::new(0) }; 10];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvent {
    pub kind: Kind,
    pub count: u64,
}

pub fn record(kind: Kind) {
    let _ = COUNTS[kind as usize].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
}

/// Snapshot aggregate events for this process lifetime. Counts are diagnostic,
/// not a durable audit trail; recording never blocks vault operations on I/O.
#[must_use]
pub fn snapshot() -> Vec<SecurityEvent> {
    KINDS
        .into_iter()
        .zip(&COUNTS)
        .map(|(kind, count)| SecurityEvent {
            kind,
            count: count.load(Ordering::Relaxed),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_schema_has_only_fixed_kinds_and_counts() {
        record(Kind::ApprovalLimited);
        let events = serde_json::to_value(snapshot()).unwrap();
        let events = events.as_array().unwrap();
        assert_eq!(events.len(), KINDS.len());
        for event in events {
            let object = event.as_object().unwrap();
            assert_eq!(object.len(), 2);
            assert!(object["count"].is_u64());
            assert!(object["kind"].is_string());
        }
    }
}
