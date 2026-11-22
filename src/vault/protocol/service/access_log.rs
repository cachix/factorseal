//! Which application read which secret, kept only on this device.
//!
//! The log is held in memory while the vault is unsealed and written every
//! half minute and before sealing to a local-only `Authorization` document,
//! which is never listed, exported, archived, or replicated. Records older
//! than the retention window are dropped, and the whole document expires if
//! nothing is read for that long.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault::{
    DeclaredApplication, DocumentKind, DocumentOperation, Provenance, SecretAddress, ServiceReason,
    VaultError, VaultResult, VaultStore,
};

use crate::vault::history::bounded;

use super::super::{
    AccessOutcome, AccessRecord, AccessRequester, PermissionPrincipal, VaultApplicationContext,
};

const NAMESPACE: &[u8] = b"factorseal/access-log/v1";
const VERSION: u8 = 1;
pub(super) const RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;
const MAX_RECORDS: usize = 1000;
const MAX_STORED_BYTES: usize = 512 * 1024;
const MERGE_SECONDS: u64 = 60;
const SAVE_SECONDS: u64 = 30;

/// The secret a request was about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AccessTarget {
    pub(super) scope: DocumentKind,
    pub(super) namespace: Vec<u8>,
    pub(super) address: Option<SecretAddress>,
}

pub(super) fn program(
    principal: PermissionPrincipal,
    application: Option<&VaultApplicationContext>,
) -> AccessRequester {
    AccessRequester::Program {
        principal,
        application: application
            .map(DeclaredApplication::from)
            .filter(|declared| *declared != DeclaredApplication::default()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLog {
    version: u8,
    next_id: u64,
    records: VecDeque<AccessRecord>,
}

/// Newest record first.
#[derive(Default)]
pub(super) struct AccessLog {
    records: VecDeque<AccessRecord>,
    next_id: u64,
    unsaved: bool,
    saved_at: u64,
}

fn log_address() -> VaultResult<SecretAddress> {
    SecretAddress::new("records", None)
}

fn encoded_len(record: &AccessRecord) -> usize {
    serde_json::to_vec(record).map_or(usize::MAX, |bytes| bytes.len() + 1)
}

impl AccessLog {
    pub(super) fn load(store: &VaultStore, now: u64) -> Self {
        let stored = log_address()
            .and_then(|address| store.get_at(DocumentKind::Authorization, NAMESPACE, &address, now))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<StoredLog>(&bytes).ok())
            .filter(|stored| stored.version == VERSION);
        let Some(stored) = stored else {
            return Self {
                saved_at: now,
                ..Self::default()
            };
        };
        let mut log = Self {
            next_id: stored
                .records
                .iter()
                .map(|record| record.id.saturating_add(1))
                .fold(stored.next_id, u64::max),
            records: stored.records,
            unsaved: false,
            saved_at: now,
        };
        log.prune(now);
        log
    }

    pub(super) fn record(
        &mut self,
        requester: AccessRequester,
        target: AccessTarget,
        outcome: AccessOutcome,
        now: u64,
    ) {
        let requester = match requester {
            AccessRequester::Browser { origin } => AccessRequester::Browser {
                origin: bounded(&origin),
            },
            AccessRequester::App { package } => AccessRequester::App {
                package: bounded(&package),
            },
            AccessRequester::Website { origin } => AccessRequester::Website {
                origin: bounded(&origin),
            },
            program @ AccessRequester::Program { .. } => program,
        };
        let repeated = self.records.front_mut().filter(|newest| {
            newest.outcome == outcome
                && newest.requester == requester
                && newest.scope == target.scope
                && newest.namespace == target.namespace
                && newest.address == target.address
                && now.abs_diff(newest.at) < MERGE_SECONDS
        });
        if let Some(newest) = repeated {
            newest.at = newest.at.max(now);
            newest.count = newest.count.saturating_add(1);
        } else {
            self.records.push_front(AccessRecord {
                id: self.next_id,
                at: now,
                count: 1,
                outcome,
                requester,
                scope: target.scope,
                namespace: target.namespace,
                address: target.address,
            });
            self.next_id = self.next_id.saturating_add(1);
        }
        self.unsaved = true;
        self.prune(now);
    }

    fn prune(&mut self, now: u64) {
        let before = self.records.len();
        let oldest = now.saturating_sub(RETENTION_SECONDS);
        self.records.retain(|record| record.at > oldest);
        let mut bytes = 0_usize;
        let kept = self
            .records
            .iter()
            .take(MAX_RECORDS)
            .take_while(|record| {
                bytes = bytes.saturating_add(encoded_len(record));
                bytes <= MAX_STORED_BYTES
            })
            .count();
        self.records.truncate(kept);
        self.unsaved |= self.records.len() != before;
    }

    /// Records below `cursor`, newest first, that fit in `budget` bytes.
    pub(super) fn page(
        &mut self,
        cursor: Option<u64>,
        budget: usize,
        now: u64,
    ) -> (Vec<AccessRecord>, Option<u64>) {
        self.prune(now);
        let mut remaining = budget;
        let mut page: Vec<AccessRecord> = Vec::new();
        let mut next_cursor = None;
        for record in self
            .records
            .iter()
            .filter(|record| cursor.is_none_or(|cursor| record.id < cursor))
        {
            let bytes = encoded_len(record);
            if bytes > remaining {
                next_cursor = page.last().map(|record| record.id);
                break;
            }
            remaining -= bytes;
            page.push(record.clone());
        }
        (page, next_cursor)
    }

    /// Whether unsaved changes have waited long enough to be written.
    pub(super) fn due(&self, now: u64) -> bool {
        self.unsaved && now.saturating_sub(self.saved_at) >= SAVE_SECONDS
    }

    /// Write the log to the store if it changed.
    pub(super) fn save(&mut self, store: &VaultStore, now: u64) -> VaultResult<()> {
        #[derive(Serialize)]
        struct Borrowed<'a> {
            version: u8,
            next_id: u64,
            records: &'a VecDeque<AccessRecord>,
        }

        if !self.unsaved {
            return Ok(());
        }
        let address = log_address()?;
        let operation = match self.records.front() {
            None => DocumentOperation::Delete { address },
            Some(newest) => DocumentOperation::Put {
                address,
                value: Zeroizing::new(
                    serde_json::to_vec(&Borrowed {
                        version: VERSION,
                        next_id: self.next_id,
                        records: &self.records,
                    })
                    .map_err(|error| VaultError::Protocol(error.to_string()))?,
                ),
                evict_at: Some(newest.at.saturating_add(RETENTION_SECONDS)),
            },
        };
        store.mutate(
            DocumentKind::Authorization,
            NAMESPACE,
            vec![operation],
            &Provenance::service(ServiceReason::AccessLog),
            now,
        )?;
        self.unsaved = false;
        self.saved_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::PermissionPrincipal;

    fn program(name: &str) -> AccessRequester {
        AccessRequester::Program {
            principal: PermissionPrincipal {
                platform: crate::vault::CallerPlatform::Linux,
                user_id: "1000".into(),
                application_id: name.into(),
                executable_digest: [0; 32],
                signer_id: None,
            },
            application: None,
        }
    }

    fn target(item: &str) -> AccessTarget {
        AccessTarget {
            scope: DocumentKind::LocalKeyring,
            namespace: b"keyring".to_vec(),
            address: Some(SecretAddress::new(item, None).unwrap()),
        }
    }

    #[test]
    fn repeated_reads_share_a_record_until_a_minute_passes() {
        let mut log = AccessLog::default();
        log.record(
            program("/usr/bin/git"),
            target("token"),
            AccessOutcome::Allowed,
            100,
        );
        log.record(
            program("/usr/bin/git"),
            target("token"),
            AccessOutcome::Allowed,
            150,
        );
        log.record(
            program("/usr/bin/git"),
            target("token"),
            AccessOutcome::Allowed,
            209,
        );
        assert_eq!(log.records.len(), 1);
        assert_eq!((log.records[0].at, log.records[0].count), (209, 3));

        log.record(
            program("/usr/bin/git"),
            target("token"),
            AccessOutcome::Allowed,
            269,
        );
        log.record(
            program("/usr/bin/git"),
            target("token"),
            AccessOutcome::Denied,
            270,
        );
        log.record(
            program("/usr/bin/curl"),
            target("token"),
            AccessOutcome::Denied,
            271,
        );
        log.record(
            program("/usr/bin/curl"),
            target("other"),
            AccessOutcome::Denied,
            272,
        );
        let ids: Vec<_> = log.records.iter().map(|record| record.id).collect();
        assert_eq!(ids, [4, 3, 2, 1, 0]);
    }

    #[test]
    fn records_older_than_ninety_days_are_dropped() {
        let mut log = AccessLog::default();
        log.record(
            program("old"),
            target("token"),
            AccessOutcome::Allowed,
            1_000,
        );
        log.record(
            program("new"),
            target("token"),
            AccessOutcome::Allowed,
            2_000,
        );
        let (page, _) = log.page(None, usize::MAX, 1_000 + RETENTION_SECONDS);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].requester, program("new"));
        let (page, _) = log.page(None, usize::MAX, 2_000 + RETENTION_SECONDS);
        assert_eq!(page.len(), 0);
    }

    #[test]
    fn the_log_keeps_the_newest_records_within_its_bounds() {
        let mut log = AccessLog::default();
        for index in 0..MAX_RECORDS + 5 {
            let item = format!("item-{index}");
            log.record(program("app"), target(&item), AccessOutcome::Allowed, 10);
        }
        assert_eq!(log.records.len(), MAX_RECORDS);
        assert_eq!(log.records[0].id, u64::try_from(MAX_RECORDS + 4).unwrap());

        let wide = "x".repeat(4 * 1024);
        for index in 0..200 {
            log.record(
                program(&wide),
                target(&format!("{index}")),
                AccessOutcome::Denied,
                20,
            );
        }
        let stored: usize = log.records.iter().map(encoded_len).sum();
        assert!(stored <= MAX_STORED_BYTES);
        assert_eq!(log.records[0].requester, program(&wide));
    }

    #[test]
    fn pages_continue_below_the_last_record() {
        let mut log = AccessLog::default();
        for index in 0..5 {
            log.record(
                program("app"),
                target(&format!("{index}")),
                AccessOutcome::Allowed,
                10,
            );
        }
        let one = encoded_len(&log.records[0]);
        let (first, cursor) = log.page(None, one * 2, 10);
        assert_eq!(first.iter().map(|r| r.id).collect::<Vec<_>>(), [4, 3]);
        assert_eq!(cursor, Some(3));
        let (rest, cursor) = log.page(cursor, usize::MAX, 10);
        assert_eq!(rest.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1, 0]);
        assert_eq!(cursor, None);
    }
}
