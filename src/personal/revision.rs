//! Local revision metadata and pending publication state.
//!
//! This journal is stored inside the signed, encrypted personal document. It is
//! not a network envelope. A pending live revision refers to the current item in
//! that same snapshot; a tombstone has no value. Only the newest local revision
//! of each item needs publication, accompanied by its causal metadata. There is
//! deliberately no retained copy of a superseded password here.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_REVISIONS: usize = 100_000;

/// Random local revision identity, independent of clocks and item titles.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct RevisionId([u8; 16]);

/// Value-free causal metadata. It still belongs inside encryption: item IDs and
/// edit relationships must not be published as plaintext transport inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalRevision {
    pub id: RevisionId,
    pub item_id: String,
    pub parent: Option<RevisionId>,
    pub deleted: bool,
}

/// Durable local publication journal. Network receive/conflict resolution and
/// authenticated remote acknowledgements are separate protocol work.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalState {
    revisions: Vec<PersonalRevision>,
    pending: BTreeSet<RevisionId>,
}

/// Validated local revision graph and durable pending publication state.
#[derive(Default)]
pub struct RevisionJournal {
    state: JournalState,
    heads: BTreeMap<String, RevisionId>,
    ids: BTreeSet<RevisionId>,
}

impl std::fmt::Debug for RevisionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevisionJournal([REDACTED])")
    }
}

impl RevisionJournal {
    /// Record a local edit/delete. Unpublished ancestors are superseded by this
    /// revision; their metadata remains to establish causality during catch-up.
    pub fn record(&mut self, item_id: &str, deleted: bool) -> anyhow::Result<RevisionId> {
        if item_id.is_empty() || item_id.len() > 1024 || self.state.revisions.len() >= MAX_REVISIONS
        {
            bail!("personal revision journal limit reached or invalid item ID");
        }
        let parent = self.heads.get(item_id).copied();
        let id = loop {
            let candidate = RevisionId(*uuid::Uuid::new_v4().as_bytes());
            if self.ids.insert(candidate) {
                break candidate;
            }
        };
        self.heads.insert(item_id.to_owned(), id);
        self.state.revisions.push(PersonalRevision {
            id,
            item_id: item_id.to_owned(),
            parent,
            deleted,
        });
        if let Some(parent) = parent {
            self.state.pending.remove(&parent);
        }
        self.state.pending.insert(id);
        Ok(id)
    }

    /// Current pending updates, including deletion markers after an item is gone.
    pub fn pending(&self) -> impl Iterator<Item = &PersonalRevision> {
        self.state
            .revisions
            .iter()
            .filter(|revision| self.state.pending.contains(&revision.id))
    }

    /// Causal metadata needed to publish the pending current values.
    #[must_use]
    pub fn revisions(&self) -> &[PersonalRevision] {
        &self.state.revisions
    }

    pub fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(&self.state).context("invalid revision journal")?);
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("personal revision journal exceeds its storage limit");
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("personal revision journal exceeds its storage limit");
        }
        let journal: JournalState =
            serde_json::from_slice(bytes).context("invalid revision journal")?;
        if journal.revisions.len() > MAX_REVISIONS {
            bail!("personal revision journal limit reached");
        }
        let mut ids = BTreeSet::new();
        let mut heads = BTreeMap::new();
        for revision in &journal.revisions {
            if revision.item_id.is_empty()
                || revision.item_id.len() > 1024
                || !ids.insert(revision.id)
                || heads.get(&revision.item_id).copied() != revision.parent
            {
                bail!("invalid local revision chain");
            }
            heads.insert(revision.item_id.clone(), revision.id);
        }
        let current_heads: BTreeSet<_> = heads.values().copied().collect();
        if !journal.pending.is_subset(&current_heads) {
            bail!("pending revisions must be current heads");
        }
        Ok(Self {
            state: journal,
            heads,
            ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_edits_coalesce_and_deletion_survives_restart() {
        let mut journal = RevisionJournal::default();
        let first = journal.record("item-a", false).unwrap();
        let second = journal.record("item-a", false).unwrap();
        journal.record("item-b", false).unwrap();
        let deleted = journal.record("item-a", true).unwrap();
        let journal = RevisionJournal::decode(&journal.encode().unwrap()).unwrap();
        assert_eq!(journal.pending().count(), 2);
        let tombstone = journal
            .pending()
            .find(|revision| revision.item_id == "item-a")
            .unwrap();
        assert!(tombstone.deleted);
        assert_eq!(tombstone.id, deleted);
        assert_eq!(tombstone.parent, Some(second));
        assert_eq!(journal.revisions()[1].parent, Some(first));
    }

    #[test]
    fn malformed_causality_and_non_head_publication_are_rejected() {
        let mut journal = RevisionJournal::default();
        let first = journal.record("item", false).unwrap();
        journal.record("item", true).unwrap();
        journal.state.pending.insert(first);
        assert!(RevisionJournal::decode(&journal.encode().unwrap()).is_err());
        journal.state.pending.remove(&first);
        journal.state.revisions[1].parent = None;
        assert!(RevisionJournal::decode(&journal.encode().unwrap()).is_err());
    }
}
