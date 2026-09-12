//! Read-only upgrade of the pre-Automerge publication journal. New edits never
//! write this format; only final deletion markers need carrying into replicas.
use crate::vault::{VaultError, VaultResult};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize)]
struct Id([u8; 16]);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    id: Id,
    item_id: String,
    parent: Option<Id>,
    deleted: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    revisions: Vec<Revision>,
    pending: BTreeSet<Id>,
}
pub(crate) fn tombstones(bytes: &[u8]) -> VaultResult<Vec<String>> {
    let invalid = || VaultError::InvalidData("invalid legacy personal journal".into());
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid());
    }
    let journal: Journal = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if journal.revisions.len() > 100_000 {
        return Err(invalid());
    }
    let mut heads = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for revision in journal.revisions {
        if revision.item_id.is_empty()
            || revision.item_id.len() > 1024
            || !ids.insert(revision.id)
            || heads.get(&revision.item_id).map(|(id, _)| *id) != revision.parent
        {
            return Err(invalid());
        }
        heads.insert(revision.item_id, (revision.id, revision.deleted));
    }
    let current: BTreeSet<_> = heads.values().map(|(id, _)| *id).collect();
    if !journal.pending.is_subset(&current) {
        return Err(invalid());
    }
    Ok(heads
        .into_iter()
        .filter_map(|(id, (_, deleted))| deleted.then_some(id))
        .collect())
}
