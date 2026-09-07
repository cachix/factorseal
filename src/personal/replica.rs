//! Automerge owns personal-item causality and conflict resolution. Each item is
//! an atomic register: password fields must not be silently mixed across edits.
use super::PersonalSecret;
use crate::vault::{VaultError, VaultResult};
use automerge::{
    ActorId, AutoCommit, Change, ROOT, ReadDoc, ScalarValue, transaction::Transactable,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

const MAX_UPDATE: usize = 1024 * 1024;
const MAX_CHANGES: usize = 4096;
const VALUE: &str = "value";
pub type ReplicaHeads = Vec<[u8; 32]>;

/// Complete Automerge change closure for one personal item. Full closures make
/// ciphertext independently forwardable without a live reader-to-reader session.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalUpdate {
    item_id: String,
    #[serde(with = "changes_encoding")]
    changes: Vec<Vec<u8>>,
}
impl Drop for PersonalUpdate {
    fn drop(&mut self) {
        self.item_id.zeroize();
        self.changes.zeroize();
    }
}
impl std::fmt::Debug for PersonalUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonalUpdate([REDACTED])")
    }
}
impl PersonalUpdate {
    pub fn new(item_id: String, changes: Vec<Vec<u8>>) -> VaultResult<Self> {
        let update = Self { item_id, changes };
        update.validate()?;
        Ok(update)
    }
    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }
    pub fn replica(&self) -> VaultResult<PersonalReplica> {
        PersonalReplica::from_update(self, b"packet-reader")
    }
    pub(crate) fn validate(&self) -> VaultResult<()> {
        self.replica().map(|_| ())
    }
}

pub struct PersonalReplica {
    id: String,
    document: AutoCommit,
}
impl std::fmt::Debug for PersonalReplica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonalReplica([REDACTED])")
    }
}
impl PersonalReplica {
    pub(crate) fn new(id: &str, actor: &[u8]) -> VaultResult<Self> {
        if id.is_empty() || id.len() > 1024 {
            return Err(invalid());
        }
        Ok(Self {
            id: id.to_owned(),
            document: AutoCommit::new().with_actor(ActorId::from(actor)),
        })
    }
    pub(crate) fn load(id: &str, bytes: &[u8], actor: &[u8]) -> VaultResult<Self> {
        let update: PersonalUpdate = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if update.item_id != id {
            return Err(invalid());
        }
        Self::from_update(&update, actor)
    }
    pub(crate) fn from_update(update: &PersonalUpdate, actor: &[u8]) -> VaultResult<Self> {
        if update.changes.is_empty() || update.changes.len() > MAX_CHANGES {
            return Err(invalid());
        }
        let mut total = 0_usize;
        let mut changes = Vec::new();
        let mut resolutions = Vec::new();
        for bytes in &update.changes {
            total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
            // Automerge binary-format chunk type 1 is an uncompressed change;
            // reject document/compressed chunks before invoking decompression.
            if total > MAX_UPDATE || bytes.get(8) != Some(&1) {
                return Err(invalid());
            }
            let change = Change::from_bytes(bytes.clone()).map_err(|_| invalid())?;
            if change.raw_bytes() != bytes {
                return Err(invalid());
            }
            if validate_change(&update.item_id, &change)? {
                resolutions.push((change.hash(), change.deps().to_vec()));
            }
            changes.push(change);
        }
        let mut replica = Self::new(&update.item_id, actor)?;
        replica
            .document
            .apply_changes(changes)
            .map_err(|_| invalid())?;
        if !replica.document.get_missing_deps(&[]).is_empty()
            || replica.document.get_changes(&[]).len() != update.changes.len()
        {
            return Err(invalid());
        }
        // Automerge can encode assigning the current winner as deleting only
        // the losing operations. Accept that native resolution optimization,
        // but never deletion of the register itself (including in old history).
        for (head, deps) in resolutions {
            let before = replica
                .document
                .get_all_at(ROOT, VALUE, &deps)
                .map_err(|_| invalid())?;
            let after = replica
                .document
                .get_all_at(ROOT, VALUE, &[head])
                .map_err(|_| invalid())?;
            if before.len() < 2
                || after.len() != 1
                || !before.iter().any(|(_, id)| *id == after[0].1)
            {
                return Err(invalid());
            }
        }
        replica.values()?;
        Ok(replica)
    }
    pub(crate) fn save(&mut self) -> VaultResult<Zeroizing<Vec<u8>>> {
        let update = self.update()?;
        let bytes = Zeroizing::new(serde_json::to_vec(&update).map_err(|_| invalid())?);
        if bytes.len() > MAX_UPDATE {
            return Err(VaultError::Protocol(
                "personal Automerge history is full".into(),
            ));
        }
        Ok(bytes)
    }
    pub fn update(&mut self) -> VaultResult<PersonalUpdate> {
        let changes = self.document.get_changes(&[]);
        if changes.len() > MAX_CHANGES {
            return Err(invalid());
        }
        Ok(PersonalUpdate {
            item_id: self.id.clone(),
            changes: changes.iter().map(|c| c.raw_bytes().to_vec()).collect(),
        })
    }
    pub fn heads(&mut self) -> ReplicaHeads {
        let mut heads: Vec<_> = self.document.get_heads().iter().map(|h| h.0).collect();
        heads.sort_unstable();
        heads
    }
    /// Every distinct concurrent register value. Null is an explicit tombstone
    /// so delete/edit races remain visible rather than using map-delete rules.
    pub fn values(&self) -> VaultResult<Vec<Option<PersonalSecret>>> {
        let mut values = Vec::new();
        for (value, _) in self.document.get_all(ROOT, VALUE).map_err(|_| invalid())? {
            let item = match value {
                automerge::Value::Scalar(scalar) => decode_value(&self.id, &scalar)?,
                automerge::Value::Object(_) => return Err(invalid()),
            };
            if !values.contains(&item) {
                values.push(item);
            }
        }
        if values.len() > 16 {
            return Err(invalid());
        }
        Ok(values)
    }
    pub(crate) fn set(
        &mut self,
        item: Option<&PersonalSecret>,
        expected: Option<&ReplicaHeads>,
    ) -> VaultResult<()> {
        if let Some(expected) = expected {
            if &self.heads() != expected {
                return Err(VaultError::Conflict);
            }
        } else if self.values()?.len() > 1 {
            return Err(VaultError::Conflict);
        }
        if item.is_some_and(|item| item.id != self.id) {
            return Err(invalid());
        }
        match item {
            Some(item) => {
                self.document
                    .put(ROOT, VALUE, item.encode().map_err(|_| invalid())?.to_vec())
                    .map_err(|_| invalid())?;
            }
            None => {
                self.document
                    .put(ROOT, VALUE, ScalarValue::Null)
                    .map_err(|_| invalid())?;
            }
        }
        self.document.commit();
        self.save()?;
        Ok(())
    }
    pub(crate) fn merge(&mut self, update: &PersonalUpdate) -> VaultResult<bool> {
        if self.id != update.item_id {
            return Err(invalid());
        }
        let before = self.heads();
        let mut incoming = Self::from_update(update, self.document.get_actor().to_bytes())?;
        self.document
            .merge(&mut incoming.document)
            .map_err(|_| invalid())?;
        self.values()?;
        self.save()?;
        Ok(self.heads() != before)
    }
}

fn validate_change(id: &str, change: &Change) -> VaultResult<bool> {
    use automerge::legacy::{Key, ObjectId, OpType};
    let expanded = change.decode();
    if expanded.operations.len() != 1
        || expanded.message.is_some()
        || !expanded.extra_bytes.is_empty()
        || expanded.author.is_some()
    {
        return Err(invalid());
    }
    let op = &expanded.operations[0];
    if op.obj != ObjectId::Root || op.key != Key::Map(VALUE.into()) || op.insert {
        return Err(invalid());
    }
    match &op.action {
        OpType::Put(value) => {
            decode_value(id, value)?;
            Ok(false)
        }
        OpType::Delete => Ok(true),
        _ => Err(invalid()),
    }
}
fn decode_value(id: &str, value: &ScalarValue) -> VaultResult<Option<PersonalSecret>> {
    match value {
        ScalarValue::Null => Ok(None),
        ScalarValue::Bytes(bytes) => {
            let item = PersonalSecret::decode_current(bytes).map_err(|_| invalid())?;
            if item.id != id {
                return Err(invalid());
            }
            Ok(Some(item))
        }
        _ => Err(invalid()),
    }
}
fn invalid() -> VaultError {
    VaultError::Protocol("invalid personal Automerge changes".into())
}
mod changes_encoding {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize as _, Deserializer, Serialize as _, Serializer};
    use zeroize::Zeroizing;
    pub fn serialize<S: Serializer>(changes: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        let strings = Zeroizing::new(
            changes
                .iter()
                .map(|bytes| STANDARD.encode(bytes))
                .collect::<Vec<_>>(),
        );
        strings.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let strings = Zeroizing::new(Vec::<String>::deserialize(deserializer)?);
        strings
            .iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests;
