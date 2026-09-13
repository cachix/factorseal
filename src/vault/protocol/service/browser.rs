//! Browser requests are delegated only by the authenticated Desktop manager.
use crate::WireSecret;
use crate::browser::{
    Action, Candidate, PAIR_NAMESPACE, Signed, WorkerAction, WorkerReply, origin, random_id,
};
use crate::personal::{
    PERSONAL_SECRET_NAMESPACE, PersonalFieldType, PersonalSecret, PersonalSecretKind,
};
use crate::vault::{DocumentKind, Provenance, SecretAddress, VaultError, VaultResult, VaultStore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(super) struct BrowserState {
    tickets: HashMap<String, Ticket>,
    seen: HashSet<String>,
}
struct Ticket {
    key: String,
    session: String,
    sequence: u32,
    origin: String,
    candidates: Vec<Candidate>,
    expires: Instant,
}
fn denied() -> VaultError {
    VaultError::AuthorizationRequired
}
fn paired(store: &VaultStore, key: &str, now: u64) -> VaultResult<()> {
    if store
        .get_at(
            DocumentKind::Authorization,
            PAIR_NAMESPACE,
            &SecretAddress::new(key, None)?,
            now,
        )?
        .is_none()
    {
        return Err(denied());
    }
    Ok(())
}
fn key_valid(key: &str) -> VaultResult<()> {
    if key.len() != 64 || hex::decode(key).is_err() {
        return Err(denied());
    }
    Ok(())
}
fn fields(item: &PersonalSecret) -> Option<(&str, &str)> {
    let fields: Vec<_> = item.sections.iter().flat_map(|s| &s.fields).collect();
    let usernames: Vec<_> = fields.iter().filter(|f| f.id == "username").collect();
    let passwords: Vec<_> = fields.iter().filter(|f| f.id == "password").collect();
    if usernames.len() != 1 || passwords.len() != 1 {
        return None;
    }
    Some((usernames[0].value.as_str()?, passwords[0].value.as_str()?))
}
fn matches(item: &PersonalSecret, site: &str) -> bool {
    item.kind == PersonalSecretKind::Login
        && !item.archived
        && fields(item).is_some()
        && item.sections.iter().flat_map(|s| &s.fields).any(|f| {
            f.field_type == PersonalFieldType::Url
                && f.value
                    .as_str()
                    .is_some_and(|s| origin(s).is_ok_and(|o| o == site))
        })
}
impl BrowserState {
    pub(super) fn execute(
        &mut self,
        store: &VaultStore,
        action: WorkerAction,
        now: u64,
        provenance: &Provenance,
    ) -> VaultResult<WorkerReply> {
        self.tickets.retain(|_, t| t.expires > Instant::now());
        match action {
            WorkerAction::Pair { key } => {
                key_valid(&key)?;
                store.put_at(
                    DocumentKind::Authorization,
                    PAIR_NAMESPACE,
                    &SecretAddress::new(key, None)?,
                    b"paired-v1",
                    None,
                    provenance,
                    now,
                )?;
                Ok(WorkerReply::Done)
            }
            WorkerAction::Revoke { key } => {
                key_valid(&key)?;
                store.delete(
                    DocumentKind::Authorization,
                    PAIR_NAMESPACE,
                    &SecretAddress::new(&key, None)?,
                    provenance,
                    now,
                )?;
                self.tickets.retain(|_, t| t.key != key);
                Ok(WorkerReply::Done)
            }
            WorkerAction::Lookup { request } => self.lookup(store, request, now),
            WorkerAction::Release {
                ticket,
                candidate,
                confirmation,
            } => {
                // Consume before any validation. A failed release cannot be retried.
                let pending = self.tickets.remove(&ticket).ok_or_else(denied)?;
                paired(store, &pending.key, now)?;
                let confirmed = confirmation.verify()?;
                if confirmation.key != pending.key
                    || confirmed.session != pending.session
                    || confirmed.sequence <= pending.sequence
                    || !matches!(confirmed.action, Action::Confirm { nonce } if nonce == ticket)
                    || !pending
                        .candidates
                        .iter()
                        .any(|c| c.id == candidate.id && c.digest == candidate.digest)
                {
                    return Err(denied());
                }
                let secret = store
                    .get_at(
                        DocumentKind::LocalKeyring,
                        PERSONAL_SECRET_NAMESPACE,
                        &SecretAddress::new(&candidate.id, None)?,
                        now,
                    )?
                    .ok_or_else(denied)?;
                if hex::encode(Sha256::digest(&secret)) != candidate.digest {
                    return Err(VaultError::Conflict);
                }
                let item = PersonalSecret::decode_current(&secret).map_err(|_| denied())?;
                if !matches(&item, &pending.origin) {
                    return Err(denied());
                }
                let (username, password) = fields(&item).ok_or_else(denied)?;
                if username.len() > 4096 || password.len() > 4096 {
                    return Err(VaultError::Protocol(
                        "login field exceeds browser limit".into(),
                    ));
                }
                Ok(WorkerReply::Fill {
                    username: WireSecret::new(username.as_bytes().to_vec())?,
                    password: WireSecret::new(password.as_bytes().to_vec())?,
                })
            }
        }
    }
    fn lookup(
        &mut self,
        store: &VaultStore,
        request: Signed,
        now: u64,
    ) -> VaultResult<WorkerReply> {
        let command = request.verify()?;
        paired(store, &request.key, now)?;
        let Action::Detect { origin: site, .. } = command.action else {
            return Err(denied());
        };
        let fingerprint = hex::encode(Sha256::digest(request.payload.as_bytes()));
        // Exhaustion fails closed for this lease, rather than evicting replay evidence.
        if self.seen.len() >= 4096 || self.tickets.len() >= 32 || !self.seen.insert(fingerprint) {
            return Err(denied());
        }
        let mut candidates = vec![];
        let mut cursor = None;
        for _ in 0..4096 {
            let page = store.list_vault_entries(cursor.as_deref(), 8, now)?;
            for entry in page.items {
                if entry.document_kind != DocumentKind::LocalKeyring
                    || entry.partition != PERSONAL_SECRET_NAMESPACE
                {
                    continue;
                }
                let Some(secret) =
                    store.get_at(entry.document_kind, &entry.partition, &entry.address, now)?
                else {
                    continue;
                };
                let Ok(item) = PersonalSecret::decode_current(&secret) else {
                    continue;
                };
                if !matches(&item, &site) {
                    continue;
                }
                let (username, _) = fields(&item).ok_or_else(denied)?;
                if candidates.len() >= 32 || item.title.len() > 512 || username.len() > 512 {
                    return Err(VaultError::Protocol(
                        "too many or oversized browser candidates".into(),
                    ));
                }
                candidates.push(Candidate {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    username: username.into(),
                    digest: hex::encode(Sha256::digest(&secret)),
                });
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                let ticket = random_id()?;
                self.tickets.insert(
                    ticket.clone(),
                    Ticket {
                        key: request.key,
                        session: command.session,
                        sequence: command.sequence,
                        origin: site,
                        candidates: candidates.clone(),
                        expires: Instant::now() + Duration::from_mins(5),
                    },
                );
                return Ok(WorkerReply::Candidates { ticket, candidates });
            }
        }
        Err(VaultError::Protocol(
            "browser lookup inventory limit exceeded".into(),
        ))
    }
}
