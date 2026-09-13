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
    save_digest: Option<String>,
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
            WorkerAction::Lookup { request } => self.lookup(store, &request, now),
            WorkerAction::Save {
                ticket,
                candidate,
                request,
            } => self.save(
                store,
                &ticket,
                candidate.as_ref(),
                &request,
                now,
                provenance,
            ),
            WorkerAction::Release {
                ticket,
                candidate,
                confirmation,
            } => {
                // Consume before any validation. A failed release cannot be retried.
                let pending = self.tickets.remove(&ticket).ok_or_else(denied)?;
                if pending.save_digest.is_some() {
                    return Err(denied());
                }
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
        request: &Signed,
        now: u64,
    ) -> VaultResult<WorkerReply> {
        let command = request.verify()?;
        paired(store, &request.key, now)?;
        let (site, saving) = match &command.action {
            Action::Detect { origin, .. } => (origin, None),
            Action::Save {
                origin,
                username,
                password,
                ..
            } => (origin, Some((username, password))),
            _ => return Err(denied()),
        };
        let fingerprint = hex::encode(Sha256::digest(request.payload.as_bytes()));
        // Exhaustion fails closed for this lease, rather than evicting replay evidence.
        if self.seen.len() >= 4096
            || self.tickets.len() >= 32
            || !self.seen.insert(fingerprint.clone())
        {
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
                if !matches(&item, site) {
                    continue;
                }
                let (username, _) = fields(&item).ok_or_else(denied)?;
                if let Some((submitted_username, password)) = saving {
                    if username != submitted_username {
                        continue;
                    }
                    if fields(&item)
                        .is_some_and(|(_, stored)| stored.as_bytes() == password.expose())
                    {
                        return Ok(WorkerReply::AlreadySaved);
                    }
                }
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
                        key: request.key.clone(),
                        session: command.session,
                        sequence: command.sequence,
                        origin: site.clone(),
                        candidates: candidates.clone(),
                        expires: Instant::now() + Duration::from_mins(5),
                        save_digest: saving.map(|_| fingerprint),
                    },
                );
                return Ok(WorkerReply::Candidates { ticket, candidates });
            }
        }
        Err(VaultError::Protocol(
            "browser lookup inventory limit exceeded".into(),
        ))
    }
    fn save(
        &mut self,
        store: &VaultStore,
        ticket: &str,
        candidate: Option<&Candidate>,
        request: &Signed,
        now: u64,
        provenance: &Provenance,
    ) -> VaultResult<WorkerReply> {
        let pending = self.tickets.remove(ticket).ok_or_else(denied)?;
        paired(store, &pending.key, now)?;
        let command = request.verify()?;
        if pending.key != request.key
            || pending.session != command.session
            || pending.sequence != command.sequence
            || pending.save_digest.as_deref()
                != Some(hex::encode(Sha256::digest(request.payload.as_bytes())).as_str())
        {
            return Err(denied());
        }
        let Action::Save {
            origin: site,
            username,
            password,
            ..
        } = command.action
        else {
            return Err(denied());
        };
        let mut item = if let Some(candidate) = candidate {
            if !pending
                .candidates
                .iter()
                .any(|c| c.id == candidate.id && c.digest == candidate.digest)
            {
                return Err(denied());
            }
            let bytes = store
                .get_at(
                    DocumentKind::LocalKeyring,
                    PERSONAL_SECRET_NAMESPACE,
                    &SecretAddress::new(&candidate.id, None)?,
                    now,
                )?
                .ok_or_else(denied)?;
            if hex::encode(Sha256::digest(&bytes)) != candidate.digest {
                return Err(VaultError::Conflict);
            }
            let item = PersonalSecret::decode_current(&bytes).map_err(|_| denied())?;
            if !matches(&item, &site) || fields(&item).is_none_or(|(name, _)| name != username) {
                return Err(denied());
            }
            item
        } else {
            let mut item = PersonalSecret::template(PersonalSecretKind::Login, site.clone());
            for field in &mut item.sections[0].fields {
                if field.id == "username" {
                    field.value = username.clone().into();
                }
                if field.id == "url-0" {
                    field.value = site.clone().into();
                }
            }
            item
        };
        let value = std::str::from_utf8(password.expose()).map_err(|_| denied())?;
        for field in item.sections.iter_mut().flat_map(|s| &mut s.fields) {
            if field.id == "password" {
                field.value = value.into();
            }
        }
        store.put_at(
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
            &SecretAddress::new(&item.id, None)?,
            &item.encode().map_err(|_| denied())?,
            None,
            provenance,
            now,
        )?;
        Ok(WorkerReply::Done)
    }
}
