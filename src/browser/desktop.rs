//! Bounded interaction coordinator. Contains no vault keys or persistent passwords.
use super::{
    Action, Candidate, Request, Response, Signed, VERSION, VaultResult, WorkerAction, WorkerReply,
    invalid, random_id,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Prompt {
    pub session: String,
    pub generation: u64,
    pub site: String,
    pub key: String,
    pub state: String,
    pub candidates: Vec<Candidate>,
    pub save_username: Option<String>,
}
#[derive(Clone)]
pub struct Work {
    pub session: String,
    pub generation: u64,
    pub action: WorkerAction,
}
struct Flow {
    signed: Signed,
    site: String,
    phase: String,
    candidates: Vec<Candidate>,
    ticket: String,
    selected: Option<Candidate>,
    started: Instant,
    context_deadline: Option<Instant>,
    generation: u64,
    save_username: Option<String>,
}
struct Session {
    key: Option<String>,
    sequence: u32,
    touched: Instant,
    flow: Option<Flow>,
    result: Option<Response>,
}
#[derive(Default)]
pub struct Hub {
    sessions: HashMap<String, Session>,
    pub paired: HashSet<String>,
    /// Signed, self-reported display metadata; never an authorization decision.
    pub browsers: HashMap<String, super::discovery::Browser>,
    work: Vec<Work>,
    unsealed: bool,
    generation: u64,
}
impl Hub {
    /// Forget prompt eligibility and cancel every pending operation for a profile.
    /// Call only after the worker has persisted revocation.
    pub fn revoked(&mut self, key: &str) {
        self.paired.remove(key);
        for session in self.sessions.values_mut() {
            if session.key.as_deref() == Some(key) {
                session.flow = None;
                session.result = Some(Response::finished("revoked"));
            }
        }
    }
    #[must_use]
    pub fn shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }
    pub fn handle(&mut self, request: Request) -> Response {
        self.expire();
        match request {
            Request::Hello { version } => {
                if version != VERSION {
                    return Response::finished("incompatible_version");
                }
                if self.sessions.len() >= 16 {
                    return Response::finished("busy");
                }
                let Ok(session) = random_id() else {
                    return Response::finished("unavailable");
                };
                self.sessions.insert(
                    session.clone(),
                    Session {
                        key: None,
                        sequence: 0,
                        touched: Instant::now(),
                        flow: None,
                        result: None,
                    },
                );
                Response::Hello {
                    version: VERSION,
                    session,
                }
            }
            Request::Signed { message } => self
                .signed(message)
                .unwrap_or_else(|_| Response::finished("unauthorized")),
        }
    }
    fn signed(&mut self, message: Signed) -> VaultResult<Response> {
        let command = message.verify()?;
        let session = self
            .sessions
            .get_mut(&command.session)
            .ok_or_else(invalid)?;
        if command.sequence <= session.sequence
            || session.key.as_ref().is_some_and(|k| k != &message.key)
        {
            return Err(invalid());
        }
        session.key = Some(message.key.clone());
        session.sequence = command.sequence;
        session.touched = Instant::now();
        if let Some(browser) = command.browser
            && (self.paired.contains(&message.key) || matches!(command.action, Action::Pair))
            && (self.browsers.len() < 128 || self.browsers.contains_key(&message.key))
        {
            self.browsers.insert(message.key.clone(), browser);
        }
        match command.action {
            Action::Cancel => {
                session.flow = None;
                session.result = None;
                Ok(Response::finished("cancelled"))
            }
            Action::Poll => {
                if let Some(result) = session.result.take() {
                    return Ok(result);
                }
                Ok(match &session.flow {
                    Some(f) if f.phase == "awaiting_context" => Response::Context {
                        nonce: f.ticket.clone(),
                    },
                    Some(f) => Response::state(&f.phase),
                    None => Response::finished("idle"),
                })
            }
            Action::Confirm { nonce } => {
                let f = session.flow.as_mut().ok_or_else(invalid)?;
                if f.phase != "awaiting_context" || f.ticket != nonce || !self.unsealed {
                    return Err(invalid());
                }
                let candidate = f.selected.clone().ok_or_else(invalid)?;
                f.phase = "releasing".into();
                self.work.push(Work {
                    session: command.session,
                    generation: f.generation,
                    action: WorkerAction::Release {
                        ticket: nonce,
                        candidate,
                        confirmation: message,
                    },
                });
                Ok(Response::state("releasing"))
            }
            action => {
                if session.flow.is_some() {
                    return Ok(Response::finished("busy"));
                }
                if !matches!(action, Action::Pair) && !self.paired.contains(&message.key) {
                    return Ok(Response::finished("pair_required"));
                }
                if self.sessions.values().any(|s| s.flow.is_some()) {
                    return Ok(Response::finished("busy"));
                }
                self.generation += 1;
                let session = self
                    .sessions
                    .get_mut(&command.session)
                    .ok_or_else(invalid)?;
                let site = match &action {
                    Action::Detect { origin, .. } | Action::Save { origin, .. } => origin.clone(),
                    Action::Pair => "Pair browser profile".into(),
                    Action::Revoke => "Disconnect browser profile".into(),
                    _ => return Err(invalid()),
                };
                session.result = None;
                session.flow = Some(Flow {
                    signed: message,
                    site,
                    phase: "awaiting_unseal".into(),
                    candidates: vec![],
                    ticket: String::new(),
                    selected: None,
                    started: Instant::now(),
                    context_deadline: None,
                    generation: self.generation,
                    save_username: match action {
                        Action::Save { username, .. } => Some(username),
                        _ => None,
                    },
                });
                Ok(Response::state("awaiting_unseal"))
            }
        }
    }
    fn expire(&mut self) {
        for session in self.sessions.values_mut() {
            let flow_expired = session.flow.as_ref().is_some_and(|f| {
                f.started.elapsed() > Duration::from_mins(5)
                    || session.touched.elapsed() > Duration::from_secs(30)
                    || f.context_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
            });
            let fill_expired = matches!(session.result, Some(Response::Fill { .. }))
                && session.touched.elapsed() > Duration::from_secs(8);
            if flow_expired || fill_expired {
                session.flow = None;
                session.result = Some(Response::finished("expired"));
            }
        }
        self.sessions
            .retain(|_, s| s.touched.elapsed() < Duration::from_mins(10));
    }
    pub fn snapshot(&mut self, unsealed: bool) {
        self.expire();
        if self.unsealed && !unsealed {
            for s in self.sessions.values_mut() {
                s.flow = None;
                s.result = Some(Response::finished("sealed"));
            }
            self.work.clear();
        }
        self.unsealed = unsealed;
        if !unsealed {
            return;
        }
        for (id, s) in &mut self.sessions {
            if let Some(f) = &mut s.flow
                && f.phase == "awaiting_unseal"
            {
                match f.signed.verify().map(|c| c.action) {
                    Ok(Action::Detect { .. } | Action::Save { .. }) => {
                        f.phase = "matching".into();
                        self.work.push(Work {
                            session: id.clone(),
                            generation: f.generation,
                            action: WorkerAction::Lookup {
                                request: f.signed.clone(),
                            },
                        });
                    }
                    _ => f.phase = "awaiting_approval".into(),
                }
            }
        }
    }
    pub fn prompt(&mut self) -> Option<Prompt> {
        self.expire();
        self.sessions.iter().find_map(|(id, s)| {
            s.flow.as_ref().map(|f| Prompt {
                session: id.clone(),
                generation: f.generation,
                site: f.site.clone(),
                key: f.signed.key.clone(),
                state: f.phase.clone(),
                candidates: f.candidates.clone(),
                save_username: f.save_username.clone(),
            })
        })
    }
    pub fn deny(&mut self, id: &str) {
        if let Some(s) = self.sessions.get_mut(id) {
            s.flow = None;
            s.result = Some(Response::finished("denied"));
        }
    }
    pub fn approve(&mut self, id: &str, generation: u64, index: Option<usize>) {
        let Some(s) = self.sessions.get_mut(id) else {
            return;
        };
        let Some(f) = s.flow.as_mut() else { return };
        if !self.unsealed || f.phase != "awaiting_approval" || f.generation != generation {
            return;
        }
        let Ok(c) = f.signed.verify() else { return };
        match c.action {
            Action::Pair | Action::Revoke => {
                let action = if matches!(c.action, Action::Pair) {
                    WorkerAction::Pair {
                        key: f.signed.key.clone(),
                    }
                } else {
                    WorkerAction::Revoke {
                        key: f.signed.key.clone(),
                    }
                };
                self.work.push(Work {
                    session: id.into(),
                    generation: f.generation,
                    action,
                });
                f.phase = "saving".into();
            }
            Action::Detect { .. } => {
                if let Some(candidate) = index.and_then(|i| f.candidates.get(i)).cloned() {
                    f.selected = Some(candidate);
                    f.phase = "awaiting_context".into();
                    f.context_deadline = Some(Instant::now() + Duration::from_secs(5));
                }
            }
            Action::Save { .. } => {
                let candidate = match index {
                    Some(index) => {
                        let Some(candidate) = f.candidates.get(index) else {
                            return;
                        };
                        Some(candidate.clone())
                    }
                    None => None,
                };
                self.work.push(Work {
                    session: id.into(),
                    generation: f.generation,
                    action: WorkerAction::Save {
                        ticket: f.ticket.clone(),
                        candidate,
                        request: f.signed.clone(),
                    },
                });
                f.phase = "saving".into();
            }
            _ => {}
        }
    }
    pub fn take_work(&mut self) -> Vec<Work> {
        self.expire();
        std::mem::take(&mut self.work)
            .into_iter()
            .filter(|work| {
                self.sessions
                    .get(&work.session)
                    .and_then(|s| s.flow.as_ref())
                    .is_some_and(|f| f.generation == work.generation)
            })
            .collect()
    }
    pub fn complete(&mut self, work: &Work, result: Result<WorkerReply, String>) {
        self.expire();
        let Some(s) = self.sessions.get_mut(&work.session) else {
            return;
        };
        let Some(f) = s.flow.as_mut().filter(|f| f.generation == work.generation) else {
            return;
        };
        if !self.unsealed {
            s.flow = None;
            return;
        }
        match result {
            Ok(WorkerReply::Candidates { ticket, candidates })
                if !candidates.is_empty() || f.save_username.is_some() =>
            {
                f.ticket = ticket;
                f.candidates = candidates;
                f.phase = "awaiting_approval".into();
            }
            Ok(WorkerReply::Candidates { .. }) => {
                s.flow = None;
                s.result = Some(Response::finished("no_match"));
            }
            Ok(WorkerReply::Fill { username, password }) => {
                s.flow = None;
                s.result = Some(Response::Fill { username, password });
            }
            Ok(WorkerReply::AlreadySaved) => {
                s.flow = None;
                s.result = Some(Response::finished("already_saved"));
            }
            Ok(WorkerReply::Done) => {
                match &work.action {
                    WorkerAction::Pair { key } => {
                        self.paired.insert(key.clone());
                    }
                    WorkerAction::Revoke { key } => {
                        self.paired.remove(key);
                    }
                    _ => {}
                }
                s.flow = None;
                s.result = Some(Response::finished("done"));
            }
            Err(_) => {
                s.flow = None;
                s.result = Some(Response::finished(
                    if matches!(work.action, WorkerAction::Save { .. }) {
                        "save_failed"
                    } else {
                        "vault_rejected"
                    },
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WireSecret, browser::Command};
    use ed25519_dalek::{Signer, SigningKey};
    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }
    fn signed(session: &str, sequence: u32, action: Action) -> Signed {
        let key = key();
        let payload = serde_json::to_string(&Command {
            browser: None,
            version: 1,
            session: session.into(),
            sequence,
            action,
        })
        .unwrap();
        Signed {
            key: hex::encode(key.verifying_key().as_bytes()),
            signature: hex::encode(key.sign(payload.as_bytes()).to_bytes()),
            payload,
        }
    }
    fn session(h: &mut Hub) -> String {
        match h.handle(Request::Hello { version: 1 }) {
            Response::Hello { session, .. } => session,
            _ => panic!("hello"),
        }
    }
    #[test]
    fn browser_label_is_signed_metadata_and_does_not_grant_pairing() {
        let mut h = Hub::default();
        let s = session(&mut h);
        let key = key();
        let public = hex::encode(key.verifying_key().as_bytes());
        let mut message = signed(&s, 1, Action::Pair);
        let mut command: super::super::Command = serde_json::from_str(&message.payload).unwrap();
        command.browser = Some(super::super::discovery::Browser::Firefox);
        message.payload = serde_json::to_string(&command).unwrap();
        h.handle(Request::Signed {
            message: message.clone(),
        });
        assert!(h.browsers.is_empty());
        message.signature = hex::encode(key.sign(message.payload.as_bytes()).to_bytes());
        h.handle(Request::Signed { message });
        assert_eq!(
            h.browsers.get(&public),
            Some(&super::super::discovery::Browser::Firefox)
        );
        assert!(h.paired.is_empty());
        h.snapshot(true);
        let generation = h.prompt().unwrap().generation;
        h.approve(&s, generation, None);
        let work = h.take_work().pop().unwrap();
        h.complete(&work, Ok(WorkerReply::Done));
        assert!(h.paired.contains(&public));
        h.revoked(&public);
        assert!(!h.paired.contains(&public));
    }
    #[test]
    fn browser_save_waits_for_review_and_cancel_discards_queued_write() {
        let mut h = Hub::default();
        let s = session(&mut h);
        h.paired
            .insert(hex::encode(key().verifying_key().as_bytes()));
        send(
            &mut h,
            &s,
            1,
            Action::Save {
                origin: "https://example.com".into(),
                document: "doc".into(),
                username: "alice".into(),
                password: WireSecret::new(b"password".to_vec()).unwrap(),
            },
        );
        assert_eq!(h.prompt().unwrap().save_username.as_deref(), Some("alice"));
        assert!(h.take_work().is_empty());
        h.snapshot(true);
        let lookup = h.take_work().pop().unwrap();
        assert!(matches!(lookup.action, WorkerAction::Lookup { .. }));
        h.complete(
            &lookup,
            Ok(WorkerReply::Candidates {
                ticket: "t".repeat(64),
                candidates: vec![],
            }),
        );
        assert_eq!(h.prompt().unwrap().state, "awaiting_approval");
        assert!(h.take_work().is_empty());
        let generation = h.prompt().unwrap().generation;
        h.approve(&s, generation, None);
        send(&mut h, &s, 2, Action::Cancel);
        assert!(h.take_work().is_empty());
    }
    fn send(h: &mut Hub, s: &str, n: u32, a: Action) -> Response {
        h.handle(Request::Signed {
            message: signed(s, n, a),
        })
    }
    #[test]
    fn sealed_detection_prompts_without_lookup_and_resumes_after_unlock() {
        let mut h = Hub::default();
        let s = session(&mut h);
        h.paired
            .insert(hex::encode(key().verifying_key().as_bytes()));
        assert!(matches!(
            send(
                &mut h,
                &s,
                1,
                Action::Detect {
                    origin: "https://example.com".into(),
                    document: "doc".into()
                }
            ),
            Response::State { .. }
        ));
        assert_eq!(h.prompt().unwrap().state, "awaiting_unseal");
        assert!(h.take_work().is_empty());
        h.snapshot(true);
        assert_eq!(h.take_work().len(), 1);
        assert_eq!(h.prompt().unwrap().state, "matching");
        h.snapshot(false);
        assert!(h.prompt().is_none());
        assert!(
            matches!(send(&mut h,&s,2,Action::Poll),Response::Finished{reason} if reason=="sealed")
        );
    }
    #[test]
    fn replay_and_tampered_signature_fail_before_prompt() {
        let mut h = Hub::default();
        let s = session(&mut h);
        let mut msg = signed(&s, 1, Action::Pair);
        msg.payload.push(' ');
        assert!(
            matches!(h.handle(Request::Signed{message:msg}),Response::Finished{reason} if reason=="unauthorized")
        );
        send(&mut h, &s, 1, Action::Pair);
        assert!(h.prompt().is_some());
        assert!(
            matches!(send(&mut h,&s,1,Action::Cancel),Response::Finished{reason} if reason=="unauthorized")
        );
        assert!(h.prompt().is_some());
        send(&mut h, &s, 2, Action::Cancel);
        assert!(h.prompt().is_none());
    }
    #[test]
    fn stale_approval_cannot_approve_replacement_request() {
        let mut h = Hub::default();
        let s = session(&mut h);
        send(&mut h, &s, 1, Action::Pair);
        h.snapshot(true);
        let original = h.prompt().unwrap().generation;
        send(&mut h, &s, 2, Action::Cancel);
        send(&mut h, &s, 3, Action::Pair);
        h.snapshot(true);
        let replacement = h.prompt().unwrap().generation;
        assert_ne!(original, replacement);
        h.approve(&s, original, None);
        assert!(h.take_work().is_empty());
        assert_eq!(h.prompt().unwrap().state, "awaiting_approval");
        h.approve(&s, replacement, None);
        assert_eq!(h.take_work().len(), 1);
    }
    #[test]
    fn cancelled_work_cannot_publish_secrets_or_restore_pairing() {
        let mut h = Hub::default();
        let s = session(&mut h);
        send(&mut h, &s, 1, Action::Pair);
        h.snapshot(true);
        let generation = h.prompt().unwrap().generation;
        h.approve(&s, generation, None);
        let work = h.take_work().pop().unwrap();
        send(&mut h, &s, 2, Action::Cancel);
        h.complete(&work, Ok(WorkerReply::Done));
        assert!(h.paired.is_empty());
        h.complete(
            &work,
            Ok(WorkerReply::Fill {
                username: WireSecret::new(b"u".to_vec()).unwrap(),
                password: WireSecret::new(b"secret".to_vec()).unwrap(),
            }),
        );
        assert!(
            matches!(send(&mut h,&s,3,Action::Poll),Response::Finished{reason} if reason=="idle")
        );
    }
    #[test]
    fn expired_undelivered_values_are_dropped() {
        let mut h = Hub::default();
        let s = session(&mut h);
        let session = h.sessions.get_mut(&s).unwrap();
        session.touched = Instant::now().checked_sub(Duration::from_secs(9)).unwrap();
        session.result = Some(Response::Fill {
            username: WireSecret::new(b"u".to_vec()).unwrap(),
            password: WireSecret::new(b"secret".to_vec()).unwrap(),
        });
        h.expire();
        assert!(matches!(
            h.sessions[&s].result,
            Some(Response::Finished { .. })
        ));
    }

    #[test]
    fn human_consent_survives_brief_polling_gaps_but_remains_bounded() {
        let mut h = Hub::default();
        let s = session(&mut h);
        send(&mut h, &s, 1, Action::Pair);
        let pending = h.sessions.get_mut(&s).unwrap();
        pending.touched = Instant::now().checked_sub(Duration::from_secs(15)).unwrap();
        pending.flow.as_mut().unwrap().started =
            Instant::now().checked_sub(Duration::from_mins(3)).unwrap();
        assert!(h.prompt().is_some());
        h.sessions
            .get_mut(&s)
            .unwrap()
            .flow
            .as_mut()
            .unwrap()
            .started = Instant::now().checked_sub(Duration::from_mins(6)).unwrap();
        assert!(h.prompt().is_none());
        assert!(
            matches!(send(&mut h, &s, 2, Action::Poll), Response::Finished { reason } if reason == "expired")
        );
    }

    #[test]
    fn disconnected_request_expires_after_heartbeat_grace() {
        let mut h = Hub::default();
        let s = session(&mut h);
        send(&mut h, &s, 1, Action::Pair);
        h.sessions.get_mut(&s).unwrap().touched =
            Instant::now().checked_sub(Duration::from_secs(31)).unwrap();
        assert!(h.prompt().is_none());
    }
}
