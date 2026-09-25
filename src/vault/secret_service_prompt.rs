//! Pending keyring decisions handed from the Secret Service adapter to its host.
//!
//! These are plain data plus a reply channel, independent of D-Bus, so a host's
//! review UI compiles on every platform. Only the Linux adapter creates them.

use tokio::sync::oneshot;

/// Information supplied with a credential lookup. Attributes are caller-provided;
/// the bus authenticates the sender, and process paths are best-effort OS data.
#[derive(Clone, Debug, Default)]
pub struct SecretServiceAccessContext {
    pub attributes: std::collections::BTreeMap<String, String>,
    pub sender: String,
    pub process_id: Option<u32>,
    pub executable: Option<std::path::PathBuf>,
    pub working_directory: Option<std::path::PathBuf>,
}

/// A pending lookup requiring a decision before it can resume after unlocking.
pub struct SecretServiceAccessRequest {
    pub context: SecretServiceAccessContext,
    pub(crate) decision: Option<oneshot::Sender<AccessDecision>>,
}

/// One user-confirmed write. No durable write grant is created.
pub struct SecretServiceInputRequest {
    pub context: SecretServiceAccessContext,
    pub initial: Option<super::WireSecret>,
    pub(crate) decision: Option<oneshot::Sender<Option<super::WireSecret>>>,
}

impl SecretServiceInputRequest {
    pub fn save(&mut self, value: super::WireSecret) {
        if let Some(sender) = self.decision.take() {
            let _ = sender.send(Some(value));
        }
    }
    pub fn deny(&mut self) {
        if let Some(sender) = self.decision.take() {
            let _ = sender.send(None);
        }
    }
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
    }
}

pub(crate) enum AccessDecision {
    Allow,
    Deny,
}

impl SecretServiceAccessRequest {
    /// Allow this pending lookup. This does not create a persistent vault grant.
    pub fn allow(&mut self) {
        if let Some(decision) = self.decision.take() {
            let _ = decision.send(AccessDecision::Allow);
        }
    }

    /// Deny explicitly; dropping the request means its dialog was dismissed.
    pub fn deny(&mut self) {
        if let Some(decision) = self.decision.take() {
            let _ = decision.send(AccessDecision::Deny);
        }
    }

    /// Whether the client stopped waiting before deciding.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(|decision| !decision.is_closed())
    }
}
