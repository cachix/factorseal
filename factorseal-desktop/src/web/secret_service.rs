#![allow(
    clippy::needless_pass_by_value,
    clippy::unused_self,
    clippy::missing_const_for_fn
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Default)]
pub(crate) struct SecretServiceAccessContext {
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) sender: String,
    pub(crate) process_id: Option<u32>,
    pub(crate) executable: Option<PathBuf>,
    pub(crate) working_directory: Option<PathBuf>,
}

pub(crate) struct SecretServiceAccessRequest {
    pub(crate) context: SecretServiceAccessContext,
}

impl SecretServiceAccessRequest {
    pub(crate) fn allow(&mut self) {}

    pub(crate) fn deny(&mut self) {}

    pub(crate) fn is_expired(&self) -> bool {
        false
    }

    pub(crate) fn is_pending(&self) -> bool {
        false
    }
}

pub(crate) struct SecretServiceInputRequest {
    pub(crate) context: SecretServiceAccessContext,
    pub(crate) initial: Option<factorseal::WireSecret>,
}

impl SecretServiceInputRequest {
    pub(crate) fn save(&mut self, _value: factorseal::WireSecret) {}

    pub(crate) fn deny(&mut self) {}

    pub(crate) fn is_expired(&self) -> bool {
        false
    }
}
