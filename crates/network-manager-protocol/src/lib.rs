//! Pure-Rust building blocks for NetworkManager's SecretAgent protocol.
//!
//! Like `secret-service-protocol`, this crate has no D-Bus, storage, runtime,
//! or policy dependency. [`Settings`] accepts the host's variant type, so it
//! can represent the full `a{sa{sv}}` connection dictionary without narrowing
//! NetworkManager's settings to Wi-Fi or string properties.
//!
//! A host exports [`SECRET_AGENT_INTERFACE`] at [`SECRET_AGENT_PATH`] on the
//! system bus and calls `Register` or `RegisterWithCapabilities` on
//! [`AGENT_MANAGER_INTERFACE`]. It must authenticate incoming calls against
//! the current owner of [`BUS_NAME`], handle cancellation, and register again
//! after NetworkManager restarts. This crate does not perform those actions.
//!
//! Protocol references:
//! - <https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.SecretAgent.html>
//! - <https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.AgentManager.html>
//! - <https://networkmanager.dev/docs/api/latest/secrets-flags.html>

use std::collections::BTreeMap;

use thiserror::Error;

mod enterprise;
mod flags;
mod wifi;

pub use enterprise::{EapSecretProperty, EapSecretValue, EapSecrets};
pub use flags::{AgentCapabilities, GetSecretsFlags, SecretFlags};
pub use wifi::WifiPsk;

/// NetworkManager's well-known system-bus name.
pub const BUS_NAME: &str = "org.freedesktop.NetworkManager";
/// Interface implemented by the secret-agent host.
pub const SECRET_AGENT_INTERFACE: &str = "org.freedesktop.NetworkManager.SecretAgent";
/// Object path exported by the secret-agent host.
pub const SECRET_AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
/// Interface used to register and unregister a secret agent.
pub const AGENT_MANAGER_INTERFACE: &str = "org.freedesktop.NetworkManager.AgentManager";
/// NetworkManager's agent registration object path.
pub const AGENT_MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
/// Personal Wi-Fi security setting name on D-Bus (not its keyfile alias).
pub const WIFI_SECURITY_SETTING: &str = "802-11-wireless-security";
/// Wi-Fi password property, also used for SAE.
pub const WIFI_PSK: &str = "psk";
/// Wi-Fi password ownership and persistence flags property.
pub const WIFI_PSK_FLAGS: &str = "psk-flags";
/// Enterprise Wi-Fi and wired 802.1X authentication setting on D-Bus.
pub const EAP_SETTING: &str = "802-1x";

/// Nested settings dictionary corresponding to D-Bus `a{sa{sv}}`.
///
/// `V` is the host's variant type. The host is responsible for protecting
/// secret values in that type and in its transport's serialization buffers.
pub type Settings<V> = BTreeMap<String, BTreeMap<String, V>>;

/// Identifies all pending requests canceled by a `CancelGetSecrets` call.
///
/// Use the connection UUID, setting, and property for persistent storage;
/// object paths identify requests but can change across daemon restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestKey<'a> {
    /// Connection's D-Bus object path, validated by the transport adapter.
    pub connection_path: &'a str,
    /// Setting whose secrets are being requested.
    pub setting_name: &'a str,
}

/// Arguments of `GetSecrets`, borrowed from a host's decoded D-Bus call.
pub struct GetSecretsRequest<'a, V> {
    /// Full connection settings, potentially including system-owned secrets.
    pub connection: &'a Settings<V>,
    /// Connection path and setting, also used by `CancelGetSecrets`.
    pub key: RequestKey<'a>,
    /// Advisory property names or VPN hints, not an exhaustive allowlist.
    pub hints: &'a [String],
    /// Requested interaction behavior.
    pub flags: GetSecretsFlags,
}

/// Arguments shared by `SaveSecrets` and `DeleteSecrets`.
///
/// Save calls contain secrets; delete calls contain connection metadata.
/// Only agent-owned, saveable secrets belong in the agent's backing store.
/// When an agent itself obtains or updates such secrets, it must save them
/// itself: NetworkManager does not send them back via `SaveSecrets`.
pub struct ConnectionRequest<'a, V> {
    /// Full connection settings supplied by NetworkManager.
    pub connection: &'a Settings<V>,
    /// Connection's D-Bus object path, validated by the transport adapter.
    pub connection_path: &'a str,
}

/// Standard failures returned by a secret agent to NetworkManager.
///
/// Messages intentionally contain no connection data or secret values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentError {
    #[error("secret-agent operation failed")]
    Failed,
    #[error("caller is not authorized")]
    PermissionDenied,
    #[error("invalid connection")]
    InvalidConnection,
    #[error("request canceled by the user")]
    UserCanceled,
    #[error("request canceled by NetworkManager")]
    AgentCanceled,
    #[error("no secrets available")]
    NoSecrets,
}

impl AgentError {
    /// Fully qualified D-Bus error name for the transport adapter.
    #[must_use]
    pub const fn dbus_name(self) -> &'static str {
        match self {
            Self::Failed => "org.freedesktop.NetworkManager.SecretAgent.Failed",
            Self::PermissionDenied => "org.freedesktop.NetworkManager.SecretAgent.PermissionDenied",
            Self::InvalidConnection => {
                "org.freedesktop.NetworkManager.SecretAgent.InvalidConnection"
            }
            Self::UserCanceled => "org.freedesktop.NetworkManager.SecretAgent.UserCanceled",
            Self::AgentCanceled => "org.freedesktop.NetworkManager.SecretAgent.AgentCanceled",
            Self::NoSecrets => "org.freedesktop.NetworkManager.SecretAgent.NoSecrets",
        }
    }
}

/// Invalid input to the network secret helpers.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    #[error("unsupported Wi-Fi key management")]
    UnsupportedKeyManagement,
    #[error("invalid Wi-Fi password")]
    InvalidPsk,
    #[error("invalid 802.1X secret type or string encoding")]
    InvalidEapSecret,
}
