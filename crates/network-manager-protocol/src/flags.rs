use bitflags::bitflags;

bitflags! {
    /// Per-secret ownership and persistence flags, such as `psk-flags`.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct SecretFlags: u32 {
        /// NetworkManager owns and stores the secret.
        const NONE = 0;
        /// A secret agent owns the secret.
        const AGENT_OWNED = 0x1;
        /// Obtain the secret when needed without saving it.
        const NOT_SAVED = 0x2;
        /// The secret is not required.
        const NOT_REQUIRED = 0x4;
    }

    /// Public D-Bus flags on a `GetSecrets` request.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct GetSecretsFlags: u32 {
        /// Retrieve existing secrets without interacting with the user.
        const NONE = 0;
        /// User interaction is permitted.
        const ALLOW_INTERACTION = 0x1;
        /// Obtain new secrets; existing ones are considered invalid.
        /// This flag also implies permission to interact with the user.
        const REQUEST_NEW = 0x2;
        /// Activation was initiated by a user action.
        const USER_REQUESTED = 0x4;
        /// WPS push-button enrollment is active.
        const WPS_PBC_ACTIVE = 0x8;
    }

    /// Capabilities passed to `RegisterWithCapabilities`.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct AgentCapabilities: u32 {
        /// No special capabilities (sufficient for a personal Wi-Fi agent).
        const NONE = 0;
        /// The host supports passing hints to VPN authentication dialogs.
        const VPN_HINTS = 0x1;
    }
}

impl SecretFlags {
    /// Whether this secret may be persisted by the agent.
    ///
    /// `NOT_SAVED` takes precedence over `AGENT_OWNED`. Unknown flags fail
    /// closed for persistence; the host must explicitly support new semantics.
    #[must_use]
    pub const fn agent_may_save(self) -> bool {
        self.contains(Self::AGENT_OWNED)
            && !self.contains(Self::NOT_SAVED)
            && self.bits() & !Self::all().bits() == 0
    }
}

impl GetSecretsFlags {
    /// Whether this request permits prompting or unlocking through a UI.
    #[must_use]
    pub const fn allows_interaction(self) -> bool {
        self.intersects(Self::ALLOW_INTERACTION.union(Self::REQUEST_NEW))
    }

    /// Whether existing stored credentials may satisfy this request.
    #[must_use]
    pub const fn allows_stored_secrets(self) -> bool {
        !self.contains(Self::REQUEST_NEW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_respects_combinations_and_unknown_bits() {
        for bits in 0..8 {
            assert_eq!(
                SecretFlags::from_bits_retain(bits).agent_may_save(),
                bits & 1 != 0 && bits & 2 == 0
            );
        }
        assert!(!SecretFlags::from_bits_retain(0x81).agent_may_save());
    }

    #[test]
    fn request_new_implies_interaction_but_user_requested_does_not() {
        for bits in 0..16 {
            let flags = GetSecretsFlags::from_bits_retain(bits);
            assert_eq!(flags.allows_interaction(), bits & 3 != 0);
            assert_eq!(flags.allows_stored_secrets(), bits & 2 == 0);
        }
        assert!(!GetSecretsFlags::from_bits_retain(0x80).allows_interaction());
    }
}
