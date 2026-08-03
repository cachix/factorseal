use serde::Serialize;

/// A factor that can participate in a vault unlock policy.
///
/// Only factors returned by [`crate::Vault::info`] are configured for that
/// vault. Some variants describe provider families whose concrete provider is
/// still being developed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum FactorKind {
    /// A legacy password wrapping the complete vault key.
    Password,
    /// Platform hardware such as a TPM or Secure Enclave.
    PlatformHardware,
    /// Platform biometric user verification gating a hardware operation.
    Biometric,
    /// A phone holding an independently protected vault-key share.
    ///
    /// The transport and mutual-authentication protocol, such as Aliro, are
    /// separate from FactorSeal's vault policy and share handling.
    Phone,
    /// A YubiKey using the PIV provider.
    #[serde(rename = "yubikey")]
    YubiKey,
    /// A passkey capable of returning stable PRF or `hmac-secret` output.
    Passkey,
}

impl FactorKind {
    /// Return the stable name used by CLI metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PlatformHardware => "platform-hardware",
            Self::Biometric => "biometric",
            Self::Phone => "phone",
            Self::YubiKey => "yubikey",
            Self::Passkey => "passkey",
        }
    }
}

impl std::fmt::Display for FactorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factor_names_are_stable() {
        for (factor, expected) in [
            (FactorKind::Password, "password"),
            (FactorKind::PlatformHardware, "platform-hardware"),
            (FactorKind::Biometric, "biometric"),
            (FactorKind::Phone, "phone"),
            (FactorKind::YubiKey, "yubikey"),
            (FactorKind::Passkey, "passkey"),
        ] {
            assert_eq!(factor.as_str(), expected);
            assert_eq!(
                serde_json::to_string(&factor).unwrap(),
                format!("\"{expected}\"")
            );
        }
    }
}
