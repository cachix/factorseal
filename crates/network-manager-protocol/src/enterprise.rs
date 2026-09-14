use std::{collections::BTreeMap, fmt};

use zeroize::Zeroizing;

use crate::{AgentError, EAP_SETTING, ProtocolError, Settings};

/// Secret properties in NetworkManager's `802-1x` setting.
///
/// These apply to enterprise Wi-Fi (`wpa-eap` and `wpa-eap-suite-b-192`)
/// and wired 802.1X. The host selects the required secrets from the connection's
/// EAP configuration; hints are advisory. Identity, certificates, private-key
/// blobs/paths, and server verification settings are connection configuration,
/// not secret-agent reply properties.
///
/// See <https://networkmanager.dev/docs/api/latest/settings-802-1x.html>.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EapSecretProperty {
    /// UTF-8 EAP password, including tunneled password authentication.
    Password,
    /// Password bytes for encodings other than UTF-8.
    PasswordRaw,
    /// PIN used by an EAP authentication method.
    Pin,
    /// Password for the outer private key.
    PrivateKeyPassword,
    /// Password for the inner (phase-two) private key.
    Phase2PrivateKeyPassword,
    /// Login password for a CA certificate on a PKCS#11 token.
    CaCertPassword,
    /// Login password for the inner CA certificate on a PKCS#11 token.
    Phase2CaCertPassword,
    /// Login password for a client certificate on a PKCS#11 token.
    ClientCertPassword,
    /// Login password for the inner client certificate on a PKCS#11 token.
    Phase2ClientCertPassword,
}

impl EapSecretProperty {
    /// Exact D-Bus property name, also usable to interpret a property hint.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::PasswordRaw => "password-raw",
            Self::Pin => "pin",
            Self::PrivateKeyPassword => "private-key-password",
            Self::Phase2PrivateKeyPassword => "phase2-private-key-password",
            Self::CaCertPassword => "ca-cert-password",
            Self::Phase2CaCertPassword => "phase2-ca-cert-password",
            Self::ClientCertPassword => "client-cert-password",
            Self::Phase2ClientCertPassword => "phase2-client-cert-password",
        }
    }

    /// Property holding this secret's independent [`crate::SecretFlags`].
    ///
    /// In particular, `password-raw` does not inherit `password-flags`.
    #[must_use]
    pub const fn flags_name(self) -> &'static str {
        match self {
            Self::Password => "password-flags",
            Self::PasswordRaw => "password-raw-flags",
            Self::Pin => "pin-flags",
            Self::PrivateKeyPassword => "private-key-password-flags",
            Self::Phase2PrivateKeyPassword => "phase2-private-key-password-flags",
            Self::CaCertPassword => "ca-cert-password-flags",
            Self::Phase2CaCertPassword => "phase2-ca-cert-password-flags",
            Self::ClientCertPassword => "client-cert-password-flags",
            Self::Phase2ClientCertPassword => "phase2-client-cert-password-flags",
        }
    }
}

/// An owned EAP secret, wiped on drop and redacted in Debug.
pub enum EapSecretValue {
    /// D-Bus string (`s`), accepted for all properties except `password-raw`.
    Text(Zeroizing<String>),
    /// D-Bus byte array (`ay`), accepted only for `password-raw`.
    Bytes(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for EapSecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EapSecretValue([REDACTED])")
    }
}

/// A collection of secrets for a single connection's `802-1x` setting.
///
/// This validates wire types, not EAP method configuration or credentials.
/// Empty values are preserved; absence is represented by a missing property.
/// No WPA-PSK length, ASCII, or numeric-only PIN restrictions are imposed.
/// Both password representations can coexist; NetworkManager prefers
/// `password` when both it and `password-raw` are present.
///
/// ```
/// use network_manager_protocol::{EapSecretProperty, EapSecretValue, EapSecrets};
/// use zeroize::Zeroizing;
///
/// let mut secrets = EapSecrets::default();
/// secrets.insert(
///     EapSecretProperty::Password,
///     EapSecretValue::Text(Zeroizing::new("enterprise-password".to_owned())),
/// )?;
/// // Stand-ins for the host's string and byte-array D-Bus variants.
/// let reply = secrets.to_reply(
///     |text| EapSecretValue::Text(Zeroizing::new(text.to_owned())),
///     |bytes| EapSecretValue::Bytes(Zeroizing::new(bytes.to_vec())),
/// )?;
/// assert!(reply["802-1x"].contains_key("password"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Default)]
pub struct EapSecrets(BTreeMap<EapSecretProperty, EapSecretValue>);

impl EapSecrets {
    /// Insert or replace a secret after checking its wire representation.
    ///
    /// Strings must not contain NUL bytes. Raw passwords may contain arbitrary
    /// bytes, including NULs. On error, existing entries remain unchanged and
    /// the rejected value is wiped on drop. Replaced values are also wiped.
    pub fn insert(
        &mut self,
        property: EapSecretProperty,
        value: EapSecretValue,
    ) -> Result<(), ProtocolError> {
        let valid = match &value {
            EapSecretValue::Text(text) => {
                property != EapSecretProperty::PasswordRaw && !text.contains('\0')
            }
            EapSecretValue::Bytes(_) => property == EapSecretProperty::PasswordRaw,
        };
        if !valid {
            return Err(ProtocolError::InvalidEapSecret);
        }
        self.0.insert(property, value);
        Ok(())
    }

    /// Borrow a secret for storage, applying its own flags from the connection.
    #[must_use]
    pub fn get(&self, property: EapSecretProperty) -> Option<&EapSecretValue> {
        self.0.get(&property)
    }

    /// Build an enterprise `GetSecrets` reply with the host's variant types.
    ///
    /// The callbacks must encode D-Bus string and byte-array variants,
    /// respectively. Only inserted secrets and the setting name are returned;
    /// neither connection metadata nor persistence flags are copied. The host
    /// is responsible for protecting any copies the callbacks or transport make.
    /// An empty collection returns [`AgentError::NoSecrets`].
    pub fn to_reply<V>(
        &self,
        mut string_variant: impl FnMut(&str) -> V,
        mut bytes_variant: impl FnMut(&[u8]) -> V,
    ) -> Result<Settings<V>, AgentError> {
        if self.0.is_empty() {
            return Err(AgentError::NoSecrets);
        }
        let mut properties = BTreeMap::from([("name".to_owned(), string_variant(EAP_SETTING))]);
        for (property, value) in &self.0 {
            let variant = match value {
                EapSecretValue::Text(text) => string_variant(text),
                EapSecretValue::Bytes(bytes) => bytes_variant(bytes),
            };
            properties.insert(property.name().to_owned(), variant);
        }
        Ok(Settings::from([(EAP_SETTING.to_owned(), properties)]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately distinct variants catch accidental byte-to-string conversion.
    #[derive(Debug, PartialEq)]
    enum Variant {
        Text(String),
        Bytes(Vec<u8>),
    }

    fn text(value: &str) -> EapSecretValue {
        EapSecretValue::Text(Zeroizing::new(value.to_owned()))
    }

    fn reply(secrets: &EapSecrets) -> Result<Settings<Variant>, AgentError> {
        secrets.to_reply(
            |value| Variant::Text(value.to_owned()),
            |value| Variant::Bytes(value.to_vec()),
        )
    }

    #[test]
    fn enterprise_passwords_preserve_unicode_and_raw_bytes() {
        let mut secrets = EapSecrets::default();
        secrets
            .insert(EapSecretProperty::Password, text("é"))
            .unwrap();
        let raw = vec![0xff, 0, 0x80];
        secrets
            .insert(
                EapSecretProperty::PasswordRaw,
                EapSecretValue::Bytes(Zeroizing::new(raw.clone())),
            )
            .unwrap();
        let reply = reply(&secrets).unwrap();
        assert_eq!(reply.len(), 1);
        let properties = &reply["802-1x"];
        assert_eq!(properties.len(), 3);
        assert_eq!(properties["name"], Variant::Text("802-1x".to_owned()));
        assert_eq!(properties["password"], Variant::Text("é".to_owned()));
        assert_eq!(properties["password-raw"], Variant::Bytes(raw));
    }

    #[test]
    fn tls_and_token_secrets_have_independent_properties_and_flags() {
        let cases = [
            (EapSecretProperty::Pin, "pin"),
            (
                EapSecretProperty::PrivateKeyPassword,
                "private-key-password",
            ),
            (
                EapSecretProperty::Phase2PrivateKeyPassword,
                "phase2-private-key-password",
            ),
            (EapSecretProperty::CaCertPassword, "ca-cert-password"),
            (
                EapSecretProperty::Phase2CaCertPassword,
                "phase2-ca-cert-password",
            ),
            (
                EapSecretProperty::ClientCertPassword,
                "client-cert-password",
            ),
            (
                EapSecretProperty::Phase2ClientCertPassword,
                "phase2-client-cert-password",
            ),
        ];
        let mut secrets = EapSecrets::default();
        for (property, name) in cases {
            assert_eq!(property.name(), name);
            assert_eq!(property.flags_name(), format!("{name}-flags"));
            secrets.insert(property, text(name)).unwrap();
        }
        let reply = reply(&secrets).unwrap();
        let properties = &reply["802-1x"];
        assert_eq!(properties.len(), cases.len() + 1);
        for (_, name) in cases {
            assert_eq!(properties[name], Variant::Text(name.to_owned()));
        }
        assert_eq!(EapSecretProperty::Password.flags_name(), "password-flags");
        assert_eq!(
            EapSecretProperty::PasswordRaw.flags_name(),
            "password-raw-flags"
        );
    }

    #[test]
    fn invalid_values_do_not_replace_existing_secrets() {
        let mut secrets = EapSecrets::default();
        secrets
            .insert(EapSecretProperty::Password, text("original"))
            .unwrap();
        for invalid in [
            text("bad\0password"),
            EapSecretValue::Bytes(Zeroizing::new(vec![1])),
        ] {
            assert_eq!(
                secrets.insert(EapSecretProperty::Password, invalid),
                Err(ProtocolError::InvalidEapSecret)
            );
        }
        assert_eq!(
            secrets.insert(EapSecretProperty::PasswordRaw, text("not bytes")),
            Err(ProtocolError::InvalidEapSecret)
        );
        assert!(secrets.get(EapSecretProperty::PasswordRaw).is_none());
        assert_eq!(
            reply(&secrets).unwrap()["802-1x"]["password"],
            Variant::Text("original".to_owned())
        );
        secrets
            .insert(EapSecretProperty::Password, text("replacement"))
            .unwrap();
        assert_eq!(
            reply(&secrets).unwrap()["802-1x"]["password"],
            Variant::Text("replacement".to_owned())
        );
    }

    #[test]
    fn absent_and_empty_secrets_are_distinct() {
        let mut secrets = EapSecrets::default();
        assert_eq!(reply(&secrets), Err(AgentError::NoSecrets));
        secrets
            .insert(EapSecretProperty::PrivateKeyPassword, text(""))
            .unwrap();
        secrets
            .insert(
                EapSecretProperty::PasswordRaw,
                EapSecretValue::Bytes(Zeroizing::new(Vec::new())),
            )
            .unwrap();
        let reply = reply(&secrets).unwrap();
        assert_eq!(
            reply["802-1x"]["private-key-password"],
            Variant::Text(String::new())
        );
        assert_eq!(reply["802-1x"]["password-raw"], Variant::Bytes(Vec::new()));
    }

    #[test]
    fn debug_redacts_both_secret_representations() {
        let secret = text("do-not-log");
        assert_eq!(format!("{secret:?}"), "EapSecretValue([REDACTED])");
        let mut secrets = EapSecrets::default();
        secrets.insert(EapSecretProperty::Password, secret).unwrap();
        secrets
            .insert(
                EapSecretProperty::PasswordRaw,
                EapSecretValue::Bytes(Zeroizing::new(vec![255, 254])),
            )
            .unwrap();
        let debug = format!("{secrets:?}");
        assert!(!debug.contains("do-not-log"));
        assert!(!debug.contains("255"));
        assert_eq!(debug.matches("[REDACTED]").count(), 2);
    }
}
