use std::fmt;

use zeroize::Zeroizing;

use crate::{ProtocolError, Settings, WIFI_PSK, WIFI_SECURITY_SETTING};

/// A validated personal Wi-Fi password, wiped on drop and redacted in Debug.
///
/// NetworkManager uses the same `psk` property for WPA-PSK and SAE. This is
/// the usable password, not an encrypted session payload: NetworkManager's
/// agent protocol has no Secret Service-style session encryption.
pub struct WifiPsk(Zeroizing<String>);

impl WifiPsk {
    /// Validate a password against the connection's `key-mgmt` property.
    ///
    /// `wpa-psk` accepts 8–63 ASCII bytes or exactly 64 hexadecimal digits.
    /// `sae` accepts a nonempty passphrase without WPA-PSK's length restriction.
    /// Embedded NULs cannot be represented in a D-Bus string. The supplied
    /// buffer is wiped on failure as well as when a successful value is dropped.
    ///
    /// See <https://networkmanager.dev/docs/api/latest/settings-802-11-wireless-security.html>.
    pub fn new(key_management: &str, value: Zeroizing<String>) -> Result<Self, ProtocolError> {
        let valid = match key_management {
            "wpa-psk" => {
                ((8..=63).contains(&value.len()) && value.is_ascii())
                    || (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            }
            "sae" => !value.is_empty(),
            _ => return Err(ProtocolError::UnsupportedKeyManagement),
        };
        if !valid || value.contains('\0') {
            return Err(ProtocolError::InvalidPsk);
        }
        Ok(Self(value))
    }

    /// Borrow the usable password for storage or transport serialization.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Build the personal Wi-Fi `GetSecrets` reply using the host's variants.
    ///
    /// `string_variant` must encode its argument as a D-Bus string variant.
    /// The host owns any copies it creates and must protect their lifetime.
    /// The dictionary includes the setting `name` required by the interface
    /// documentation, and the `psk` secret; no input connection fields leak
    /// into the reply.
    pub fn to_reply<V>(&self, mut string_variant: impl FnMut(&str) -> V) -> Settings<V> {
        Settings::from([(
            WIFI_SECURITY_SETTING.to_owned(),
            std::collections::BTreeMap::from([
                ("name".to_owned(), string_variant(WIFI_SECURITY_SETTING)),
                (WIFI_PSK.to_owned(), string_variant(self.expose_secret())),
            ]),
        )])
    }
}

impl fmt::Debug for WifiPsk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WifiPsk([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn psk(key_management: &str, value: &str) -> Result<WifiPsk, ProtocolError> {
        WifiPsk::new(key_management, Zeroizing::new(value.to_owned()))
    }

    #[test]
    fn wpa_psk_checks_passphrase_and_raw_key_boundaries() {
        for length in [8, 63, 64] {
            assert!(psk("wpa-psk", &"a".repeat(length)).is_ok());
        }
        for value in [
            String::new(),
            "a".repeat(7),
            "a".repeat(65),
            "g".repeat(64),
            "é".repeat(8),
            "1234567\0".to_owned(),
        ] {
            assert_eq!(
                psk("wpa-psk", &value).unwrap_err(),
                ProtocolError::InvalidPsk
            );
        }
        assert!(psk("wpa-psk", &"Ab09".repeat(16)).is_ok());
    }

    #[test]
    fn sae_does_not_inherit_wpa_psk_restrictions() {
        for value in [
            "x".to_owned(),
            "é".repeat(40),
            "g".repeat(64),
            "x".repeat(100),
        ] {
            assert!(psk("sae", &value).is_ok());
        }
        for value in ["", "secret\0"] {
            assert_eq!(psk("sae", value).unwrap_err(), ProtocolError::InvalidPsk);
        }
        for key_management in ["", "none", "wpa-eap", "owe"] {
            assert_eq!(
                psk(key_management, "password").unwrap_err(),
                ProtocolError::UnsupportedKeyManagement
            );
        }
    }

    #[test]
    fn reply_uses_dbus_setting_name_and_debug_hides_password() {
        let secret = psk("wpa-psk", "test-password").unwrap();
        let reply = secret.to_reply(|value| Zeroizing::new(value.to_owned()));
        assert_eq!(reply.len(), 1);
        let setting = &reply["802-11-wireless-security"];
        assert_eq!(setting.len(), 2);
        assert_eq!(setting["name"].as_str(), "802-11-wireless-security");
        assert_eq!(setting["psk"].as_str(), "test-password");
        assert_eq!(format!("{secret:?}"), "WifiPsk([REDACTED])");
    }
}
