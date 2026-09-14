use network_manager_protocol::{
    EapSecretProperty, EapSecretValue, EapSecrets, SecretFlags, WifiPsk,
};
use zeroize::Zeroizing;

use super::{Error, Settings};
use crate::vault::{WireSecret, WireSecretAddress};

pub(super) const NAMESPACE: &[u8] = b"factorseal/network-manager/v1";
pub(super) const NAME_FIELD: &str = "connection-name";
const MAX_VALUE: usize = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) enum Property {
    Psk,
    Eap(EapSecretProperty),
}

pub(super) const PROPERTIES: [Property; 10] = [
    Property::Psk,
    Property::Eap(EapSecretProperty::Password),
    Property::Eap(EapSecretProperty::PasswordRaw),
    Property::Eap(EapSecretProperty::Pin),
    Property::Eap(EapSecretProperty::PrivateKeyPassword),
    Property::Eap(EapSecretProperty::Phase2PrivateKeyPassword),
    Property::Eap(EapSecretProperty::CaCertPassword),
    Property::Eap(EapSecretProperty::Phase2CaCertPassword),
    Property::Eap(EapSecretProperty::ClientCertPassword),
    Property::Eap(EapSecretProperty::Phase2ClientCertPassword),
];

impl Property {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Psk => "Wi-Fi password",
            Self::Eap(EapSecretProperty::Password | EapSecretProperty::PasswordRaw) => {
                "Enterprise password"
            }
            Self::Eap(EapSecretProperty::Pin) => "Token PIN",
            Self::Eap(EapSecretProperty::PrivateKeyPassword) => "Private key password",
            Self::Eap(EapSecretProperty::Phase2PrivateKeyPassword) => {
                "Inner authentication private key password"
            }
            Self::Eap(EapSecretProperty::CaCertPassword) => "CA certificate token password",
            Self::Eap(EapSecretProperty::Phase2CaCertPassword) => {
                "Inner authentication CA certificate token password"
            }
            Self::Eap(EapSecretProperty::ClientCertPassword) => "Client certificate token password",
            Self::Eap(EapSecretProperty::Phase2ClientCertPassword) => {
                "Inner authentication client certificate token password"
            }
        }
    }

    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Psk => "psk",
            Self::Eap(property) => property.name(),
        }
    }

    pub(super) const fn setting(self) -> &'static str {
        match self {
            Self::Psk => network_manager_protocol::WIFI_SECURITY_SETTING,
            Self::Eap(_) => network_manager_protocol::EAP_SETTING,
        }
    }

    pub(super) const fn flags_name(self) -> &'static str {
        match self {
            Self::Psk => "psk-flags",
            Self::Eap(property) => property.flags_name(),
        }
    }

    pub(super) const fn is_raw(self) -> bool {
        matches!(self, Self::Eap(EapSecretProperty::PasswordRaw))
    }

    pub(super) fn address(self, uuid: &str) -> WireSecretAddress {
        WireSecretAddress::new(uuid, Some(format!("{}/{}", self.setting(), self.name())))
    }

    pub(super) fn validate(self, key_management: &str, value: &[u8]) -> Result<(), Error> {
        if value.len() > MAX_VALUE {
            return Err(Error::invalid());
        }
        let text = || {
            std::str::from_utf8(value)
                .map(|text| Zeroizing::new(text.to_owned()))
                .map_err(|_| Error::invalid())
        };
        match self {
            Self::Psk => {
                WifiPsk::new(key_management, text()?).map_err(|_| Error::invalid())?;
            }
            Self::Eap(property) => {
                let value = if self.is_raw() {
                    EapSecretValue::Bytes(Zeroizing::new(value.to_vec()))
                } else {
                    EapSecretValue::Text(text()?)
                };
                EapSecrets::default()
                    .insert(property, value)
                    .map_err(|_| Error::invalid())?;
            }
        }
        Ok(())
    }
}

pub(super) struct Credential {
    pub property: Property,
    pub flags: SecretFlags,
    pub supplied: Option<WireSecret>,
    pub needed: bool,
}

pub(super) struct Profile {
    pub uuid: String,
    pub label: String,
    pub key_management: String,
    pub setting: &'static str,
    pub credentials: Vec<Credential>,
}

fn string<'a>(settings: &'a Settings, section: &str, key: &str) -> Result<&'a str, Error> {
    settings
        .get(section)
        .and_then(|values| values.get(key))
        .and_then(|value| <&str>::try_from(value).ok())
        .ok_or_else(Error::invalid)
}

fn strings(value: Option<&zbus::zvariant::OwnedValue>) -> Result<Vec<String>, Error> {
    value
        .map(|value| {
            Vec::<String>::try_from(value.try_clone().map_err(|_| Error::invalid())?)
                .map_err(|_| Error::invalid())
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

impl Profile {
    pub(super) fn uuid(settings: &Settings) -> Result<String, Error> {
        if string(settings, "connection", "type")? != "802-11-wireless" {
            return Err(Error::NoSecrets(
                "Only Wi-Fi connections are supported".into(),
            ));
        }
        let uuid = string(settings, "connection", "uuid")?;
        if uuid.len() != 36
            || !uuid.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return Err(Error::invalid());
        }
        Ok(uuid.to_ascii_lowercase())
    }

    pub(super) fn parse(settings: &Settings, hints: &[String]) -> Result<Self, Error> {
        let uuid = Self::uuid(settings)?;
        let label = string(settings, "connection", "id")?;
        if label.len() > 1024 {
            return Err(Error::invalid());
        }
        let key_management = string(
            settings,
            network_manager_protocol::WIFI_SECURITY_SETTING,
            "key-mgmt",
        )?;
        let setting = match key_management {
            "wpa-psk" | "sae" => network_manager_protocol::WIFI_SECURITY_SETTING,
            "wpa-eap" | "wpa-eap-suite-b-192" => network_manager_protocol::EAP_SETTING,
            _ => return Err(Error::NoSecrets("Unsupported Wi-Fi security".into())),
        };
        let values = settings.get(setting).ok_or_else(Error::invalid)?;
        let eap = strings(values.get("eap"))?;
        let inner_tls = ["phase2-auth", "phase2-autheap"].into_iter().any(|key| {
            values
                .get(key)
                .and_then(|value| <&str>::try_from(value).ok())
                == Some("tls")
        });
        let raw = values.contains_key("password-raw")
            || hints.iter().any(|hint| hint == "password-raw")
            || (values
                .get("password-raw-flags")
                .and_then(|value| u32::try_from(value).ok())
                .is_some_and(|flags| flags != 0)
                && values
                    .get("password-flags")
                    .and_then(|value| u32::try_from(value).ok())
                    .is_none_or(|flags| flags == 0));
        let mut credentials = Vec::new();
        // Hints select which missing values to ask the user for. They do not
        // filter stored values from the reply (the protocol calls them advisory).
        let has_secret_hints = hints.iter().any(|hint| {
            PROPERTIES
                .iter()
                .any(|property| property.setting() == setting && property.name() == hint)
        });
        for property in PROPERTIES
            .into_iter()
            .filter(|property| property.setting() == setting)
        {
            let flags = values
                .get(property.flags_name())
                .map(|value| u32::try_from(value).map_err(|_| Error::invalid()))
                .transpose()?
                .unwrap_or(0);
            let flags = SecretFlags::from_bits_retain(flags);
            let supplied = values
                .get(property.name())
                .map(|value| {
                    let bytes = if property.is_raw() {
                        Vec::<u8>::try_from(value.try_clone().map_err(|_| Error::invalid())?)
                            .map_err(|_| Error::invalid())?
                    } else {
                        <&str>::try_from(value)
                            .map_err(|_| Error::invalid())?
                            .as_bytes()
                            .to_vec()
                    };
                    // Supplied secrets are locked immediately. GetSecrets may contain an
                    // invalid previous password, so validate only before saving/returning.
                    WireSecret::new(bytes).map_err(|_| Error::failed())
                })
                .transpose()?;
            let default_needed = match property {
                Property::Psk => true,
                Property::Eap(EapSecretProperty::Password) => {
                    !raw && eap.iter().any(|method| method != "tls") && !inner_tls
                }
                Property::Eap(EapSecretProperty::PasswordRaw) => raw && !inner_tls,
                Property::Eap(EapSecretProperty::PrivateKeyPassword) => {
                    eap.iter().any(|method| method == "tls")
                }
                Property::Eap(EapSecretProperty::Phase2PrivateKeyPassword) => inner_tls,
                Property::Eap(_) => false,
            };
            let needed = !flags.contains(SecretFlags::NOT_REQUIRED)
                && ((!has_secret_hints && default_needed)
                    || hints.iter().any(|hint| hint == property.name()));
            credentials.push(Credential {
                property,
                flags,
                supplied,
                needed,
            });
        }
        Ok(Self {
            uuid,
            label: label.to_owned(),
            key_management: key_management.to_owned(),
            setting,
            credentials,
        })
    }
}
