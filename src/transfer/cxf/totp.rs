use super::{Value, array, cxf, text};
use anyhow::{Context as _, bail};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde::Deserialize as _;
use zeroize::Zeroizing;

pub(super) fn export(value: &str) -> anyhow::Result<Value> {
    let credential = Zeroizing::new(export_credential(value)?);
    serde_json::to_value(&*credential).context("cannot encode TOTP")
}

fn empty_totp() -> cxf::TotpCredential {
    cxf::TotpCredential {
        secret: Vec::new().into(),
        period: 30,
        digits: 6,
        algorithm: cxf::OTPHashAlgorithm::Sha1,
        username: None,
        issuer: None,
        additional_fields: cxf::AdditionalFields::default(),
    }
}

pub(super) fn export_credential(value: &str) -> anyhow::Result<cxf::Credential> {
    let mut result = Zeroizing::new(empty_totp());
    if let Some(uri) = value.strip_prefix("otpauth://totp/") {
        let (label, query) = uri
            .split_once('?')
            .context("TOTP URI is missing its secret")?;
        let label = decode(label)?;
        let (issuer, username) = label
            .split_once(':')
            .map_or((None, label.as_str()), |(i, u)| (Some(i), u));
        if !username.is_empty() {
            result.username = Some(username.into());
        }
        if let Some(issuer) = issuer {
            result.issuer = Some(issuer.into());
        }
        let mut keys = std::collections::HashSet::new();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').context("invalid TOTP URI parameter")?;
            if !keys.insert(key) {
                bail!("duplicate TOTP URI parameter");
            }
            let value = decode(value)?;
            match key {
                "secret" => result.secret = parse_secret(&value)?,
                "issuer" => {
                    if issuer.is_some_and(|i| i != value.as_str()) {
                        bail!("conflicting TOTP issuer");
                    }
                    result.issuer = Some(value.to_string());
                }
                "algorithm" => {
                    result.algorithm = match value.to_ascii_lowercase().as_str() {
                        "sha1" => cxf::OTPHashAlgorithm::Sha1,
                        "sha256" => cxf::OTPHashAlgorithm::Sha256,
                        "sha512" => cxf::OTPHashAlgorithm::Sha512,
                        _ => bail!("unsupported TOTP algorithm"),
                    }
                }
                "period" | "digits" => {
                    let number = value
                        .parse::<u8>()
                        .context("invalid TOTP numeric parameter")?;
                    if key == "period" {
                        result.period = number;
                    } else {
                        result.digits = number;
                    }
                }
                _ => bail!("unsupported TOTP URI parameter; use a FactorSeal archive"),
            }
        }
    } else {
        result.secret = parse_secret(value)?;
    }
    validate(&result)?;
    Ok(cxf::Credential::Totp(Box::new(std::mem::replace(
        &mut *result,
        empty_totp(),
    ))))
}

pub(super) fn import(value: &Value) -> anyhow::Result<Zeroizing<String>> {
    // Enforce our input policy before the crate's permissive base32 parser
    // normalizes spelling. The crate validates the encoding and field schema.
    let _secret = Zeroizing::new(parse_secret(text(value, "secret")?)?);
    let credential = Zeroizing::new(
        cxf::Credential::<()>::deserialize(value)
            .map_err(|_| anyhow::anyhow!("invalid TOTP credential"))?,
    );
    let cxf::Credential::Totp(totp) = &*credential else {
        bail!("invalid TOTP credential");
    };
    validate(totp)?;
    let mut uri = Zeroizing::new(String::from("otpauth://totp/"));
    if let Some(issuer) = &totp.issuer {
        uri.push_str(&utf8_percent_encode(issuer, NON_ALPHANUMERIC).to_string());
        uri.push(':');
    }
    let username = totp.username.as_deref().unwrap_or("");
    uri.push_str(&utf8_percent_encode(username, NON_ALPHANUMERIC).to_string());
    uri.push_str("?secret=");
    uri.push_str(text(value, "secret")?);
    uri.push_str("&period=");
    uri.push_str(&totp.period.to_string());
    uri.push_str("&digits=");
    uri.push_str(&totp.digits.to_string());
    uri.push_str("&algorithm=");
    uri.push_str(match totp.algorithm {
        cxf::OTPHashAlgorithm::Sha1 => "SHA1",
        cxf::OTPHashAlgorithm::Sha256 => "SHA256",
        cxf::OTPHashAlgorithm::Sha512 => "SHA512",
        _ => bail!("unsupported TOTP algorithm"),
    });
    Ok(uri)
}

fn parse_secret(secret: &str) -> anyhow::Result<cxf::B32> {
    if secret.is_empty()
        || !secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    {
        bail!("TOTP secret must be unpadded uppercase base32");
    }
    cxf::B32::try_from(secret).map_err(|_| anyhow::anyhow!("invalid TOTP base32"))
}

fn validate(value: &cxf::TotpCredential) -> anyhow::Result<()> {
    if !matches!(
        value.algorithm,
        cxf::OTPHashAlgorithm::Sha1 | cxf::OTPHashAlgorithm::Sha256 | cxf::OTPHashAlgorithm::Sha512
    ) {
        bail!("unsupported TOTP algorithm");
    }
    if value.secret.as_ref().is_empty() || value.period == 0 || value.digits == 0 {
        bail!("invalid TOTP parameters");
    }
    Ok(())
}

fn decode(value: &str) -> anyhow::Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        percent_decode_str(value)
            .decode_utf8()
            .context("invalid TOTP URI encoding")?
            .into_owned(),
    ))
}

pub(super) fn field_metadata(
    native: Option<&Value>,
    index: usize,
) -> anyhow::Result<Option<&Value>> {
    let Some(native) = native else {
        return Ok(None);
    };
    if native.get("totpFields").is_none() {
        return Ok(None);
    }
    Ok(array(native, "totpFields")?
        .iter()
        .find(|m| m["index"].as_u64() == Some(index as u64)))
}
