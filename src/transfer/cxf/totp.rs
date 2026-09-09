use super::{SensitiveJson, Value, array, text};
use anyhow::{Context as _, bail};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::json;
use zeroize::Zeroizing;

pub(super) fn export(value: &str) -> anyhow::Result<Value> {
    let mut result =
        SensitiveJson(json!({"type":"totp","secret":"","period":30,"digits":6,"algorithm":"sha1"}));
    if let Some(uri) = value.strip_prefix("otpauth://totp/") {
        let (label, query) = uri
            .split_once('?')
            .context("TOTP URI is missing its secret")?;
        let label = decode(label)?;
        let (issuer, username) = label
            .split_once(':')
            .map_or((None, label.as_str()), |(i, u)| (Some(i), u));
        if !username.is_empty() {
            result.0["username"] = username.into();
        }
        if let Some(issuer) = issuer {
            result.0["issuer"] = issuer.into();
        }
        let mut keys = std::collections::HashSet::new();
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').context("invalid TOTP URI parameter")?;
            if !keys.insert(key) {
                bail!("duplicate TOTP URI parameter");
            }
            let value = decode(value)?;
            match key {
                "secret" => result.0["secret"] = value.as_str().into(),
                "issuer" => {
                    if issuer.is_some_and(|i| i != value.as_str()) {
                        bail!("conflicting TOTP issuer");
                    }
                    result.0["issuer"] = value.as_str().into();
                }
                "algorithm" => result.0["algorithm"] = value.to_ascii_lowercase().into(),
                "period" | "digits" => {
                    result.0[key] = value
                        .parse::<u16>()
                        .context("invalid TOTP numeric parameter")?
                        .into();
                }
                _ => bail!("unsupported TOTP URI parameter; use a FactorSeal archive"),
            }
        }
    } else {
        result.0["secret"] = value.into();
    }
    validate(&result)?;
    Ok(result.0.take())
}

pub(super) fn import(value: &Value) -> anyhow::Result<Zeroizing<String>> {
    validate(value)?;
    let mut uri = Zeroizing::new(String::from("otpauth://totp/"));
    if let Some(issuer) = value.get("issuer") {
        uri.push_str(
            &utf8_percent_encode(
                issuer.as_str().context("invalid TOTP issuer")?,
                NON_ALPHANUMERIC,
            )
            .to_string(),
        );
        uri.push(':');
    }
    let username = value
        .get("username")
        .map(|v| v.as_str().context("invalid TOTP username"))
        .transpose()?
        .unwrap_or("");
    uri.push_str(&utf8_percent_encode(username, NON_ALPHANUMERIC).to_string());
    uri.push_str("?secret=");
    uri.push_str(text(value, "secret")?);
    uri.push_str("&period=");
    uri.push_str(&value["period"].to_string());
    uri.push_str("&digits=");
    uri.push_str(&value["digits"].to_string());
    uri.push_str("&algorithm=");
    uri.push_str(&text(value, "algorithm")?.to_ascii_uppercase());
    Ok(uri)
}

fn validate(value: &Value) -> anyhow::Result<()> {
    let secret = text(value, "secret")?;
    if secret.is_empty()
        || !secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    {
        bail!("TOTP secret must be unpadded uppercase base32");
    }
    let unused = match secret.len() % 8 {
        0 => 0,
        2 => 2,
        4 => 4,
        5 => 1,
        7 => 3,
        _ => bail!("invalid TOTP base32 length"),
    };
    let last = secret.as_bytes()[secret.len() - 1];
    let digit = if last.is_ascii_uppercase() {
        last - b'A'
    } else {
        last - b'2' + 26
    };
    if digit & ((1 << unused) - 1) != 0 {
        bail!("invalid TOTP base32 trailing bits");
    }
    if !matches!(text(value, "algorithm")?, "sha1" | "sha256" | "sha512") {
        bail!("unsupported TOTP algorithm");
    }
    for key in ["period", "digits"] {
        if !value[key]
            .as_u64()
            .is_some_and(|n| n > 0 && u16::try_from(n).is_ok())
        {
            bail!("invalid TOTP parameters");
        }
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
