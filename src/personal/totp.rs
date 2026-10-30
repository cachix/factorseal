use hmac::Hmac;
use percent_encoding::percent_decode_str;
use zeroize::Zeroizing;

const SCHEME: &str = "otpauth://totp/";
const PARAMETERS: [&str; 5] = ["secret", "issuer", "algorithm", "digits", "period"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[derive(PartialEq)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl Totp {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let secret = if let Some(link) = link(value) {
            let (_, query) = link.split_once('?')?;
            let mut secret = None;
            for (key, value) in query.split('&').filter_map(|pair| pair.split_once('=')) {
                match key {
                    "secret" => secret = Some(decoded(value)?),
                    "algorithm" => {
                        totp.algorithm = match decoded(value)?.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return None,
                        };
                    }
                    "digits" => totp.digits = decoded(value)?.parse().ok()?,
                    "period" => totp.period = decoded(value)?.parse().ok()?,
                    _ => {}
                }
            }
            secret?
        } else {
            Zeroizing::new(value.to_owned())
        };
        totp.secret = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(base32(&secret).as_bytes())
                .ok()?,
        );
        (!totp.secret.is_empty() && (6..=8).contains(&totp.digits) && totp.period > 0)
            .then_some(totp)
    }

    #[must_use]
    pub fn period(&self) -> u64 {
        self.period
    }

    #[must_use]
    pub fn remaining(&self, now: u64) -> u64 {
        self.period - now % self.period
    }

    #[must_use]
    pub fn code(&self, now: u64) -> Zeroizing<String> {
        let counter = (now / self.period).to_be_bytes();
        let digest = Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => mac::<Hmac<sha1::Sha1>>(&self.secret, &counter),
            Algorithm::Sha256 => mac::<Hmac<sha2::Sha256>>(&self.secret, &counter),
            Algorithm::Sha512 => mac::<Hmac<sha2::Sha512>>(&self.secret, &counter),
        });
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let digits = self.digits as usize;
        Zeroizing::new(format!("{:0digits$}", binary % 10_u32.pow(self.digits)))
    }
}

#[must_use]
pub fn same_key(first: &str, second: &str) -> bool {
    Totp::parse(first)
        .zip(Totp::parse(second))
        .is_some_and(|(first, second)| first == second)
}

#[must_use]
pub fn setup_link(text: &str) -> Option<Zeroizing<String>> {
    let text = text.trim();
    link(text)?;
    normalized(text)
}

#[must_use]
pub fn stored(value: &str) -> Option<Zeroizing<String>> {
    if value.trim().is_empty() {
        return Some(Zeroizing::new(String::new()));
    }
    normalized(value)
}

fn normalized(value: &str) -> Option<Zeroizing<String>> {
    let value = value.trim();
    Totp::parse(value)?;
    let Some(link) = link(value) else {
        return Some(base32(value));
    };
    let (label, query) = link.split_once('?')?;
    let mut stored = Zeroizing::new(String::with_capacity(value.len()));
    stored.push_str(SCHEME);
    stored.push_str(label);
    let mut separator = '?';
    for (key, value) in query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .filter(|(key, _)| PARAMETERS.contains(key))
    {
        stored.push(separator);
        separator = '&';
        stored.push_str(key);
        stored.push('=');
        if key == "secret" {
            stored.push_str(&base32(&decoded(value)?));
        } else {
            stored.push_str(value);
        }
    }
    Some(stored)
}

#[derive(Debug, Default, PartialEq)]
pub struct Origin {
    pub issuer: Option<String>,
    pub account: Option<String>,
}

#[must_use]
pub fn origin(value: &str) -> Origin {
    let Some(link) = link(value) else {
        return Origin::default();
    };
    let (label, query) = link.split_once('?').unwrap_or((link, ""));
    let label = decoded(label)
        .map(|label| label.to_string())
        .unwrap_or_default();
    let (named, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer), account),
        None => (None, label.as_str()),
    };
    let issuer = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "issuer")
        .and_then(|(_, value)| decoded(value))
        .map(|issuer| issuer.to_string())
        .or_else(|| named.map(str::to_owned));
    let present = |text: Option<String>| {
        text.map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    Origin {
        issuer: present(issuer),
        account: present(Some(account.to_owned())),
    }
}

#[must_use]
pub fn grouped(code: &str) -> String {
    let middle = code.len().div_ceil(2);
    format!("{} {}", &code[..middle], &code[middle..])
}

fn link(value: &str) -> Option<&str> {
    value
        .get(..SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SCHEME))
        .map(|_| &value[SCHEME.len()..])
}

fn decoded(value: &str) -> Option<Zeroizing<String>> {
    let value = percent_decode_str(value).decode_utf8().ok()?;
    Some(Zeroizing::new(value.into_owned()))
}

fn base32(key: &str) -> Zeroizing<String> {
    let mut base32 = Zeroizing::new(String::with_capacity(key.len()));
    base32.extend(
        key.chars()
            .filter(|c| !c.is_whitespace() && !matches!(c, '-' | '='))
            .map(|c| c.to_ascii_uppercase()),
    );
    base32
}

fn mac<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const RFC_SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const RFC_SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn uri(secret: &str, algorithm: &str) -> String {
        format!("otpauth://totp/Example:alice?secret={secret}&algorithm={algorithm}&digits=8")
    }

    #[test]
    fn codes_match_rfc_6238_vectors() {
        for (now, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
        ] {
            let code = |secret, algorithm| {
                Totp::parse(&uri(secret, algorithm))
                    .unwrap()
                    .code(now)
                    .to_string()
            };
            assert_eq!(code(RFC_SHA1, "SHA1"), sha1);
            assert_eq!(code(RFC_SHA256, "SHA256"), sha256);
            assert_eq!(code(RFC_SHA512, "SHA512"), sha512);
        }
    }

    #[test]
    fn bare_secrets_use_six_digits_every_thirty_seconds() {
        let totp = Totp::parse(" gezd gnbv gy3t qojq gezd gnbv gy3t qojq ").unwrap();
        assert_eq!(totp.code(59).as_str(), "287082");
        assert_eq!(totp.period(), 30);
        assert_eq!(totp.remaining(59), 1);
        assert_eq!(totp.remaining(60), 30);
    }

    #[test]
    fn links_accept_an_uppercase_scheme_and_encoded_values() {
        for value in [
            format!("OTPAUTH://TOTP/EXAMPLE?secret={RFC_SHA1}"),
            "otpauth://totp/Example?secret=JBSWY3DPEE%3D%3D%3D%3D%3D%3D".to_owned(),
        ] {
            assert!(Totp::parse(&value).is_some(), "{value}");
        }
        let encoded = format!("otpauth://totp/x?secret={RFC_SHA1}&algorithm=%53HA256&digits=8");
        assert_eq!(
            Totp::parse(&encoded).unwrap().code(59).as_str(),
            Totp::parse(&uri(RFC_SHA1, "SHA256"))
                .unwrap()
                .code(59)
                .as_str()
        );
    }

    #[test]
    fn invalid_values_have_no_code() {
        for value in [
            "",
            "not base32!",
            "otpauth://totp/Example",
            "otpauth://totp/Example?issuer=Example",
            "otpauth://hotp/Example?secret=GEZDGNBV&counter=1",
            &format!("otpauth://totp/x?secret={RFC_SHA1}&algorithm=MD5"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&digits=4"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&period=0"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&period=%FF"),
        ] {
            assert!(Totp::parse(value).is_none(), "{value}");
            assert!(normalized(value).is_none(), "{value}");
        }
    }

    #[test]
    fn links_name_their_issuer_and_account() {
        assert_eq!(
            origin(&format!(
                "otpauth://totp/Example%20Co:alice%40example.com?secret={RFC_SHA1}"
            )),
            Origin {
                issuer: Some("Example Co".into()),
                account: Some("alice@example.com".into()),
            }
        );
        assert_eq!(
            origin(&format!(
                "otpauth://totp/alice?secret={RFC_SHA1}&issuer=GitHub"
            )),
            Origin {
                issuer: Some("GitHub".into()),
                account: Some("alice".into()),
            }
        );
        assert_eq!(origin(RFC_SHA1), Origin::default());
        assert_eq!(
            origin(&format!("otpauth://totp/?secret={RFC_SHA1}")),
            Origin::default()
        );
    }

    #[test]
    fn keys_match_when_they_make_the_same_codes() {
        assert!(same_key(
            "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
            &format!("otpauth://totp/Example:alice?secret={RFC_SHA1}&digits=6&period=30")
        ));
        assert!(!same_key(RFC_SHA1, &uri(RFC_SHA1, "SHA256")));
        assert!(!same_key(RFC_SHA1, "JBSWY3DPEHPK3PXP"));
        assert!(!same_key("not base32!", "not base32!"));
    }

    #[test]
    fn only_links_that_make_codes_are_setup_links() {
        assert_eq!(
            setup_link(&format!(
                " OTPAUTH://TOTP/Example?secret={}\n",
                RFC_SHA1.to_lowercase()
            ))
            .unwrap()
            .as_str(),
            format!("otpauth://totp/Example?secret={RFC_SHA1}")
        );
        assert!(setup_link(RFC_SHA1).is_none());
        assert!(setup_link("otpauth://totp/Example?secret=not base32!").is_none());
        assert!(setup_link("https://example.com").is_none());
        assert!(link("otpauth://totp/Example?secret=not base32!").is_some());
        assert!(link(RFC_SHA1).is_none());
    }

    #[test]
    fn keys_are_stored_without_spaces_padding_or_lowercase() {
        assert_eq!(
            stored(" gezd-gnbv gy3t qojq\tgezd gnbv gy3t qojq== ")
                .unwrap()
                .as_str(),
            RFC_SHA1
        );
        assert_eq!(stored("  ").unwrap().as_str(), "");
        assert!(stored("not base32!").is_none());
    }

    #[test]
    fn links_keep_their_label_and_exchanged_parameters() {
        let stored = normalized(&format!(
            "OTPAUTH://TOTP/Example%20Co:alice%40example.com?secret={}&issuer=Example%20Co&image=https%3A%2F%2Fexample.com%2Fa.png&digits=8&period=60&algorithm=SHA256",
            RFC_SHA1.to_lowercase()
        ))
        .unwrap();
        assert_eq!(
            stored.as_str(),
            format!(
                "otpauth://totp/Example%20Co:alice%40example.com?secret={RFC_SHA1}&issuer=Example%20Co&digits=8&period=60&algorithm=SHA256"
            )
        );
        assert_eq!(normalized(&stored).unwrap(), stored);
    }

    #[test]
    fn codes_are_split_in_the_middle() {
        assert_eq!(grouped("123456"), "123 456");
        assert_eq!(grouped("1234567"), "1234 567");
        assert_eq!(grouped("12345678"), "1234 5678");
    }
}
