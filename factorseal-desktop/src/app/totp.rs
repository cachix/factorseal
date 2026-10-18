use hmac::Hmac;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(super) struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl Totp {
    pub(super) fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        let secret = if let Some(uri) = value.strip_prefix("otpauth://totp/") {
            let (_, query) = uri.split_once('?')?;
            let mut secret = None;
            for (key, value) in query.split('&').filter_map(|pair| pair.split_once('=')) {
                match key {
                    "secret" => secret = Some(value),
                    "algorithm" => {
                        totp.algorithm = match value.to_ascii_uppercase().as_str() {
                            "SHA1" => Algorithm::Sha1,
                            "SHA256" => Algorithm::Sha256,
                            "SHA512" => Algorithm::Sha512,
                            _ => return None,
                        };
                    }
                    "digits" => totp.digits = value.parse().ok()?,
                    "period" => totp.period = value.parse().ok()?,
                    _ => {}
                }
            }
            secret?
        } else {
            value
        };
        let secret = Zeroizing::new(
            secret
                .chars()
                .filter(|c| !matches!(c, ' ' | '-' | '='))
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>(),
        );
        totp.secret = Zeroizing::new(data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).ok()?);
        (!totp.secret.is_empty() && (6..=8).contains(&totp.digits) && totp.period > 0)
            .then_some(totp)
    }

    pub(super) fn period(&self) -> u64 {
        self.period
    }

    pub(super) fn remaining(&self, now: u64) -> u64 {
        self.period - now % self.period
    }

    pub(super) fn code(&self, now: u64) -> Zeroizing<String> {
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

fn mac<M: hmac::Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

pub(super) fn grouped(code: &str) -> String {
    let middle = code.len().div_ceil(2);
    format!("{} {}", &code[..middle], &code[middle..])
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
    fn invalid_values_have_no_code() {
        for value in [
            "",
            "not base32!",
            "otpauth://totp/Example",
            "otpauth://totp/Example?issuer=Example",
            &format!("otpauth://totp/x?secret={RFC_SHA1}&algorithm=MD5"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&digits=4"),
            &format!("otpauth://totp/x?secret={RFC_SHA1}&period=0"),
        ] {
            assert!(Totp::parse(value).is_none(), "{value}");
        }
    }

    #[test]
    fn codes_are_split_in_the_middle() {
        assert_eq!(grouped("123456"), "123 456");
        assert_eq!(grouped("1234567"), "1234 567");
        assert_eq!(grouped("12345678"), "1234 5678");
    }
}
