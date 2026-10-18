/// Validate a newly chosen vault password or archive passphrase. Never call
/// this when opening existing protection: policy changes must not lock out data.
pub fn validate_new_password(password: &[u8]) -> Result<(), String> {
    if password.len() > 64 * 1024 {
        return Err("password must not exceed 64 KiB".to_owned());
    }
    let text = std::str::from_utf8(password)
        .map_err(|_| "new passwords must be valid UTF-8".to_owned())?;
    let estimate = estimate(text);
    if estimate.score() >= zxcvbn::Score::Three {
        return Ok(());
    }
    let guidance = estimate
        .feedback()
        .map(ToString::to_string)
        .filter(|feedback| !feedback.is_empty())
        .unwrap_or_else(|| "Use a few uncommon words that are easy to remember.".to_owned());
    Err(format!("Choose a stronger password. {guidance}"))
}

#[must_use]
pub fn password_score(password: &str) -> u8 {
    if password.len() > 64 * 1024 {
        return 0;
    }
    u8::from(estimate(password).score())
}

fn estimate(password: &str) -> zxcvbn::Entropy {
    zxcvbn::zxcvbn(password, &["FactorSeal", "vault"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_password_policy_rejects_guessable_and_accepts_strong_secrets() {
        for password in [b"".as_slice(), b"password", b"P@ssword1", b"factorseal"] {
            assert!(validate_new_password(password).is_err());
        }
        assert!(validate_new_password(b"opal nebula lantern saffron velocity").is_ok());
        assert!(validate_new_password(&vec![b'x'; 65537]).is_err());
        assert!(validate_new_password(&[0xff; 32]).is_err());
    }

    #[test]
    fn password_score_matches_the_new_password_policy() {
        for password in [
            "",
            "password",
            "P@ssword1",
            "factorseal",
            "opal nebula lantern saffron velocity",
        ] {
            assert_eq!(
                password_score(password) >= 3,
                validate_new_password(password.as_bytes()).is_ok()
            );
        }
    }

    #[test]
    fn password_score_ranks_guessable_below_strong_secrets() {
        assert_eq!(password_score(""), 0);
        assert!(password_score("password") <= 1);
        assert_eq!(password_score("opal nebula lantern saffron velocity"), 4);
        assert_eq!(password_score(&"x".repeat(64 * 1024 + 1)), 0);
    }
}
