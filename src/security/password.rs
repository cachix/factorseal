/// Validate a newly chosen vault password or archive passphrase. Never call
/// this when opening existing protection: policy changes must not lock out data.
pub fn validate_new_password(password: &[u8]) -> Result<(), String> {
    if password.len() > 64 * 1024 {
        return Err("password must not exceed 64 KiB".to_owned());
    }
    let text = std::str::from_utf8(password)
        .map_err(|_| "new passwords must be valid UTF-8".to_owned())?;
    let estimate = zxcvbn::zxcvbn(text, &["FactorSeal", "vault"]);
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
}
