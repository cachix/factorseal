#![allow(clippy::unnecessary_wraps)]

pub(crate) const fn configured() -> bool {
    false
}

pub(crate) fn submit_issue(_description: &str) -> std::io::Result<String> {
    Err(std::io::Error::other("Sentry submission unavailable"))
}

pub(crate) const fn issue_sent(_id: &str) -> std::io::Result<bool> {
    Ok(false)
}

pub(crate) const fn set_enabled(_enabled: bool) {}
