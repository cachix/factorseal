const PRIVATE_SUFFIXES: [&str; 15] = [
    "alt",
    "arpa",
    "corp",
    "example",
    "home",
    "internal",
    "intranet",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "private",
    "test",
];

#[must_use]
pub fn host(website: &str) -> Option<String> {
    let website = website.trim();
    if website
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return None;
    }
    let rest = match website.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http") =>
        {
            rest
        }
        Some(_) => return None,
        None => website,
    };
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.split_once(':') {
        Some((host, port))
            if !port.is_empty()
                && port.len() <= 5
                && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        Some(_) => return None,
        None => authority,
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    is_public_host(&host).then_some(host)
}

#[must_use]
pub fn is_public_host(host: &str) -> bool {
    let labels: Vec<_> = host.split('.').collect();
    let Some(suffix) = labels.last() else {
        return false;
    };
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && (suffix.starts_with("xn--")
            || (suffix.len() >= 2 && suffix.bytes().all(|byte| byte.is_ascii_lowercase())))
        && !PRIVATE_SUFFIXES.contains(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn website_host_is_the_lowercase_domain_name() {
        for (website, expected) in [
            ("github.com", "github.com"),
            (" https://GitHub.com/login?next=/ ", "github.com"),
            ("http://app.cachix.org:8443/path", "app.cachix.org"),
            (
                "https://user:pass@console.hetzner.cloud/",
                "console.hetzner.cloud",
            ),
            ("studio.youtube.com/channel#x", "studio.youtube.com"),
            ("https://discourse.nixos.org.", "discourse.nixos.org"),
            (
                "https://xn--bcher-kva.example.xn--p1ai",
                "xn--bcher-kva.example.xn--p1ai",
            ),
        ] {
            assert_eq!(host(website).as_deref(), Some(expected), "{website}");
        }
    }

    #[test]
    fn website_host_rejects_addresses_that_are_not_public_domain_names() {
        for website in [
            "",
            "localhost",
            "http://localhost:8080",
            "router.local",
            "nas.lan",
            "printer.internal",
            "app.localhost",
            "intranet",
            "http://192.168.1.1",
            "10.0.0.1",
            "https://[::1]/",
            "ftp://example.com",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "not a site",
            "https://exa mple.com",
            "https://-bad.com",
            "https://bad-.com",
            "https://under_score.com",
            "https://bücher.de",
            "https://github.com:http",
            "https://a..com",
            "https://example.c",
            "https://example.123",
        ] {
            assert_eq!(host(website), None, "{website}");
        }
        assert!(!is_public_host(&format!("{}.com", "a".repeat(64))));
        assert!(!is_public_host(&vec!["a".repeat(63); 5].join(".")));
        assert!(!is_public_host("GitHub.com"));
        assert!(!is_public_host("github.com/"));
        assert!(is_public_host("github.com"));
    }
}
