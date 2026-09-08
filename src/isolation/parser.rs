#[cfg(feature = "vault")]
use super::process;
use super::{codec, sandbox};
use crate::VaultRequest;
#[cfg(feature = "vault")]
use crate::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};
use std::io;

const MAXIMUM: usize = 1024 * 1024;
/// One budget covers spawning the helper, its cold start, the request write,
/// and the reply read. A fresh sandboxed process pays for loader work, sandbox
/// installation, and on Windows an AppContainer registration plus a first
/// execution scan of a never-seen private copy, so the bound is well above a
/// warm decode. It stays below the client's response timeout and is finite:
/// a stuck helper is reaped when the budget ends.
#[cfg(feature = "vault")]
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    version: u8,
    request: Option<VaultRequest>,
}

/// Packaged parser entry point. The sandbox is installed before reading any
/// client-controlled bytes; stdin/stdout are inherited private capabilities.
pub fn run() -> io::Result<()> {
    sandbox::parser()?;
    let bytes = codec::read(&mut io::stdin().lock(), MAXIMUM)?;
    let reply = Reply {
        version: 1,
        request: VaultRequest::decode(&bytes).ok(),
    };
    codec::send(&mut io::stdout().lock(), &reply, MAXIMUM)
}

/// Parse raw JSON outside the key owner. The owner receives bounded typed CBOR
/// and independently checks the complete request before authorization.
#[cfg(feature = "vault")]
pub(crate) fn parse(bytes: &[u8]) -> VaultResult<VaultRequest> {
    #[cfg(any(unix, windows))]
    {
        let executable = process::helper_executable(
            &std::env::current_exe().map_err(failure)?,
            "factorseal-parser",
        )
        .map_err(failure)?;
        parse_with(&executable, bytes, TIMEOUT)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        Err(failure("isolated parser is unavailable on this platform"))
    }
}

#[cfg(all(any(unix, windows), feature = "vault"))]
fn parse_with(
    executable: &std::path::Path,
    bytes: &[u8],
    timeout: std::time::Duration,
) -> VaultResult<VaultRequest> {
    use crate::vault::transport::{IoBudget, read_frame, write_frame};
    let (_owner, mut channel) = process::spawn(executable, None).map_err(failure)?;
    let budget = IoBudget::new(timeout);
    write_frame(&mut channel, bytes, budget)?;
    let response = read_frame(&mut channel, budget)?;
    let reply: Reply = codec::decode(&response, MAXIMUM).map_err(failure)?;
    if reply.version != 1 {
        return Err(failure("unsupported parser reply version"));
    }
    let request = reply.request.ok_or_else(|| {
        crate::security::events::record(crate::security::events::Kind::MalformedRequest);
        failure("request rejected by isolated parser")
    })?;
    request.validate_fields()?;
    Ok(request)
}

#[cfg(feature = "vault")]
fn failure(error: impl std::fmt::Display) -> VaultError {
    VaultError::Protocol(format!("isolated request parsing failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(unix, feature = "vault"))]
    #[test]
    fn parser_failure_never_falls_back_to_parsing_valid_json_in_the_owner() {
        use std::{os::unix::fs::PermissionsExt, time::Duration};
        let fixture = tempfile::tempdir().unwrap();
        let executable = fixture.path().join("parser");
        let request = VaultRequest::new(crate::VaultAction::Status)
            .unwrap()
            .encode()
            .unwrap();
        for script in [
            "exit 1",
            "while :; do :; done",
            "printf '\\000\\000\\000\\001\\377'",
        ] {
            std::fs::write(&executable, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(parse_with(&executable, &request, Duration::from_millis(50)).is_err());
        }
        assert!(parse_with(&fixture.path().join("missing"), &request, TIMEOUT).is_err());
    }
    #[cfg(all(any(unix, windows), feature = "vault"))]
    #[test]
    fn installed_sandboxed_parser_accepts_valid_requests_and_rejects_invalid_input() {
        let request = VaultRequest::new(crate::VaultAction::Status).unwrap();
        assert_eq!(
            parse(&request.encode().unwrap()).unwrap().request_id(),
            request.request_id()
        );
        let malformed_count = || {
            crate::security::events::snapshot()
                .into_iter()
                .find(|event| event.kind == crate::security::events::Kind::MalformedRequest)
                .unwrap()
                .count
        };
        let before = malformed_count();
        assert!(parse(b"invalid json").is_err());
        assert!(malformed_count() > before);
        assert!(parse(&vec![b'['; MAXIMUM + 1]).is_err());
    }
    #[test]
    fn private_reply_codec_preserves_requests_with_optional_context_and_secrets() {
        use crate::{VaultAction, WireSecretAddress};
        let request = VaultRequest::new(VaultAction::Put {
            namespace: b"test".to_vec(),
            address: WireSecretAddress::new("secret", None),
            value: crate::WireSecret::new(b"secret bytes".to_vec()).unwrap(),
            evict_at: None,
        })
        .unwrap();
        let expected = request.encode().unwrap();
        let encoded = codec::encode(
            &Reply {
                version: 1,
                request: Some(request),
            },
            MAXIMUM,
        )
        .unwrap();
        let reply: Reply = codec::decode(&encoded, MAXIMUM).unwrap();
        assert_eq!(&*reply.request.unwrap().encode().unwrap(), &*expected);
    }
}
