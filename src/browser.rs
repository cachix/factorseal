//! Experimental browser protocol. Browser metadata is never a vault address.
use crate::{VaultError, VaultResult, WireSecret};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub mod desktop;
pub mod discovery;
pub mod registration;
pub use crate::vault::browser_transport as transport;

pub const VERSION: u16 = 1;
pub const MAX_FRAME: usize = 64 * 1024;
pub const PAIR_NAMESPACE: &[u8] = b"factorseal/browser-pairing/v1";

pub(crate) fn random_id() -> VaultResult<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| invalid())?;
    Ok(hex::encode(bytes))
}

pub fn origin(value: &str) -> VaultResult<String> {
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid());
    }
    Ok(url.origin().ascii_serialization())
}
fn invalid() -> VaultError {
    VaultError::Protocol("invalid browser request".into())
}

/// The exact UTF-8 payload is signed; no cross-language JSON canonicalization.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub key: String,
    pub payload: String,
    pub signature: String,
}
impl std::fmt::Debug for Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}
impl Drop for Signed {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.payload.zeroize();
    }
}
impl Signed {
    pub fn verify(&self) -> VaultResult<Command> {
        use ed25519_dalek::{Signature, VerifyingKey};
        if self.payload.len() > MAX_FRAME - 1024
            || self.key.len() != 64
            || self.signature.len() != 128
        {
            return Err(invalid());
        }
        let key: [u8; 32] = hex::decode(&self.key)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        let sig: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| invalid())?
            .try_into()
            .map_err(|_| invalid())?;
        VerifyingKey::from_bytes(&key)
            .map_err(|_| invalid())?
            .verify_strict(self.payload.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| invalid())?;
        let command: Command = serde_json::from_str(&self.payload).map_err(|_| invalid())?;
        command.validate()?;
        Ok(command)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub version: u16,
    pub session: String,
    pub sequence: u32,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<discovery::Browser>,
}
impl Command {
    fn validate(&self) -> VaultResult<()> {
        if self.version != VERSION || self.session.len() != 64 || self.sequence == 0 {
            return Err(invalid());
        }
        if let Action::Detect {
            origin: site,
            document,
        }
        | Action::Save {
            origin: site,
            document,
            ..
        } = &self.action
            && (site.len() > 2048
                || origin(site)? != *site
                || document.is_empty()
                || document.len() > 128)
        {
            return Err(invalid());
        }
        if let Action::Save {
            username, password, ..
        } = &self.action
            && (username.is_empty()
                || username.len() > 512
                || password.expose().is_empty()
                || password.expose().len() > 4096
                || std::str::from_utf8(password.expose()).is_err())
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Pair,
    Detect {
        origin: String,
        document: String,
    },
    Save {
        origin: String,
        document: String,
        username: String,
        password: WireSecret,
    },
    Poll,
    Confirm {
        nonce: String,
    },
    Cancel,
    Revoke,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Hello { version: u16 },
    Signed { message: Signed },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Hello {
        version: u16,
        session: String,
    },
    State {
        state: String,
    },
    Context {
        nonce: String,
    },
    Fill {
        username: WireSecret,
        password: WireSecret,
    },
    Finished {
        reason: String,
    },
}
impl Response {
    #[must_use]
    pub fn state(state: &str) -> Self {
        Self::State {
            state: state.into(),
        }
    }
    #[must_use]
    pub fn finished(reason: &str) -> Self {
        Self::Finished {
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub username: String,
    pub digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerAction {
    Pair {
        key: String,
    },
    Revoke {
        key: String,
    },
    Lookup {
        request: Signed,
    },
    Release {
        ticket: String,
        candidate: Candidate,
        confirmation: Signed,
    },
    Save {
        ticket: String,
        candidate: Option<Candidate>,
        request: Signed,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerReply {
    Done,
    AlreadySaved,
    Candidates {
        ticket: String,
        candidates: Vec<Candidate>,
    },
    Fill {
        username: WireSecret,
        password: WireSecret,
    },
}

pub fn read_native(reader: &mut impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_ne_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::other("invalid native frame size"));
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_native(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::other("invalid native frame size"));
    }
    writer.write_all(
        &u32::try_from(bytes.len())
            .map_err(io::Error::other)?
            .to_ne_bytes(),
    )?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn origin_boundaries() {
        assert_eq!(
            origin("https://EXAMPLE.com:443/path?q=1").unwrap(),
            "https://example.com"
        );
        assert_ne!(
            origin("https://example.com:444").unwrap(),
            origin("https://example.com").unwrap()
        );
        assert_ne!(
            origin("https://login.example.com").unwrap(),
            origin("https://example.com").unwrap()
        );
        for bad in [
            "http://example.com",
            "https://u:p@example.com",
            "data:text/html,hi",
            "https://",
        ] {
            assert!(origin(bad).is_err());
        }
    }
    #[test]
    fn framing_rejects_oversize_and_truncation() {
        assert!(read_native(&mut &(u32::MAX.to_ne_bytes())[..]).is_err());
        assert!(read_native(&mut &[0, 0, 0, 0][..]).is_err());
        let mut bytes = vec![];
        write_native(&mut bytes, b"ok").unwrap();
        bytes.push(7);
        let mut input = bytes.as_slice();
        assert_eq!(&*read_native(&mut input).unwrap(), b"ok");
        assert_eq!(input, [7]);
    }
}

#[cfg(test)]
mod interoperability {
    #[test]
    fn webcrypto_fixture_verifies_without_json_reserialization() {
        let signed: super::Signed = serde_json::from_str(include_str!(
            "../extensions/browser/fixtures/signed-request.json"
        ))
        .unwrap();
        let command = signed.verify().unwrap();
        assert!(
            matches!(command.action,super::Action::Detect{origin,..} if origin=="https://example.com")
        );
        let mut altered = signed;
        altered.payload.push(' ');
        assert!(altered.verify().is_err());
    }
}
