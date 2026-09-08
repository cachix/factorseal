//! A bounded OpenSSH agent endpoint alongside the native vault socket.

use std::io;
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

mod binding;
pub(crate) mod crypto;
use binding::Bindings;

pub(crate) fn grant_namespace(
    fingerprint: &str,
    destination: Option<&super::SshDestination>,
) -> VaultResult<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let scope = serde_json::to_vec(&destination).map_err(|_| invalid())?;
    Ok(format!(
        "factorseal/ssh-sign/v2/{fingerprint}/{}",
        hex::encode(Sha256::digest(scope))
    )
    .into_bytes())
}

use super::transport::{IoBudget, read_frame, unix_time, write_frame};
use super::{
    CallerIdentity, PermissionWaitStatus, SecretAddress, VaultError, VaultResult, VaultService,
};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const MAX_CONNECTIONS: usize = 8;
const CONNECTION_TIMEOUT: Duration = Duration::from_mins(2);
const APPROVAL_TIMEOUT: Duration = Duration::from_mins(1);

pub(crate) struct SshIdentity {
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub title: String,
    pub address: SecretAddress,
}

pub(crate) enum AgentRequest<'a> {
    Identities,
    Sign {
        public_key: &'a [u8],
        data: &'a [u8],
        flags: u32,
        destination: Option<super::SshDestination>,
    },
    Bind {
        host_key: &'a [u8],
        session_id: &'a [u8],
        signature: &'a [u8],
        forwarding: bool,
    },
}

pub(crate) enum AgentReply {
    Pending(String),
    Ready {
        bytes: Vec<u8>,
        deadline: Option<Instant>,
        cancelled: Arc<AtomicBool>,
    },
}

impl<'a> AgentRequest<'a> {
    fn decode(bytes: &'a [u8]) -> VaultResult<Self> {
        let Some((&kind, mut rest)) = bytes.split_first() else {
            return Err(invalid());
        };
        let request = match kind {
            REQUEST_IDENTITIES => Self::Identities,
            SIGN_REQUEST => {
                let public_key = string(&mut rest)?;
                let data = string(&mut rest)?;
                let flags = uint32(&mut rest)?;
                if !matches!(flags, 0 | 2 | 4)
                    || public_key.len() > 16 * 1024
                    || data.len() > 256 * 1024
                {
                    return Err(invalid());
                }
                Self::Sign {
                    public_key,
                    data,
                    flags,
                    destination: None,
                }
            }
            27 => {
                if string(&mut rest)? != b"session-bind@openssh.com" {
                    return Err(invalid());
                }
                let host_key = string(&mut rest)?;
                let session_id = string(&mut rest)?;
                let signature = string(&mut rest)?;
                let forwarding = match rest.split_first() {
                    Some((0, tail)) => {
                        rest = tail;
                        false
                    }
                    Some((1, tail)) => {
                        rest = tail;
                        true
                    }
                    _ => return Err(invalid()),
                };
                Self::Bind {
                    host_key,
                    session_id,
                    signature,
                    forwarding,
                }
            }
            // Key mutation, lock/unlock and provider extensions
            // are deliberately unsupported. Vault management owns key lifecycle.
            _ => return Err(invalid()),
        };
        if !rest.is_empty() {
            return Err(invalid());
        }
        Ok(request)
    }
}

fn invalid() -> VaultError {
    VaultError::Protocol("unsupported or malformed SSH agent request".into())
}

fn uint32(bytes: &mut &[u8]) -> VaultResult<u32> {
    let head = bytes.get(..4).ok_or_else(invalid)?;
    let value = u32::from_be_bytes(head.try_into().map_err(|_| invalid())?);
    *bytes = &bytes[4..];
    Ok(value)
}

fn string<'a>(bytes: &mut &'a [u8]) -> VaultResult<&'a [u8]> {
    let len = usize::try_from(uint32(bytes)?).map_err(|_| invalid())?;
    let value = bytes.get(..len).ok_or_else(invalid)?;
    *bytes = &bytes[len..];
    Ok(value)
}

fn put_string(bytes: &mut Vec<u8>, value: &[u8]) -> VaultResult<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid())?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

pub(crate) fn encode_identities(identities: &[SshIdentity]) -> VaultResult<Vec<u8>> {
    let mut bytes = vec![IDENTITIES_ANSWER];
    bytes.extend_from_slice(
        &u32::try_from(identities.len())
            .map_err(|_| invalid())?
            .to_be_bytes(),
    );
    for identity in identities {
        put_string(&mut bytes, &identity.public_key)?;
        // Item titles can contain terminal control characters.
        let comment: String = identity
            .title
            .chars()
            .filter(|character| character.is_ascii_graphic() || *character == ' ')
            .collect();
        put_string(&mut bytes, comment.as_bytes())?;
    }
    Ok(bytes)
}

pub(crate) fn encode_signature(signature: &[u8]) -> VaultResult<Vec<u8>> {
    let mut bytes = vec![SIGN_RESPONSE];
    put_string(&mut bytes, signature)?;
    Ok(bytes)
}

struct ConnectionSlot<'a>(&'a AtomicUsize);
impl Drop for ConnectionSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(unix)]
pub(crate) fn serve(
    service: &VaultService,
    listener: &UnixListener,
    stopping: &AtomicBool,
    authenticate: &(impl Fn(&UnixStream) -> VaultResult<CallerIdentity> + Sync),
) -> VaultResult<()> {
    serve_listener(
        service,
        stopping,
        || {
            let (stream, _) = listener.accept()?;
            stream.set_nonblocking(true)?;
            Ok(stream)
        },
        authenticate,
    )
}

pub(crate) fn serve_listener<S: io::Read + io::Write + Send>(
    service: &VaultService,
    stopping: &AtomicBool,
    accept: impl Fn() -> io::Result<S>,
    authenticate: &(impl Fn(&S) -> VaultResult<CallerIdentity> + Sync),
) -> VaultResult<()> {
    let active = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        while !stopping.load(Ordering::Acquire) {
            if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            match accept() {
                Ok(mut stream) => {
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = &active;
                    if let Err(error) = std::thread::Builder::new()
                        .name("factorseal-ssh".into())
                        .spawn_scoped(scope, move || {
                            let _slot = ConnectionSlot(active);
                            let _ = handle_connection(service, &mut stream, stopping, authenticate);
                        })
                    {
                        active.fetch_sub(1, Ordering::AcqRel);
                        return Err(VaultError::Protocol(format!(
                            "could not start SSH worker: {error}"
                        )));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => {
                    return Err(VaultError::Protocol(format!("SSH accept failed: {error}")));
                }
            }
        }
        Ok(())
    })
}

pub(crate) fn handle_connection<S: io::Read + io::Write>(
    service: &VaultService,
    stream: &mut S,
    stopping: &AtomicBool,
    authenticate: &impl Fn(&S) -> VaultResult<CallerIdentity>,
) -> VaultResult<()> {
    let end = Instant::now() + CONNECTION_TIMEOUT;
    let mut bindings = Bindings::default();
    while !stopping.load(Ordering::Acquire) && Instant::now() < end {
        let bytes = read_frame(
            stream,
            IoBudget::new(Duration::from_secs(30))
                .capped(Some(end))
                .cancelled_by(Some(stopping)),
        )?;
        let caller = authenticate(stream)?;
        let reply = match AgentRequest::decode(&bytes) {
            Ok(AgentRequest::Bind {
                host_key,
                session_id,
                signature,
                forwarding,
            }) => {
                // An invalid binding closes the connection; it can never fall
                // back to an unrestricted signing grant after a failed bind.
                bindings.bind(host_key, session_id, signature, forwarding)?;
                write_frame(
                    stream,
                    &[6],
                    IoBudget::new(Duration::from_millis(500)).cancelled_by(Some(stopping)),
                )?;
                continue;
            }
            Ok(mut request) => {
                if let AgentRequest::Sign {
                    public_key,
                    data,
                    flags,
                    destination,
                } = &mut request
                {
                    *destination = bindings.destination(public_key, data, *flags)?;
                }
                if matches!(request, AgentRequest::Identities) && bindings.is_forwarding() {
                    write_frame(
                        stream,
                        &[12, 0, 0, 0, 0],
                        IoBudget::new(Duration::from_millis(500)).cancelled_by(Some(stopping)),
                    )?;
                    continue;
                }
                resolve_request(
                    service,
                    stream,
                    &caller,
                    &request,
                    stopping,
                    authenticate,
                    end,
                )
            }
            Err(error) => Err(error),
        };
        match reply {
            Ok(AgentReply::Ready {
                bytes,
                deadline,
                cancelled,
            }) => {
                write_frame(
                    stream,
                    &bytes,
                    IoBudget::new(Duration::from_millis(500))
                        .capped(deadline)
                        .capped(Some(end))
                        .cancelled_by(Some(&cancelled)),
                )?;
            }
            _ => write_frame(
                stream,
                &[FAILURE],
                IoBudget::new(Duration::from_millis(500))
                    .capped(Some(end))
                    .cancelled_by(Some(stopping)),
            )?,
        }
    }
    Ok(())
}

fn resolve_request<S>(
    service: &VaultService,
    stream: &S,
    caller: &CallerIdentity,
    request: &AgentRequest<'_>,
    stopping: &AtomicBool,
    authenticate: &impl Fn(&S) -> VaultResult<CallerIdentity>,
    connection_end: Instant,
) -> VaultResult<AgentReply> {
    // Re-authenticate after reading the request and after approval: exec on a
    // live connection cannot inherit the original executable's grant.
    if authenticate(stream)? != *caller {
        return Err(VaultError::AuthorizationRequired);
    }
    let reply = service.ssh_request(caller, request, unix_time()?)?;
    let AgentReply::Pending(id) = reply else {
        return Ok(reply);
    };
    let end = (Instant::now() + APPROVAL_TIMEOUT).min(connection_end);
    while Instant::now() < end && !stopping.load(Ordering::Acquire) {
        match service.ssh_wait_permission(caller, &id, unix_time()?)? {
            PermissionWaitStatus::Pending => (),
            PermissionWaitStatus::Granted => {
                if authenticate(stream)? != *caller {
                    return Err(VaultError::AuthorizationRequired);
                }
                return service.ssh_request(caller, request, unix_time()?);
            }
            PermissionWaitStatus::Denied | PermissionWaitStatus::Expired => break,
        }
    }
    Err(VaultError::AuthorizationRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_agent_frames() {
        assert!(matches!(
            AgentRequest::decode(&[11]),
            Ok(AgentRequest::Identities)
        ));
        for frame in [
            &[][..],
            &[11, 0],
            &[17],
            &[22],
            &[27],
            &[13, 255, 255, 255, 255],
        ] {
            assert!(AgentRequest::decode(frame).is_err());
        }
        let mut frame = vec![13];
        put_string(&mut frame, &[0; 51]).unwrap();
        put_string(&mut frame, b"authentication").unwrap();
        frame.extend_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            AgentRequest::decode(&frame),
            Ok(AgentRequest::Sign { .. })
        ));
        for end in 0..frame.len() {
            assert!(AgentRequest::decode(&frame[..end]).is_err());
        }
        *frame.last_mut().unwrap() = 1;
        assert!(AgentRequest::decode(&frame).is_err());
        *frame.last_mut().unwrap() = 0;
        frame.push(0);
        assert!(AgentRequest::decode(&frame).is_err());
    }
}
