//! Bounded iroh ciphertext exchange. The host owns endpoint lifetime and pins
//! signed membership; this component never receives vault or reader keys.
use super::{CiphertextSpool, PacketId, VerifiedGroup, encode, invalid};
use crate::vault::VaultResult;
use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Configure this ALPN on the host-owned endpoint.
pub const ALPN: &[u8] = b"factorseal/personal-sync/1";
const MAX_FRAME: usize = 3 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(20);

struct Session(Connection);
impl Drop for Session {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"complete");
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    group: [u8; 32],
    operation: Operation,
}
#[derive(Serialize, Deserialize)]
enum Operation {
    Inventory { after: Option<PacketId> },
    Get(PacketId),
}
#[derive(Serialize, Deserialize)]
enum Response {
    Inventory(Vec<PacketId>),
    Packet(#[serde(with = "super::bytes")] Vec<u8>),
    Rejected,
}
struct State {
    group: VerifiedGroup,
    spool: CiphertextSpool,
}
/// Keyless courier. Public certificates authorize transport endpoints; packet
/// signatures independently authorize content. Clone shares the single spool.
#[derive(Clone)]
pub struct CiphertextCourier {
    state: Arc<Mutex<State>>,
}
impl CiphertextCourier {
    #[must_use]
    pub fn new(group: VerifiedGroup, spool: CiphertextSpool) -> Self {
        Self {
            state: Arc::new(Mutex::new(State { group, spool })),
        }
    }
    /// Serialized access for trusted local publication/application. The callback
    /// runs synchronously, must not reenter this courier, and should be invoked
    /// from a blocking worker. No callback or reader keys are retained here.
    pub fn with_spool<T>(
        &self,
        operation: impl FnOnce(&mut CiphertextSpool, &super::Membership) -> VaultResult<T>,
    ) -> VaultResult<T> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        let State { group, spool } = &mut *state;
        operation(spool, group.membership())
    }
    /// The host must durably pin the accepted chain before enabling it here.
    pub fn update_group(&self, group: VerifiedGroup) -> VaultResult<()> {
        let mut state = self.state.lock().map_err(|_| invalid())?;
        state.group.accept_extension(&group)?;
        state.group = group;
        Ok(())
    }
    /// Serve one incoming connection. Hosts can loop serially to bound resource
    /// use; callers that run concurrent sessions must impose their own limit.
    pub async fn serve_one(&self, endpoint: &Endpoint) -> VaultResult<()> {
        self.authorize(endpoint.id().as_bytes(), None)?;
        let incoming = endpoint.accept().await.ok_or_else(invalid)?;
        tokio::time::timeout(TIMEOUT, async {
            let session = Session(incoming.await.map_err(|_| invalid())?);
            self.serve_connection(&session.0).await
        })
        .await
        .map_err(|_| invalid())?
    }
    /// Dispatch a connection accepted by the host's ALPN router.
    pub async fn serve_peer(&self, connection: &Connection) -> VaultResult<()> {
        tokio::time::timeout(TIMEOUT, self.serve_connection(connection))
            .await
            .map_err(|_| invalid())?
    }
    async fn serve_connection(&self, connection: &Connection) -> VaultResult<()> {
        if connection.alpn() != ALPN {
            return Err(invalid());
        }
        let remote = *connection.remote_id().as_bytes();
        self.authorize(&remote, None)?;
        let (mut send, mut recv) = connection.accept_bi().await.map_err(|_| invalid())?;
        let bytes = recv.read_to_end(MAX_FRAME).await.map_err(|_| invalid())?;
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let courier = self.clone();
        let response = tokio::task::spawn_blocking(move || courier.respond(remote, &request))
            .await
            .map_err(|_| invalid())??;
        send.write_all(&encode(&response)?)
            .await
            .map_err(|_| invalid())?;
        send.finish().map_err(|_| invalid())?;
        send.stopped().await.map_err(|_| invalid())?;
        Ok(())
    }
    fn authorize(&self, endpoint: &[u8; 32], digest: Option<[u8; 32]>) -> VaultResult<[u8; 32]> {
        let state = self.state.lock().map_err(|_| invalid())?;
        let current = state.group.digest()?;
        if !state.group.permits(endpoint) || digest.is_some_and(|digest| digest != current) {
            return Err(invalid());
        }
        Ok(current)
    }
    fn respond(&self, remote: [u8; 32], request: &Request) -> VaultResult<Response> {
        let state = self.state.lock().map_err(|_| invalid())?;
        if !state.group.permits(&remote) || state.group.digest()? != request.group {
            return Err(invalid());
        }
        match request.operation {
            Operation::Inventory { after } => {
                // Inventory includes old epochs; Get rejects obsolete packets.
                let ids = state.spool.inventory(after, 128)?;
                Ok(Response::Inventory(ids))
            }
            Operation::Get(id) => Ok(match state.spool.get(id, state.group.membership()) {
                Ok(packet) => Response::Packet(packet.as_bytes().to_vec()),
                Err(_) => Response::Rejected,
            }),
        }
    }
    /// Pull at most one inventory page. Call with the returned cursor until it
    /// is None. This reports durable ciphertext possession, not vault apply.
    /// Each device pulls independently, so reconnects/retries are idempotent.
    pub async fn pull_page(
        &self,
        endpoint: &Endpoint,
        peer: EndpointAddr,
        after: Option<PacketId>,
    ) -> VaultResult<PullPage> {
        tokio::time::timeout(Duration::from_mins(1), self.pull(endpoint, peer, after))
            .await
            .map_err(|_| invalid())?
    }
    async fn pull(
        &self,
        endpoint: &Endpoint,
        peer: EndpointAddr,
        after: Option<PacketId>,
    ) -> VaultResult<PullPage> {
        let remote = *peer.id.as_bytes();
        let group = self.authorize(&remote, None)?;
        self.authorize(endpoint.id().as_bytes(), Some(group))?;
        let Response::Inventory(ids) = rpc(
            endpoint,
            peer.clone(),
            Request {
                group,
                operation: Operation::Inventory { after },
            },
        )
        .await?
        else {
            return Err(invalid());
        };
        if ids.len() > 128
            || ids.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || ids
                .first()
                .is_some_and(|id| after.is_some_and(|after| id.0 <= after.0))
        {
            return Err(invalid());
        }
        let next = if ids.len() == 128 {
            ids.last().copied()
        } else {
            None
        };
        let mut stored = 0;
        let mut rejected = 0;
        for id in ids {
            self.authorize(&remote, Some(group))?;
            let courier = self.clone();
            let present = tokio::task::spawn_blocking(move || {
                let state = courier.state.lock().map_err(|_| invalid())?;
                if state.group.digest()? != group {
                    return Err(invalid());
                }
                Ok(state.spool.get(id, state.group.membership()).is_ok())
            })
            .await
            .map_err(|_| invalid())??;
            if present {
                stored += 1;
                continue;
            }
            let Response::Packet(bytes) = rpc(
                endpoint,
                peer.clone(),
                Request {
                    group,
                    operation: Operation::Get(id),
                },
            )
            .await?
            else {
                rejected += 1;
                continue;
            };
            let courier = self.clone();
            tokio::task::spawn_blocking(move || {
                let mut state = courier.state.lock().map_err(|_| invalid())?;
                if state.group.digest()? != group || !state.group.permits(&remote) {
                    return Err(invalid());
                }
                let membership = state.group.membership().clone();
                if super::VerifiedPacket::verify(&bytes, &membership)?.id() != id {
                    return Err(invalid());
                }
                state.spool.put(&bytes, &membership)?;
                Ok(())
            })
            .await
            .map_err(|_| invalid())??;
            stored += 1;
        }
        Ok(PullPage {
            stored,
            rejected,
            next,
        })
    }
}
/// Counts include duplicates already durably stored, never decrypted/applied.
#[derive(Debug, Default)]
pub struct PullPage {
    pub stored: usize,
    pub rejected: usize,
    pub next: Option<PacketId>,
}
async fn rpc(endpoint: &Endpoint, peer: EndpointAddr, request: Request) -> VaultResult<Response> {
    tokio::time::timeout(TIMEOUT, async {
        let session = Session(endpoint.connect(peer, ALPN).await.map_err(|_| invalid())?);
        let connection = &session.0;
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| invalid())?;
        send.write_all(&encode(&request)?)
            .await
            .map_err(|_| invalid())?;
        send.finish().map_err(|_| invalid())?;
        let bytes = recv.read_to_end(MAX_FRAME).await.map_err(|_| invalid())?;
        let response = serde_json::from_slice(&bytes).map_err(|_| invalid());
        connection.close(0u32.into(), b"complete");
        response
    })
    .await
    .map_err(|_| invalid())?
}

#[cfg(test)]
mod tests;
