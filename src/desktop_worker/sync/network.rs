//! Desktop-owned networking. Keeps only transport keys, ciphertext and public
//! membership while sealed; private management is delegated to inherited pipes.
use super::{Command, PublicGroup, Reply, State};
use crate::personal::sync::{
    CiphertextSpool, PairingInvitation, PairingRequest, VerifiedGroup,
    network::{ALPN, CiphertextCourier},
};
use crate::security::{read_private_file, write_private_file};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{Connection, QuicTransportConfig, presets},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const GROUP_ALPN: &[u8] = b"factorseal/personal-membership/1";
const PAIR_ALPN: &[u8] = b"factorseal/personal-pairing/1";
const FRAME: usize = 12 * 1024 * 1024;
type Host = dyn Fn(Command) -> Result<Reply, String> + Send + Sync;
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct View {
    pub devices: Vec<crate::personal::sync::TransportBinding>,
    pub endpoint: [u8; 32],
    pub state: State,
    pub reachable: usize,
    pub last_exchange: Option<u64>,
    pub error: Option<String>,
}
#[derive(Serialize, Deserialize)]
pub enum Action {
    Refresh,
    Invite(String),
    Join {
        #[serde(with = "ticket_string")]
        ticket: zeroize::Zeroizing<String>,
        name: String,
    },
    Approve([u8; 32]),
    ApproveJoin([u8; 32]),
    Cancel,
}

mod ticket_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;
    pub(super) fn serialize<S: Serializer>(
        value: &Zeroizing<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value)
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<String>, D::Error> {
        String::deserialize(deserializer).map(Zeroizing::new)
    }
}
#[derive(Serialize, Deserialize)]
struct Ticket(String);
impl Drop for Ticket {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
enum Request {
    Group(Option<Ticket>),
    Stage(PairingRequest),
    Update(PublicGroup),
}
#[derive(Serialize, Deserialize)]
enum Response {
    Group(PublicGroup),
    Pending,
    Rejected,
}
struct Inner {
    endpoint: Endpoint,
    root: PathBuf,
    host: Arc<Host>,
    group: Mutex<Option<VerifiedGroup>>,
    courier: Mutex<Option<CiphertextCourier>>,
    spare: Mutex<Option<CiphertextSpool>>,
    apply_cursor: Mutex<Option<crate::personal::sync::PacketId>>,
    view: Mutex<View>,
    gate: tokio::sync::Mutex<()>,
    refresh: tokio::sync::Notify,
    progress: tokio::sync::watch::Sender<Progress>,
    #[cfg(test)]
    peers: Mutex<std::collections::BTreeMap<[u8; 32], EndpointAddr>>,
}
/// Counters of background passes, so a refresh can wait for one that began
/// after it was requested instead of returning the view of an older pass.
#[derive(Clone, Copy, Default)]
struct Progress {
    requested: u64,
    started: u64,
    completed: u64,
}
pub struct Manager {
    runtime: Option<tokio::runtime::Runtime>,
    inner: Arc<Inner>,
}
impl Manager {
    pub fn open(root: &Path, host: Arc<Host>) -> Result<Self, String> {
        std::fs::create_dir_all(root).map_err(err)?;
        let spool = CiphertextSpool::open(&root.join("packets"), 256 * 1024 * 1024).map_err(err)?;
        let key_path = root.join("transport.key");
        if !key_path.try_exists().map_err(err)?
            && root.join("membership.json").try_exists().map_err(err)?
        {
            return Err("The paired device’s transport key is missing".into());
        }
        let key = if key_path.try_exists().map_err(err)? {
            let bytes = read_private_file(&key_path, 32).map_err(err)?;
            SecretKey::from_bytes(&bytes.as_slice().try_into().map_err(err)?)
        } else {
            let key = SecretKey::generate();
            write_private_file(&key_path, &zeroize::Zeroizing::new(key.to_bytes())[..])
                .map_err(err)?;
            key
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(err)?;
        let endpoint = runtime
            .block_on(
                Endpoint::builder(presets::N0)
                    .secret_key(key)
                    .transport_config(
                        QuicTransportConfig::builder()
                            .max_concurrent_bidi_streams(1u32.into())
                            .max_concurrent_uni_streams(0u32.into())
                            .stream_receive_window((12 * 1024 * 1024u32).into())
                            .receive_window((12 * 1024 * 1024u32).into())
                            .build(),
                    )
                    .alpns(vec![ALPN.to_vec(), PAIR_ALPN.to_vec(), GROUP_ALPN.to_vec()])
                    .bind(),
            )
            .map_err(err)?;
        let inner = Arc::new(Inner {
            endpoint,
            root: root.into(),
            host,
            group: Mutex::new(None),
            courier: Mutex::new(None),
            spare: Mutex::new(Some(spool)),
            apply_cursor: Mutex::new(None),
            view: Mutex::new(View::default()),
            gate: tokio::sync::Mutex::new(()),
            refresh: tokio::sync::Notify::new(),
            progress: tokio::sync::watch::Sender::new(Progress::default()),
            #[cfg(test)]
            peers: Mutex::new(std::collections::BTreeMap::default()),
        });
        let path = root.join("membership.json");
        if path.try_exists().map_err(err)? {
            let public: PublicGroup =
                serde_json::from_slice(&read_private_file(&path, FRAME as u64).map_err(err)?)
                    .map_err(err)?;
            inner.install(public.verified().map_err(err)?)?;
        }
        runtime.spawn(Arc::clone(&inner).listen());
        runtime.spawn(Arc::clone(&inner).poll());
        Ok(Self {
            runtime: Some(runtime),
            inner,
        })
    }
    #[must_use]
    pub fn view(&self) -> View {
        let mut view = self
            .inner
            .view
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        view.endpoint = *self.inner.endpoint.id().as_bytes();
        view.devices = self
            .inner
            .group()
            .map_or_else(Vec::new, |group| group.transports().to_vec());
        view
    }
    pub fn action(&self, action: Action) -> Result<View, String> {
        self.runtime
            .as_ref()
            .ok_or("sync is closing")?
            .block_on(async {
                self.inner.action(action).await?;
                Ok(self.view())
            })
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}
impl Inner {
    #[allow(clippy::unused_self)] // Direct-address injection avoids public relays in tests.
    fn address(&self, id: [u8; 32]) -> Result<EndpointAddr, String> {
        #[cfg(test)]
        if let Some(address) = self.peers.lock().map_err(err)?.get(&id) {
            return Ok(address.clone());
        }
        address(id)
    }
    async fn host(&self, command: Command) -> Result<Reply, String> {
        let host = Arc::clone(&self.host);
        tokio::task::spawn_blocking(move || host(command))
            .await
            .map_err(err)?
    }
    fn group(&self) -> Option<VerifiedGroup> {
        self.group.lock().expect("sync group").clone()
    }
    fn courier(&self) -> Option<CiphertextCourier> {
        self.courier.lock().expect("sync courier").clone()
    }
    fn install(&self, group: VerifiedGroup) -> Result<(), String> {
        if !group.permits(self.endpoint.id().as_bytes()) {
            return Err("This endpoint is not authorized by the paired membership".into());
        }
        let mut pinned = self.group.lock().map_err(err)?;
        if let Some(current) = &*pinned {
            current.accept_extension(&group).map_err(err)?;
            if current.digest().map_err(err)? == group.digest().map_err(err)? {
                return Ok(());
            }
        }
        // Persist the public pin before enabling new transport authorization.
        write_private_file(
            &self.root.join("membership.json"),
            &serde_json::to_vec(&PublicGroup::new(&group).map_err(err)?).map_err(err)?,
        )
        .map_err(err)?;
        let mut courier = self.courier.lock().map_err(err)?;
        if let Some(courier) = courier.as_ref() {
            courier.update_group(group.clone()).map_err(err)?;
        } else {
            *courier = Some(CiphertextCourier::new(
                group.clone(),
                self.spare
                    .lock()
                    .map_err(err)?
                    .take()
                    .ok_or("ciphertext spool unavailable")?,
            ));
        }
        *pinned = Some(group);
        Ok(())
    }
    async fn action(&self, action: Action) -> Result<(), String> {
        // Refresh schedules one background pass and returns once a pass that
        // began after this request has completed, so the caller's view holds
        // the pulled packets and the desktop spinner covers the wait. Notify
        // coalesces repeated clicks into one pass; every waiter sees it.
        if matches!(action, Action::Refresh) {
            let mut progress = self.progress.subscribe();
            let target = progress.borrow().started.saturating_add(1);
            self.progress
                .send_modify(|progress| progress.requested += 1);
            self.refresh.notify_one();
            progress
                .wait_for(|progress| progress.completed >= target)
                .await
                .map_err(|_| "sync is closing".to_owned())?;
            let error = self.view.lock().map_err(err)?.error.clone();
            return error.map_or(Ok(()), Err);
        }
        let _guard = self.gate.lock().await;
        match action {
            Action::Refresh => {}
            Action::Invite(name) => {
                self.host(Command::Offer {
                    endpoint: *self.endpoint.id().as_bytes(),
                    name,
                })
                .await?;
            }

            Action::Join { ticket, name } => {
                let invitation = PairingInvitation::from_ticket(&ticket).map_err(err)?;
                if invitation.endpoint() == *self.endpoint.id().as_bytes() {
                    return Err("This pairing code belongs to this device. Use the code from your other device.".into());
                }
                let peer = self.address(invitation.endpoint())?;
                let Response::Group(group) = rpc(
                    &self.endpoint,
                    peer,
                    Request::Group(Some(Ticket(ticket.to_string()))),
                )
                .await?
                else {
                    return Err("invitation is unavailable or expired".into());
                };
                // Worker validates the exact QR anchor before persisting a request.
                self.host(Command::Join {
                    invitation,
                    group,
                    endpoint: *self.endpoint.id().as_bytes(),
                    name,
                })
                .await?;
            }
            Action::ApproveJoin(id) => {
                self.host(Command::ApproveJoin(id)).await?;
            }
            Action::Approve(id) => {
                let Reply::Group(group) = self.host(Command::Approve(id)).await? else {
                    return Err("unexpected worker response".into());
                };
                self.install(group.verified().map_err(err)?)?;
            }
            Action::Cancel => {
                self.host(Command::Cancel).await?;
            }
        }
        self.local().await?;
        Ok(())
    }
    async fn local(&self) -> Result<(), String> {
        let response = self.host(Command::State).await;
        if response.is_err() {
            self.view.lock().map_err(err)?.state = State::default();
        }
        let Reply::State(mut state) = response? else {
            return Err("unexpected worker response".into());
        };
        self.view.lock().map_err(err)?.state = (*state).clone();
        if let Some(public) = &state.group {
            let worker = public.verified().map_err(err)?;
            if let Some(current) = self.group() {
                if worker.accept_extension(&current).is_ok() {
                    self.host(Command::Accept(PublicGroup::new(&current).map_err(err)?))
                        .await?;
                } else {
                    self.install(worker)?;
                }
            } else {
                self.install(worker)?;
            }
        }
        if state.joining
            && let (Some(invitation), Some(request)) = (&state.invitation, &state.request)
            && let Response::Group(group) = rpc(
                &self.endpoint,
                self.address(invitation.endpoint())?,
                Request::Stage(request.clone()),
            )
            .await?
        {
            self.host(Command::Accept(group.clone())).await?;
            self.install(group.verified().map_err(err)?)?;
            if let Reply::State(updated) = self.host(Command::State).await? {
                state = updated;
            }
        }
        self.view.lock().map_err(err)?.state = *state;
        if let Some(courier) = self.courier() {
            for _ in 0..16 {
                let Reply::Packet(packet) = self.host(Command::Prepare).await? else {
                    break;
                };
                let Some(bytes) = packet else {
                    break;
                };
                let spool = courier.clone();
                let id = tokio::task::spawn_blocking(move || {
                    spool.with_spool(|spool, membership| spool.put(&bytes, membership))
                })
                .await
                .map_err(err)?
                .map_err(err)?;
                self.host(Command::Stored(id)).await?;
            }
            let cursor = *self.apply_cursor.lock().map_err(err)?;
            let spool = courier.clone();
            let ids = tokio::task::spawn_blocking(move || {
                spool.with_spool(|spool, _| spool.inventory(cursor, 16))
            })
            .await
            .map_err(err)?
            .map_err(err)?;
            let next = if ids.len() == 16 {
                ids.last().copied()
            } else {
                None
            };
            for id in ids {
                let spool = courier.clone();
                let packet = tokio::task::spawn_blocking(move || {
                    spool.with_spool(|spool, membership| spool.get(id, membership))
                })
                .await
                .map_err(err)?;
                // Failed application retains the packet and retries on the next
                // inventory cycle without starving packets after it.
                *self.apply_cursor.lock().map_err(err)? = Some(id);
                if let Ok(packet) = packet {
                    self.host(Command::Receive(packet.as_bytes().to_vec()))
                        .await?;
                }
            }
            *self.apply_cursor.lock().map_err(err)? = next;
        }
        Ok(())
    }
    async fn poll(self: Arc<Self>) {
        loop {
            {
                let _guard = self.gate.lock().await;
                self.progress.send_modify(|progress| progress.started += 1);
                if let Err(error) = self.local().await {
                    let mut view = self.view.lock().expect("sync view");
                    // Clear capability/approval material immediately when sealed.
                    view.error = Some(error);
                } else {
                    self.view.lock().expect("sync view").error = None;
                }
            }
            self.exchange().await;
            self.progress
                .send_modify(|progress| progress.completed += 1);
            tokio::select! {
                () = self.refresh.notified() => {},
                () = tokio::time::sleep(Duration::from_secs(5)) => {},
            }
        }
    }
    async fn exchange(&self) {
        let mut reachable = 0;
        if let (Some(group), Some(courier)) = (self.group(), self.courier()) {
            for binding in group.transports() {
                if binding.endpoint == *self.endpoint.id().as_bytes() {
                    continue;
                }
                let Ok(peer) = self.address(binding.endpoint) else {
                    continue;
                };
                let exchange = async {
                    if let Response::Group(public) = rpc(
                        &self.endpoint,
                        peer.clone(),
                        Request::Update(PublicGroup::new(&group).map_err(err)?),
                    )
                    .await?
                    {
                        let incoming = public.verified().map_err(err)?;
                        group.accept_extension(&incoming).map_err(err)?;
                        self.install(incoming)?;
                    }
                    let mut after = None;
                    loop {
                        let page = courier
                            .pull_page(&self.endpoint, peer.clone(), after)
                            .await
                            .map_err(err)?;
                        after = page.next;
                        if after.is_none() {
                            break;
                        }
                    }
                    Ok::<_, String>(())
                };
                if matches!(
                    tokio::time::timeout(Duration::from_secs(8), exchange).await,
                    Ok(Ok(()))
                ) {
                    reachable += 1;
                }
            }
            let mut view = self.view.lock().expect("sync view");
            view.reachable = reachable;
            if reachable > 0 {
                view.last_exchange = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs());
            }
            // Paired count remains available to the sealed desktop.
            view.state.readers = self
                .group()
                .map_or(0, |group| group.membership().members().len());
        }
    }
    async fn listen(self: Arc<Self>) {
        let slots = Arc::new(tokio::sync::Semaphore::new(8));
        while let Some(incoming) = self.endpoint.accept().await {
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tokio::time::timeout(Duration::from_secs(20), async {
                    let session = Session(incoming.await.map_err(err)?);
                    match session.0.alpn() {
                        ALPN => {
                            this.courier()
                                .ok_or("sync is not configured")?
                                .serve_peer(&session.0)
                                .await
                                .map_err(err)?;
                        }
                        PAIR_ALPN | GROUP_ALPN => this.serve_pair(&session.0).await?,
                        _ => return Err("unsupported protocol".into()),
                    }
                    Ok::<_, String>(())
                })
                .await;
            });
        }
    }
    async fn serve_pair(&self, connection: &Connection) -> Result<(), String> {
        let remote = *connection.remote_id().as_bytes();
        let (mut send, mut recv) = connection.accept_bi().await.map_err(err)?;
        let update = connection.alpn() == GROUP_ALPN;
        let bytes = zeroize::Zeroizing::new(recv.read_to_end(FRAME).await.map_err(err)?);
        let request: Request = serde_json::from_slice(&bytes).map_err(err)?;
        if matches!(request, Request::Update(_)) != update {
            return Err("wrong membership protocol".into());
        }
        let response = match request {
            Request::Update(public) => {
                let current = self.group().ok_or("sync is not configured")?;
                let incoming = public.verified().map_err(err)?;
                let next = if incoming.accept_extension(&current).is_ok() {
                    incoming.accept_extension(&current).map_err(err)?;
                    current
                } else {
                    current.accept_extension(&incoming).map_err(err)?;
                    incoming
                };
                if !next.permits(&remote) {
                    return Err("endpoint is not enrolled".into());
                }
                self.install(next.clone())?;
                Response::Group(PublicGroup::new(&next).map_err(err)?)
            }
            Request::Group(ticket) => {
                let group = if let Some(group) = self.group() {
                    group
                } else {
                    let Reply::State(state) = self.host(Command::State).await? else {
                        return Err("unavailable".into());
                    };
                    state
                        .introduction
                        .ok_or("no introduction")?
                        .verified()
                        .map_err(err)?
                };
                if !group.permits(&remote) {
                    let Reply::State(state) = self.host(Command::State).await? else {
                        return Err("unavailable".into());
                    };
                    let invitation = state.invitation.ok_or("no invitation")?;
                    let offered = ticket.ok_or("invitation required")?;
                    if Sha256::digest(offered.0.as_bytes())
                        != Sha256::digest(invitation.ticket().map_err(err)?.as_bytes())
                    {
                        return Err("invalid invitation".into());
                    }
                    invitation
                        .check(
                            &group,
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map_err(err)?
                                .as_secs(),
                        )
                        .map_err(err)?;
                }
                Response::Group(PublicGroup::new(&group).map_err(err)?)
            }
            Request::Stage(request) => {
                if request.endpoint() != remote {
                    return Err("endpoint mismatch".into());
                }
                if let Some(group) = self.group()
                    && group.contains_enrollment(request.id().map_err(err)?)
                    && group.transports().iter().any(|binding| {
                        binding.endpoint == remote && binding.reader == Some(request.reader().id())
                    })
                {
                    Response::Group(PublicGroup::new(&group).map_err(err)?)
                } else {
                    self.host(Command::Stage {
                        request,
                        peer: remote,
                    })
                    .await?;
                    Response::Pending
                }
            }
        };
        send.write_all(&serde_json::to_vec(&response).map_err(err)?)
            .await
            .map_err(err)?;
        send.finish().map_err(err)?;
        send.stopped().await.map_err(err)?;
        Ok(())
    }
}
struct Session(Connection);
impl Drop for Session {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"complete");
    }
}
async fn rpc(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    request: Request,
) -> Result<Response, String> {
    tokio::time::timeout(Duration::from_secs(8), async {
        let alpn = if matches!(request, Request::Update(_)) {
            GROUP_ALPN
        } else {
            PAIR_ALPN
        };
        let session = Session(endpoint.connect(peer, alpn).await.map_err(err)?);
        let (mut send, mut recv) = session.0.open_bi().await.map_err(err)?;
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&request).map_err(err)?);
        send.write_all(&bytes).await.map_err(err)?;
        send.finish().map_err(err)?;
        serde_json::from_slice(&recv.read_to_end(FRAME).await.map_err(err)?).map_err(err)
    })
    .await
    .map_err(err)?
}
fn address(bytes: [u8; 32]) -> Result<EndpointAddr, String> {
    Ok(EndpointId::from_bytes(&bytes).map_err(err)?.into())
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(all(test, feature = "hardware"))]
mod tests;
