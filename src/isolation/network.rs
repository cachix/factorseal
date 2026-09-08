//! Network-only child and Desktop supervisor. Child callbacks have a closed
//! capability set; pairing approval requires a matching one-use UI permit.

use crate::desktop_worker::sync::network::{Action, View};
use crate::desktop_worker::sync::{Command, Reply};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};

const MAXIMUM: usize = 12 * 1024 * 1024;
type Host = dyn Fn(Command) -> Result<Reply, String> + Send + Sync;

#[cfg(all(test, feature = "hardware", any(unix, windows)))]
mod acceptance;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    version: u8,
    root: std::path::PathBuf,
}
#[derive(Serialize, Deserialize)]
enum ToChild {
    View(u64),
    Action {
        id: u64,
        action: Action,
    },
    HostReply {
        id: u64,
        result: Result<Reply, String>,
    },
}
#[derive(Serialize, Deserialize)]
enum ToParent {
    Ready,
    StartupFailed(String),
    Failed(String),
    View {
        id: u64,
        result: Result<Box<View>, String>,
    },
    Host {
        id: u64,
        command: Box<Command>,
    },
}

enum Permit {
    Offer(String),
    Join {
        ticket: zeroize::Zeroizing<String>,
        name: String,
    },
    Approve([u8; 32]),
    ApproveJoin([u8; 32]),
    Cancel,
}
impl Permit {
    fn for_action(action: &Action) -> Option<Self> {
        match action {
            Action::Refresh => None,
            Action::Invite(name) => Some(Self::Offer(name.clone())),
            Action::Join { ticket, name } => Some(Self::Join {
                ticket: ticket.clone(),
                name: name.clone(),
            }),
            Action::Approve(id) => Some(Self::Approve(*id)),
            Action::ApproveJoin(id) => Some(Self::ApproveJoin(*id)),
            Action::Cancel => Some(Self::Cancel),
        }
    }
    fn matches(&self, command: &Command) -> bool {
        match (self, command) {
            (Self::Offer(expected), Command::Offer { name, .. }) => expected == name,
            (
                Self::Join { ticket, name },
                Command::Join {
                    invitation,
                    name: actual,
                    ..
                },
            ) => {
                name == actual
                    && invitation
                        .ticket()
                        .is_ok_and(|canonical| canonical == *ticket)
            }
            (Self::Approve(expected), Command::Approve(actual))
            | (Self::ApproveJoin(expected), Command::ApproveJoin(actual)) => expected == actual,
            (Self::Cancel, Command::Cancel) => true,
            _ => false,
        }
    }
}

fn authorize(command: &Command, permit: &mut Option<Permit>) -> bool {
    match command {
        Command::State
        | Command::Stage { .. }
        | Command::Accept(_)
        | Command::Prepare
        | Command::Stored(_)
        | Command::Receive(_) => true,
        _ if permit
            .as_ref()
            .is_some_and(|permit| permit.matches(command)) =>
        {
            *permit = None;
            true
        }
        _ => false,
    }
}

#[cfg(any(unix, windows))]
mod native {
    use super::{
        Action, Arc, Bootstrap, Host, MAXIMUM, Path, Permit, Reply, ToChild, ToParent, View,
        authorize,
    };
    use crate::isolation::{codec, process, sandbox};
    use process::Channel;
    use std::{
        collections::HashMap,
        io,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc,
        },
        time::Duration,
    };
    const WAIT: Duration = Duration::from_secs(30);
    type Pending = HashMap<u64, mpsc::SyncSender<Result<View, String>>>;
    type Callbacks = Mutex<HashMap<u64, mpsc::SyncSender<Result<Reply, String>>>>;

    struct Shared {
        writer: Mutex<Channel>,
        pending: Mutex<Pending>,
        permit: Mutex<Option<Permit>>,
        // Pairing identity shown to the user comes only from the vault host.
        // The untrusted network process may report transport liveness, but it
        // cannot relabel a pairing request before the user approves its ID.
        state: Mutex<crate::desktop_worker::sync::State>,
        failure: Mutex<Option<String>>,
        live: AtomicBool,
    }

    impl Shared {
        fn fail(&self, message: String) {
            if let Ok(mut failure) = self.failure.lock() {
                failure.get_or_insert(message);
            }
            self.live.store(false, Ordering::Release);
        }
    }

    pub struct ProcessManager {
        owner: Arc<Mutex<process::Owner>>,
        shared: Arc<Shared>,
        sequence: AtomicU64,
        action_gate: Mutex<()>,
    }

    impl ProcessManager {
        pub fn open(executable: &Path, root: &Path, host: Arc<Host>) -> Result<Self, String> {
            #[cfg(not(windows))]
            std::fs::create_dir_all(root).map_err(err)?;
            #[cfg(windows)]
            match crate::security::windows::create_owner_only_directory(root) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(err(error)),
            }
            let metadata = std::fs::symlink_metadata(root).map_err(err)?;
            if !metadata.file_type().is_dir() {
                return Err("network spool must be a real directory".into());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    return Err("network spool cannot be a reparse point".into());
                }
            }
            let root = std::fs::canonicalize(root).map_err(err)?;
            let (owner, mut channel) = process::spawn(executable, Some(&root)).map_err(err)?;
            let owner = Arc::new(Mutex::new(owner));
            process::send(&mut channel, &Bootstrap { version: 1, root }, 16384).map_err(err)?;
            let shared = Arc::new(Shared {
                writer: Mutex::new(channel.try_clone().map_err(err)?),
                pending: Mutex::new(HashMap::new()),
                permit: Mutex::new(None),
                state: Mutex::new(crate::desktop_worker::sync::State::default()),
                failure: Mutex::new(None),
                live: AtomicBool::new(true),
            });
            let (ready, received) = mpsc::sync_channel(1);
            let reader_shared = Arc::clone(&shared);
            let reader_owner = Arc::clone(&owner);
            std::thread::Builder::new()
                .name("factorseal-network-control".into())
                .spawn(move || {
                    let result = listen(&mut channel, &reader_shared, &host, &ready);
                    let message = result
                        .err()
                        .unwrap_or_else(|| "network helper closed".into());
                    #[cfg(windows)]
                    let message = reader_owner.lock().map_or_else(
                        |_| message.clone(),
                        |owner| owner.exited_error(message.clone()),
                    );
                    reader_shared.fail(message.clone());
                    if let Ok(mut owner) = reader_owner.lock() {
                        owner.stop();
                    }
                    let _ = ready.try_send(Err(message.clone()));
                    if let Ok(mut pending) = reader_shared.pending.lock() {
                        for (_, sender) in pending.drain() {
                            let _ = sender.send(Err(message.clone()));
                        }
                    }
                })
                .map_err(err)?;
            if let Err(error) = received
                .recv_timeout(WAIT)
                .map_err(err)
                .and_then(|result| result)
            {
                owner.lock().map_err(err)?.stop();
                return Err(error);
            }
            Ok(Self {
                owner,
                shared,
                sequence: AtomicU64::new(1),
                action_gate: Mutex::new(()),
            })
        }

        #[must_use]
        pub fn view(&self) -> View {
            self.request(ToChild::View).unwrap_or_else(|error| View {
                error: Some(error),
                ..View::default()
            })
        }

        pub fn action(&self, action: Action) -> Result<View, String> {
            let _gate = self.action_gate.lock().map_err(err)?;
            *self.shared.permit.lock().map_err(err)? = Permit::for_action(&action);
            let result = self.request(|id| ToChild::Action { id, action });
            *self.shared.permit.lock().map_err(err)? = None;
            result
        }

        fn request(&self, message: impl FnOnce(u64) -> ToChild) -> Result<View, String> {
            if !self.shared.live.load(Ordering::Acquire) {
                return Err(self
                    .shared
                    .failure
                    .lock()
                    .map_err(err)?
                    .clone()
                    .unwrap_or_else(|| "network helper is unavailable".into()));
            }
            // Allocate IDs while holding the write lock so concurrent view and
            // action requests always reach the helper in sequence order.
            let mut writer = self.shared.writer.lock().map_err(err)?;
            let id = self
                .sequence
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(err)?;
            let (sender, receiver) = mpsc::sync_channel(1);
            {
                let mut pending = self.shared.pending.lock().map_err(err)?;
                if pending.len() >= 8 {
                    return Err("network helper is busy".into());
                }
                pending.insert(id, sender);
            }
            let sent = process::send(&mut writer, &message(id), MAXIMUM).map_err(err);
            drop(writer);
            // Keep transport failure separate from a valid operation rejection.
            // A timed-out child loses all authority and is reaped immediately.
            let result = sent.and_then(|()| receiver.recv_timeout(WAIT).map_err(err));
            self.shared.pending.lock().map_err(err)?.remove(&id);
            if let Err(error) = &result {
                self.shared.fail(error.clone());
                self.owner.lock().map_err(err)?.stop();
            }
            result?
        }
    }

    impl Drop for ProcessManager {
        fn drop(&mut self) {
            self.shared.live.store(false, Ordering::Release);
            if let Ok(mut owner) = self.owner.lock() {
                owner.stop();
            }
        }
    }

    fn listen(
        channel: &mut Channel,
        shared: &Shared,
        host: &Arc<Host>,
        ready: &mpsc::SyncSender<Result<(), String>>,
    ) -> Result<(), String> {
        let mut started = false;
        let mut previous_host_id = 0;
        loop {
            match process::receive(channel, MAXIMUM).map_err(err)? {
                ToParent::Ready if !started => {
                    started = true;
                    ready.send(Ok(())).map_err(err)?;
                }
                ToParent::Ready => return Err("duplicate network readiness message".into()),
                ToParent::StartupFailed(error) => {
                    return Err(format!("network helper could not start: {error}"));
                }
                ToParent::Failed(error) => {
                    return Err(format!("network helper stopped: {error}"));
                }
                ToParent::View { id, result } => {
                    let sender = shared
                        .pending
                        .lock()
                        .map_err(err)?
                        .remove(&id)
                        .ok_or("unexpected network reply")?;
                    let result = result
                        .map(|mut view| {
                            view.state = shared.state.lock().map_err(err)?.clone();
                            view.devices = view
                                .state
                                .group
                                .as_ref()
                                .map(|group| {
                                    group
                                        .verified()
                                        .map(|group| group.transports().to_vec())
                                        .map_err(err)
                                })
                                .transpose()?
                                .unwrap_or_default();
                            Ok(*view)
                        })
                        .and_then(|result| result);
                    sender.send(result).map_err(err)?;
                }
                ToParent::Host { id, command } => {
                    if id <= previous_host_id {
                        return Err("replayed network callback".into());
                    }
                    previous_host_id = id;
                    let state_request =
                        matches!(&*command, crate::desktop_worker::sync::Command::State);
                    let permitted = authorize(&command, &mut *shared.permit.lock().map_err(err)?);
                    let result = if permitted {
                        host(*command)
                    } else {
                        Err("network helper has no authority for this command".into())
                    };
                    if let Ok(Reply::State(state)) = &result {
                        *shared.state.lock().map_err(err)? = *state.clone();
                    }
                    if let Ok(Reply::Group(group)) = &result {
                        shared.state.lock().map_err(err)?.group = Some(group.clone());
                    }
                    if state_request && result.is_err() {
                        // Public membership can remain visible while sealed.
                        // Tickets and pending approvals must leave the parent
                        // cache as soon as the key owner becomes unavailable.
                        let mut state = shared.state.lock().map_err(err)?;
                        *state = crate::desktop_worker::sync::State {
                            group: state.group.take(),
                            readers: state.readers,
                            ..Default::default()
                        };
                        *shared.permit.lock().map_err(err)? = None;
                    }
                    process::send(
                        &mut *shared.writer.lock().map_err(err)?,
                        &ToChild::HostReply { id, result },
                        MAXIMUM,
                    )
                    .map_err(err)?;
                }
            }
        }
    }

    pub fn run() -> io::Result<()> {
        run_inner().inspect_err(|error| {
            // Send only a bounded error over the existing private channel.
            // This preserves the cause of a child exit without logging the
            // channel contents or making the parent accept further work.
            let message: String = error.to_string().chars().take(512).collect();
            let _ = codec::send(&mut io::stdout().lock(), &ToParent::Failed(message), 4096);
        })
    }

    fn run_inner() -> io::Result<()> {
        let bootstrap: Bootstrap =
            codec::decode(&codec::read(&mut io::stdin().lock(), 16384)?, 16384)?;
        if bootstrap.version != 1 || !bootstrap.root.is_absolute() {
            return Err(io::Error::other("invalid network bootstrap"));
        }
        sandbox::network(&bootstrap.root).inspect_err(|error| {
            let _ = codec::send(
                &mut io::stdout().lock(),
                &ToParent::StartupFailed(format!("sandbox: {error}")),
                MAXIMUM,
            );
        })?;
        let channel = process::stdio_channel()?;
        let writer = Arc::new(Mutex::new(channel.try_clone()?));
        let callbacks = Arc::new(Mutex::new(HashMap::<
            u64,
            mpsc::SyncSender<Result<Reply, String>>,
        >::new()));
        let callback_writer = Arc::clone(&writer);
        let callback_pending = Arc::clone(&callbacks);
        let sequence = AtomicU64::new(1);
        // Serialize callbacks so sequence numbers reach the parent in order.
        let callback_gate = Mutex::new(());
        let host = Arc::new(move |command| {
            let _gate = callback_gate.lock().map_err(err)?;
            let id = sequence
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(err)?;
            let (sender, receiver) = mpsc::sync_channel(1);
            callback_pending.lock().map_err(err)?.insert(id, sender);
            let result = (|| {
                process::send(
                    &mut *callback_writer.lock().map_err(err)?,
                    &ToParent::Host {
                        id,
                        command: Box::new(command),
                    },
                    MAXIMUM,
                )
                .map_err(err)?;
                receiver.recv_timeout(WAIT).map_err(err)?
            })();
            callback_pending.lock().map_err(err)?.remove(&id);
            result
        });
        let manager = Arc::new(
            crate::desktop_worker::sync::network::Manager::open(&bootstrap.root, host)
                .map_err(io::Error::other)
                .inspect_err(|error| {
                    if let Ok(mut writer) = writer.lock() {
                        let _ = process::send(
                            &mut writer,
                            &ToParent::StartupFailed(format!("runtime: {error}")),
                            MAXIMUM,
                        );
                    }
                })?,
        );
        let (actions, incoming) = mpsc::sync_channel::<(u64, Action)>(1);
        let action_manager = Arc::clone(&manager);
        let action_writer = Arc::clone(&writer);
        std::thread::Builder::new()
            .name("factorseal-network-actions".into())
            .spawn(move || {
                while let Ok((id, action)) = incoming.recv() {
                    let result = action_manager.action(action);
                    if write_view(&action_writer, id, result).is_err() {
                        break;
                    }
                }
            })?;
        // The IPC reader must keep accepting host replies while output is
        // backpressured. Writing a large view on that reader can deadlock
        // against the parent writing a large callback reply in the opposite
        // direction (especially with macOS's smaller socket buffers).
        let (views, incoming_views) = mpsc::sync_channel::<u64>(8);
        let view_manager = Arc::clone(&manager);
        let view_writer = Arc::clone(&writer);
        std::thread::Builder::new()
            .name("factorseal-network-views".into())
            .spawn(move || {
                while let Ok(id) = incoming_views.recv() {
                    let result = Ok(view_manager.view());
                    if write_view(&view_writer, id, result).is_err() {
                        break;
                    }
                }
            })?;
        process::send(
            &mut *writer
                .lock()
                .map_err(|_| io::Error::other("helper writer unavailable"))?,
            &ToParent::Ready,
            MAXIMUM,
        )?;
        serve(channel, &callbacks, &views, &actions)
    }

    fn write_view(
        writer: &Mutex<Channel>,
        id: u64,
        result: Result<View, String>,
    ) -> io::Result<()> {
        let mut writer = writer
            .lock()
            .map_err(|_| io::Error::other("helper writer unavailable"))?;
        process::send(
            &mut writer,
            &ToParent::View {
                id,
                result: result.map(Box::new),
            },
            MAXIMUM,
        )
    }

    fn serve(
        mut channel: Channel,
        callbacks: &Callbacks,
        views: &mpsc::SyncSender<u64>,
        actions: &mpsc::SyncSender<(u64, Action)>,
    ) -> io::Result<()> {
        let mut previous_request = 0;
        loop {
            match process::receive(&mut channel, MAXIMUM)? {
                ToChild::HostReply { id, result } => {
                    let sender = callbacks
                        .lock()
                        .map_err(|_| io::Error::other("callback lock unavailable"))?
                        .remove(&id)
                        .ok_or_else(|| io::Error::other("unexpected callback reply"))?;
                    sender.send(result).map_err(io::Error::other)?;
                }
                ToChild::View(id) => {
                    if id <= previous_request {
                        return Err(io::Error::other("replayed control request"));
                    }
                    previous_request = id;
                    views.try_send(id).map_err(io::Error::other)?;
                }
                ToChild::Action { id, action } => {
                    if id <= previous_request {
                        return Err(io::Error::other("replayed control request"));
                    }
                    previous_request = id;
                    actions.try_send((id, action)).map_err(io::Error::other)?;
                }
            }
        }
    }

    fn err(error: impl std::fmt::Display) -> String {
        error.to_string()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::desktop_worker::sync::Command;
        #[cfg(unix)]
        use crate::desktop_worker::sync::State;

        #[test]
        fn installed_helper_reads_callbacks_while_a_large_view_write_is_blocked() {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path().join("spool");
            #[cfg(unix)]
            std::fs::create_dir(&root).unwrap();
            #[cfg(windows)]
            crate::security::windows::create_owner_only_directory(&root).unwrap();
            let root = std::fs::canonicalize(root).unwrap();
            let executable = crate::isolation::helper_executable(
                &std::env::current_exe().unwrap(),
                "factorseal-network",
            )
            .unwrap();
            let (_owner, mut channel) = process::spawn(&executable, Some(&root)).unwrap();
            process::send(&mut channel, &Bootstrap { version: 1, root }, 16384).unwrap();
            let mut ready = false;
            let mut callback = None;
            while !ready || callback.is_none() {
                match process::receive::<ToParent>(&mut channel, MAXIMUM).unwrap() {
                    ToParent::Ready => ready = true,
                    ToParent::Host { id, command } if matches!(*command, Command::State) => {
                        callback = Some(id);
                    }
                    ToParent::StartupFailed(error) | ToParent::Failed(error) => {
                        panic!("helper startup failed: {error}")
                    }
                    _ => panic!("unexpected startup reply"),
                }
            }
            // Larger than the native socket buffers in both directions.
            let message = "x".repeat(1024 * 1024);
            process::send(
                &mut channel,
                &ToChild::HostReply {
                    id: callback.unwrap(),
                    result: Err(message.clone()),
                },
                MAXIMUM,
            )
            .unwrap();
            let ToParent::Host { id, command } = process::receive(&mut channel, MAXIMUM).unwrap()
            else {
                panic!("expected next state callback");
            };
            assert!(matches!(*command, Command::State));
            process::send(&mut channel, &ToChild::View(1), MAXIMUM).unwrap();
            let mut header = [0; 4];
            process::read_exact_for_test(&mut channel, &mut header).unwrap();
            let length = u32::from_be_bytes(header) as usize;
            assert!(length > message.len());
            // Do not drain the view yet: its writer must be blocked. The
            // helper's reader must still accept the outstanding callback.
            process::send(
                &mut channel,
                &ToChild::HostReply {
                    id,
                    result: Err(message.clone()),
                },
                MAXIMUM,
            )
            .unwrap();
            let mut bytes = crate::security::LockedBytes::zeroed(length).unwrap();
            process::read_exact_for_test(&mut channel, &mut bytes).unwrap();
            let ToParent::View {
                id: 1,
                result: Ok(view),
            } = codec::decode(&bytes, MAXIMUM).unwrap()
            else {
                panic!("expected complete view reply");
            };
            assert_eq!(view.error.as_deref(), Some(message.as_str()));
        }

        #[test]
        fn helper_exit_preserves_its_first_failure_for_later_views() {
            let fixture = tempfile::tempdir().unwrap();
            let executable = crate::isolation::helper_executable(
                &std::env::current_exe().unwrap(),
                "factorseal-network",
            )
            .unwrap();
            let manager = ProcessManager::open(
                &executable,
                &fixture.path().join("spool"),
                Arc::new(|_| Err("vault is sealed".into())),
            )
            .unwrap();
            manager.owner.lock().unwrap().stop();
            let until = std::time::Instant::now() + Duration::from_secs(5);
            while manager.shared.live.load(Ordering::Acquire) {
                assert!(std::time::Instant::now() < until, "exit was not observed");
                std::thread::sleep(Duration::from_millis(10));
            }
            let first = manager.view().error.unwrap();
            assert_ne!(first, "network helper is unavailable");
            assert_eq!(manager.view().error.as_deref(), Some(first.as_str()));
        }

        #[cfg(unix)]
        #[test]
        fn compromised_helper_cannot_forge_pairing_display_or_approve_itself() {
            let (mut parent, mut child) = Channel::pair().unwrap();
            parent.set_nonblocking(true).unwrap();
            child.set_nonblocking(true).unwrap();
            let (reply, received) = mpsc::sync_channel(1);
            let (ready, started) = mpsc::sync_channel(1);
            let shared = Shared {
                writer: Mutex::new(parent.try_clone().unwrap()),
                pending: Mutex::new(HashMap::from([(1, reply)])),
                permit: Mutex::new(None),
                state: Mutex::new(State::default()),
                failure: Mutex::new(None),
                live: AtomicBool::new(true),
            };
            let host: Arc<Host> = Arc::new(|command| {
                assert!(
                    matches!(command, Command::State),
                    "unapproved command reached the vault"
                );
                Ok(Reply::State(Box::new(State {
                    joining: true,
                    pending: 3,
                    ..State::default()
                })))
            });
            let supervisor =
                std::thread::spawn(move || listen(&mut parent, &shared, &host, &ready));
            process::send(&mut child, &ToParent::Ready, MAXIMUM).unwrap();
            started
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            process::send(
                &mut child,
                &ToParent::Host {
                    id: 1,
                    command: Box::new(Command::State),
                },
                MAXIMUM,
            )
            .unwrap();
            assert!(matches!(
                read_reply(&mut child),
                ToChild::HostReply {
                    id: 1,
                    result: Ok(Reply::State(_))
                }
            ));
            let fabricated = View {
                state: State {
                    joining: false,
                    pending: 999,
                    ..State::default()
                },
                ..View::default()
            };
            process::send(
                &mut child,
                &ToParent::View {
                    id: 1,
                    result: Ok(Box::new(fabricated)),
                },
                MAXIMUM,
            )
            .unwrap();
            let shown = received
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            assert!(shown.state.joining);
            assert_eq!(shown.state.pending, 3);
            process::send(
                &mut child,
                &ToParent::Host {
                    id: 2,
                    command: Box::new(Command::Approve([1; 32])),
                },
                MAXIMUM,
            )
            .unwrap();
            assert!(matches!(
                read_reply(&mut child),
                ToChild::HostReply {
                    id: 2,
                    result: Err(_)
                }
            ));
            drop(child);
            assert!(supervisor.join().unwrap().is_err());
        }

        #[cfg(unix)]
        fn read_reply(channel: &mut Channel) -> ToChild {
            use crate::vault::transport::{IoBudget, read_frame};
            let bytes = read_frame(channel, IoBudget::new(Duration::from_secs(2))).unwrap();
            codec::decode(&bytes, MAXIMUM).unwrap()
        }

        #[cfg(unix)]
        #[test]
        fn unavailable_key_owner_clears_cached_tickets_and_outstanding_approval() {
            use crate::personal::sync::{PairingInvitation, ReaderIdentity};
            let identity = ReaderIdentity::generate().unwrap();
            let group = identity.create_group([9; 32], "Device".into()).unwrap();
            let state = State {
                group: Some(crate::desktop_worker::sync::PublicGroup::new(&group).unwrap()),
                readers: 1,
                invitation: Some(PairingInvitation::new(&group, 100).unwrap()),
                joining: true,
                ..State::default()
            };
            let fabricated = View {
                state: state.clone(),
                ..View::default()
            };
            let (mut parent, mut child) = Channel::pair().unwrap();
            parent.set_nonblocking(true).unwrap();
            child.set_nonblocking(true).unwrap();
            let (reply, received) = mpsc::sync_channel(1);
            let (ready, started) = mpsc::sync_channel(1);
            let shared = Shared {
                writer: Mutex::new(parent.try_clone().unwrap()),
                pending: Mutex::new(HashMap::from([(1, reply)])),
                permit: Mutex::new(Some(Permit::Approve([3; 32]))),
                state: Mutex::new(state),
                failure: Mutex::new(None),
                live: AtomicBool::new(true),
            };
            let host: Arc<Host> = Arc::new(|command| {
                assert!(matches!(command, Command::State));
                Err("vault is sealed".into())
            });
            let supervisor =
                std::thread::spawn(move || listen(&mut parent, &shared, &host, &ready));
            process::send(&mut child, &ToParent::Ready, MAXIMUM).unwrap();
            started
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            process::send(
                &mut child,
                &ToParent::Host {
                    id: 1,
                    command: Box::new(Command::State),
                },
                MAXIMUM,
            )
            .unwrap();
            assert!(matches!(
                read_reply(&mut child),
                ToChild::HostReply {
                    id: 1,
                    result: Err(_)
                }
            ));
            process::send(
                &mut child,
                &ToParent::View {
                    id: 1,
                    result: Ok(Box::new(fabricated)),
                },
                MAXIMUM,
            )
            .unwrap();
            let shown = received
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap();
            assert!(shown.state.invitation.is_none());
            assert!(!shown.state.joining);
            assert_eq!(shown.state.readers, 1);
            assert_eq!(shown.devices.len(), 1);
            process::send(
                &mut child,
                &ToParent::Host {
                    id: 2,
                    command: Box::new(Command::Approve([3; 32])),
                },
                MAXIMUM,
            )
            .unwrap();
            assert!(matches!(
                read_reply(&mut child),
                ToChild::HostReply {
                    id: 2,
                    result: Err(_)
                }
            ));
            drop(child);
            assert!(supervisor.join().unwrap().is_err());
        }
    }
}

#[cfg(any(unix, windows))]
pub use native::{ProcessManager, run};

#[cfg(not(any(unix, windows)))]
pub fn run() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "network isolation is unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(unix, windows))]
    #[test]
    fn installed_network_helper_survives_rejected_actions_and_concurrent_views() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("spool");
        let executable = crate::isolation::helper_executable(
            &std::env::current_exe().unwrap(),
            "factorseal-network",
        )
        .unwrap();
        let host = Arc::new(|command| match command {
            Command::State => Ok(Reply::State(Box::default())),
            _ => Err("vault is sealed".into()),
        });
        let manager = Arc::new(ProcessManager::open(&executable, &root, host).unwrap());
        let endpoint = manager.view().endpoint;
        assert_ne!(endpoint, [0; 32]);
        assert!(
            manager
                .action(Action::Invite("Test device".into()))
                .is_err()
        );
        let readers: Vec<_> = (0..6)
            .map(|_| {
                let manager = Arc::clone(&manager);
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        assert_eq!(manager.view().endpoint, endpoint);
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().unwrap();
        }
        drop(manager);
        let reopened = ProcessManager::open(
            &executable,
            &root,
            Arc::new(|_| Err("vault is sealed".into())),
        )
        .unwrap();
        assert_eq!(reopened.view().endpoint, endpoint);
    }
    #[test]
    fn network_cannot_approve_pairings_without_an_exact_single_use_ui_permit() {
        let mut permit = None;
        assert!(!authorize(&Command::Approve([1; 32]), &mut permit));
        assert!(!authorize(&Command::Cancel, &mut permit));
        permit = Permit::for_action(&Action::Approve([1; 32]));
        assert!(!authorize(&Command::Approve([2; 32]), &mut permit));
        assert!(authorize(&Command::State, &mut permit));
        assert!(authorize(&Command::Approve([1; 32]), &mut permit));
        assert!(!authorize(&Command::Approve([1; 32]), &mut permit));
        permit = Permit::for_action(&Action::Invite("My laptop".into()));
        assert!(!authorize(
            &Command::Offer {
                endpoint: [0; 32],
                name: "another device".into()
            },
            &mut permit
        ));
        assert!(authorize(
            &Command::Offer {
                endpoint: [0; 32],
                name: "My laptop".into()
            },
            &mut permit
        ));
    }
}
