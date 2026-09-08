//! Opt-in acceptance against the production discovery and relay configuration.
//! Only synthetic vaults and ciphertext are used. No sandbox bypass or test
//! transport command is added to the installed helper protocol.
use super::{Action, Arc, Command, Path, ProcessManager, View};
use crate::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret};
use crate::vault::{Provenance, VaultStore};
use crate::{DocumentKind, SecretAddress, UnsealLeasePolicy, Vault, VaultService};
use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

struct Device {
    helper: Option<ProcessManager>,
    service: Arc<Mutex<Arc<VaultService>>>,
    stored: Arc<Mutex<Vec<crate::personal::sync::PacketId>>>,
    received: Arc<AtomicUsize>,
    executable: PathBuf,
    root: tempfile::TempDir,
    callback: Arc<Mutex<Option<Callback>>>,
}

struct Callback {
    command: &'static str,
    started: Instant,
    finished: Option<Duration>,
}

// Diagnostics name operations and timings, never their payloads or key data.
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::State => "state",
        Command::Initialize { .. } => "initialize",
        Command::Invite => "invite",
        Command::Offer { .. } => "offer",
        Command::Join { .. } => "join",
        Command::Stage { .. } => "stage",
        Command::Approve(_) => "approve",
        Command::ApproveJoin(_) => "approve join",
        Command::Accept(_) => "accept",
        Command::Cancel => "cancel",
        Command::Prepare => "prepare",
        Command::Stored(_) => "stored",
        Command::Receive(_) => "receive",
    }
}

impl Device {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("vault");
        VaultStore::open(&vault, Vault::create_for_test(&vault).unwrap())
            .unwrap()
            .seal();
        let service = Arc::new(Mutex::new(Arc::new(open_service(&vault))));
        let executable = crate::isolation::helper_executable(
            &std::env::current_exe().unwrap(),
            "factorseal-network",
        )
        .unwrap();
        let mut device = Self {
            helper: None,
            service,
            stored: Arc::default(),
            received: Arc::default(),
            executable,
            root,
            callback: Arc::default(),
        };
        device.start();
        device
    }

    fn start(&mut self) {
        assert!(self.helper.is_none());
        let service = Arc::clone(&self.service);
        let stored = Arc::clone(&self.stored);
        let received = Arc::clone(&self.received);
        let callback = Arc::clone(&self.callback);
        self.helper = Some(
            ProcessManager::open(
                &self.executable,
                &self.root.path().join("spool"),
                Arc::new(move |command| {
                    let started = Instant::now();
                    *callback.lock().unwrap() = Some(Callback {
                        command: command_name(&command),
                        started,
                        finished: None,
                    });
                    let receiving = matches!(&command, Command::Receive(_));
                    let id = if let Command::Stored(id) = &command {
                        Some(*id)
                    } else {
                        None
                    };
                    let host = Arc::clone(&service.lock().unwrap());
                    let reply = command.execute(&host).map_err(|error| error.to_string());
                    callback.lock().unwrap().as_mut().unwrap().finished = Some(started.elapsed());
                    let reply = reply?;
                    if receiving {
                        received.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(id) = id {
                        stored.lock().unwrap().push(id);
                    }
                    Ok(reply)
                }),
            )
            .unwrap(),
        );
    }

    fn host(&self) -> Arc<VaultService> {
        Arc::clone(&self.service.lock().unwrap())
    }
    fn callback_progress(&self) -> String {
        self.callback.lock().unwrap().as_ref().map_or_else(
            || "no callback received".to_owned(),
            |callback| {
                format!(
                    "{} started {:?} ago; completed in {:?}",
                    callback.command,
                    callback.started.elapsed(),
                    callback.finished
                )
            },
        )
    }
    fn helper(&self) -> &ProcessManager {
        self.helper.as_ref().unwrap()
    }
    fn wait(&self, description: &str, predicate: impl Fn(&View) -> bool) -> View {
        let until = Instant::now() + Duration::from_secs(90);
        loop {
            let view = self.helper().view();
            assert_ne!(view.endpoint, [0; 32], "{description}: {:?}", view.error);
            if predicate(&view) {
                return view;
            }
            assert!(Instant::now() < until, "{description}: {:?}", view.error);
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn pair(&self, other: &Self) {
        let offered = self
            .helper()
            .action(Action::Invite("Sender".into()))
            .unwrap();
        let invitation = offered.state.invitation.unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            match other.helper().action(Action::Join {
                ticket: invitation.ticket().unwrap(),
                name: "Receiver".into(),
            }) {
                Ok(_) => break,
                // Binding an endpoint precedes its public discovery record.
                // This error occurs before the joining host is called.
                Err(error)
                    if error == "No addressing information available" && Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(error) => panic!(
                    "pairing join failed: {error}; inviter: {}; joiner: {}",
                    self.callback_progress(),
                    other.callback_progress()
                ),
            }
        }
        let request = self
            .wait("incoming pairing request", |view| {
                view.state.request.is_some()
            })
            .state
            .request
            .unwrap();
        let joining = other
            .wait("matching joining request", |view| {
                view.state.request.is_some()
            })
            .state
            .request
            .unwrap();
        assert_eq!(
            request.verification_code().unwrap(),
            joining.verification_code().unwrap()
        );
        let id = request.id().unwrap();
        assert!(self.helper().action(Action::Approve(id)).is_err());
        other.helper().action(Action::ApproveJoin(id)).unwrap();
        self.wait("joiner approval", |view| {
            view.state
                .request
                .as_ref()
                .is_some_and(|request| !request.needs_merge_approval())
        });
        let request = self.helper().view().state.request.unwrap();
        self.helper()
            .action(Action::Approve(request.id().unwrap()))
            .unwrap();
        other.wait("accepted membership", |view| {
            !view.state.joining && view.state.readers >= 2
        });
    }

    fn put(&self, item: &PersonalSecret) {
        self.host().seal().unwrap();
        let vault = self.root.path().join("vault");
        let store = VaultStore::open(&vault, Vault::unseal_for_test(&vault).unwrap()).unwrap();
        store
            .put_at(
                DocumentKind::LocalKeyring,
                PERSONAL_SECRET_NAMESPACE,
                &SecretAddress::new(&item.id, None).unwrap(),
                &item.encode().unwrap(),
                None,
                &Provenance::Redacted,
                100,
            )
            .unwrap();
        store.seal();
        *self.service.lock().unwrap() = Arc::new(open_service(&vault));
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        drop(self.helper.take());
        let _ = self.host().seal();
    }
}
fn open_service(vault: &Path) -> VaultService {
    VaultService::open(
        vault,
        Vault::unseal_for_test(vault).unwrap(),
        100,
        UnsealLeasePolicy::default(),
    )
    .unwrap()
}

#[test]
#[ignore = "requires live production discovery/relays and installed sandboxed helpers"]
fn helpers_pair_and_deliver_through_a_sealed_courier_after_sender_exit() {
    let a = Device::new();
    let b = Device::new();
    let mut c = Device::new();
    eprintln!("Pairing the sender and middle device");
    a.pair(&b);
    eprintln!("Pairing the receiver");
    a.pair(&c);
    b.wait("three-member group", |view| view.state.readers == 3);
    b.host().seal().unwrap();
    drop(c.helper.take());
    eprintln!("Publishing while the receiver is offline and the middle vault is sealed");
    assert_eq!(c.received.load(Ordering::Relaxed), 0);
    let item = PersonalSecret::generic(
        "Helper acceptance".into(),
        "synthetic encrypted payload".into(),
    );
    a.put(&item);
    a.wait("durable publication", |_| {
        !a.stored.lock().unwrap().is_empty()
    });
    let ids = a.stored.lock().unwrap().clone();
    b.wait("sealed courier receipt", |_| {
        ids.iter().all(|id| {
            let filename = format!("{id}.packet");
            let sender = std::fs::read(a.root.path().join("spool/packets").join(&filename));
            let courier = std::fs::read(b.root.path().join("spool/packets").join(&filename));
            matches!((sender, courier), (Ok(a), Ok(b)) if !a.is_empty() && a == b)
        })
    });
    assert!(b.host().personal_sync_status().is_err());
    // C's helper was stopped before this item existed, so it cannot have
    // received it. Querying a nonexistent replica is a fail-closed error.
    assert_eq!(c.host().personal_sync_status().unwrap().readers, 3);
    drop(a);
    eprintln!("Restarting the receiver after sender exit");
    c.start();
    c.wait("delivery after sender exit", |_| {
        c.received.load(Ordering::Relaxed) > 0
    });
    assert_eq!(
        c.host().personal_sync_conflicts(&item.id).unwrap().values,
        vec![Some(item)]
    );
    assert_eq!(c.host().personal_sync_status().unwrap().readers, 3);
    assert!(b.host().personal_sync_status().is_err());
}
