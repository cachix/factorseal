use crate::api::{Device, ErrorCode, Invitation, Revealed, Review, SyncView};
use crate::core::{Failure, Outcome};
use factorseal::VaultService;
use factorseal::desktop_worker::sync::network::{Action, Manager, View};
use factorseal::desktop_worker::sync::{Command, unavailable};
use factorseal::personal::sync::TransportBinding;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use zeroize::Zeroizing;

type Session = Arc<RwLock<Option<Arc<VaultService>>>>;

pub(crate) struct Devices {
    root: PathBuf,
    session: Session,
    manager: Mutex<Option<Arc<Manager>>>,
    name: Mutex<Option<String>>,
}

impl Devices {
    pub(crate) fn new(root: PathBuf, session: Session) -> Self {
        Self {
            root,
            session,
            manager: Mutex::new(None),
            name: Mutex::new(None),
        }
    }

    pub(crate) fn paired(&self) -> bool {
        self.root.join("membership.json").is_file()
    }

    fn manager(&self) -> Option<Arc<Manager>> {
        self.manager
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn start(&self, name: &str, exists: bool) -> Outcome<SyncView> {
        if !exists {
            return Err(Failure::new(ErrorCode::Absent, "there is no vault yet"));
        }
        *self.name.lock().unwrap_or_else(PoisonError::into_inner) = Some(name.trim().to_owned());
        if self.root.join("transport.key").is_file() || self.paired() {
            self.open()?;
        }
        Ok(self.view(self.session_is_live()))
    }

    fn open(&self) -> Outcome<Arc<Manager>> {
        let mut manager = self.manager.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(manager) = &*manager {
            return Ok(Arc::clone(manager));
        }
        let session = Arc::clone(&self.session);
        let host = Arc::new(move |command: Command| {
            let service = session
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            match service {
                Some(service) => command.execute(&service).map_err(|error| error.to_string()),
                None => Err(unavailable().to_string()),
            }
        });
        let opened = Arc::new(
            Manager::open(&self.root, host)
                .map_err(|error| Failure::new(ErrorCode::Sync, error))?,
        );
        *manager = Some(Arc::clone(&opened));
        Ok(opened)
    }

    fn session_is_live(&self) -> bool {
        self.session
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    pub(crate) fn stop(&self) {
        self.manager
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        self.name
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    pub(crate) fn view(&self, unsealed: bool) -> SyncView {
        let paired = self.paired();
        let name = self
            .name
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .unwrap_or_default();
        let Some(manager) = self.manager() else {
            return SyncView {
                paired,
                devices: devices(&[], [0; 32], &name),
                ..SyncView::default()
            };
        };
        convert(&manager.view(), unsealed, paired, &name)
    }

    fn act(&self, action: Action, unsealed: bool) -> Outcome<SyncView> {
        let manager = self
            .manager()
            .ok_or_else(|| Failure::new(ErrorCode::Sync, "sync is not running"))?;
        manager
            .action(action)
            .map_err(|error| Failure::new(ErrorCode::Sync, error))?;
        Ok(self.view(unsealed))
    }

    fn pair(&self, action: Action, unsealed: bool) -> Outcome<SyncView> {
        require(unsealed)?;
        if self
            .name
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none()
        {
            return Err(Failure::new(ErrorCode::Sync, "sync is not running"));
        }
        self.open()?;
        self.act(action, unsealed)
    }

    pub(crate) fn invite(&self, name: &str, unsealed: bool) -> Outcome<SyncView> {
        self.pair(Action::Invite(name.trim().to_owned()), unsealed)
    }

    pub(crate) fn join(&self, ticket: &str, name: &str, unsealed: bool) -> Outcome<SyncView> {
        let ticket = Zeroizing::new(ticket.trim().to_owned());
        self.pair(
            Action::Join {
                ticket,
                name: name.trim().to_owned(),
            },
            unsealed,
        )
    }

    pub(crate) fn approve(&self, request: &str, unsealed: bool) -> Outcome<SyncView> {
        require(unsealed)?;
        let mut id = [0; 32];
        hex::decode_to_slice(request, &mut id)
            .map_err(|_| Failure::new(ErrorCode::Invalid, "the pairing request is malformed"))?;
        let joining = self
            .manager()
            .is_some_and(|manager| manager.view().state.joining);
        self.act(
            if joining {
                Action::ApproveJoin(id)
            } else {
                Action::Approve(id)
            },
            unsealed,
        )
    }

    pub(crate) fn cancel(&self, unsealed: bool) -> Outcome<SyncView> {
        self.act(Action::Cancel, unsealed)
    }

    pub(crate) fn refresh(&self, unsealed: bool) -> Outcome<SyncView> {
        self.act(Action::Refresh, unsealed)
    }
}

fn require(unsealed: bool) -> Outcome<()> {
    if unsealed {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::Sealed, "the vault is sealed"))
    }
}

fn convert(view: &View, unsealed: bool, paired: bool, name: &str) -> SyncView {
    let state = &view.state;
    let hidden = unavailable().to_string();
    SyncView {
        running: true,
        paired,
        devices: devices(&view.devices, view.endpoint, name),
        reachable: view.reachable,
        last_exchange: view.last_exchange,
        pending: state.pending,
        conflicts: state.conflicts,
        readers: state.readers,
        invitation: state
            .invitation
            .as_ref()
            .filter(|_| unsealed && state.request.is_none())
            .and_then(|invitation| {
                Some(Invitation {
                    ticket: Revealed(invitation.ticket().ok()?),
                    modules: invitation.qr_modules().ok()?,
                    expires: invitation.expires(),
                })
            }),
        review: if unsealed { review(view) } else { None },
        joining: state.joining,
        error: view.error.clone().filter(|error| *error != hidden),
    }
}

fn devices(bindings: &[TransportBinding], endpoint: [u8; 32], name: &str) -> Vec<Device> {
    let local = bindings.iter().find(|device| device.endpoint == endpoint);
    let local_name = local
        .map(|device| device.name.clone())
        .or_else(|| (!name.is_empty()).then(|| name.to_owned()));
    local_name
        .map(|name| Device {
            name,
            local: true,
            reader: local.is_none_or(|device| device.reader.is_some()),
        })
        .into_iter()
        .chain(
            bindings
                .iter()
                .filter(|device| device.endpoint != endpoint)
                .map(|device| Device {
                    name: device.name.clone(),
                    local: false,
                    reader: device.reader.is_some(),
                }),
        )
        .collect()
}

fn review(view: &View) -> Option<Review> {
    let state = &view.state;
    let request = state.request.as_ref()?;
    let id = hex::encode(request.id().ok()?);
    let target = if state.joining {
        state.target.as_ref()
    } else {
        state.group.as_ref().or(state.introduction.as_ref())
    }
    .and_then(|group| group.verified().ok());
    let (verified, devices) = match (request.origin(), target) {
        (Ok(origin), Some(target)) => {
            let mut devices = target.transports().to_vec();
            if let Some(origin) = origin {
                devices.extend_from_slice(origin.transports());
            } else {
                devices.push(TransportBinding {
                    endpoint: request.endpoint(),
                    reader: None,
                    name: request.name().into(),
                });
            }
            devices.sort_by_key(|device| device.endpoint);
            devices.dedup_by_key(|device| device.endpoint);
            (
                true,
                devices
                    .into_iter()
                    .map(|device| Device {
                        local: device.endpoint == view.endpoint,
                        reader: device.reader.is_some(),
                        name: device.name,
                    })
                    .collect(),
            )
        }
        _ => (false, Vec::new()),
    };
    Some(Review {
        request: id,
        code: request.verification_code().unwrap_or_default(),
        devices,
        verified,
        waiting: !state.joining && request.needs_merge_approval(),
        approved_here: state.joining && !request.needs_merge_approval(),
    })
}
