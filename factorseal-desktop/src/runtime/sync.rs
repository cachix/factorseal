#![allow(clippy::unnecessary_wraps, clippy::unused_self)]

use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use super::unix_time;

const LOCAL: [u8; 32] = [1; 32];
const PHONE: [u8; 32] = [2; 32];
const LAPTOP: [u8; 32] = [3; 32];
const REQUEST_AFTER_SECONDS: u64 = 6;
const JOIN_AFTER_SECONDS: u64 = 4;
const INVITATION_SECONDS: u64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MemberId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransportBinding {
    pub(crate) endpoint: [u8; 32],
    pub(crate) reader: Option<MemberId>,
    pub(crate) name: String,
}

#[derive(Clone, Default)]
pub(crate) struct View {
    pub(crate) devices: Vec<TransportBinding>,
    pub(crate) endpoint: [u8; 32],
    pub(crate) state: State,
    pub(crate) reachable: usize,
    pub(crate) last_exchange: Option<u64>,
    pub(crate) error: Option<String>,
}

#[derive(Clone, Default)]
pub(crate) struct State {
    pub(crate) group: Option<Group>,
    pub(crate) introduction: Option<Group>,
    pub(crate) target: Option<Group>,
    pub(crate) invitation: Option<Invitation>,
    pub(crate) request: Option<Request>,
    pub(crate) joining: bool,
    pub(crate) pending: usize,
    pub(crate) conflicts: usize,
    pub(crate) readers: usize,
}

#[derive(Clone)]
pub(crate) struct Group(Vec<TransportBinding>);

impl Group {
    pub(crate) fn verified(&self) -> Result<Self, String> {
        Ok(self.clone())
    }

    pub(crate) fn transports(&self) -> &[TransportBinding] {
        &self.0
    }
}

#[derive(Clone)]
pub(crate) struct Invitation {
    created: u64,
    ticket: String,
}

impl Invitation {
    pub(crate) const fn expires(&self) -> u64 {
        self.created + INVITATION_SECONDS
    }

    pub(crate) fn ticket(&self) -> Result<Zeroizing<String>, String> {
        Ok(Zeroizing::new(self.ticket.clone()))
    }

    pub(crate) fn qr_modules(&self) -> Result<Vec<Vec<bool>>, String> {
        let code =
            qrcode::QrCode::new(self.ticket.as_bytes()).map_err(|error| error.to_string())?;
        let width = code.width();
        Ok(code
            .to_colors()
            .chunks(width)
            .map(|row| {
                row.iter()
                    .map(|color| *color == qrcode::Color::Dark)
                    .collect()
            })
            .collect())
    }
}

#[derive(Clone)]
pub(crate) struct Request {
    binding: TransportBinding,
    code: &'static str,
    origin: Option<Group>,
    merge: bool,
}

impl Request {
    pub(crate) const fn id(&self) -> Result<[u8; 32], String> {
        Ok(self.binding.endpoint)
    }

    pub(crate) fn verification_code(&self) -> Result<String, String> {
        Ok(self.code.to_owned())
    }

    pub(crate) fn name(&self) -> &str {
        &self.binding.name
    }

    pub(crate) const fn endpoint(&self) -> [u8; 32] {
        self.binding.endpoint
    }

    pub(crate) fn origin(&self) -> Result<Option<Group>, String> {
        Ok(self.origin.clone())
    }

    pub(crate) const fn needs_merge_approval(&self) -> bool {
        self.merge
    }
}

pub(crate) enum Action {
    Refresh,
    Invite(String),
    Join {
        ticket: Zeroizing<String>,
        name: String,
    },
    Approve([u8; 32]),
    ApproveJoin([u8; 32]),
    Cancel,
}

pub(crate) struct Devices(Mutex<Mock>);

struct Mock {
    local_name: String,
    devices: Vec<TransportBinding>,
    invited: Option<u64>,
    joining: Option<Joining>,
    last_exchange: u64,
}

struct Joining {
    approved: Option<u64>,
}

impl Default for Devices {
    fn default() -> Self {
        let now = unix_time().unwrap_or_default();
        Self(Mutex::new(Mock {
            local_name: crate::platform::host_name(),
            devices: vec![binding(PHONE, "Phone")],
            invited: None,
            joining: None,
            last_exchange: now.saturating_sub(120),
        }))
    }
}

impl Devices {
    pub(crate) fn view(&self) -> View {
        let mut mock = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let now = unix_time().unwrap_or_default();
        if mock
            .joining
            .as_ref()
            .and_then(|joining| joining.approved)
            .is_some_and(|approved| now >= approved + JOIN_AFTER_SECONDS)
        {
            mock.joining = None;
            mock.connect_laptop(now);
        }
        if mock
            .invited
            .is_some_and(|created| now >= created + INVITATION_SECONDS)
        {
            mock.invited = None;
        }
        let mut devices = vec![binding(LOCAL, &mock.local_name)];
        devices.extend(mock.devices.iter().cloned());
        let group = Group(devices.clone());
        let laptop = binding(LAPTOP, "Work laptop");
        let request = match (&mock.joining, mock.invited) {
            (Some(joining), _) => Some(Request {
                binding: laptop.clone(),
                code: "731 205",
                origin: Some(group.clone()),
                merge: joining.approved.is_none(),
            }),
            (None, Some(created)) if now >= created + REQUEST_AFTER_SECONDS => Some(Request {
                binding: laptop.clone(),
                code: "482 913",
                origin: None,
                merge: false,
            }),
            _ => None,
        };
        View {
            reachable: devices.len() - 1,
            devices,
            endpoint: LOCAL,
            state: State {
                target: mock.joining.as_ref().map(|_| Group(vec![laptop])),
                joining: mock.joining.is_some(),
                group: Some(group),
                invitation: mock.invited.map(|created| Invitation {
                    created,
                    ticket: format!("factorseal-pair:{created:x}-browser-demo"),
                }),
                request,
                ..State::default()
            },
            last_exchange: Some(mock.last_exchange),
            error: None,
        }
    }

    pub(crate) fn action(&self, action: Action) -> Result<View, String> {
        {
            let mut mock = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            let now = unix_time().unwrap_or_default();
            match action {
                Action::Refresh => mock.last_exchange = now,
                Action::Invite(name) => {
                    mock.local_name = name;
                    mock.invited = Some(now);
                }
                Action::Join { ticket, name } => {
                    if ticket.trim().is_empty() {
                        return Err("Enter the pairing code from your other device.".to_owned());
                    }
                    mock.local_name = name;
                    mock.joining = Some(Joining { approved: None });
                }
                Action::Approve(endpoint) => {
                    if endpoint == LAPTOP {
                        mock.connect_laptop(now);
                    }
                    mock.invited = None;
                }
                Action::ApproveJoin(_) => {
                    if let Some(joining) = &mut mock.joining {
                        joining.approved = Some(now);
                    }
                }
                Action::Cancel => {
                    mock.invited = None;
                    mock.joining = None;
                }
            }
        }
        Ok(self.view())
    }
}

impl Mock {
    fn connect_laptop(&mut self, now: u64) {
        if !self.devices.iter().any(|device| device.endpoint == LAPTOP) {
            self.devices.push(binding(LAPTOP, "Work laptop"));
        }
        self.last_exchange = now;
    }
}

fn binding(endpoint: [u8; 32], name: &str) -> TransportBinding {
    TransportBinding {
        endpoint,
        reader: Some(MemberId),
        name: name.to_owned(),
    }
}
