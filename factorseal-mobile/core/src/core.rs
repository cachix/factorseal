use crate::api::{
    Code, Draft, ErrorCode, Factor, Format, GeneratorOptions, GeneratorStyle, Kind, Lease,
    LoginChange, Platform, Request, Response, Revealed, Secret, Site, Status, Strength, Summary,
    TransferKey, VaultState,
};
use crate::autofill::{self, Target};
use crate::items;
use crate::sync::Devices;
use crate::transfer;
use factorseal::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret, generator, templates, totp};
use factorseal::transfer::import_plan::PreparedImport;
use factorseal::vault::{
    MAX_LIST_PAGE_SIZE, VaultAction, VaultMutation, VaultRequest, VaultResponseBody,
    VaultResponseErrorCode, WireSecret, WireSecretAddress,
};
use factorseal::{
    CallerIdentity, CallerPlatform, DocumentKind, GrantAuthorization, GrantAuthorizationTarget,
    GrantPermission, KeyProtectorFactory, NativeAuthorizationError, UnlockCredentials,
    UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealLeasePolicy, Vault, VaultError,
    VaultPlatform, VaultService,
};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;
use zeroize::Zeroizing;

const APPLICATION: &str = "com.cachix.factorseal";

#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
}

impl Failure {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        let code = match &error {
            VaultError::Sealed => ErrorCode::Sealed,
            VaultError::PasswordRejected => ErrorCode::PasswordRejected,
            VaultError::HardwareUnavailable => ErrorCode::HardwareUnavailable,
            VaultError::HardwarePolicyUnsupported => ErrorCode::PolicyUnsupported,
            VaultError::Conflict => ErrorCode::Conflict,
            VaultError::NativeAuthorization(kind) => match kind {
                NativeAuthorizationError::Cancelled => ErrorCode::Cancelled,
                NativeAuthorizationError::Denied => ErrorCode::Denied,
                NativeAuthorizationError::UiUnavailable => ErrorCode::UiUnavailable,
                NativeAuthorizationError::SessionLocked => ErrorCode::SessionLocked,
                NativeAuthorizationError::CredentialInvalidated => ErrorCode::CredentialInvalidated,
                _ => ErrorCode::Failed,
            },
            _ => ErrorCode::Failed,
        };
        Self::new(code, error.to_string())
    }
}

pub(crate) type Outcome<T> = Result<T, Failure>;

pub(crate) struct Core {
    root: PathBuf,
    platform: Platform,
    factory: Box<dyn KeyProtectorFactory + Send + Sync>,
    caller: CallerIdentity,
    session: Arc<RwLock<Option<Arc<VaultService>>>>,
    sync: Devices,
    restore: Mutex<Option<PersonalSecret>>,
    import: Mutex<Option<PreparedImport>>,
    codes: Mutex<Option<(String, Vec<Generator>)>>,
}

struct Generator {
    section: String,
    field: String,
    totp: totp::Totp,
    origin: totp::Origin,
}

impl Core {
    pub(crate) fn new(
        directory: &Path,
        platform: Platform,
        factory: Box<dyn KeyProtectorFactory + Send + Sync>,
    ) -> Outcome<Self> {
        let caller = CallerIdentity::new(
            match platform {
                Platform::Android => CallerPlatform::Android,
                Platform::Ios => CallerPlatform::Ios,
            },
            "device",
            APPLICATION,
            Sha256::digest(APPLICATION.as_bytes()).into(),
            None,
        )?;
        let root = directory.join("vault");
        let session = Arc::new(RwLock::new(None));
        Ok(Self {
            sync: Devices::new(root.join("personal-sync"), Arc::clone(&session)),
            root,
            platform,
            factory,
            caller,
            session,
            restore: Mutex::new(None),
            import: Mutex::new(None),
            codes: Mutex::new(None),
        })
    }

    pub(crate) fn handle(&self, request: Request) -> Outcome<Response> {
        match request {
            Request::Start { .. } | Request::Status => self.status().map(Response::Status),
            Request::Touch => {
                self.request(VaultAction::ListVaultEntries {
                    cursor: None,
                    limit: 1,
                })?;
                self.status().map(Response::Status)
            }
            Request::Create {
                groups,
                password,
                lease,
            } => self.create(&groups, password, lease),
            Request::Unlock {
                group,
                password,
                lease,
            } => self.unlock(&group, password, lease),
            Request::Seal => {
                self.seal();
                self.status().map(Response::Status)
            }
            Request::RatePassword { password } => Ok(rate(&password.0)),
            Request::Items => self.items().map(|items| Response::Items { items }),
            Request::Item { id } => self.item(&id),
            Request::Reveal { id, section, field } => self.reveal(&id, &section, &field),
            Request::Codes { id } => self.codes(&id),
            Request::Template { kind } => Ok(Response::Draft {
                item: items::draft(&templates::new_item(items::kind_to_core(kind)), None),
            }),
            Request::Edit { id } => {
                let (item, version) = self.read(&id)?;
                Ok(Response::Draft {
                    item: items::draft(&item, Some(&version)),
                })
            }
            Request::Save { item, version } => self.save(&item, version.as_deref()),
            Request::Favorite { id, favorite } => {
                let (mut item, version) = self.read(&id)?;
                item.favorite = favorite;
                let version = self.write(&item, Some(&version))?;
                Ok(Response::Saved { id, version })
            }
            Request::Delete { id, version } => self.delete(&id, &version),
            Request::Restore => self.restore(),
            Request::Generate { options } => generate(options),
            Request::SetupKey { value, same_as } => Ok(setup_key(&value.0, same_as.as_ref())),
            Request::SyncStart { name } => {
                self.sync.start(&name, self.exists()?).map(Response::Sync)
            }
            Request::SyncStop => {
                self.sync.stop();
                Ok(Response::Sync(self.sync.view(self.live().is_some())))
            }
            Request::SyncView => Ok(Response::Sync(self.sync.view(self.live().is_some()))),
            Request::SyncInvite { name } => self
                .sync
                .invite(&name, self.require_live().is_ok())
                .map(Response::Sync),
            Request::SyncJoin { ticket, name } => self
                .sync
                .join(&ticket.0, &name, self.require_live().is_ok())
                .map(Response::Sync),
            Request::SyncApprove { request } => self
                .sync
                .approve(&request, self.require_live().is_ok())
                .map(Response::Sync),
            Request::SyncCancel => self.sync.cancel(self.live().is_some()).map(Response::Sync),
            Request::SyncRefresh => self.sync.refresh(self.live().is_some()).map(Response::Sync),
            Request::Classify { text } => Ok(Response::Scanned {
                scan: crate::qr::classify(&text.0),
            }),
            Request::Export { format, key } => self.export(format, key.as_ref()),
            Request::Import { format, file, key } => self.import(format, &file.0, key.as_ref()),
            Request::ImportCommit { replace } => self.commit_import(replace),
            Request::ImportCancel => {
                self.clear_import();
                self.status().map(Response::Status)
            }
            Request::Logins { site } => self.logins(&site),
            Request::Fill { id, site } => self.fill(&id, &site),
            Request::SaveLogin {
                site,
                title,
                username,
                password,
            } => self.save_login(&site, &title, &username.0, &password.0),
        }
    }

    fn item(&self, id: &str) -> Outcome<Response> {
        let (item, version) = self.read(id)?;
        *self.codes.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((item.id.clone(), generators(&item)));
        Ok(Response::Item {
            item: items::view(&item, Some(&version), false),
        })
    }

    fn codes(&self, id: &str) -> Outcome<Response> {
        self.require_live()?;
        let cached = self
            .codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_if(|(cached, _)| cached == id);
        let generators = match cached {
            Some((_, generators)) => generators,
            None => generators(&self.read(id)?.0),
        };
        let codes = codes(&generators, totp::unix_now());
        *self.codes.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((id.to_owned(), generators));
        Ok(Response::Codes { codes })
    }

    fn reveal(&self, id: &str, section: &str, field: &str) -> Outcome<Response> {
        let (item, _) = self.read(id)?;
        items::reveal(&item, section, field)
            .map(|value| Response::Value {
                value: Revealed(value),
            })
            .ok_or_else(|| Failure::new(ErrorCode::NotFound, "the field has no value"))
    }

    fn logins(&self, site: &Site) -> Outcome<Response> {
        let target = Target::of(site)?;
        let (linked, others): (Vec<_>, Vec<_>) = self
            .login_items()?
            .into_iter()
            .map(|(item, _)| item)
            .filter(PersonalSecret::is_fillable_login)
            .partition(|item| target.links(item));
        Ok(Response::Logins {
            linked: linked.iter().map(autofill::login).collect(),
            others: if target.learns() {
                others.iter().map(autofill::login).collect()
            } else {
                Vec::new()
            },
        })
    }

    fn fill(&self, id: &str, site: &Site) -> Outcome<Response> {
        let target = Target::of(site)?;
        let (mut item, version) = self.read(id)?;
        if !item.is_fillable_login() {
            return Err(Failure::new(
                ErrorCode::Invalid,
                "this item is not a login with one username and one password",
            ));
        }
        if !target.links(&item) {
            if !target.learns() {
                return Err(Failure::new(
                    ErrorCode::Denied,
                    "this login is not saved for this website",
                ));
            }
            autofill::link(&mut item, &target);
            self.write(&item, Some(&version))?;
        }
        let (username, password) = item.login_credentials().ok_or_else(unexpected)?;
        Ok(Response::Credentials {
            username: Revealed(Zeroizing::new(username.to_owned())),
            password: Revealed(Zeroizing::new(password.to_owned())),
        })
    }

    fn save_login(
        &self,
        site: &Site,
        title: &str,
        username: &str,
        password: &str,
    ) -> Outcome<Response> {
        let target = Target::of(site)?;
        if password.is_empty() {
            return Err(Failure::new(ErrorCode::Invalid, "the password is empty"));
        }
        let mut saved: Vec<_> = self
            .login_items()?
            .into_iter()
            .filter(|(item, _)| {
                target.links(item)
                    && item
                        .login_credentials()
                        .is_some_and(|(name, _)| name == username)
            })
            .collect();
        let (item, change) = match saved.pop() {
            None => {
                let item = autofill::new_login(&target, title, username, password);
                self.write(&item, None)?;
                (item, LoginChange::Added)
            }
            Some(_) if !saved.is_empty() => {
                return Err(Failure::new(
                    ErrorCode::Conflict,
                    "several saved logins use this username",
                ));
            }
            Some((item, _))
                if item
                    .login_credentials()
                    .is_some_and(|(_, stored)| stored == password) =>
            {
                (item, LoginChange::Unchanged)
            }
            Some((mut item, version)) => {
                item.set_password(password);
                self.write(&item, Some(&version))?;
                (item, LoginChange::Updated)
            }
        };
        Ok(Response::LoginSaved {
            id: item.id.clone(),
            change,
        })
    }

    fn login_items(&self) -> Outcome<Vec<(PersonalSecret, [u8; 32])>> {
        self.items()?
            .into_iter()
            .filter(|summary| summary.kind == Kind::Login)
            .filter_map(|summary| match self.read(&summary.id) {
                Err(failure) if failure.code != ErrorCode::Sealed => None,
                read => Some(read),
            })
            .collect()
    }

    fn export(&self, format: Format, key: Option<&TransferKey>) -> Outcome<Response> {
        let service = self.require_live()?;
        let data = transfer::export(&self.client(&service), format, key)?;
        Ok(Response::File {
            name: transfer::file_name(format),
            data: Revealed(data),
        })
    }

    fn import(&self, format: Format, file: &str, key: Option<&TransferKey>) -> Outcome<Response> {
        self.require_live()?;
        let prepared = transfer::prepare(format, file, key)?;
        let review = Response::ImportReview {
            items: prepared.len(),
            preserved: prepared.preserved_only(),
        };
        *self.import.lock().unwrap_or_else(PoisonError::into_inner) = Some(prepared);
        Ok(review)
    }

    fn commit_import(&self, replace: bool) -> Outcome<Response> {
        let service = self.require_live()?;
        let prepared = self
            .import
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| Failure::new(ErrorCode::NotFound, "there is no import to finish"))?;
        let summary = transfer::commit(&self.client(&service), prepared, replace)?;
        Ok(Response::Imported {
            added: summary.added,
            replaced: summary.replaced,
            kept: summary.kept_existing,
            preserved: summary.preserved_only,
        })
    }

    fn client<'a>(&'a self, service: &'a VaultService) -> transfer::Client<'a> {
        transfer::Client {
            service,
            caller: &self.caller,
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    fn exists(&self) -> Outcome<bool> {
        self.root
            .join("factorseal.json")
            .try_exists()
            .map_err(|error| Failure::new(ErrorCode::Failed, error.to_string()))
    }

    fn live(&self) -> Option<Arc<VaultService>> {
        let mut session = self.session.write().unwrap_or_else(PoisonError::into_inner);
        let sealed = session
            .as_ref()
            .is_some_and(|service| service.expire_if_needed(totp::unix_now()).unwrap_or(true));
        if sealed {
            *session = None;
            drop(session);
            self.clear_restore();
            self.clear_import();
            self.clear_codes();
            return None;
        }
        session.clone()
    }

    fn require_live(&self) -> Outcome<Arc<VaultService>> {
        self.live()
            .ok_or_else(|| Failure::new(ErrorCode::Sealed, "the vault is sealed"))
    }

    fn status(&self) -> Outcome<Status> {
        if !self.exists()? {
            return Ok(Status {
                vault: VaultState::Absent,
                groups: Vec::new(),
                backend: None,
                paired: false,
                idle_deadline: None,
                absolute_deadline: None,
            });
        }
        let metadata = Vault::inspect(&self.root)?;
        let live = self.live();
        let deadlines = live.as_deref().and_then(|service| self.deadlines(service));
        Ok(Status {
            vault: if live.is_some() {
                VaultState::Unsealed
            } else {
                VaultState::Sealed
            },
            idle_deadline: deadlines.map(|(idle, _)| idle),
            absolute_deadline: deadlines.map(|(_, absolute)| absolute),
            groups: metadata
                .unlock_policy()
                .groups()
                .iter()
                .map(|group| group.factors().iter().filter_map(|&f| factor(f)).collect())
                .collect(),
            backend: Some(metadata.hardware_backend().to_owned()),
            paired: self.sync.paired(),
        })
    }

    fn deadlines(&self, service: &VaultService) -> Option<(u64, u64)> {
        let request = VaultRequest::new(VaultAction::Status).ok()?;
        match service
            .handle(&self.caller, request, totp::unix_now())
            .result
        {
            Ok(VaultResponseBody::Status {
                idle_deadline,
                absolute_deadline,
                ..
            }) => Some((idle_deadline, absolute_deadline)),
            _ => None,
        }
    }

    fn create(
        &self,
        groups: &[Vec<Factor>],
        password: Option<Secret>,
        lease: Lease,
    ) -> Outcome<Response> {
        if self.exists()? {
            return Err(Failure::new(ErrorCode::Exists, "a vault already exists"));
        }
        let policy = UnlockPolicy::new(
            groups
                .iter()
                .map(|group| UnlockGroup::new(group.iter().copied().map(core_factor)))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let password = password_for(
            policy
                .groups()
                .iter()
                .any(|group| group.requires(UnlockFactorKind::Password)),
            password,
        )?;
        if let Some(password) = &password {
            factorseal::security::validate_new_password(password.as_bytes())
                .map_err(|error| Failure::new(ErrorCode::WeakPassword, error))?;
        }
        let lease = lease_policy(lease)?;
        if let Some(parent) = self.root.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Failure::new(ErrorCode::Failed, error.to_string()))?;
        }
        let credentials = password
            .as_ref()
            .map_or_else(UnlockCredentials::none, |password| {
                UnlockCredentials::with_password(password.as_bytes())
            });
        let unsealed = Vault::create_with_key_protector_policy(
            &self.root,
            self.vault_platform(),
            &policy,
            credentials,
            self.factory.as_ref(),
        )?;
        match self.open(unsealed, lease) {
            Ok(()) => self.status().map(Response::Status),
            Err(failure) => {
                let _ = Vault::discard_initialization_with_key_protector(
                    &self.root,
                    self.factory.as_ref(),
                );
                Err(failure)
            }
        }
    }

    fn unlock(
        &self,
        group: &[Factor],
        password: Option<Secret>,
        lease: Lease,
    ) -> Outcome<Response> {
        if !self.exists()? {
            return Err(Failure::new(ErrorCode::Absent, "there is no vault yet"));
        }
        if self.live().is_some() {
            return self.status().map(Response::Status);
        }
        let group = UnlockGroup::new(group.iter().copied().map(core_factor))?;
        let password = password_for(group.requires(UnlockFactorKind::Password), password)?;
        let lease = lease_policy(lease)?;
        let credentials = password
            .as_ref()
            .map_or_else(UnlockCredentials::none, |password| {
                UnlockCredentials::with_password(password.as_bytes())
            });
        let unsealed = Vault::unseal_with_key_protector_group(
            &self.root,
            &group,
            credentials,
            self.factory.as_ref(),
        )?;
        self.open(unsealed, lease)?;
        self.status().map(Response::Status)
    }

    fn open(&self, unsealed: factorseal::UnsealedVault, lease: UnsealLeasePolicy) -> Outcome<()> {
        let now = totp::unix_now();
        let service = VaultService::open(&self.root, unsealed, now, lease)?;
        let namespace = GrantAuthorizationTarget::Namespace {
            scope: DocumentKind::LocalKeyring,
            namespace: PERSONAL_SECRET_NAMESPACE,
        };
        let grants = [
            GrantAuthorization {
                caller: &self.caller,
                target: namespace,
                permissions: &[
                    GrantPermission::List,
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Delete,
                ],
                expires_at: None,
            },
            GrantAuthorization {
                caller: &self.caller,
                target: GrantAuthorizationTarget::PermissionManagement,
                permissions: &[GrantPermission::ManagePermissions],
                expires_at: None,
            },
        ];
        if let Err(error) = service.authorize_batch(&grants, now) {
            let _ = service.seal();
            return Err(error.into());
        }
        *self.session.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(service));
        Ok(())
    }

    pub(crate) fn seal(&self) {
        if let Some(service) = self
            .session
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = service.seal();
        }
        self.clear_restore();
        self.clear_import();
        self.clear_codes();
    }

    fn clear_restore(&self) {
        self.restore
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn clear_import(&self) {
        self.import
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn clear_codes(&self) {
        self.codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    fn vault_platform(&self) -> VaultPlatform {
        match self.platform {
            Platform::Android => VaultPlatform::Android,
            Platform::Ios => VaultPlatform::Ios,
        }
    }

    fn request(&self, action: VaultAction) -> Outcome<VaultResponseBody> {
        let service = self.require_live()?;
        let response = service.handle(&self.caller, VaultRequest::new(action)?, totp::unix_now());
        response.result.map_err(|error| {
            let code = match error.code {
                VaultResponseErrorCode::Sealed => {
                    drop(self.live());
                    ErrorCode::Sealed
                }
                VaultResponseErrorCode::Conflict => ErrorCode::Conflict,
                _ => ErrorCode::Failed,
            };
            Failure::new(code, error.message)
        })
    }

    fn items(&self) -> Outcome<Vec<Summary>> {
        let mut entries = Vec::new();
        let mut cursor = None;
        loop {
            let VaultResponseBody::VaultEntries {
                entries: page,
                next_cursor,
            } = self.request(VaultAction::ListVaultEntries {
                cursor: cursor.clone(),
                limit: MAX_LIST_PAGE_SIZE,
            })?
            else {
                return Err(unexpected());
            };
            entries.extend(page);
            if next_cursor.is_none() || next_cursor == cursor {
                break;
            }
            cursor = next_cursor;
        }
        Ok(items::summaries(entries))
    }

    fn read(&self, id: &str) -> Outcome<(PersonalSecret, [u8; 32])> {
        let VaultResponseBody::Secret { value } = self.request(VaultAction::Get {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: WireSecretAddress::new(id, None),
        })?
        else {
            return Err(unexpected());
        };
        let value = value.ok_or_else(|| Failure::new(ErrorCode::NotFound, "the item is gone"))?;
        let item = PersonalSecret::decode_current(value.expose())
            .map_err(|error| Failure::new(ErrorCode::Failed, error.to_string()))?;
        Ok((item, Sha256::digest(value.expose()).into()))
    }

    fn write(&self, item: &PersonalSecret, expected: Option<&[u8; 32]>) -> Outcome<String> {
        let encoded = item
            .encode()
            .map_err(|error| Failure::new(ErrorCode::Invalid, error.to_string()))?;
        let version: [u8; 32] = Sha256::digest(&encoded).into();
        self.mutate(
            &item.id,
            expected,
            VaultMutation::Put {
                address: WireSecretAddress::new(item.id.clone(), None),
                value: WireSecret::new(encoded.to_vec())?,
                evict_at: None,
            },
        )?;
        Ok(hex::encode(version))
    }

    fn mutate(
        &self,
        id: &str,
        expected: Option<&[u8; 32]>,
        mutation: VaultMutation,
    ) -> Outcome<()> {
        self.codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_if(|(cached, _)| cached == id);
        match self.request(VaultAction::Mutate {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            mutations: vec![
                VaultMutation::Check {
                    address: WireSecretAddress::new(id, None),
                    expected_sha256: expected.copied(),
                },
                mutation,
            ],
        }) {
            Ok(VaultResponseBody::Mutated) => Ok(()),
            Ok(_) => Err(unexpected()),
            Err(failure) if failure.code == ErrorCode::Conflict => Err(Failure::new(
                ErrorCode::Changed,
                "the item changed since it was opened",
            )),
            Err(failure) => Err(failure),
        }
    }

    fn save(&self, draft: &Draft, version: Option<&str>) -> Outcome<Response> {
        let expected = version.map(parse_version).transpose()?;
        let current = match expected {
            Some(expected) => {
                let (item, version) = self.read(&draft.id)?;
                if version != expected {
                    return Err(Failure::new(
                        ErrorCode::Changed,
                        "the item changed since it was opened",
                    ));
                }
                Some(item)
            }
            None => None,
        };
        let item = items::apply(draft, current)?;
        let version = self.write(&item, expected.as_ref())?;
        Ok(Response::Saved {
            id: item.id.clone(),
            version,
        })
    }

    fn delete(&self, id: &str, version: &str) -> Outcome<Response> {
        let expected = parse_version(version)?;
        let (item, current) = self.read(id)?;
        if current != expected {
            return Err(Failure::new(
                ErrorCode::Changed,
                "the item changed since it was opened",
            ));
        }
        self.mutate(
            id,
            Some(&expected),
            VaultMutation::Delete {
                address: WireSecretAddress::new(id, None),
            },
        )?;
        *self.restore.lock().unwrap_or_else(PoisonError::into_inner) = Some(item);
        Ok(Response::Deleted)
    }

    fn restore(&self) -> Outcome<Response> {
        let item = self
            .restore
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| Failure::new(ErrorCode::NothingToRestore, "nothing to restore"))?;
        let version = self.write(&item, None)?;
        Ok(Response::Saved {
            id: item.id.clone(),
            version,
        })
    }
}

fn unexpected() -> Failure {
    Failure::new(
        ErrorCode::Failed,
        "the vault returned an unexpected response",
    )
}

fn parse_version(version: &str) -> Outcome<[u8; 32]> {
    let mut bytes = [0; 32];
    hex::decode_to_slice(version, &mut bytes)
        .map_err(|_| Failure::new(ErrorCode::Invalid, "the item version is malformed"))?;
    Ok(bytes)
}

fn password_for(required: bool, password: Option<Secret>) -> Outcome<Option<Zeroizing<String>>> {
    match (required, password) {
        (true, Some(password)) if !password.0.is_empty() => Ok(Some(password.0)),
        (true, _) => Err(Failure::new(
            ErrorCode::PasswordRequired,
            "enter the vault password",
        )),
        (false, _) => Ok(None),
    }
}

fn lease_policy(lease: Lease) -> Outcome<UnsealLeasePolicy> {
    if lease.idle_seconds == 0 || lease.idle_seconds > lease.maximum_seconds {
        return Err(Failure::new(
            ErrorCode::Invalid,
            "the lock timeouts are invalid",
        ));
    }
    Ok(UnsealLeasePolicy {
        idle_timeout: Duration::from_secs(lease.idle_seconds),
        maximum_lifetime: Duration::from_secs(lease.maximum_seconds),
    })
}

fn core_factor(factor: Factor) -> UnlockFactorKind {
    match factor {
        Factor::Password => UnlockFactorKind::Password,
        Factor::Biometric => UnlockFactorKind::Biometric,
    }
}

fn factor(factor: UnlockFactorKind) -> Option<Factor> {
    match factor {
        UnlockFactorKind::Password => Some(Factor::Password),
        UnlockFactorKind::Biometric => Some(Factor::Biometric),
        _ => None,
    }
}

fn strength(strength: generator::Strength) -> Strength {
    match strength {
        generator::Strength::Weak => Strength::Weak,
        generator::Strength::Good => Strength::Good,
        generator::Strength::Strong => Strength::Strong,
    }
}

fn rate(password: &str) -> Response {
    Response::Rating {
        score: factorseal::security::password_score(password),
        strength: strength(generator::Strength::of(password)),
        acceptable: factorseal::security::validate_new_password(password.as_bytes()).is_ok(),
    }
}

fn generate(options: GeneratorOptions) -> Outcome<Response> {
    let options = generator::Options {
        style: match options.style {
            GeneratorStyle::Random => generator::Style::Random,
            GeneratorStyle::Words => generator::Style::Words,
        },
        length: options.length,
        words: options.words,
        digits: options.digits,
        symbols: options.symbols,
    };
    if !options.is_valid() {
        return Err(Failure::new(
            ErrorCode::Invalid,
            "the generator options are out of range",
        ));
    }
    let password = generator::generate(options)
        .map_err(|error| Failure::new(ErrorCode::Failed, error.to_string()))?;
    Ok(Response::Generated {
        password: Revealed(password),
        strength: strength(options.strength()),
    })
}

fn setup_key(value: &str, same_as: Option<&Secret>) -> Response {
    let origin = totp::origin(value);
    Response::SetupKey {
        value: totp::stored(value)
            .filter(|stored| !stored.is_empty())
            .map(Revealed),
        issuer: origin.issuer,
        account: origin.account,
        same: same_as.is_some_and(|other| totp::same_key(value, &other.0)),
    }
}

fn generators(item: &PersonalSecret) -> Vec<Generator> {
    item.sections
        .iter()
        .flat_map(|section| {
            section
                .fields
                .iter()
                .filter(|field| field.field_type == factorseal::personal::PersonalFieldType::Totp)
                .filter_map(move |field| {
                    let value = field.text()?;
                    Some(Generator {
                        section: section.id.clone(),
                        field: field.id.clone(),
                        totp: totp::Totp::parse(value)?,
                        origin: totp::origin(value),
                    })
                })
        })
        .collect()
}

fn codes(generators: &[Generator], now: u64) -> Vec<Code> {
    generators
        .iter()
        .map(|generator| Code {
            section: generator.section.clone(),
            field: generator.field.clone(),
            value: Revealed(generator.totp.code(now)),
            period: generator.totp.period(),
            remaining: generator.totp.remaining(now),
            issuer: generator.origin.issuer.clone(),
            account: generator.origin.account.clone(),
        })
        .collect()
}
