//! Command implementations for vault lifecycle, project secrets, and grants.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, IsTerminal as _, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use directories::ProjectDirs;
use factorseal::{
    DocumentKind, GrantPermission, MAX_LIST_PAGE_SIZE, MAX_PERMISSION_WAIT_MS, Permission,
    PermissionChange, PermissionState, SecretSpecAddress, UnlockCredentials, UnlockFactorKind,
    UnlockGroup, UnlockPolicy, UnsealLeasePolicy, UnsealedVault, Vault, VaultAction, VaultClient,
    VaultError, VaultMetadata, VaultRequest, VaultResponseBody, VaultResponseErrorCode,
    VaultService,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::cli::PermissionCommand;
use super::factor::{FactorSource, read_factor};
use super::platform::{caller_identity_for_executable, native_client, serve_vault};
use super::{CLI_CONTROL_NAMESPACE, CliError, MAX_PROJECT_VALUE_BYTES, PROJECT_PERMISSIONS};

#[derive(Serialize)]
struct Status<'a> {
    path: String,
    vault_id: String,
    device_key_id: String,
    public_signing_key: String,
    actor_id: String,
    platform: &'a str,
    hardware_backend: &'a str,
    unlock_policy: Vec<String>,
    preferred_unlock_group: String,
    key_epoch: u64,
    created_at: u64,
    state: &'static str,
}

const VAULT_METADATA_FILE: &str = "factorseal.json";
const INITIALIZATION_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(super) fn initialize(
    root: &Path,
    unlock_groups: Vec<UnlockGroup>,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let unlock_groups = init_unlock_groups(unlock_groups)?;
    let policy = UnlockPolicy::new(unlock_groups)?;
    let password = read_password_for_groups(policy.groups(), factor, true)?;
    let unsealed = Vault::prepare_with_unlock_policy(
        root,
        &policy,
        credentials(password.as_ref().map(|value| value.as_slice())),
    )?;
    let device = unsealed.public().clone();
    let initialized = (|| -> Result<(), CliError> {
        let now = unix_time()?;
        let service = VaultService::open(root, unsealed, now, UnsealLeasePolicy::default())?;
        authorize_cli(&service, now)?;
        service.seal()?;
        Vault::complete_initialization(root)?;
        Ok(())
    })();
    if let Err(initialization_error) = initialized {
        return match Vault::discard_initialization(root) {
            Ok(()) => Err(initialization_error),
            Err(cleanup_error) => Err(VaultError::Protection(format!(
                "{initialization_error}; initialization rollback failed: {cleanup_error}"
            ))
            .into()),
        };
    }
    println!(
        "Initialized Factorseal vault {} at {} using {}",
        device.vault_id(),
        root.display(),
        device.hardware_backend()
    );
    Ok(())
}

fn init_unlock_groups(configured: Vec<UnlockGroup>) -> Result<Vec<UnlockGroup>, CliError> {
    if !configured.is_empty() {
        return Ok(configured);
    }

    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    if stdin.is_terminal() && stderr.is_terminal() {
        return read_init_unlock_groups(&mut stdin.lock(), &mut stderr.lock());
    }

    Ok(vec![UnlockGroup::new([UnlockFactorKind::Password])?])
}

pub(super) fn read_init_unlock_groups(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Vec<UnlockGroup>, CliError> {
    writeln!(
        output,
        "Factorseal creates a local secrets vault protected by this device's hardware.\n\
         Choose how you want to unlock it. 'And' requires both factors; 'or' creates\n\
         two alternatives. The vault will be sealed after setup.\n\n\
           1. Password\n\
           2. Biometric approval\n\
           3. Password and biometric approval\n\
           4. Password or biometric approval (password preferred by default)"
    )
    .map_err(|error| CliError::InitPrompt(error.to_string()))?;

    loop {
        write!(output, "Unlock method [1]: ")
            .and_then(|()| output.flush())
            .map_err(|error| CliError::InitPrompt(error.to_string()))?;
        let mut answer = String::new();
        if input
            .read_line(&mut answer)
            .map_err(|error| CliError::InitPrompt(error.to_string()))?
            == 0
        {
            return Err(CliError::InitPrompt("input was closed".to_owned()));
        }

        let password = || UnlockGroup::new([UnlockFactorKind::Password]);
        let biometric = || UnlockGroup::new([UnlockFactorKind::Biometric]);
        let both = || UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Biometric]);
        return match answer.trim() {
            "" | "1" => Ok(vec![password()?]),
            "2" => Ok(vec![biometric()?]),
            "3" => Ok(vec![both()?]),
            "4" => Ok(vec![password()?, biometric()?]),
            _ => {
                writeln!(output, "Enter a number from 1 to 4.")
                    .map_err(|error| CliError::InitPrompt(error.to_string()))?;
                continue;
            }
        };
    }
}

pub(super) fn show_status(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    let device = Vault::inspect(root)?;
    let state = live_state(root, socket, &device);
    let status = Status {
        path: root.display().to_string(),
        vault_id: device.vault_id().to_string(),
        device_key_id: device.device_key_id().to_string(),
        public_signing_key: hex::encode(device.public_signing_key()),
        actor_id: hex::encode(device.actor_id()),
        platform: device.platform(),
        hardware_backend: device.hardware_backend(),
        unlock_policy: device
            .unlock_policy()
            .groups()
            .iter()
            .map(ToString::to_string)
            .collect(),
        preferred_unlock_group: device.preferred_unlock_group().to_string(),
        key_epoch: device.key_epoch(),
        created_at: device.created_at(),
        state,
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

/// Run the hardware sealing self-test and report one line per policy.
///
/// This exists in the shipped binary rather than only in the crate's tests
/// because the machines that can answer it are physical hosts running a
/// release archive, not a CI runner and not a developer checkout.
pub(super) fn hardware_self_test(biometric: bool) -> Result<(), CliError> {
    let mut policies = vec![hardwareseal::AccessPolicy::None];
    if biometric {
        policies.push(hardwareseal::AccessPolicy::Biometric);
    }
    for policy in policies {
        match hardwareseal::self_test(policy) {
            Ok(backend) => println!("{policy:?}: pass, served by {backend:?}"),
            Err(error) => {
                println!("{policy:?}: FAIL");
                return Err(CliError::HardwareSelfTest(error.to_string()));
            }
        }
    }
    Ok(())
}

pub(super) fn seal_vault(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let request = VaultRequest::new(VaultAction::Seal {
        namespace: CLI_CONTROL_NAMESPACE.to_vec(),
    })?;
    let response = client.request(&request)?;
    match response.result {
        Ok(VaultResponseBody::Sealed) => {
            println!("Sealed Factorseal vault");
            Ok(())
        }
        Ok(_) => Err(VaultError::Protocol(
            "vault returned an unexpected response to a seal request".to_owned(),
        )
        .into()),
        Err(error) => Err(CliError::VaultRequest {
            code: error.code,
            message: error.message,
        }),
    }
}

/// Ask the running agent which state this vault is in.
///
/// A `Status` answer is itself the proof of an unsealed vault: the action is
/// served behind the live-state lock, so a sealed vault answers with the
/// `Sealed` code and a vault with no agent cannot be reached at all. Anything
/// else, including an agent serving a different vault, stays `unknown`.
fn live_state(root: &Path, socket: Option<&Path>, device: &VaultMetadata) -> &'static str {
    let Ok(request) = VaultRequest::new(VaultAction::Status) else {
        return "unknown";
    };
    let Ok(client) = native_client(root, socket) else {
        return "unknown";
    };
    match client.request(&request) {
        Ok(response) => match response.result {
            Ok(VaultResponseBody::Status {
                vault_id,
                device_key_id,
                ..
            }) if vault_id == device.vault_id().to_string()
                && device_key_id == device.device_key_id().to_string() =>
            {
                "unsealed"
            }
            Err(error) if error.code == VaultResponseErrorCode::Sealed => "sealed",
            _ => "unknown",
        },
        Err(VaultError::AgentUnreachable(_)) => "sealed",
        Err(_) => "unknown",
    }
}

pub(super) fn set_project_value(
    root: &Path,
    socket: Option<&Path>,
    project: String,
    profile: &str,
    item: String,
    field: Option<String>,
    value_file: Option<&Path>,
) -> Result<(), CliError> {
    let value = read_project_value(value_file)?;
    let client = native_client(root, socket)?;
    let address = project_address(&project, profile, item, field)?;
    expect_response(
        &client,
        VaultAction::PutProject {
            project,
            address,
            value: factorseal::WireSecret::new(value.to_vec()),
        },
        |body| matches!(body, VaultResponseBody::Stored),
    )
}

pub(super) fn get_project_value(
    root: &Path,
    socket: Option<&Path>,
    project: String,
    profile: &str,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let address = project_address(&project, profile, item, field)?;
    let request = VaultRequest::new(VaultAction::GetProject { project, address })?;
    let response = client.request(&request)?;
    let value = match response.result {
        Ok(VaultResponseBody::Secret { value: Some(value) }) => value,
        Ok(VaultResponseBody::Secret { value: None }) => {
            return Err(CliError::ProjectEntryNotFound);
        }
        Ok(_) => {
            return Err(
                VaultError::Protocol("vault returned an unexpected response".to_owned()).into(),
            );
        }
        Err(error) => {
            return Err(CliError::VaultRequest {
                code: error.code,
                message: error.message,
            });
        }
    };
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.expose())
        .and_then(|()| stdout.flush())
        .map_err(|error| CliError::ProjectInput(error.to_string()))
}

pub(super) fn delete_project_value(
    root: &Path,
    socket: Option<&Path>,
    project: String,
    profile: &str,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let address = project_address(&project, profile, item, field)?;
    let request = VaultRequest::new(VaultAction::DeleteProject { project, address })?;
    let response = client.request(&request)?;
    let existed = match response.result {
        Ok(VaultResponseBody::Deleted { existed }) => existed,
        Ok(_) => {
            return Err(
                VaultError::Protocol("vault returned an unexpected response".to_owned()).into(),
            );
        }
        Err(error) => {
            return Err(CliError::VaultRequest {
                code: error.code,
                message: error.message,
            });
        }
    };
    if !existed {
        return Err(CliError::ProjectEntryNotFound);
    }
    Ok(())
}

pub(super) fn list_projects(
    root: &Path,
    socket: Option<&Path>,
    json: bool,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let projects = fetch_projects(&client)?;
    write_metadata(&mut std::io::stdout().lock(), &projects, json)
}

pub(super) fn list_project_addresses(
    root: &Path,
    socket: Option<&Path>,
    project: &str,
    json: bool,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let addresses = fetch_project_addresses(&client, project)?;
    write_metadata(&mut std::io::stdout().lock(), &addresses, json)
}

pub(super) fn fetch_projects(client: &dyn VaultClient) -> Result<Vec<String>, CliError> {
    let mut projects = Vec::new();
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();
    loop {
        let request = VaultRequest::new(VaultAction::ListProjects {
            cursor: cursor.clone(),
            limit: MAX_LIST_PAGE_SIZE,
        })?;
        let response = client.request(&request)?;
        let (page, next_cursor) = match response.result {
            Ok(VaultResponseBody::Projects {
                projects,
                next_cursor,
            }) => (projects, next_cursor),
            Ok(_) => {
                return Err(VaultError::Protocol(
                    "vault returned an unexpected project-list response".to_owned(),
                )
                .into());
            }
            Err(error) => return Err(vault_request_error(error)),
        };
        if page.len() > usize::from(MAX_LIST_PAGE_SIZE) {
            return Err(VaultError::Protocol("project-list page is too large".to_owned()).into());
        }
        let page_is_empty = page.is_empty();
        for project in page {
            SecretSpecAddress::convention(&project, "default", "validation")?;
            if projects.last().is_some_and(|previous| previous >= &project) {
                return Err(VaultError::Protocol(
                    "project-list response is not strictly ordered".to_owned(),
                )
                .into());
            }
            projects.push(project);
        }
        cursor = advance_cursor(
            cursor.as_deref(),
            next_cursor,
            &mut seen_cursors,
            page_is_empty,
        )?;
        if cursor.is_none() {
            return Ok(projects);
        }
    }
}

pub(super) fn fetch_project_addresses(
    client: &dyn VaultClient,
    project: &str,
) -> Result<Vec<SecretSpecAddress>, CliError> {
    let mut addresses = Vec::new();
    let mut seen_addresses = HashSet::new();
    let mut cursor = None;
    let mut seen_cursors = HashSet::new();
    loop {
        let request = VaultRequest::new(VaultAction::ListProjectAddresses {
            project: project.to_owned(),
            cursor: cursor.clone(),
            limit: MAX_LIST_PAGE_SIZE,
        })?;
        let response = client.request(&request)?;
        let (page, next_cursor) = match response.result {
            Ok(VaultResponseBody::ProjectAddresses {
                addresses,
                next_cursor,
            }) => (addresses, next_cursor),
            Ok(_) => {
                return Err(VaultError::Protocol(
                    "vault returned an unexpected project-address response".to_owned(),
                )
                .into());
            }
            Err(error) => return Err(vault_request_error(error)),
        };
        if page.len() > usize::from(MAX_LIST_PAGE_SIZE) {
            return Err(
                VaultError::Protocol("project-address page is too large".to_owned()).into(),
            );
        }
        let page_is_empty = page.is_empty();
        for address in page {
            address.validate()?;
            if address
                .project()
                .is_some_and(|address_project| address_project != project)
            {
                return Err(VaultError::Protocol(
                    "project-address response contains another project's address".to_owned(),
                )
                .into());
            }
            if !seen_addresses.insert(address.clone()) {
                return Err(VaultError::Protocol(
                    "project-address response contains a duplicate".to_owned(),
                )
                .into());
            }
            addresses.push(address);
        }
        cursor = advance_cursor(
            cursor.as_deref(),
            next_cursor,
            &mut seen_cursors,
            page_is_empty,
        )?;
        if cursor.is_none() {
            return Ok(addresses);
        }
    }
}

fn advance_cursor(
    current: Option<&str>,
    next: Option<String>,
    seen: &mut HashSet<String>,
    page_is_empty: bool,
) -> Result<Option<String>, CliError> {
    let Some(next) = next else {
        return Ok(None);
    };
    if page_is_empty || current == Some(next.as_str()) || !seen.insert(next.clone()) {
        return Err(VaultError::Protocol("vault returned a stalled list cursor".to_owned()).into());
    }
    Ok(Some(next))
}

pub(super) fn write_metadata<T: Serialize>(
    output: &mut impl Write,
    values: &[T],
    json: bool,
) -> Result<(), CliError> {
    if json {
        serde_json::to_writer(&mut *output, values)?;
        writeln!(output).map_err(|error| CliError::ProjectOutput(error.to_string()))?;
        return Ok(());
    }
    for value in values {
        serde_json::to_writer(&mut *output, value)?;
        writeln!(output).map_err(|error| CliError::ProjectOutput(error.to_string()))?;
    }
    Ok(())
}

fn vault_request_error(error: factorseal::VaultResponseError) -> CliError {
    CliError::VaultRequest {
        code: error.code,
        message: error.message,
    }
}

fn project_address(
    project: &str,
    profile: &str,
    item: String,
    field: Option<String>,
) -> Result<SecretSpecAddress, CliError> {
    if let Some(field) = field {
        return SecretSpecAddress::native(factorseal::SecretSpecCoordinates {
            item,
            field: Some(field),
            vault: None,
            section: None,
            version: None,
        })
        .map_err(Into::into);
    }
    SecretSpecAddress::convention(project, profile, item).map_err(Into::into)
}

fn expect_response(
    client: &dyn VaultClient,
    action: VaultAction,
    accepted: impl FnOnce(&VaultResponseBody) -> bool,
) -> Result<(), CliError> {
    let request = VaultRequest::new(action)?;
    let response = client.request(&request)?;
    match response.result {
        Ok(body) if accepted(&body) => Ok(()),
        Ok(_) => {
            Err(VaultError::Protocol("vault returned an unexpected response".to_owned()).into())
        }
        Err(error) => Err(CliError::VaultRequest {
            code: error.code,
            message: error.message,
        }),
    }
}

pub(super) fn destroy_vault(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    confirmed: bool,
    requested_group: Option<&UnlockGroup>,
) -> Result<(), CliError> {
    if !confirmed {
        return Err(CliError::DestroyConfirmationRequired);
    }
    let device = Vault::inspect(root)?;
    match live_state(root, socket, &device) {
        "sealed" => {}
        "unsealed" => return Err(CliError::VaultIsLive),
        _ => return Err(CliError::VaultStateUnknown),
    }
    let group = select_unlock_group(&device, requested_group)?;
    let password = read_password_for_groups(std::slice::from_ref(&group), factor, false)?;
    Vault::destroy_with_unlock_group(
        root,
        &group,
        credentials(password.as_ref().map(|value| value.as_slice())),
    )?;
    println!("Destroyed Factorseal vault at {}", root.display());
    Ok(())
}

pub(super) fn read_project_value(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let value = if let Some(path) = path {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| CliError::ProjectInput(format!("{}: {error}", path.display())))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_PROJECT_VALUE_BYTES {
            return Err(CliError::ProjectInput(format!(
                "{} must be a regular file no larger than 64 KiB",
                path.display()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| CliError::ProjectInput(format!("{}: {error}", path.display())))?;
        read_bounded(file, MAX_PROJECT_VALUE_BYTES)
            .map_err(|error| CliError::ProjectInput(format!("{}: {error}", path.display())))?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Project secret value: ")
            .map(|secret| Zeroizing::new(secret.into_bytes()))
            .map_err(|error| CliError::ProjectInput(error.to_string()))?
    } else {
        read_bounded(std::io::stdin().lock(), MAX_PROJECT_VALUE_BYTES)
            .map_err(|error| CliError::ProjectInput(error.to_string()))?
    };
    if value.is_empty() {
        return Err(CliError::ProjectInput(
            "the project value must not be empty".to_owned(),
        ));
    }
    if value.len() as u64 > MAX_PROJECT_VALUE_BYTES {
        return Err(CliError::ProjectInput(
            "the project value must not exceed 64 KiB".to_owned(),
        ));
    }
    Ok(value)
}

pub(super) fn read_bounded(reader: impl Read, maximum: u64) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::new());
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut value)?;
    Ok(value)
}

pub(super) fn run_agent(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    policy: UnsealLeasePolicy,
    requested_group: Option<&UnlockGroup>,
) -> Result<(), CliError> {
    wait_for_initialization(root, INITIALIZATION_POLL_INTERVAL);
    let device = Vault::inspect(root)?;
    let unsealed = unseal_selected(root, &device, requested_group, factor)?;
    let service = Arc::new(VaultService::open(root, unsealed, unix_time()?, policy)?);
    serve_vault(&device, &service, root, socket)
}

pub(super) fn wait_for_initialization(root: &Path, poll_interval: Duration) {
    let metadata = root.join(VAULT_METADATA_FILE);
    if metadata.is_file() {
        return;
    }

    eprintln!(
        "factorseal: vault is not initialized at `{}`; run `factorseal init` to create it; waiting for initialization",
        root.display()
    );
    while !metadata.is_file() {
        std::thread::sleep(poll_interval);
    }
}

pub(super) fn grant_cli(
    root: &Path,
    factor: FactorSource<'_>,
    requested_group: Option<&UnlockGroup>,
) -> Result<(), CliError> {
    let now = unix_time()?;
    let device = Vault::inspect(root)?;
    let unsealed = unseal_selected(root, &device, requested_group, factor)?;
    let service = VaultService::open(root, unsealed, now, UnsealLeasePolicy::default())?;
    authorize_cli(&service, now)?;
    service.seal()?;
    println!("Authorized this Factorseal CLI for durable project secrets");
    Ok(())
}

fn authorize_cli(service: &VaultService, now: u64) -> Result<(), CliError> {
    let executable =
        std::env::current_exe().map_err(|error| CliError::CurrentExecutable(error.to_string()))?;
    let caller = caller_identity_for_executable(&executable)?;
    service.authorize_document_kind(
        &caller,
        DocumentKind::SecretSpecProject,
        PROJECT_PERMISSIONS,
        None,
        now,
    )?;
    service.authorize_namespace(
        &caller,
        CLI_CONTROL_NAMESPACE,
        [GrantPermission::Seal],
        None,
        now,
    )?;
    service.authorize_permission_manager(&caller, now)?;
    Ok(())
}

pub(super) fn manage_permissions(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    action: &PermissionCommand,
) -> Result<(), CliError> {
    match action {
        PermissionCommand::List { json } => list_permissions(root, socket, false, *json),
        PermissionCommand::Watch { prompt: true, .. } => prompt_permissions(root, socket, factor),
        PermissionCommand::Watch { json, .. } => list_permissions(root, socket, true, *json),
        PermissionCommand::Approve { id } => approve_with_prompted_group(root, socket, factor, id),
        PermissionCommand::Deny { id } => change_permission(
            root,
            socket,
            VaultAction::DenyPermission { id: id.clone() },
            PermissionChange::Denied,
        ),
        PermissionCommand::Revoke { id } => change_permission(
            root,
            socket,
            VaultAction::RevokePermission { id: id.clone() },
            PermissionChange::Revoked,
        ),
    }
}

fn permissions(
    client: &dyn VaultClient,
    after_revision: Option<u64>,
) -> Result<(u64, Vec<Permission>), CliError> {
    let action = after_revision.map_or(VaultAction::ListPermissions, |after_revision| {
        VaultAction::WaitPermissions {
            after_revision,
            timeout_ms: MAX_PERMISSION_WAIT_MS,
        }
    });
    let request = VaultRequest::new(action)?;
    let response = client.request(&request)?;
    match response.result {
        Ok(VaultResponseBody::Permissions {
            revision,
            permissions,
        }) => Ok((revision, permissions)),
        Ok(_) => Err(VaultError::Protocol(
            "vault returned an unexpected permissions response".to_owned(),
        )
        .into()),
        Err(error) => Err(CliError::VaultRequest {
            code: error.code,
            message: error.message,
        }),
    }
}

fn list_permissions(
    root: &Path,
    socket: Option<&Path>,
    watch: bool,
    json: bool,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let mut last_revision = None;
    loop {
        let (revision, current) = permissions(&client, last_revision)?;
        if last_revision != Some(revision) {
            print_permissions(&current, json)?;
            last_revision = Some(revision);
        }
        if !watch {
            return Ok(());
        }
    }
}

fn print_permissions(current: &[Permission], json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string(current)?);
        return Ok(());
    }
    if current.is_empty() {
        println!("No permissions");
        return Ok(());
    }
    for permission in current {
        write_permission(&mut std::io::stdout().lock(), permission)?;
    }
    Ok(())
}

fn write_permission(output: &mut impl Write, approval: &Permission) -> Result<(), CliError> {
    let project = approval.application.project.as_deref().unwrap_or("unknown");
    let profile = approval.application.profile.as_deref().unwrap_or("default");
    let reason = approval
        .application
        .reason
        .as_deref()
        .unwrap_or("unspecified");
    let base_dir = approval
        .application
        .base_dir
        .as_deref()
        .unwrap_or("unknown");
    let signer = approval
        .principal
        .signer_id
        .as_deref()
        .unwrap_or("unsigned");
    let state = match approval.state {
        PermissionState::Pending {
            created_at,
            expires_at,
            ..
        } => format!("pending  created: {created_at}  expires: {expires_at}"),
        PermissionState::Granted {
            granted_at,
            expires_at,
        } => format!(
            "granted  granted: {granted_at}  expires: {}",
            expires_at.map_or_else(|| "never".to_owned(), |value| value.to_string())
        ),
    };
    writeln!(output, "{}  {:?}  {state}", approval.id, approval.operation)
        .and_then(|()| {
            writeln!(
                output,
                "  trusted: {:?} {}  user: {}  signer: {signer}",
                approval.principal.platform,
                approval.principal.application_id,
                approval.principal.user_id,
            )
        })
        .and_then(|()| {
            writeln!(
                output,
                "  executable digest: {}",
                hex::encode(approval.principal.executable_digest)
            )
        })
        .and_then(|()| {
            writeln!(
                output,
                "  declared: {project}/{profile}  base directory: {base_dir}"
            )
        })
        .and_then(|()| writeln!(output, "  reason: {reason}"))
        .and_then(|()| {
            if let Some(duration) = approval.application.requested_permission_duration_seconds {
                writeln!(
                    output,
                    "  requested permission duration: {}",
                    format_grant_duration(duration)
                )
            } else {
                Ok(())
            }
        })
        .map_err(|error| CliError::ApprovalPrompt(error.to_string()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApprovalDecision {
    Approve,
    Deny,
    Ignore,
}

const DEFAULT_GRANT_DURATION_SECONDS: u64 = 60 * 60;

fn format_grant_duration(seconds: u64) -> String {
    for (unit, size) in [
        ("w", 7 * 24 * 60 * 60),
        ("d", 24 * 60 * 60),
        ("h", 60 * 60),
        ("m", 60),
    ] {
        if seconds.is_multiple_of(size) {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParsedGrantDuration {
    Forever,
    Seconds(u64),
}

pub(super) fn parse_grant_duration(value: &str) -> Option<ParsedGrantDuration> {
    let value = value.trim().to_ascii_lowercase();
    if value == "forever" {
        return Some(ParsedGrantDuration::Forever);
    }
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        Some(b'w') => (&value[..value.len() - 1], 7 * 24 * 60 * 60),
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .and_then(|number| number.checked_mul(multiplier))
        .map(ParsedGrantDuration::Seconds)
}

pub(super) fn read_grant_duration(
    input: &mut impl BufRead,
    output: &mut impl Write,
    requested_default: Option<u64>,
) -> Result<Option<u64>, CliError> {
    let default = requested_default.unwrap_or(DEFAULT_GRANT_DURATION_SECONDS);
    loop {
        write!(
            output,
            "Permission duration [{}]: ",
            format_grant_duration(default)
        )
        .and_then(|()| output.flush())
        .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
        let mut answer = String::new();
        if input
            .read_line(&mut answer)
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?
            == 0
        {
            return Err(CliError::ApprovalPrompt("input was closed".to_owned()));
        }
        if answer.trim().is_empty() {
            return Ok(Some(default));
        }
        if let Some(duration) = parse_grant_duration(&answer) {
            return Ok(match duration {
                ParsedGrantDuration::Forever => None,
                ParsedGrantDuration::Seconds(seconds) => Some(seconds),
            });
        }
        writeln!(output, "Enter a duration such as 30m, 8h, 7d, or forever.")
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
    }
}

pub(super) fn require_prompt_terminal(input: bool, output: bool) -> Result<(), CliError> {
    if input && output {
        Ok(())
    } else {
        Err(CliError::ApprovalPromptRequiresTerminal)
    }
}

pub(super) fn read_approval_decision(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<ApprovalDecision, CliError> {
    loop {
        write!(output, "Action [a]pprove/[d]eny/[i]gnore: ")
            .and_then(|()| output.flush())
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
        let mut answer = String::new();
        if input
            .read_line(&mut answer)
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?
            == 0
        {
            return Err(CliError::ApprovalPrompt("input was closed".to_owned()));
        }
        match answer.trim().to_ascii_lowercase().as_str() {
            "a" | "approve" => return Ok(ApprovalDecision::Approve),
            "d" | "deny" => return Ok(ApprovalDecision::Deny),
            "i" | "ignore" => return Ok(ApprovalDecision::Ignore),
            _ => writeln!(output, "Enter approve, deny, or ignore.")
                .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?,
        }
    }
}

pub(super) fn read_unlock_group_choice(
    groups: &[UnlockGroup],
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<UnlockGroup, CliError> {
    if groups.is_empty() {
        return Err(VaultError::Protocol("vault has no unlock groups".to_owned()).into());
    }
    writeln!(output, "Choose how to authorize this approval:")
        .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
    for (index, group) in groups.iter().enumerate() {
        writeln!(output, "  {}. {group}", index + 1)
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
    }
    loop {
        write!(output, "Factor [1-{}]: ", groups.len())
            .and_then(|()| output.flush())
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
        let mut answer = String::new();
        if input
            .read_line(&mut answer)
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?
            == 0
        {
            return Err(CliError::ApprovalPrompt("input was closed".to_owned()));
        }
        if let Ok(index) = answer.trim().parse::<usize>()
            && let Some(group) = index.checked_sub(1).and_then(|index| groups.get(index))
        {
            return Ok(group.clone());
        }
        writeln!(output, "Enter a number from 1 to {}.", groups.len())
            .map_err(|error| CliError::ApprovalPrompt(error.to_string()))?;
    }
}

fn prompt_unlock_group(
    root: &Path,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<UnlockGroup, CliError> {
    let device = Vault::inspect(root)?;
    match device.unlock_policy().groups() {
        [group] => Ok(group.clone()),
        groups => read_unlock_group_choice(groups, input, output),
    }
}

fn prompt_permissions(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    require_prompt_terminal(stdin.is_terminal(), stderr.is_terminal())?;
    let client = native_client(root, socket)?;
    let mut last_revision = None;
    let mut handled = HashSet::new();
    loop {
        let (revision, pending) = permissions(&client, last_revision)?;
        if last_revision != Some(revision) {
            handled.retain(|id| pending.iter().any(|approval| &approval.id == id));
            for approval in &pending {
                if !matches!(approval.state, PermissionState::Pending { .. }) {
                    continue;
                }
                if handled.contains(&approval.id) {
                    continue;
                }
                let decision = {
                    let mut input = stdin.lock();
                    let mut output = stderr.lock();
                    write_permission(&mut output, approval)?;
                    read_approval_decision(&mut input, &mut output)?
                };
                handled.insert(approval.id.clone());
                match decision {
                    ApprovalDecision::Approve => {
                        let (grant_duration_seconds, group) = {
                            let mut input = stdin.lock();
                            let mut output = stderr.lock();
                            let duration = read_grant_duration(
                                &mut input,
                                &mut output,
                                approval.application.requested_permission_duration_seconds,
                            )?;
                            let group = prompt_unlock_group(root, &mut input, &mut output)?;
                            (duration, group)
                        };
                        approve(
                            root,
                            socket,
                            factor,
                            &approval.id,
                            grant_duration_seconds,
                            Some(&group),
                        )?;
                    }
                    ApprovalDecision::Deny => change_permission(
                        root,
                        socket,
                        VaultAction::DenyPermission {
                            id: approval.id.clone(),
                        },
                        PermissionChange::Denied,
                    )?,
                    ApprovalDecision::Ignore => {}
                }
            }
            last_revision = Some(revision);
        }
    }
}

fn approve_with_prompted_group(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    id: &str,
) -> Result<(), CliError> {
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    require_prompt_terminal(stdin.is_terminal(), stderr.is_terminal())?;
    let client = native_client(root, socket)?;
    let (_, pending) = permissions(&client, None)?;
    let approval = pending
        .iter()
        .find(|approval| approval.id == id)
        .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
    let device = Vault::inspect(root)?;
    let (grant_duration_seconds, group) = {
        let mut input = stdin.lock();
        let mut output = stderr.lock();
        let duration = read_grant_duration(
            &mut input,
            &mut output,
            approval.application.requested_permission_duration_seconds,
        )?;
        let group = match device.unlock_policy().groups() {
            [group] => group.clone(),
            groups => read_unlock_group_choice(groups, &mut input, &mut output)?,
        };
        (duration, group)
    };
    approve(
        root,
        socket,
        factor,
        id,
        grant_duration_seconds,
        Some(&group),
    )
}

fn approve(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    id: &str,
    grant_duration_seconds: Option<u64>,
    requested_group: Option<&UnlockGroup>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let (_, pending) = permissions(&client, None)?;
    let approval = pending
        .iter()
        .find(|approval| approval.id == id)
        .ok_or_else(|| VaultError::Protocol("permission is missing or expired".to_owned()))?;
    let device = Vault::inspect(root)?;
    let unsealed = unseal_selected(root, &device, requested_group, factor)?;
    let PermissionState::Pending { challenge, .. } = &approval.state else {
        return Err(VaultError::Protocol("permission is already granted".to_owned()).into());
    };
    let signature =
        unsealed.sign_permission_challenge(&approval.id, challenge, grant_duration_seconds)?;
    drop(unsealed);
    change_permission(
        root,
        socket,
        VaultAction::ApprovePermission {
            id: id.to_owned(),
            signature,
            duration_seconds: grant_duration_seconds,
        },
        PermissionChange::Granted,
    )
}

fn change_permission(
    root: &Path,
    socket: Option<&Path>,
    action: VaultAction,
    expected: PermissionChange,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let request = VaultRequest::new(action)?;
    let response = client.request(&request)?;
    match response.result {
        Ok(VaultResponseBody::PermissionChanged { status }) if status == expected => {
            println!(
                "{} permission",
                match status {
                    PermissionChange::Granted => "Granted",
                    PermissionChange::Denied => "Denied",
                    PermissionChange::Revoked => "Revoked",
                }
            );
            Ok(())
        }
        Ok(_) => Err(VaultError::Protocol(
            "vault returned an unexpected permission response".to_owned(),
        )
        .into()),
        Err(error) => Err(CliError::VaultRequest {
            code: error.code,
            message: error.message,
        }),
    }
}

fn unseal_selected(
    root: &Path,
    device: &VaultMetadata,
    requested_group: Option<&UnlockGroup>,
    factor: FactorSource<'_>,
) -> Result<UnsealedVault, CliError> {
    let group = select_unlock_group(device, requested_group)?;
    let password = read_password_for_groups(std::slice::from_ref(&group), factor, false)?;
    Vault::unseal_with_unlock_group(
        root,
        &group,
        credentials(password.as_ref().map(|value| value.as_slice())),
    )
    .map_err(Into::into)
}

fn select_unlock_group(
    device: &VaultMetadata,
    requested: Option<&UnlockGroup>,
) -> Result<UnlockGroup, CliError> {
    resolve_unlock_group(
        device.unlock_policy().groups(),
        device.preferred_unlock_group(),
        requested,
    )
}

pub(super) fn resolve_unlock_group(
    groups: &[UnlockGroup],
    preferred: &UnlockGroup,
    requested: Option<&UnlockGroup>,
) -> Result<UnlockGroup, CliError> {
    if let Some(requested) = requested {
        return groups
            .iter()
            .find(|group| *group == requested)
            .cloned()
            .ok_or_else(|| CliError::UnlockGroupNotConfigured(requested.to_string()));
    }
    Ok(preferred.clone())
}

pub(super) fn read_password_for_groups(
    groups: &[UnlockGroup],
    factor: FactorSource<'_>,
    confirm: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    groups
        .iter()
        .any(|group| group.requires(UnlockFactorKind::Password))
        .then(|| read_factor(factor, confirm))
        .transpose()
}

fn credentials(password: Option<&[u8]>) -> UnlockCredentials<'_> {
    password.map_or_else(UnlockCredentials::none, UnlockCredentials::with_password)
}

pub(super) fn resolve_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_owned());
    }
    let directories =
        ProjectDirs::from("dev", "Factorseal", "Factorseal").ok_or(CliError::NoDefaultRoot)?;
    Ok(directories.data_local_dir().to_owned())
}

fn unix_time() -> Result<u64, VaultError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Protocol(error.to_string()))
}
