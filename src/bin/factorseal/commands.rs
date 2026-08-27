//! Command implementations for vault lifecycle, keyring, and grant operations.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, IsTerminal as _, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use directories::ProjectDirs;
use factorseal::{
    Keyring, PendingApproval, UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy,
    UnsealLeasePolicy, UnsealedVault, Vault, VaultAction, VaultClient, VaultError, VaultMetadata,
    VaultRequest, VaultResponseBody, VaultResponseErrorCode, VaultService, WireSecretAddress,
};
use serde::Serialize;
use zeroize::Zeroizing;

use super::cli::ApprovalCommand;
use super::factor::{FactorSource, read_factor};
use super::platform::{caller_identity_for_executable, native_client, serve_vault};
use super::{CliError, KEYRING_NAMESPACE, KEYRING_PERMISSIONS, MAX_KEYRING_VALUE_BYTES};

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
    key_epoch: u64,
    created_at: u64,
    state: &'static str,
}

pub(super) fn initialize(
    root: &Path,
    unlock_groups: Vec<UnlockGroup>,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let policy = UnlockPolicy::new(unlock_groups)?;
    let password = read_password_for_groups(policy.groups(), factor, true)?;
    let unsealed = Vault::create_with_unlock_policy(
        root,
        &policy,
        credentials(password.as_ref().map(|value| value.as_slice())),
    )?;
    let device = unsealed.public().clone();
    // The vault metadata is already on disk, and `create` refuses to run again while it
    // is there. Undo what this command wrote so `init` can simply be retried
    // rather than leaving a root nothing can finish or open.
    let now = unix_time()?;
    let service = match VaultService::open(root, unsealed, now, UnsealLeasePolicy::default()) {
        Ok(service) => service,
        Err(open_error) => {
            return match Vault::discard_initialization(root) {
                Ok(()) => Err(open_error.into()),
                Err(cleanup_error) => Err(VaultError::Protection(format!(
                    "{open_error}; initialization rollback failed: {cleanup_error}"
                ))
                .into()),
            };
        }
    };
    authorize_cli(&service, now)?;
    service.seal()?;
    println!(
        "Initialized Factorseal vault {} at {} using {}",
        device.vault_id(),
        root.display(),
        device.hardware_backend()
    );
    Ok(())
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
        key_epoch: device.key_epoch(),
        created_at: device.created_at(),
        state,
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

pub(super) fn seal_vault(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let request = VaultRequest::new(VaultAction::Seal {
        namespace: KEYRING_NAMESPACE.to_vec(),
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

pub(super) fn set_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
    value_file: Option<&Path>,
) -> Result<(), CliError> {
    let value = read_keyring_value(value_file)?;
    let client = native_client(root, socket)?;
    client.set(
        KEYRING_NAMESPACE,
        &WireSecretAddress::new(item, field),
        &value,
    )?;
    Ok(())
}

pub(super) fn get_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let value = client.get(KEYRING_NAMESPACE, &WireSecretAddress::new(item, field))?;
    let value = value.ok_or(CliError::KeyringEntryNotFound)?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(value.expose())
        .and_then(|()| stdout.flush())
        .map_err(|error| CliError::KeyringInput(error.to_string()))
}

pub(super) fn delete_keyring_value(
    root: &Path,
    socket: Option<&Path>,
    item: String,
    field: Option<String>,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let existed = client.delete(KEYRING_NAMESPACE, &WireSecretAddress::new(item, field))?;
    if !existed {
        return Err(CliError::KeyringEntryNotFound);
    }
    Ok(())
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

pub(super) fn read_keyring_value(path: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let value = if let Some(path) = path {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_KEYRING_VALUE_BYTES {
            return Err(CliError::KeyringInput(format!(
                "{} must be a regular file no larger than 64 KiB",
                path.display()
            )));
        }
        let file = fs::File::open(path)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?;
        read_bounded(file, MAX_KEYRING_VALUE_BYTES)
            .map_err(|error| CliError::KeyringInput(format!("{}: {error}", path.display())))?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Keyring value: ")
            .map(|secret| Zeroizing::new(secret.into_bytes()))
            .map_err(|error| CliError::KeyringInput(error.to_string()))?
    } else {
        read_bounded(std::io::stdin().lock(), MAX_KEYRING_VALUE_BYTES)
            .map_err(|error| CliError::KeyringInput(error.to_string()))?
    };
    if value.is_empty() {
        return Err(CliError::KeyringInput(
            "the keyring value must not be empty".to_owned(),
        ));
    }
    if value.len() as u64 > MAX_KEYRING_VALUE_BYTES {
        return Err(CliError::KeyringInput(
            "the keyring value must not exceed 64 KiB".to_owned(),
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

pub(super) fn run_vault(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    policy: UnsealLeasePolicy,
    requested_group: Option<&UnlockGroup>,
) -> Result<(), CliError> {
    let device = Vault::inspect(root)?;
    let unsealed = unseal_selected(root, &device, requested_group, factor)?;
    let service = Arc::new(VaultService::open(root, unsealed, unix_time()?, policy)?);
    serve_vault(&device, &service, root, socket)
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
    println!("Authorized this Factorseal CLI for the local keyring");
    Ok(())
}

fn authorize_cli(service: &VaultService, now: u64) -> Result<(), CliError> {
    let executable =
        std::env::current_exe().map_err(|error| CliError::CurrentExecutable(error.to_string()))?;
    let caller = caller_identity_for_executable(&executable)?;
    service.authorize_namespace(&caller, KEYRING_NAMESPACE, KEYRING_PERMISSIONS, None, now)?;
    service.authorize_approval_manager(&caller, now)?;
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct ApprovalOptions<'a> {
    pub(super) watch: bool,
    pub(super) prompt: bool,
    pub(super) json: bool,
    pub(super) action: Option<&'a ApprovalCommand>,
}

pub(super) fn manage_approvals(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    options: ApprovalOptions<'_>,
) -> Result<(), CliError> {
    let ApprovalOptions {
        watch,
        prompt,
        json,
        action,
    } = options;
    match action {
        Some(ApprovalCommand::Approve { id }) => {
            if watch || prompt || json {
                return Err(VaultError::Protocol(
                    "listing flags cannot be combined with approvals approve".to_owned(),
                )
                .into());
            }
            approve_with_prompted_group(root, socket, factor, id)
        }
        Some(ApprovalCommand::Deny { id }) => {
            if watch || prompt || json {
                return Err(VaultError::Protocol(
                    "listing flags cannot be combined with approvals deny".to_owned(),
                )
                .into());
            }
            resolve_approval(root, socket, VaultAction::Deny { id: id.clone() }, false)
        }
        None if prompt => prompt_approvals(root, socket, factor),
        None => list_approvals(root, socket, watch, json),
    }
}

fn approvals(client: &dyn VaultClient) -> Result<(u64, Vec<PendingApproval>), CliError> {
    let request = VaultRequest::new(VaultAction::ListApprovals)?;
    let response = client.request(&request)?;
    match response.result {
        Ok(VaultResponseBody::Approvals {
            revision,
            approvals,
        }) => Ok((revision, approvals)),
        Ok(_) => Err(VaultError::Protocol(
            "vault returned an unexpected approvals response".to_owned(),
        )
        .into()),
        Err(error) => Err(CliError::VaultRequest {
            code: error.code,
            message: error.message,
        }),
    }
}

fn list_approvals(
    root: &Path,
    socket: Option<&Path>,
    watch: bool,
    json: bool,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let mut last_revision = None;
    loop {
        let (revision, pending) = approvals(&client)?;
        if last_revision != Some(revision) {
            print_approvals(&pending, json)?;
            last_revision = Some(revision);
        }
        if !watch {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn print_approvals(pending: &[PendingApproval], json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string(pending)?);
        return Ok(());
    }
    if pending.is_empty() {
        println!("No pending approvals");
        return Ok(());
    }
    for approval in pending {
        write_approval(&mut std::io::stdout().lock(), approval)?;
    }
    Ok(())
}

fn write_approval(output: &mut impl Write, approval: &PendingApproval) -> Result<(), CliError> {
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
    writeln!(output, "{}  {:?}", approval.id, approval.operation)
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
        .and_then(|()| {
            writeln!(
                output,
                "  reason: {reason}  created: {}  expires: {}",
                approval.created_at, approval.expires_at
            )
        })
        .and_then(|()| {
            if let Some(duration) = approval
                .application
                .requested_authorization_duration_seconds
            {
                writeln!(
                    output,
                    "  requested grant duration: {}",
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
            "Grant access for [{}]: ",
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

fn prompt_approvals(
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
        let (revision, pending) = approvals(&client)?;
        if last_revision != Some(revision) {
            handled.retain(|id| pending.iter().any(|approval| &approval.id == id));
            for approval in &pending {
                if handled.contains(&approval.id) {
                    continue;
                }
                let decision = {
                    let mut input = stdin.lock();
                    let mut output = stderr.lock();
                    write_approval(&mut output, approval)?;
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
                                approval
                                    .application
                                    .requested_authorization_duration_seconds,
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
                    ApprovalDecision::Deny => resolve_approval(
                        root,
                        socket,
                        VaultAction::Deny {
                            id: approval.id.clone(),
                        },
                        false,
                    )?,
                    ApprovalDecision::Ignore => {}
                }
            }
            last_revision = Some(revision);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
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
    let (_, pending) = approvals(&client)?;
    let approval = pending
        .iter()
        .find(|approval| approval.id == id)
        .ok_or_else(|| VaultError::Protocol("approval is missing or expired".to_owned()))?;
    let device = Vault::inspect(root)?;
    let (grant_duration_seconds, group) = {
        let mut input = stdin.lock();
        let mut output = stderr.lock();
        let duration = read_grant_duration(
            &mut input,
            &mut output,
            approval
                .application
                .requested_authorization_duration_seconds,
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
    let (_, pending) = approvals(&client)?;
    let approval = pending
        .iter()
        .find(|approval| approval.id == id)
        .ok_or_else(|| VaultError::Protocol("approval is missing or expired".to_owned()))?;
    let device = Vault::inspect(root)?;
    let unsealed = unseal_selected(root, &device, requested_group, factor)?;
    let signature = unsealed.sign_approval_challenge(
        &approval.id,
        &approval.challenge,
        grant_duration_seconds,
    )?;
    drop(unsealed);
    resolve_approval(
        root,
        socket,
        VaultAction::Approve {
            id: id.to_owned(),
            signature,
            grant_duration_seconds,
        },
        true,
    )
}

fn resolve_approval(
    root: &Path,
    socket: Option<&Path>,
    action: VaultAction,
    expected_approved: bool,
) -> Result<(), CliError> {
    let client = native_client(root, socket)?;
    let request = VaultRequest::new(action)?;
    let response = client.request(&request)?;
    match response.result {
        Ok(VaultResponseBody::ApprovalResolved { approved }) if approved == expected_approved => {
            println!(
                "{}",
                if approved {
                    "Approved pending request"
                } else {
                    "Denied pending request"
                }
            );
            Ok(())
        }
        Ok(_) => Err(VaultError::Protocol(
            "vault returned an unexpected approval response".to_owned(),
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
    let groups = device.unlock_policy().groups();
    if let Some(requested) = requested {
        return groups
            .iter()
            .find(|group| *group == requested)
            .cloned()
            .ok_or_else(|| CliError::UnlockGroupNotConfigured(requested.to_string()));
    }
    match groups {
        [group] => Ok(group.clone()),
        _ => Err(CliError::UnlockGroupRequired(
            groups.iter().map(ToString::to_string).collect(),
        )),
    }
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
