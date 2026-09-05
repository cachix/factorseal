//! Dedicated key owner launched by Desktop. No GUI libraries are linked here.

use super::CliError;
use factorseal::desktop_worker::{Bootstrap, Operation, receive, send};
use factorseal::{
    DocumentKind, GrantPermission, UnlockCredentials, UnsealLeasePolicy, Vault, VaultCryptoProfile,
    VaultService,
};
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const DESKTOP_CONTROL: &[u8] = b"factorseal/desktop-control/v1";

pub(super) fn run(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    super::platform::harden_key_owner()?;
    let mut reported = false;
    let result = run_inner(root, socket, &mut reported);
    // This pipe carries only status, never keys or secret values.
    if !reported {
        let status = result.as_ref().map_err(ToString::to_string);
        send(&mut std::io::stdout(), &status)
            .map_err(|e| CliError::DesktopLaunch(e.to_string()))?;
    }
    result
}

fn run_inner(root: &Path, socket: Option<&Path>, reported: &mut bool) -> Result<(), CliError> {
    let Bootstrap {
        desktop_executable,
        operation,
        password,
    } = receive(&mut std::io::stdin()).map_err(|e| CliError::DesktopLaunch(e.to_string()))?;
    if !desktop_executable.is_absolute() || !desktop_executable.is_file() {
        return Err(CliError::DesktopLaunch(
            "desktop executable must be an absolute regular file".to_owned(),
        ));
    }
    let owner = Arc::new(Mutex::new(Weak::<VaultService>::new()));
    watch_parent(Arc::clone(&owner))?;
    let lifecycle = super::platform::prepare_lifecycle()?;
    lifecycle.arm()?;
    let initializing = matches!(operation, Operation::Initialize { .. });
    #[cfg(feature = "secretspec-provider")]
    super::commands::publish_secretspec_claim_for_default_root(root)?;
    let (unsealed, lease) = match operation {
        Operation::Initialize { policy } => (
            Vault::prepare_with_unlock_policy_and_profile(
                root,
                &policy,
                UnlockCredentials::with_password(password.expose()),
                VaultCryptoProfile::Default,
            )?,
            UnsealLeasePolicy::default(),
        ),
        Operation::Unlock {
            group,
            idle_seconds,
            maximum_seconds,
        } => (
            Vault::unseal_with_unlock_group(
                root,
                &group,
                UnlockCredentials::with_password(password.expose()),
            )?,
            UnsealLeasePolicy {
                idle_timeout: Duration::from_secs(idle_seconds),
                maximum_lifetime: Duration::from_secs(maximum_seconds),
            },
        ),
    };
    // Drop the only bootstrap factor before opening the database or serving.
    drop(password);
    let device = unsealed.public().clone();
    let result = (|| {
        let now = super::commands::unix_time()?;
        let service = Arc::new(VaultService::open(root, unsealed, now, lease)?);
        *owner
            .lock()
            .map_err(|_| CliError::DesktopLaunch("owner lock unavailable".to_owned()))? =
            Arc::downgrade(&service);
        super::commands::authorize_cli(&service, now)?;
        let caller = super::platform::caller_identity_for_executable(&desktop_executable)?;
        service.authorize_document_kind(
            &caller,
            DocumentKind::SecretSpecProject,
            super::PROJECT_PERMISSIONS,
            None,
            now,
        )?;
        service.authorize_namespace(
            &caller,
            super::PERSONAL_SECRET_NAMESPACE,
            [
                GrantPermission::List,
                GrantPermission::Get,
                GrantPermission::Put,
                GrantPermission::Delete,
            ],
            None,
            now,
        )?;
        service.authorize_namespace(
            &caller,
            DESKTOP_CONTROL,
            [GrantPermission::Seal],
            None,
            now,
        )?;
        service.authorize_permission_manager(&caller, now)?;
        if initializing {
            service.seal()?;
            Vault::complete_initialization(root)?;
        } else {
            send(&mut std::io::stdout(), &Ok::<(), String>(()))
                .map_err(|e| CliError::DesktopLaunch(e.to_string()))?;
            *reported = true;
            super::platform::serve_vault(&device, &service, root, socket, &lifecycle)?;
        }
        Ok(())
    })();
    lifecycle.disarm();
    if initializing && result.is_err() {
        Vault::discard_initialization(root)?;
    }
    result
}

fn watch_parent(owner: Arc<Mutex<Weak<VaultService>>>) -> Result<(), CliError> {
    std::thread::Builder::new()
        .name("desktop-parent-lifeline".to_owned())
        .spawn(move || {
            // EOF or any extra byte means the parent has requested shutdown.
            let _ = std::io::stdin().read(&mut [0]);
            let _ = std::thread::Builder::new()
                .name("desktop-parent-watchdog".to_owned())
                .spawn(|| {
                    std::thread::sleep(Duration::from_secs(4));
                    std::process::exit(0);
                });
            if let Ok(owner) = owner.lock()
                && let Some(service) = owner.upgrade()
            {
                let _ = service.seal();
            }
            // Also bounds a native prompt or initialization before service ownership.
            std::process::exit(0);
        })
        .map_err(|e| CliError::DesktopLaunch(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, Write as _};
    use std::process::{Command, Stdio};
    use std::time::Instant;

    #[test]
    fn parent_loss_terminates_worker_before_service_creation() {
        const CHILD: &str = "FACTORSEAL_TEST_PARENT_LIFELINE";
        if std::env::var_os(CHILD).is_some() {
            super::super::platform::harden_key_owner().unwrap();
            watch_parent(Arc::new(Mutex::new(Weak::new()))).unwrap();
            println!("lifeline ready");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "desktop_worker::tests::parent_loss_terminates_worker_before_service_creation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = std::io::BufReader::new(child.stdout.take().unwrap());
        assert!(
            output
                .lines()
                .any(|line| line.unwrap().contains("lifeline ready"))
        );
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("worker survived parent loss");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
