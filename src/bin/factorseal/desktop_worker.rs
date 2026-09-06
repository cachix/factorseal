//! Dedicated key owner launched by Desktop. No GUI libraries are linked here.

use super::{CliError, timing};
use factorseal::desktop_worker::{Bootstrap, Operation, receive, send};
use factorseal::{
    CallerIdentity, DocumentKind, GrantAuthorization, GrantAuthorizationTarget, GrantPermission,
    UnlockCredentials, UnsealLeasePolicy, Vault, VaultCryptoProfile, VaultService,
};
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const DESKTOP_CONTROL: &[u8] = b"factorseal/desktop-control/v1";

pub(super) fn run(root: &Path, socket: Option<&Path>) -> Result<(), CliError> {
    timing::result(
        "desktop_worker",
        "harden_key_owner",
        super::platform::harden_key_owner,
    )?;
    factorseal::diagnostics::event("worker", "bootstrap", "start");
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
    } = timing::result("desktop_worker", "receive_bootstrap", || {
        receive(&mut std::io::stdin())
    })
    .map_err(|e| CliError::DesktopLaunch(e.to_string()))?;
    if !desktop_executable.is_absolute() || !desktop_executable.is_file() {
        return Err(CliError::DesktopLaunch(
            "desktop executable must be an absolute regular file".to_owned(),
        ));
    }
    let owner = Arc::new(Mutex::new(Weak::<VaultService>::new()));
    timing::result("desktop_worker", "watch_parent", || {
        watch_parent(Arc::clone(&owner))
    })?;
    let lifecycle = timing::result(
        "desktop_worker",
        "prepare_lifecycle",
        super::platform::prepare_lifecycle,
    )?;
    timing::result("desktop_worker", "arm_lifecycle", || lifecycle.arm())?;
    let initializing = matches!(operation, Operation::Initialize { .. });
    #[cfg(feature = "secretspec-provider")]
    timing::result("desktop_worker", "publish_secretspec_claim", || {
        super::secretspec_discovery::publish_for_default_root(root)
    })?;
    let ((unsealed, lease), hosts) = prepare_unlock(
        || identify_hosts(&desktop_executable),
        || {
            let unlocked = match operation {
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
            // Release the bootstrap factor before waiting for identification
            // or opening the database.
            drop(password);
            Ok(unlocked)
        },
    )?;
    let device = unsealed.public().clone();
    let result = (|| {
        let now = super::commands::unix_time()?;
        let service = Arc::new(VaultService::open(root, unsealed, now, lease)?);
        *owner
            .lock()
            .map_err(|_| CliError::DesktopLaunch("owner lock unavailable".to_owned()))? =
            Arc::downgrade(&service);
        authorize_hosts(&service, &hosts, now)?;
        if initializing {
            service.seal()?;
            Vault::complete_initialization(root)?;
        } else {
            factorseal::diagnostics::event("worker", "serve_vault", "start");
            super::platform::serve_vault(&device, &service, root, socket, &lifecycle, || {
                timing::result("desktop_worker", "send_ready", || {
                    send(&mut std::io::stdout(), &Ok::<(), String>(()))
                })
                .map_err(|e| factorseal::VaultError::Protocol(e.to_string()))?;
                *reported = true;
                Ok(())
            })?;
        }
        Ok(())
    })();
    lifecycle.disarm();
    if initializing && result.is_err() {
        Vault::discard_initialization(root)?;
    }
    result
}

struct HostIdentities {
    cli: CallerIdentity,
    desktop: CallerIdentity,
}

// Keep native unsealing on the calling thread; the helper sees executable
// paths only, never the password or unsealed keys. Scoped joining also reaps
// the helper when either operation fails.
fn prepare_unlock<T>(
    identify: impl FnOnce() -> Result<HostIdentities, CliError> + Send,
    unlock: impl FnOnce() -> Result<T, CliError>,
) -> Result<(T, HostIdentities), CliError> {
    std::thread::scope(|scope| {
        let identities = std::thread::Builder::new()
            .name("factorseal-host-identities".to_owned())
            .spawn_scoped(scope, identify)
            .map_err(|error| CliError::DesktopLaunch(error.to_string()))?;
        let unsealed = unlock();
        let hosts = timing::result("desktop_worker", "wait_host_identities", || {
            identities.join().map_err(|_| {
                CliError::DesktopLaunch("executable identification thread panicked".to_owned())
            })?
        });
        Ok((unsealed?, hosts?))
    })
}

fn identify_hosts(executable: &Path) -> Result<HostIdentities, CliError> {
    let cli = super::commands::cli_caller_identity()?;
    let desktop = timing::result("desktop_worker", "identify_desktop_executable", || {
        super::platform::caller_identity_for_executable(executable)
    })?;
    Ok(HostIdentities { cli, desktop })
}

fn authorize_hosts(
    service: &VaultService,
    hosts: &HostIdentities,
    now: u64,
) -> Result<(), CliError> {
    let caller = &hosts.desktop;
    let mut grants = Vec::from(super::commands::cli_authorizations(&hosts.cli));
    grants.extend([
        GrantAuthorization {
            caller,
            target: GrantAuthorizationTarget::Kind {
                kind: DocumentKind::SecretSpecProject,
            },
            permissions: &super::PROJECT_PERMISSIONS,
            expires_at: None,
        },
        GrantAuthorization {
            caller,
            target: GrantAuthorizationTarget::Namespace {
                scope: DocumentKind::LocalKeyring,
                namespace: super::PERSONAL_SECRET_NAMESPACE,
            },
            permissions: &[
                GrantPermission::List,
                GrantPermission::Get,
                GrantPermission::Put,
                GrantPermission::Delete,
            ],
            expires_at: None,
        },
        GrantAuthorization {
            caller,
            target: GrantAuthorizationTarget::Namespace {
                scope: DocumentKind::LocalKeyring,
                namespace: DESKTOP_CONTROL,
            },
            permissions: &[GrantPermission::Seal],
            expires_at: None,
        },
        GrantAuthorization {
            caller,
            target: GrantAuthorizationTarget::PermissionManagement,
            permissions: &[GrantPermission::ManagePermissions],
            expires_at: None,
        },
    ]);
    timing::result("desktop_worker", "authorize_host_permissions", || {
        service.authorize_batch(&grants, now)
    })?;
    Ok(())
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
            factorseal::diagnostics::finish(true);
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

    fn test_hosts() -> HostIdentities {
        let caller = CallerIdentity::new(
            factorseal::CallerPlatform::Linux,
            "uid:1000",
            "test-executable",
            [1; 32],
            None,
        )
        .unwrap();
        HostIdentities {
            cli: caller.clone(),
            desktop: caller,
        }
    }

    #[test]
    fn executable_identification_overlaps_unlock_on_the_calling_thread() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let calling_thread = std::thread::current().id();
        let (value, _) = prepare_unlock(
            move || {
                assert_ne!(std::thread::current().id(), calling_thread);
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(test_hosts())
            },
            || {
                assert_eq!(std::thread::current().id(), calling_thread);
                started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                release_tx.send(()).unwrap();
                Ok(42)
            },
        )
        .unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn failed_identification_drops_the_unsealed_result() {
        struct Unsealed<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Unsealed<'_> {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        let dropped = std::sync::atomic::AtomicBool::new(false);
        let result = prepare_unlock(
            || Err(CliError::DesktopLaunch("identity failed".to_owned())),
            || Ok(Unsealed(&dropped)),
        );
        assert!(result.is_err());
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn failed_unlock_still_joins_executable_identification() {
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let finished = std::sync::atomic::AtomicBool::new(false);
        let identification_finished = &finished;
        let result = prepare_unlock(
            move || {
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                identification_finished.store(true, std::sync::atomic::Ordering::Release);
                Ok(test_hosts())
            },
            || {
                release_tx.send(()).unwrap();
                Err::<(), _>(CliError::DesktopLaunch("unlock failed".to_owned()))
            },
        );
        assert!(result.is_err());
        assert!(finished.load(std::sync::atomic::Ordering::Acquire));
    }

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
