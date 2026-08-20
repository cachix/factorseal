use std::fs;
use std::io::{IsTerminal as _, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use factorseal::{
    AgentError, AgentService, AgentStore, CallerIdentity, DeviceSeal, GrantPermission, Seal,
    UnlockFactor, UnlockLeasePolicy,
};
#[cfg(target_os = "linux")]
use factorseal::{LinuxAgentOptions, linux_caller_identity_for_executable, serve_linux_agent};
#[cfg(target_os = "macos")]
use factorseal::{MacosAgentOptions, macos_caller_identity_for_executable, serve_macos_agent};
#[cfg(target_os = "windows")]
use factorseal::{
    WindowsAgentOptions, serve_windows_agent, windows_caller_identity_for_executable,
};
use serde::Serialize;
use std::sync::Arc;
use zeroize::Zeroizing;

const MAX_FACTOR_BYTES: u64 = 64 * 1024;
const SECRETSPEC_CACHE_NAMESPACE: &[u8] = b"secretspec-cache/v1";

#[derive(Debug, Parser)]
#[command(
    name = "factorseal",
    version,
    about = "Hardware-bound per-user Factorseal secret agent"
)]
struct Cli {
    /// Agent seal directory. Defaults to platform-local user data.
    #[arg(long, global = true, env = "FACTORSEAL_AGENT_ROOT")]
    root: Option<PathBuf>,

    /// Read the nested factor from a private regular file.
    #[arg(long, global = true)]
    password_file: Option<PathBuf>,

    /// Run this helper to obtain the nested factor and read it from the
    /// helper's standard output. Packages use it to prompt without a
    /// controlling terminal; the prompt text is passed as the one argument.
    #[arg(long, global = true, env = "FACTORSEAL_ASKPASS")]
    askpass: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create this permanent Factorseal device and its embedded Turso store.
    Init {
        /// Require platform biometric verification when supported by key use.
        #[arg(long)]
        biometric: bool,
    },

    /// Unlock and serve authenticated local clients until the lease ends.
    Run {
        /// Local socket path. Linux defaults inside the private agent root.
        #[arg(long, env = "FACTORSEAL_AGENT_SOCKET")]
        socket: Option<PathBuf>,

        /// Idle seconds before hardware-unwrapped keys are discarded.
        #[arg(long, default_value_t = 300)]
        idle_seconds: u64,

        /// Absolute maximum seconds for one unlock lease.
        #[arg(long, default_value_t = 28_800)]
        maximum_seconds: u64,
    },

    /// Print validated non-secret seal metadata without unlocking.
    Status,

    /// Authorize one exact SecretSpec or embedding application executable.
    GrantSecretspec {
        executable: PathBuf,

        /// Optional lifetime for the durable grant.
        #[arg(long)]
        expires_in_seconds: Option<u64>,
    },
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Agent(#[from] AgentError),

    #[error("could not determine the platform user-data directory; pass --root")]
    NoDefaultRoot,

    #[error("the requested lifetime is outside the supported range")]
    LifetimeOverflow,

    #[error("password input failed: {0}")]
    Password(String),

    #[error("askpass helper failed: {0}")]
    Askpass(String),

    #[error(
        "no way to obtain the Factorseal factor: there is no controlling \
         terminal, and neither --askpass nor --password-file was given"
    )]
    NoFactorSource,

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[error("this platform transport has not been implemented")]
    UnsupportedPlatform,

    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct Status<'a> {
    path: String,
    seal_id: String,
    device_key_id: String,
    public_signing_key: String,
    actor_id: String,
    platform: &'a str,
    hardware_backend: &'a str,
    nested_factor: &'a str,
    key_epoch: u64,
    created_at: u64,
    state: &'static str,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("factorseal: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    let root = resolve_root(cli.root.as_deref())?;
    let factor = FactorSource {
        password_file: cli.password_file.as_deref(),
        askpass: cli.askpass.as_deref(),
    };
    match cli.command {
        Command::Init { biometric } => initialize(&root, biometric, factor),
        Command::Run {
            socket,
            idle_seconds,
            maximum_seconds,
        } => run_agent(
            &root,
            socket.as_deref(),
            factor,
            UnlockLeasePolicy {
                idle_timeout: Duration::from_secs(idle_seconds),
                maximum_lifetime: Duration::from_secs(maximum_seconds),
            },
        ),
        Command::Status => show_status(&root),
        Command::GrantSecretspec {
            executable,
            expires_in_seconds,
        } => grant_secretspec(&root, &executable, expires_in_seconds, factor),
    }
}

fn initialize(root: &Path, biometric: bool, factor: FactorSource<'_>) -> Result<(), CliError> {
    let password = read_factor(factor, true)?;
    let unlocked = Seal::create(root, UnlockFactor::Password(&password), biometric)?;
    let device = unlocked.public().clone();
    // The seal is already on disk, and `create` refuses to run again while it
    // is there. Undo what this command wrote so `init` can simply be retried
    // rather than leaving a root nothing can finish or open.
    let store = AgentStore::open(root, unlocked).inspect_err(|_| {
        let _ = Seal::discard_initialization(root);
    })?;
    store.lock();
    println!(
        "Initialized Factorseal device {} at {} using {}",
        device.seal_id(),
        root.display(),
        device.hardware_backend()
    );
    Ok(())
}

fn show_status(root: &Path) -> Result<(), CliError> {
    let device = Seal::inspect(root)?;
    let status = Status {
        path: root.display().to_string(),
        seal_id: device.seal_id().to_string(),
        device_key_id: device.device_key_id().to_string(),
        public_signing_key: hex::encode(device.public_signing_key()),
        actor_id: hex::encode(device.actor_id()),
        platform: device.platform(),
        hardware_backend: device.hardware_backend(),
        nested_factor: device.nested_factor().as_str(),
        key_epoch: device.key_epoch(),
        created_at: device.created_at(),
        state: "locked",
    };
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn run_agent(
    root: &Path,
    socket: Option<&Path>,
    factor: FactorSource<'_>,
    policy: UnlockLeasePolicy,
) -> Result<(), CliError> {
    let password = read_factor(factor, false)?;
    let device = Seal::inspect(root)?;
    let unlocked = Seal::unlock(root, UnlockFactor::Password(&password))?;
    let store = AgentStore::open(root, unlocked)?;
    let service = Arc::new(AgentService::new(store, unix_time()?, policy)?);
    serve_agent(&device, &service, root, socket)
}

#[cfg(target_os = "linux")]
fn serve_agent(
    _device: &DeviceSeal,
    service: &Arc<AgentService>,
    root: &Path,
    socket: Option<&Path>,
) -> Result<(), CliError> {
    let socket = socket.map_or_else(|| root.join("agent.sock"), Path::to_owned);
    serve_linux_agent(service, &LinuxAgentOptions::new(socket))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn serve_agent(
    _device: &DeviceSeal,
    service: &Arc<AgentService>,
    root: &Path,
    socket: Option<&Path>,
) -> Result<(), CliError> {
    let socket = socket.map_or_else(|| root.join("agent.sock"), Path::to_owned);
    serve_macos_agent(service, &MacosAgentOptions::new(socket))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn serve_agent(
    device: &DeviceSeal,
    service: &Arc<AgentService>,
    _root: &Path,
    socket: Option<&Path>,
) -> Result<(), CliError> {
    let pipe_name = socket.map_or_else(
        || format!(r"\\.\pipe\factorseal-{}", device.seal_id()),
        |path| path.to_string_lossy().into_owned(),
    );
    serve_windows_agent(service, &WindowsAgentOptions::new(pipe_name))?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn serve_agent(
    _device: &DeviceSeal,
    _service: &Arc<AgentService>,
    _root: &Path,
    _socket: Option<&Path>,
) -> Result<(), CliError> {
    Err(CliError::UnsupportedPlatform)
}

fn grant_secretspec(
    root: &Path,
    executable: &Path,
    expires_in_seconds: Option<u64>,
    factor: FactorSource<'_>,
) -> Result<(), CliError> {
    let now = unix_time()?;
    let expires_at = expires_in_seconds
        .map(|seconds| now.checked_add(seconds).ok_or(CliError::LifetimeOverflow))
        .transpose()?;
    let caller = caller_identity_for_executable(executable)?;
    let password = read_factor(factor, false)?;
    let unlocked = Seal::unlock(root, UnlockFactor::Password(&password))?;
    let store = AgentStore::open(root, unlocked)?;
    let service = AgentService::new(store, now, UnlockLeasePolicy::default())?;
    service.authorize_namespace(
        &caller,
        SECRETSPEC_CACHE_NAMESPACE,
        [
            GrantPermission::Get,
            GrantPermission::Put,
            GrantPermission::Delete,
            GrantPermission::Clear,
        ],
        expires_at,
        now,
    )?;
    service.lock()?;
    println!(
        "Authorized {} for the Factorseal SecretSpec cache",
        caller.application_id()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn caller_identity_for_executable(executable: &Path) -> Result<CallerIdentity, CliError> {
    Ok(linux_caller_identity_for_executable(executable)?)
}

#[cfg(target_os = "macos")]
fn caller_identity_for_executable(executable: &Path) -> Result<CallerIdentity, CliError> {
    Ok(macos_caller_identity_for_executable(executable)?)
}

#[cfg(target_os = "windows")]
fn caller_identity_for_executable(executable: &Path) -> Result<CallerIdentity, CliError> {
    Ok(windows_caller_identity_for_executable(executable)?)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn caller_identity_for_executable(_executable: &Path) -> Result<CallerIdentity, CliError> {
    Err(CliError::UnsupportedPlatform)
}

/// Where the agent obtains the seal's nested factor.
#[derive(Clone, Copy)]
struct FactorSource<'a> {
    password_file: Option<&'a Path>,
    askpass: Option<&'a Path>,
}

/// Read the nested factor from an explicit file, an askpass helper, or the
/// controlling terminal, in that order.
///
/// A package that starts the agent from launchd, a logon task, or a systemd
/// unit has no terminal, so it must supply one of the first two. Failing with
/// a terminal prompt error in that case would say nothing useful.
fn read_factor(source: FactorSource<'_>, confirm: bool) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let secret = if let Some(path) = source.password_file {
        read_password_file(path)?
    } else if let Some(helper) = source.askpass {
        let first = run_askpass(helper, "Factorseal password:")?;
        if confirm {
            let second = run_askpass(helper, "Confirm Factorseal password:")?;
            if first.as_slice() != second.as_slice() {
                return Err(CliError::Password("passwords do not match".to_owned()));
            }
        }
        first
    } else if std::io::stdin().is_terminal() {
        let first = prompt_on_terminal("Factorseal password: ")?;
        if confirm {
            let second = prompt_on_terminal("Confirm Factorseal password: ")?;
            if first.as_slice() != second.as_slice() {
                return Err(CliError::Password("passwords do not match".to_owned()));
            }
        }
        first
    } else {
        return Err(CliError::NoFactorSource);
    };
    if secret.is_empty() {
        return Err(CliError::Password(
            "the Factorseal factor must not be empty".to_owned(),
        ));
    }
    Ok(secret)
}

fn prompt_on_terminal(label: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    rpassword::prompt_password(label)
        .map(|secret| Zeroizing::new(secret.into_bytes()))
        .map_err(|error| CliError::Password(error.to_string()))
}

/// Run the askpass helper and take its standard output as the factor.
///
/// The secret crosses a pipe rather than the filesystem, so it is never
/// written next to the seal it protects.
fn run_askpass(helper: &Path, label: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut child = process::Command::new(helper)
        .arg(label)
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .spawn()
        .map_err(|error| CliError::Askpass(format!("{}: {error}", helper.display())))?;
    let mut secret = Zeroizing::new(Vec::new());
    let read = child
        .stdout
        .take()
        .ok_or_else(|| CliError::Askpass("helper produced no output stream".to_owned()))
        .and_then(|mut stdout| {
            (&mut stdout)
                .take(MAX_FACTOR_BYTES)
                .read_to_end(&mut secret)
                .map_err(|error| CliError::Askpass(error.to_string()))
        });
    let status = child
        .wait()
        .map_err(|error| CliError::Askpass(error.to_string()))?;
    read?;
    if !status.success() {
        return Err(CliError::Askpass(format!(
            "{} exited without providing a factor",
            helper.display()
        )));
    }
    strip_one_line_ending(&mut secret);
    Ok(secret)
}

fn strip_one_line_ending(bytes: &mut Zeroizing<Vec<u8>>) {
    if bytes.ends_with(b"\r\n") {
        let new_length = bytes.len() - 2;
        bytes.truncate(new_length);
    } else if bytes.ends_with(b"\n") {
        let new_length = bytes.len() - 1;
        bytes.truncate(new_length);
    }
}

fn read_password_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CliError::Password(format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_FACTOR_BYTES {
        return Err(CliError::Password(format!(
            "{} must be a regular file no larger than 64 KiB",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(CliError::Password(format!(
                "{} is accessible by group or other users (mode {mode:o})",
                path.display()
            )));
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(64 * 1024),
    ));
    fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| CliError::Password(format!("{}: {error}", path.display())))?;
    strip_one_line_ending(&mut bytes);
    Ok(bytes)
}

fn resolve_root(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_owned());
    }
    let directories =
        ProjectDirs::from("dev", "Factorseal", "Factorseal").ok_or(CliError::NoDefaultRoot)?;
    Ok(directories.data_local_dir().join("agent"))
}

fn unix_time() -> Result<u64, AgentError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| AgentError::Protocol(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test writing a helper script while another forks makes the child
    /// inherit the open write handle, and the exec of that script then fails
    /// with ETXTBSY. Serializing helper use removes the overlap.
    #[cfg(unix)]
    static HELPER_EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    fn askpass_helper(directory: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = directory.join("askpass");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    fn lock_helper_exec() -> std::sync::MutexGuard<'static, ()> {
        HELPER_EXEC
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(unix)]
    #[test]
    fn askpass_output_is_the_factor_without_its_line_ending() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "printf 'correct horse\\n'");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"correct horse"
        );
    }

    #[cfg(unix)]
    #[test]
    fn askpass_receives_the_prompt_and_rejects_a_mismatched_confirmation() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        // Echo the prompt back, so the two confirmation prompts disagree.
        let helper = askpass_helper(directory.path(), "printf '%s' \"$1\"");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(read_factor(source, true).is_err());
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"Factorseal password:"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_cancelled_askpass_helper_does_not_yield_a_factor() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "exit 1");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(matches!(
            read_factor(source, false),
            Err(CliError::Askpass(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_factor_is_rejected() {
        let _serialized = lock_helper_exec();
        let directory = tempfile::tempdir().unwrap();
        let helper = askpass_helper(directory.path(), "printf ''");

        let source = FactorSource {
            password_file: None,
            askpass: Some(&helper),
        };
        assert!(read_factor(source, false).is_err());
    }

    #[test]
    fn an_explicit_file_takes_precedence_over_the_helper() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("factor");
        fs::write(&file, "from the file\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let source = FactorSource {
            password_file: Some(&file),
            askpass: Some(Path::new("/nonexistent/askpass")),
        };
        assert_eq!(
            read_factor(source, false).unwrap().as_slice(),
            b"from the file"
        );
    }

    #[test]
    fn askpass_is_configurable_through_the_environment() {
        let cli = Cli::try_parse_from(["factorseal", "--askpass", "/usr/bin/true", "run"]).unwrap();
        assert_eq!(cli.askpass.unwrap(), PathBuf::from("/usr/bin/true"));
    }

    #[test]
    fn run_policy_and_root_are_explicitly_configurable() {
        let cli = Cli::try_parse_from([
            "factorseal",
            "--root",
            "/tmp/factorseal-test",
            "run",
            "--idle-seconds",
            "10",
            "--maximum-seconds",
            "20",
        ])
        .unwrap();
        assert_eq!(cli.root.unwrap(), PathBuf::from("/tmp/factorseal-test"));
        let Command::Run {
            idle_seconds,
            maximum_seconds,
            ..
        } = cli.command
        else {
            panic!("expected run command");
        };
        assert_eq!(idle_seconds, 10);
        assert_eq!(maximum_seconds, 20);
    }
}
