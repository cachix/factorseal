//! Native messaging host and per-user browser registration.
use clap::Parser;
use factorseal::browser::registration::{self, Config};
use factorseal::browser::{self, Request, Response, transport};
use std::{io, path::PathBuf};
#[derive(Parser)]
struct Args {
    #[arg(long)]
    install: Option<String>,
    #[arg(long)]
    extension_id: Option<String>,
    #[arg(long)]
    root: Option<PathBuf>,
    /// Browser launch arguments are not an authentication mechanism.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _browser: Vec<String>,
}
fn dirs() -> io::Result<directories::ProjectDirs> {
    directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .ok_or_else(|| io::Error::other("no user data directory"))
}
fn main() {
    if let Err(error) = run() {
        eprintln!("factorseal-browser: {error}");
        std::process::exit(1);
    }
}
fn run() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    normalize_empty_loader_environment()?;
    let args = Args::parse();
    let dirs = dirs()?;
    if let Some(browser) = args.install {
        return registration::install(
            &browser,
            args.extension_id.as_deref(),
            args.root.as_deref(),
            &dirs,
            &std::env::current_exe()?,
        );
    }
    let config = dirs.config_dir().join("browser-host.json");
    let config = if config.is_file() {
        Some(serde_json::from_slice::<Config>(&std::fs::read(config)?).map_err(io::Error::other)?)
    } else {
        None
    };
    let root = config.as_ref().map_or_else(
        || dirs.data_local_dir().to_path_buf(),
        |config| config.root.clone(),
    );
    // A long-running browser can retain environment variables from an older
    // installation. Desktop's refreshed registration identifies the live build.
    let desktop = config
        .as_ref()
        .and_then(|config| config.desktop.clone())
        .or_else(|| std::env::var_os("FACTORSEAL_DESKTOP_EXECUTABLE").map(PathBuf::from))
        .unwrap_or(std::env::current_exe()?.with_file_name(if cfg!(windows) {
            "factorseal-desktop.exe"
        } else {
            "factorseal-desktop"
        }));
    let desktop_identity = config
        .as_ref()
        .and_then(|config| config.desktop_identity.clone())
        .or_else(|| std::env::var_os("FACTORSEAL_DESKTOP_IDENTITY").map(PathBuf::from))
        .unwrap_or_else(|| desktop.clone());
    let client = transport::Client::new(&root, &desktop_identity).map_err(io::Error::other)?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut activated = false;
    loop {
        let bytes = match browser::read_native(&mut input) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let request: Request = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if !activated {
            activated = true;
            if client.exchange(&Request::Hello { version: 0 }).is_err() {
                std::process::Command::new(&desktop)
                    .arg("--background")
                    .arg("--root")
                    .arg(&root)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()?;
                for _ in 0..50 {
                    if client.exchange(&Request::Hello { version: 0 }).is_ok() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
        let response = client
            .exchange(&request)
            .unwrap_or_else(|_| Response::finished("desktop_unavailable"));
        let bytes =
            zeroize::Zeroizing::new(serde_json::to_vec(&response).map_err(io::Error::other)?);
        browser::write_native(&mut output, &bytes)?;
    }
}

/// Chromium wrappers may export empty loader variables. Re-exec so /proc's
/// initial environment also loses them; mutating this process's environment
/// would not satisfy Desktop's existing peer-image authentication. Never strip
/// nonempty values: those may already have loaded foreign code.
#[cfg(target_os = "linux")]
fn normalize_empty_loader_environment() -> io::Result<()> {
    use std::os::unix::process::CommandExt as _;
    let empty: Vec<_> = ["LD_PRELOAD", "LD_AUDIT"]
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|value| value.is_empty()))
        .collect();
    if empty.is_empty() {
        return Ok(());
    }
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.args(std::env::args_os().skip(1));
    for name in empty {
        command.env_remove(name);
    }
    Err(command.exec())
}
