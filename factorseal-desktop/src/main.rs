mod app;
mod branding;
mod instance;
mod runtime;
mod secret_input;
mod theming;
mod timing;

use std::{borrow::Cow, path::PathBuf};

use clap::Parser;
use gpui::{AssetSource, QuitMode, SharedString};

struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> gpui::Result<Option<Cow<'static, [u8]>>> {
        match path {
            branding::MARK_ASSET => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../assets/logo/factorseal-mark.svg"
            )))),
            branding::MICRO_MARK_ASSET => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../assets/logo/factorseal-mark-micro.svg"
            )))),
            branding::SEARCH_ASSET => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../assets/logo/factorseal-search.svg"
            )))),
            branding::CLOSE_ASSET => Ok(Some(Cow::Borrowed(include_bytes!(
                "../../assets/logo/factorseal-close.svg"
            )))),
            _ => gpui_component_assets::Assets.load(path),
        }
    }

    fn list(&self, path: &str) -> gpui::Result<Vec<SharedString>> {
        let mut assets = gpui_component_assets::Assets.list(path)?;
        assets.extend(
            vec![
                branding::MARK_ASSET.into(),
                branding::MICRO_MARK_ASSET.into(),
                branding::SEARCH_ASSET.into(),
                branding::CLOSE_ASSET.into(),
            ]
            .into_iter()
            .filter(|asset: &SharedString| asset.starts_with(path)),
        );
        Ok(assets)
    }
}

#[cfg(target_os = "linux")]
const SECRET_SERVICE_NAME: &str = "org.freedesktop.secrets";
#[cfg(target_os = "linux")]
const ACTIVATION_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(name = "factorseal-desktop", version, about = "FactorSeal Desktop")]
struct Args {
    /// Vault directory. Defaults to platform-local user data.
    #[arg(long, env = "FACTORSEAL_ROOT")]
    root: Option<PathBuf>,

    /// Local service socket or named pipe override.
    #[arg(long, env = "FACTORSEAL_SOCKET")]
    socket: Option<PathBuf>,

    /// Start in the tray without opening the main window.
    #[arg(long)]
    background: bool,

    #[arg(long, hide = true, conflicts_with_all = ["background", "keyring_activation"])]
    no_tray: bool,

    /// Activate Desktop for a queued Secret Service request.
    #[arg(long, hide = true)]
    keyring_activation: bool,

    /// Idle seconds before hardware-unwrapped keys are discarded.
    #[arg(long, env = "FACTORSEAL_IDLE_SECONDS", default_value_t = 300)]
    idle_seconds: u64,

    /// Absolute maximum seconds for one unseal lease.
    #[arg(long, env = "FACTORSEAL_MAXIMUM_SECONDS", default_value_t = 28_800)]
    maximum_seconds: u64,
}

fn main() {
    if let Err(error) = factorseal::security::disable_core_dumps() {
        eprintln!("factorseal-desktop: could not disable core dumps: {error}");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    if let Some(argument) = std::env::args().nth(1) {
        match argument.as_str() {
            "--gtk-theme-probe" => theming::exit_after_probe(theming::Backend::Gtk),
            "--qt-theme-probe" => theming::exit_after_probe(theming::Backend::Qt),
            "--theme-probe-only" => theming::exit_after_probe_only(),
            _ => {}
        }
    }

    let args = Args::parse();
    let root = runtime::explicit_or_default_root(args.root.as_deref()).unwrap_or_else(|error| {
        eprintln!("factorseal-desktop: {error}");
        std::process::exit(1);
    });
    let lease =
        runtime::lease_policy(args.idle_seconds, args.maximum_seconds).unwrap_or_else(|error| {
            eprintln!("factorseal-desktop: {error}");
            std::process::exit(1);
        });
    let config = runtime::RuntimeConfig {
        root,
        socket: args.socket,
        lease,
    };
    let instance = instance::acquire(&config.root, !args.background || args.keyring_activation)
        .unwrap_or_else(|error| {
            eprintln!("factorseal-desktop: {error}");
            std::process::exit(1);
        });
    if matches!(instance, instance::Instance::Secondary) {
        #[cfg(target_os = "linux")]
        if args.keyring_activation
            && let Err(error) = wait_for_secret_service(ACTIVATION_WAIT)
        {
            eprintln!("factorseal-desktop: {error}");
        }
        return;
    }
    let instance::Instance::Primary {
        _lock: instance_lock,
        activations,
    } = instance
    else {
        unreachable!("secondary Desktop instances return before application startup")
    };
    gpui_platform::application()
        .with_assets(Assets)
        .with_quit_mode(QuitMode::Explicit)
        .run(move |cx| app::setup(config, args.background, args.no_tray, activations, cx));
    drop(instance_lock);
}

#[cfg(target_os = "linux")]
fn wait_for_secret_service(timeout: std::time::Duration) -> Result<(), String> {
    use dbus::blocking::Connection;

    let connection = Connection::new_session()
        .map_err(|error| format!("could not monitor Secret Service activation: {error}"))?;
    let proxy = connection.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        std::time::Duration::from_secs(2),
    );
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let (has_owner,): (bool,) = proxy
            .method_call(
                "org.freedesktop.DBus",
                "NameHasOwner",
                (SECRET_SERVICE_NAME,),
            )
            .map_err(|error| format!("could not inspect Secret Service activation: {error}"))?;
        if has_owner {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for Desktop to unseal the keyring".to_owned());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::Args;

    #[test]
    fn component_and_brand_icons_are_available() {
        use gpui::AssetSource as _;

        let assets = super::Assets;
        for path in assets.list("").unwrap() {
            assert!(!assets.load(&path).unwrap().unwrap().is_empty(), "{path}");
        }
        for path in [
            "icons/eye.svg",
            "icons/chevron-down.svg",
            super::branding::MARK_ASSET,
        ] {
            assert!(assets.load(path).unwrap().is_some(), "{path}");
        }
        assert!(
            assets
                .list("icons/")
                .unwrap()
                .iter()
                .all(|path| path.starts_with("icons/"))
        );
    }

    #[test]
    fn keyring_activation_is_a_hidden_foreground_launch() {
        let args = Args::try_parse_from(["factorseal-desktop", "--keyring-activation"]).unwrap();
        assert!(args.keyring_activation);
        assert!(!args.background);

        let help = Args::command().render_long_help().to_string();
        assert!(!help.contains("keyring-activation"));
    }

    #[test]
    fn tray_free_mode_requires_a_visible_launch() {
        assert!(
            Args::try_parse_from(["factorseal-desktop", "--no-tray"])
                .unwrap()
                .no_tray
        );
        for argument in ["--background", "--keyring-activation"] {
            assert!(Args::try_parse_from(["factorseal-desktop", "--no-tray", argument]).is_err());
        }
    }
}
