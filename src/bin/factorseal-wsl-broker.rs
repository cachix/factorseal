//! Windows broker for WSL2-relayed vault requests, executed via WSL2
//! interop. Connects to the existing named-pipe transport exactly like any
//! other Windows client -- transport authentication is completely
//! unchanged, and the normal interactive-approval and grant-lookup flow
//! (`AuthorizationRequired` -> approve in Desktop -> retry) works exactly as
//! it does for any native caller. The only new behavior is tagging the
//! request with the distro name that invoked this process
//! (`VaultApplicationContext::declared_wsl_origin`): an unauthenticated,
//! display-only hint that caps whatever grant approval creates to a short
//! lifetime (`MAX_WSL_GRANT_SECONDS` in `src/vault/protocol/grant.rs`),
//! since this broker has no equivalent of the executable-identity hint a
//! native caller gets, even as defense in depth.
//!
//! Usage:
//!   factorseal-wsl-broker.exe <pipe-name> <distro> status
//!   factorseal-wsl-broker.exe <pipe-name> <distro> get <namespace> <item> [field]

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_impl::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("factorseal-wsl-broker only runs on Windows");
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_impl {
    use factorseal::vault::{
        PermissionWaitStatus, VaultAction, VaultApplicationContext, VaultClient, VaultRequest,
        VaultResponseBody, VaultResponseError, WindowsVaultClient, WireSecretAddress,
    };

    const USAGE: &str =
        "usage: factorseal-wsl-broker <pipe-name> <distro> <status|get> [namespace] [item] [field]";

    /// `VaultAction` deliberately doesn't derive `Clone` (some variants carry
    /// secret material), so the request this broker sends twice -- once
    /// before approval, once after -- is rebuilt from this small, plainly
    /// clonable description instead of cloning a constructed `VaultAction`.
    #[derive(Clone)]
    enum RequestedAction {
        Status,
        Get {
            namespace: Vec<u8>,
            item: String,
            field: Option<String>,
        },
    }

    impl RequestedAction {
        fn parse(
            name: &str,
            args: &mut impl Iterator<Item = String>,
        ) -> Result<Self, &'static str> {
            match name {
                "status" => Ok(Self::Status),
                "get" => Ok(Self::Get {
                    namespace: args.next().ok_or(USAGE)?.into_bytes(),
                    item: args.next().ok_or(USAGE)?,
                    field: args.next(),
                }),
                _ => Err(USAGE),
            }
        }

        fn into_vault_action(self) -> VaultAction {
            match self {
                Self::Status => VaultAction::Status,
                Self::Get {
                    namespace,
                    item,
                    field,
                } => VaultAction::Get {
                    namespace,
                    address: WireSecretAddress::new(item, field),
                },
            }
        }
    }

    pub(super) fn run() -> Result<(), String> {
        let mut args = std::env::args().skip(1);
        let pipe_name = args.next().ok_or(USAGE)?;
        let distro = args.next().ok_or(USAGE)?;
        let action_name = args.next().ok_or(USAGE)?;
        let requested = RequestedAction::parse(&action_name, &mut args)?;

        let application = VaultApplicationContext::new(
            None,
            None,
            None,
            Some(format!("Relayed from WSL distro {distro}")),
        )
        .and_then(|context| context.with_declared_wsl_origin(Some(distro)))
        .map_err(|error| error.to_string())?;

        let client = WindowsVaultClient::new(pipe_name);
        match send(
            &client,
            requested.clone().into_vault_action(),
            application.clone(),
        )? {
            Ok(body) => print_result(&body),
            Err(error) => {
                let Some(interaction) = error.interaction else {
                    return Err(describe(&error));
                };
                println!(
                    "approval required (id {}); approve in Factorseal Desktop, then this will retry once...",
                    interaction.id
                );
                let wait_request = VaultRequest::new(VaultAction::WaitPermission {
                    id: interaction.id,
                    timeout_ms: 120_000,
                })
                .map_err(|error| error.to_string())?;
                let wait_response = client
                    .request(&wait_request)
                    .map_err(|error| error.to_string())?;
                let status = match wait_response.result {
                    Ok(VaultResponseBody::PermissionWait { status }) => status,
                    Ok(_) => return Err("unexpected response waiting for approval".to_owned()),
                    Err(error) => return Err(describe(&error)),
                };
                match status {
                    PermissionWaitStatus::Granted => {
                        match send(&client, requested.into_vault_action(), application)? {
                            Ok(body) => print_result(&body),
                            Err(error) => return Err(describe(&error)),
                        }
                    }
                    other => return Err(format!("approval not granted: {other:?}")),
                }
            }
        }
        Ok(())
    }

    fn send(
        client: &WindowsVaultClient,
        action: VaultAction,
        application: VaultApplicationContext,
    ) -> Result<Result<VaultResponseBody, VaultResponseError>, String> {
        let request = VaultRequest::new_with_application(action, application)
            .map_err(|error| error.to_string())?;
        let response = client
            .request(&request)
            .map_err(|error| error.to_string())?;
        Ok(response.result)
    }

    fn print_result(body: &VaultResponseBody) {
        println!("{body:?}");
    }

    fn describe(error: &VaultResponseError) -> String {
        format!("{:?}: {}", error.code, error.message)
    }
}
