use std::sync::Arc;

use gpui::{
    AnyWindowHandle, App, Bounds, Context, Div, Global, Hsla, MenuItem, Render, Subscription, Task,
    Window, WindowBounds, WindowOptions, actions, div, prelude::*, px, size, svg,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Root, Selectable as _, Sizable as _, Size, StyledExt as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    h_flex,
    input::{Input, InputEvent, InputState},
    link::Link,
    scroll::ScrollableElement as _,
    spinner::Spinner,
    tooltip::Tooltip,
    v_flex,
};
use gpui_tray::{Icon, Tray};
use zeroize::Zeroizing;

use crate::runtime::{
    DesktopRuntime, PERSONAL_SECRET_NAMESPACE, RuntimeConfig, Snapshot, TransferSummary,
    VaultContents,
};
use crate::{branding, theming};
use factorseal::transfer::{TransferFormat, read_transfer_file, write_private_file};

actions!(
    factorseal_desktop,
    [OpenDesktop, CloseDesktop, ToggleDesktop, SealVault, Quit]
);

struct DesktopTray(Tray);

impl Global for DesktopTray {}

struct DesktopWindow {
    view: Arc<std::sync::Mutex<Option<gpui::Entity<DesktopView>>>>,
    handle: Option<AnyWindowHandle>,
    visible: bool,
    snapshot: Snapshot,
    refresh_generation: u64,
}

impl Global for DesktopWindow {}

struct RuntimeGlobal(Arc<DesktopRuntime>);

impl Global for RuntimeGlobal {}

struct DesktopStatus {
    unsealed: bool,
    quitting: bool,
    no_tray: bool,
}

impl Global for DesktopStatus {}

struct EventTask {
    _task: Task<()>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SetupMethod {
    #[default]
    Password,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Biometric,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    PasswordAndBiometric,
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    PasswordOrBiometric,
}

impl SetupMethod {
    const fn label(self) -> &'static str {
        match self {
            Self::Password => "Password",
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Biometric => "Biometric approval",
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::PasswordAndBiometric => "Password and biometric",
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::PasswordOrBiometric => "Password or biometric",
        }
    }

    const fn needs_password(self) -> bool {
        match self {
            Self::Password => true,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Biometric => false,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::PasswordAndBiometric | Self::PasswordOrBiometric => true,
        }
    }

    fn policy(self) -> factorseal::VaultResult<factorseal::UnlockPolicy> {
        use factorseal::{UnlockFactorKind, UnlockGroup, UnlockPolicy};

        let password = || UnlockGroup::new([UnlockFactorKind::Password]);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let biometric = || UnlockGroup::new([UnlockFactorKind::Biometric]);
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let both = || UnlockGroup::new([UnlockFactorKind::Password, UnlockFactorKind::Biometric]);
        let groups = match self {
            Self::Password => vec![password()?],
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Biometric => vec![biometric()?],
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::PasswordAndBiometric => vec![both()?],
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::PasswordOrBiometric => vec![password()?, biometric()?],
        };
        UnlockPolicy::new(groups)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PersonalPanel {
    #[default]
    Overview,
    NewItem,
}

#[derive(Clone, Debug)]
enum TransferNotice {
    Success(String),
    Error(String),
}

struct TransferCompletion {
    summary: Option<TransferSummary>,
    contents: Option<VaultContents>,
    path: std::path::PathBuf,
}

impl Global for EventTask {}

fn brand_mark(size: f32, color: Hsla) -> impl IntoElement {
    svg()
        .path(if size < 32. {
            branding::MICRO_MARK_ASSET
        } else {
            branding::MARK_ASSET
        })
        .size(px(size))
        .text_color(color)
}

fn vault_card(theme: &gpui_component::theme::Theme) -> Div {
    v_flex()
        .w_full()
        .gap_5()
        .p_8()
        .rounded_xl()
        .bg(theme.popover)
        .border_1()
        .border_color(theme.border)
}

fn field_label(label: &'static str, field: impl IntoElement) -> Div {
    v_flex()
        .gap_2()
        .child(div().text_sm().font_medium().child(label))
        .child(field)
}

fn search_icon(color: Hsla) -> impl IntoElement {
    svg()
        .path(branding::SEARCH_ASSET)
        .size(px(14.))
        .text_color(color)
}

fn close_icon(color: Hsla) -> impl IntoElement {
    svg()
        .path(branding::CLOSE_ASSET)
        .size(px(14.))
        .text_color(color)
}

fn error_banner(message: String, color: Hsla) -> Div {
    div()
        .w_full()
        .px_4()
        .py_3()
        .rounded_lg()
        .bg(color.opacity(0.1))
        .text_color(color)
        .child(message)
}

fn password_strength_error(password: &str) -> Option<String> {
    let estimate = zxcvbn::zxcvbn(password, &["FactorSeal", "vault"]);
    if estimate.score() >= zxcvbn::Score::Three {
        return None;
    }

    let guidance = estimate
        .feedback()
        .map(ToString::to_string)
        .filter(|feedback| !feedback.is_empty())
        .unwrap_or_else(|| {
            "Use a few uncommon words that are easy for you to remember.".to_owned()
        });
    Some(format!("Choose a stronger password. {guidance}"))
}

fn hardware_backend_label(backend: &str) -> &str {
    match backend {
        "tpm" => "TPM",
        "windows-tpm" => "Windows TPM",
        "secure-enclave" => "Secure Enclave",
        "android-strongbox" => "Android StrongBox",
        "android-trusted-environment" => "Android Trusted Environment",
        _ => backend,
    }
}

fn setup_protection_description() -> Div {
    if cfg!(target_os = "linux") {
        h_flex()
            .gap_1()
            .flex_wrap()
            .child("Your password and this device's")
            .child(
                Link::new("tpm-explanation-link")
                    .href("https://trustedcomputinggroup.org/about/what-is-a-trusted-platform-module-tpm/")
                    .child("TPM"),
            )
            .child("protect your vault. Both are required to unlock it.")
    } else {
        h_flex().child("Choose how this device should authorize access to your secrets.")
    }
}

fn secret_spec_address_label(address: &factorseal::SecretSpecAddress) -> (String, String) {
    match address {
        factorseal::SecretSpecAddress::Convention { profile, key, .. } => {
            (key.clone(), format!("Profile: {profile}"))
        }
        factorseal::SecretSpecAddress::Native { coordinates } => {
            let mut details = Vec::new();
            for (label, value) in [
                ("Field", coordinates.field.as_deref()),
                ("Vault", coordinates.vault.as_deref()),
                ("Section", coordinates.section.as_deref()),
                ("Version", coordinates.version.as_deref()),
            ] {
                if let Some(value) = value {
                    details.push(format!("{label}: {value}"));
                }
            }
            let detail = if details.is_empty() {
                "Native SecretSpec item".to_owned()
            } else {
                details.join(" · ")
            };
            (coordinates.item.clone(), detail)
        }
    }
}

fn visible_vault_entry(entry: &factorseal::VaultEntryMetadata) -> bool {
    !(entry.document_kind == factorseal::DocumentKind::LinuxSecretService
        && entry
            .address
            .as_local()
            .is_some_and(|(item, _)| item == "secret-service-index"))
}

fn is_personal_secret(entry: &factorseal::VaultEntryMetadata) -> bool {
    entry.document_kind == factorseal::DocumentKind::LocalKeyring
        && entry.partition == PERSONAL_SECRET_NAMESPACE
}

fn desired_vault_browser_height(contents: &VaultContents) -> gpui::Pixels {
    let document_count = contents
        .entries
        .iter()
        .filter(|entry| visible_vault_entry(entry))
        .count()
        + contents.permissions.len();
    px(440.) + px(54.) * document_count
}

fn desired_window_height(snapshot: &Snapshot, cx: &App) -> gpui::Pixels {
    let desired = match snapshot {
        Snapshot::Unsealed { contents, .. } => desired_vault_browser_height(contents) + px(210.),
        _ => px(620.),
    };
    let usable_display_height = cx.primary_display().map_or(px(820.), |display| {
        display.default_bounds().size.height - px(48.)
    });
    if desired > usable_display_height {
        usable_display_height
    } else {
        desired
    }
}

fn vault_entry_label(entry: &factorseal::VaultEntryMetadata) -> (String, String) {
    let partition = String::from_utf8_lossy(&entry.partition);
    if let Some(address) = entry.address.as_secret_spec() {
        let (label, detail) = secret_spec_address_label(address);
        return (label, format!("{partition} · {detail}"));
    }
    let Some((item, field)) = entry.address.as_local() else {
        return ("Vault item".to_owned(), partition.into_owned());
    };
    if is_personal_secret(entry) {
        return (
            item.to_owned(),
            field.map_or_else(|| "Personal secret".to_owned(), ToOwned::to_owned),
        );
    }
    if entry.document_kind == factorseal::DocumentKind::LinuxSecretService {
        (
            "System keyring item".to_owned(),
            item.strip_prefix("secret-").unwrap_or(item).to_owned(),
        )
    } else {
        let detail = field.map_or_else(
            || format!("Namespace: {partition}"),
            |field| format!("Namespace: {partition} · Field: {field}"),
        );
        (item.to_owned(), detail)
    }
}

fn vault_category_label(kind: factorseal::DocumentKind) -> &'static str {
    match kind {
        factorseal::DocumentKind::SecretSpecProject => "Project secret",
        factorseal::DocumentKind::LinuxSecretService => "System keyring",
        factorseal::DocumentKind::LocalKeyring => "Application keyring",
        factorseal::DocumentKind::SecretSpecProviderCache => "Provider cache",
        factorseal::DocumentKind::Authorization => "Access",
        _ => "Vault item",
    }
}

fn search_matches(value: &str, query: &str) -> bool {
    query.is_empty() || value.to_lowercase().contains(query)
}

fn category_matches_search(kind: factorseal::DocumentKind, title: &str, query: &str) -> bool {
    search_matches(title, query) || search_matches(vault_category_label(kind), query)
}

fn entry_matches_search(entry: &factorseal::VaultEntryMetadata, query: &str) -> bool {
    let (label, detail) = vault_entry_label(entry);
    search_matches(&label, query)
        || search_matches(&detail, query)
        || search_matches(vault_category_label(entry.document_kind), query)
}

fn category_is_visible(
    contents: &VaultContents,
    kind: factorseal::DocumentKind,
    title: &str,
    query: &str,
) -> bool {
    category_matches_search(kind, title, query)
        || contents.entries.iter().any(|entry| {
            entry.document_kind == kind
                && visible_vault_entry(entry)
                && !(kind == factorseal::DocumentKind::LocalKeyring && is_personal_secret(entry))
                && entry_matches_search(entry, query)
        })
}

fn permission_matches_search(permission: &factorseal::Permission, query: &str) -> bool {
    search_matches(&permission.principal.application_id, query)
        || permission
            .application
            .project
            .as_deref()
            .is_some_and(|project| search_matches(project, query))
        || search_matches(permission_operation_label(permission.operation), query)
}

fn vault_entry_details(entry: &factorseal::VaultEntryMetadata) -> Vec<(&'static str, String)> {
    let mut details = vec![
        (
            "Type",
            if is_personal_secret(entry) {
                "Personal secret".to_owned()
            } else {
                vault_category_label(entry.document_kind).to_owned()
            },
        ),
        (
            "Partition",
            String::from_utf8_lossy(&entry.partition).into_owned(),
        ),
    ];
    match &entry.address {
        factorseal::SecretAddress::Local { item, field } => {
            details.push(("Item", item.clone()));
            if let Some(field) = field {
                details.push(("Field", field.clone()));
            }
        }
        factorseal::SecretAddress::SecretSpec { address } => match address {
            factorseal::SecretSpecAddress::Convention {
                project,
                profile,
                key,
            } => {
                details.push(("Project", project.clone()));
                details.push(("Profile", profile.clone()));
                details.push(("Key", key.clone()));
            }
            factorseal::SecretSpecAddress::Native { coordinates } => {
                details.push(("Item", coordinates.item.clone()));
                for (label, value) in [
                    ("Field", &coordinates.field),
                    ("Vault", &coordinates.vault),
                    ("Section", &coordinates.section),
                    ("Version", &coordinates.version),
                ] {
                    if let Some(value) = value {
                        details.push((label, value.clone()));
                    }
                }
            }
        },
    }
    details
}

fn permission_operation_label(operation: factorseal::PermissionOperation) -> &'static str {
    match operation {
        factorseal::PermissionOperation::Get => "Read",
        factorseal::PermissionOperation::Put => "Write",
        factorseal::PermissionOperation::Delete => "Delete",
        factorseal::PermissionOperation::Clear => "Clear",
    }
}

struct CategoryGuidance {
    title: &'static str,
    description: &'static str,
    instructions: &'static [&'static str],
}

fn category_guidance(kind: factorseal::DocumentKind) -> CategoryGuidance {
    match kind {
        factorseal::DocumentKind::SecretSpecProject => CategoryGuidance {
            title: "Projects",
            description: "Secrets declared by your SecretSpec projects and profiles.",
            instructions: &[
                "Run secretspec init in your project directory, then declare the secrets your application needs in secretspec.toml.",
                "Store a value with secretspec set TOKEN --provider factorseal://default.",
                "Start your application with secretspec run --provider factorseal://default -- your-command.",
            ],
        },
        factorseal::DocumentKind::LinuxSecretService => CategoryGuidance {
            title: "System keyring",
            description: "Passwords saved through Linux's standard Secret Service appear here.",
            instructions: &[
                "Use the normal keyring API in your application; FactorSeal provides org.freedesktop.secrets while unsealed.",
                "On NixOS, set services.factorseal.mode = \"desktop\".",
                "Disable competing Secret Service providers such as GNOME Keyring so only one service owns the bus name.",
            ],
        },
        factorseal::DocumentKind::LocalKeyring => CategoryGuidance {
            title: "Application keyrings",
            description: "Durable, namespace-isolated credentials stored through FactorSeal's Rust API.",
            instructions: &[
                "Create a NativeVaultClient connected to the running FactorSeal endpoint.",
                "Import the factorseal::Keyring trait.",
                "Call set, get, or delete with an application-owned namespace and WireSecretAddress.",
            ],
        },
        factorseal::DocumentKind::Authorization => CategoryGuidance {
            title: "Access",
            description: "Review applications requesting or holding access to FactorSeal secrets.",
            instructions: &[
                "List: factorseal permissions list",
                "Review continuously: factorseal permissions watch --prompt",
                "Use factorseal permissions approve, deny, or revoke with the displayed permission ID.",
            ],
        },
        factorseal::DocumentKind::SecretSpecProviderCache => CategoryGuidance {
            title: "Provider cache",
            description: "Expiring local copies that make remote SecretSpec providers faster.",
            instructions: &[
                "Define factorseal = \"factorseal://default\" under [providers] in secretspec.toml.",
                "Add cache = { provider = \"factorseal\", max_age = \"8h\" } to an authoritative provider alias.",
                "Use that alias normally; run secretspec cache clear when you need to invalidate its local copies.",
            ],
        },
        _ => CategoryGuidance {
            title: "Vault items",
            description: "Items protected by FactorSeal.",
            instructions: &[],
        },
    }
}

fn category_documentation(
    kind: factorseal::DocumentKind,
) -> Option<(&'static str, &'static str, &'static str)> {
    match kind {
        factorseal::DocumentKind::SecretSpecProject => Some((
            "secretspec-projects-documentation",
            "Open the SecretSpec Quick Start",
            "https://secretspec.dev/quick-start/",
        )),
        factorseal::DocumentKind::SecretSpecProviderCache => Some((
            "secretspec-cache-documentation",
            "Read the SecretSpec provider caching guide",
            "https://secretspec.dev/concepts/providers/caching/",
        )),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VaultSelection {
    PersonalSecrets,
    Import,
    Export,
    Category(factorseal::DocumentKind),
    Entry(factorseal::VaultEntryMetadata),
    Permission(factorseal::Permission),
}

fn selection_for_search(selection: Option<&VaultSelection>) -> Option<VaultSelection> {
    match selection {
        Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => {
            Some(VaultSelection::PersonalSecrets)
        }
        Some(VaultSelection::Entry(entry)) => Some(VaultSelection::Category(entry.document_kind)),
        Some(VaultSelection::Permission(_)) => Some(VaultSelection::Category(
            factorseal::DocumentKind::Authorization,
        )),
        Some(VaultSelection::PersonalSecrets) => Some(VaultSelection::PersonalSecrets),
        Some(VaultSelection::Category(kind)) => Some(VaultSelection::Category(*kind)),
        _ => None,
    }
}

#[allow(clippy::struct_excessive_bools)]
struct DesktopView {
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    selected_group: Option<factorseal::UnlockGroup>,
    password: gpui::Entity<InputState>,
    password_confirmation: gpui::Entity<InputState>,
    vault_search: gpui::Entity<InputState>,
    personal_name: gpui::Entity<InputState>,
    personal_value: gpui::Entity<InputState>,
    archive_passphrase: gpui::Entity<InputState>,
    archive_passphrase_confirmation: gpui::Entity<InputState>,
    setup_method: SetupMethod,
    setup_error: Option<String>,
    selected_vault_item: Option<VaultSelection>,
    personal_panel: PersonalPanel,
    personal_error: Option<String>,
    transfer_format: TransferFormat,
    transfer_busy: bool,
    transfer_replace_existing: bool,
    transfer_plaintext_confirmed: bool,
    transfer_notice: Option<TransferNotice>,
    system_integrations_expanded: bool,
    _subscriptions: Vec<Subscription>,
}

impl DesktopView {
    fn security_label(&self) -> String {
        let backend = self.snapshot.metadata().map_or_else(
            || {
                if cfg!(target_os = "linux") {
                    "TPM"
                } else if cfg!(target_os = "windows") {
                    "Windows TPM"
                } else if cfg!(target_os = "macos") {
                    "Secure Enclave"
                } else {
                    "device hardware"
                }
            },
            |metadata| hardware_backend_label(metadata.hardware_backend()),
        );
        if self.snapshot.metadata().is_some() {
            format!("Protected by {backend}")
        } else {
            "About device protection".to_owned()
        }
    }

    fn new(
        runtime: Arc<DesktopRuntime>,
        snapshot: Snapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let selected_group = snapshot
            .metadata()
            .map(|metadata| metadata.preferred_unlock_group().clone());
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("FactorSeal password")
                .masked(true)
                .clean_on_escape()
        });
        let password_confirmation = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Confirm password")
                .masked(true)
                .clean_on_escape()
        });
        let vault_search = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search secrets")
                .clean_on_escape()
        });
        let personal_name = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Name")
                .clean_on_escape()
        });
        let personal_value = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Secret value")
                .masked(true)
                .clean_on_escape()
        });
        let archive_passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Archive passphrase")
                .masked(true)
                .clean_on_escape()
        });
        let archive_passphrase_confirmation = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Confirm archive passphrase")
                .masked(true)
                .clean_on_escape()
        });
        let password_submit = cx.subscribe_in(
            &password,
            window,
            |view, _, event: &InputEvent, window, cx| {
                if matches!(
                    event,
                    InputEvent::PressEnter {
                        secondary: false,
                        ..
                    }
                ) && matches!(view.snapshot, Snapshot::Sealed { .. })
                {
                    view.unlock(window, cx);
                }
            },
        );
        let vault_search_change = cx.subscribe_in(
            &vault_search,
            window,
            |view, _, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    view.selected_vault_item =
                        selection_for_search(view.selected_vault_item.as_ref());
                    cx.notify();
                }
            },
        );
        Self {
            runtime,
            snapshot,
            selected_group,
            password,
            password_confirmation,
            vault_search,
            personal_name,
            personal_value,
            archive_passphrase,
            archive_passphrase_confirmation,
            setup_method: SetupMethod::default(),
            setup_error: None,
            selected_vault_item: None,
            personal_panel: PersonalPanel::Overview,
            personal_error: None,
            transfer_format: TransferFormat::default(),
            transfer_busy: false,
            transfer_replace_existing: false,
            transfer_plaintext_confirmed: false,
            transfer_notice: None,
            system_integrations_expanded: false,
            _subscriptions: vec![password_submit, vault_search_change],
        }
    }

    fn choose_setup_method(
        &mut self,
        method: SetupMethod,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.setup_method = method;
        self.setup_error = None;
        cx.notify();
    }

    fn initialize(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Uninitialized { .. }) {
            return;
        }
        let password = self.password.read(cx).value().to_string();
        let confirmation = self.password_confirmation.read(cx).value().to_string();
        if self.setup_method.needs_password() && password.is_empty() {
            self.setup_error = Some("Choose a non-empty password.".to_owned());
            cx.notify();
            return;
        }
        if self.setup_method.needs_password() && password != confirmation {
            self.setup_error = Some("The passwords do not match.".to_owned());
            cx.notify();
            return;
        }
        if self.setup_method.needs_password()
            && let Some(error) = password_strength_error(&password)
        {
            self.setup_error = Some(error);
            cx.notify();
            return;
        }
        let policy = match self.setup_method.policy() {
            Ok(policy) => policy,
            Err(error) => {
                self.setup_error = Some(error.to_string());
                cx.notify();
                return;
            }
        };
        self.password
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.password_confirmation
            .update(cx, |input, cx| input.set_value("", window, cx));
        match self
            .runtime
            .initialize(policy, Zeroizing::new(password.into_bytes()))
        {
            Ok(()) => {
                self.setup_error = None;
                self.snapshot = Snapshot::Initializing;
            }
            Err(error) => self.setup_error = Some(error.to_owned()),
        }
        cx.notify();
    }

    fn apply_snapshot(&mut self, snapshot: Snapshot, cx: &mut Context<Self>) {
        if self.selected_group.is_none() {
            self.selected_group = snapshot
                .metadata()
                .map(|metadata| metadata.preferred_unlock_group().clone());
        }
        if !matches!(snapshot, Snapshot::Unsealed { .. }) {
            self.selected_vault_item = None;
        }
        self.snapshot = snapshot;
        cx.notify();
    }

    fn select_vault_item(&mut self, selection: VaultSelection, cx: &mut Context<Self>) {
        if matches!(selection, VaultSelection::Import | VaultSelection::Export) {
            self.transfer_notice = None;
        }
        self.selected_vault_item = Some(selection);
        cx.notify();
    }

    fn show_vault_browser(&mut self, cx: &mut Context<Self>) {
        self.selected_vault_item = None;
        cx.notify();
    }

    fn select_transfer_format(&mut self, format: TransferFormat, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        self.transfer_format = format;
        self.transfer_plaintext_confirmed = false;
        self.transfer_notice = None;
        cx.notify();
    }

    #[allow(clippy::too_many_lines)]
    fn start_transfer(&mut self, is_import: bool, window: &mut Window, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        let Snapshot::Unsealed {
            metadata, contents, ..
        } = &self.snapshot
        else {
            self.transfer_notice = Some(TransferNotice::Error(
                "Unseal the vault before transferring secrets.".to_owned(),
            ));
            cx.notify();
            return;
        };
        let metadata = metadata.clone();
        let entries = contents.entries.clone();
        let format = self.transfer_format;
        let passphrase = self.archive_passphrase.read(cx).value().to_string();
        let confirmation = self
            .archive_passphrase_confirmation
            .read(cx)
            .value()
            .to_string();
        if format.is_native() && passphrase.is_empty() {
            self.transfer_notice = Some(TransferNotice::Error(
                "Enter the archive passphrase.".to_owned(),
            ));
            cx.notify();
            return;
        }
        if !is_import && format.is_native() && passphrase != confirmation {
            self.transfer_notice = Some(TransferNotice::Error(
                "The archive passphrases do not match.".to_owned(),
            ));
            cx.notify();
            return;
        }
        if !is_import
            && format.is_native()
            && let Some(error) = password_strength_error(&passphrase)
        {
            self.transfer_notice = Some(TransferNotice::Error(error));
            cx.notify();
            return;
        }
        if !is_import && !format.is_native() && !self.transfer_plaintext_confirmed {
            self.transfer_notice = Some(TransferNotice::Error(
                "Confirm that you understand the export will contain plaintext secrets.".to_owned(),
            ));
            cx.notify();
            return;
        }

        let passphrase = Zeroizing::new(passphrase.into_bytes());
        for input in [
            &self.archive_passphrase,
            &self.archive_passphrase_confirmation,
        ] {
            input.update(cx, |input, cx| input.set_value("", window, cx));
        }
        self.transfer_busy = true;
        self.transfer_notice = None;
        let replace_existing = self.transfer_replace_existing;
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |view, cx| {
            let dialog =
                rfd::AsyncFileDialog::new().add_filter(format.label(), &[format.extension()]);
            let chosen = if is_import {
                dialog.pick_file().await
            } else {
                dialog
                    .set_file_name(format!("factorseal-export.{}", format.extension()))
                    .save_file()
                    .await
            };
            let Some(chosen) = chosen else {
                let _ = view.update(cx, |view, cx| {
                    view.transfer_busy = false;
                    cx.notify();
                });
                return;
            };
            let path = chosen.path().to_owned();
            let operation_path = path.clone();
            let result = smol::unblock(move || {
                if is_import {
                    let bytes =
                        read_transfer_file(&operation_path).map_err(|error| error.to_string())?;
                    let (summary, contents) = if format.is_native() {
                        runtime.import_native_archive(
                            &metadata,
                            &bytes,
                            &passphrase,
                            replace_existing,
                        )?
                    } else {
                        runtime.import_password_manager(
                            &metadata,
                            &bytes,
                            format,
                            replace_existing,
                        )?
                    };
                    Ok(TransferCompletion {
                        summary: Some(summary),
                        contents: Some(contents),
                        path: operation_path,
                    })
                } else {
                    let output = if format.is_native() {
                        runtime.export_native_archive(&metadata, &entries, &passphrase)?
                    } else {
                        runtime.export_password_manager(&metadata, &entries, format)?
                    };
                    write_private_file(&operation_path, &output)
                        .map_err(|error| error.to_string())?;
                    Ok(TransferCompletion {
                        summary: None,
                        contents: None,
                        path: operation_path,
                    })
                }
            })
            .await;
            let _ = view.update(cx, |view, cx| {
                view.finish_transfer(is_import, result);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_transfer(&mut self, is_import: bool, result: Result<TransferCompletion, String>) {
        self.transfer_busy = false;
        match result {
            Ok(completion) => {
                if let Some(contents) = completion.contents
                    && let Snapshot::Unsealed {
                        contents: current,
                        contents_error,
                        ..
                    } = &mut self.snapshot
                {
                    *current = contents;
                    *contents_error = None;
                }
                let message = if let Some(summary) = completion.summary {
                    format!(
                        "Imported {} items: {} added, {} replaced, {} kept existing.",
                        summary.processed(),
                        summary.added,
                        summary.replaced,
                        summary.kept_existing
                    )
                } else if is_import {
                    "Import complete.".to_owned()
                } else {
                    format!("Exported secrets to {}.", completion.path.display())
                };
                self.transfer_notice = Some(TransferNotice::Success(message));
            }
            Err(error) => {
                self.transfer_notice = Some(TransferNotice::Error(format!(
                    "{} failed: {error}",
                    if is_import { "Import" } else { "Export" }
                )));
            }
        }
    }

    fn show_personal_panel(&mut self, panel: PersonalPanel, cx: &mut Context<Self>) {
        self.personal_panel = panel;
        self.personal_error = None;
        self.selected_vault_item = Some(VaultSelection::PersonalSecrets);
        cx.notify();
    }

    fn save_personal_secret(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = self.personal_name.read(cx).value().trim().to_owned();
        let value = self.personal_value.read(cx).value().as_bytes().to_vec();
        if name.is_empty() {
            self.personal_error = Some("Give this secret a name.".to_owned());
            cx.notify();
            return;
        }
        if value.is_empty() {
            self.personal_error = Some("Enter a secret value.".to_owned());
            cx.notify();
            return;
        }
        if let Snapshot::Unsealed { contents, .. } = &self.snapshot
            && contents.entries.iter().any(|entry| {
                is_personal_secret(entry)
                    && entry
                        .address
                        .as_local()
                        .is_some_and(|(item, _)| item == name)
            })
        {
            self.personal_error =
                Some("A personal secret with this name already exists.".to_owned());
            cx.notify();
            return;
        }
        let value = Zeroizing::new(value);
        match self.runtime.put_personal_secret(name, &value) {
            Ok(updated_contents) => {
                if let Snapshot::Unsealed {
                    contents,
                    contents_error,
                    ..
                } = &mut self.snapshot
                {
                    *contents = updated_contents;
                    *contents_error = None;
                }
                for input in [&self.personal_name, &self.personal_value] {
                    input.update(cx, |input, cx| input.set_value("", window, cx));
                }
                self.personal_panel = PersonalPanel::Overview;
                self.personal_error = None;
                self.selected_vault_item = Some(VaultSelection::PersonalSecrets);
                cx.notify();
            }
            Err(error) => {
                self.personal_error = Some(format!("Could not save the secret: {error}"));
                cx.notify();
            }
        }
    }

    fn toggle_system_integrations(&mut self, cx: &mut Context<Self>) {
        self.system_integrations_expanded = !self.system_integrations_expanded;
        cx.notify();
    }

    fn choose_group(
        &mut self,
        group: factorseal::UnlockGroup,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_group = Some(group);
        cx.notify();
    }

    fn unlock(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Snapshot::Sealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        let group = self
            .selected_group
            .clone()
            .unwrap_or_else(|| metadata.preferred_unlock_group().clone());
        let password = if group.requires(factorseal::UnlockFactorKind::Password) {
            let value = self.password.read(cx).value().to_string();
            if value.is_empty() {
                self.snapshot = Snapshot::Sealed {
                    metadata,
                    error: Some("Enter the password required by this unlock method.".to_owned()),
                };
                cx.notify();
                return;
            }
            Zeroizing::new(value.into_bytes())
        } else {
            Zeroizing::new(Vec::new())
        };
        self.password.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        if let Err(error) = self
            .runtime
            .unlock(metadata.clone(), group.clone(), password)
        {
            self.snapshot = Snapshot::Sealed {
                metadata,
                error: Some(error.to_owned()),
            };
        } else {
            self.snapshot = Snapshot::Unlocking { metadata, group };
        }
        cx.notify();
    }

    fn seal(&mut self, cx: &mut Context<Self>) {
        let Snapshot::Unsealed {
            metadata,
            idle_deadline,
            absolute_deadline,
            owned,
            ..
        } = &self.snapshot
        else {
            return;
        };
        let metadata = metadata.clone();
        let idle_deadline = *idle_deadline;
        let absolute_deadline = *absolute_deadline;
        let owned = *owned;
        let (contents, contents_error) = match &self.snapshot {
            Snapshot::Unsealed {
                contents,
                contents_error,
                ..
            } => (contents.clone(), contents_error.clone()),
            _ => unreachable!("the unsealed snapshot was matched above"),
        };
        if !owned {
            self.snapshot = Snapshot::Unsealed {
                metadata,
                idle_deadline,
                absolute_deadline,
                owned,
                contents,
                contents_error,
                error: Some("Another FactorSeal process owns the unsealed vault.".to_owned()),
            };
            cx.notify();
            return;
        }

        self.snapshot = Snapshot::Sealing {
            metadata: metadata.clone(),
        };
        cx.notify();
        if let Err(error) = self.runtime.start_seal(metadata.clone()) {
            self.snapshot = Snapshot::Unsealed {
                metadata,
                idle_deadline,
                absolute_deadline,
                owned,
                contents,
                contents_error,
                error: Some(format!("Could not seal the vault: {error}")),
            };
            cx.notify();
        }
    }

    fn render_sealed(
        &self,
        metadata: &factorseal::VaultMetadata,
        error: Option<&str>,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let has_multiple_groups = metadata.unlock_policy().groups().len() > 1;
        let mut choices = h_flex().gap_2().flex_wrap();
        for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
            let selected = self.selected_group.as_ref() == Some(group);
            let chosen = group.clone();
            choices = choices.child(
                Button::new(("unlock-group", index))
                    .label(group.to_string())
                    .selected(selected)
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.choose_group(chosen.clone(), window, cx);
                    })),
            );
        }
        let needs_password = self
            .selected_group
            .as_ref()
            .unwrap_or(metadata.preferred_unlock_group())
            .requires(factorseal::UnlockFactorKind::Password);

        vault_card(&theme)
            .child(
                v_flex()
                    .items_center()
                    .gap_3()
                    .pb_2()
                    .child(brand_mark(72., theme.foreground))
                    .child(div().text_2xl().font_semibold().child("Vault is sealed"))
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .text_center()
                            .text_sm()
                            .child(
                                "Unlock to make your secrets available to authorized applications.",
                            ),
                    ),
            )
            .when(has_multiple_groups, |element| {
                element
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .child("Choose how to unlock this vault."),
                    )
                    .child(choices)
            })
            .when(needs_password, |element| {
                element.child(field_label(
                    "Password",
                    Input::new(&self.password)
                        .bg(theming::input_background(cx))
                        .mask_toggle()
                        .large(),
                ))
            })
            .when_some(error.map(str::to_owned), |element, error| {
                element.child(error_banner(error, theme.danger))
            })
            .child(
                Button::new("unlock-vault")
                    .primary()
                    .large()
                    .w_full()
                    .label(if needs_password {
                        "Unlock vault"
                    } else {
                        "Continue with biometrics"
                    })
                    .on_click(cx.listener(|view, _, window, cx| view.unlock(window, cx))),
            )
    }

    fn render_sidebar_section(
        &self,
        contents: &VaultContents,
        kind: factorseal::DocumentKind,
        title: &'static str,
        category_index: usize,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let category_matches = category_matches_search(kind, title, query);
        let entries: Vec<_> = contents
            .entries
            .iter()
            .filter(|entry| {
                entry.document_kind == kind
                    && visible_vault_entry(entry)
                    && !(kind == factorseal::DocumentKind::LocalKeyring
                        && is_personal_secret(entry))
                    && (category_matches || entry_matches_search(entry, query))
            })
            .collect();
        if !category_matches && entries.is_empty() {
            return div();
        }
        let category_selection = VaultSelection::Category(kind);
        let category_selected = self.selected_vault_item.as_ref() == Some(&category_selection);
        let integration_error = kind == factorseal::DocumentKind::LinuxSecretService
            && contents.secret_service_error.is_some();
        v_flex().gap_1().child(
            h_flex()
                .id(("vault-category", category_index))
                .w_full()
                .items_center()
                .justify_between()
                .px_3()
                .py_2()
                .rounded_lg()
                .cursor_pointer()
                .when(category_selected, |element| {
                    element
                        .bg(theme.primary)
                        .text_color(theme.primary_foreground)
                        .font_semibold()
                })
                .when(!category_selected, |element| {
                    element.hover(|style| style.bg(theme.sidebar_accent))
                })
                .child(
                    div()
                        .when(integration_error && !category_selected, |element| {
                            element.text_color(theme.danger)
                        })
                        .child(title),
                )
                .child(
                    div()
                        .min_w(px(24.))
                        .px_2()
                        .py(px(2.))
                        .rounded_full()
                        .bg(if category_selected {
                            theme.primary_foreground.opacity(0.16)
                        } else {
                            theme.background.opacity(0.65)
                        })
                        .text_sm()
                        .text_color(if category_selected {
                            theme.primary_foreground
                        } else if integration_error {
                            theme.danger
                        } else {
                            theme.muted_foreground
                        })
                        .child(if integration_error {
                            "!".to_owned()
                        } else {
                            entries.len().to_string()
                        }),
                )
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.select_vault_item(category_selection.clone(), cx);
                })),
        )
    }

    fn render_personal_secrets_sidebar(
        &self,
        contents: &VaultContents,
        query: &str,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let category_matches =
            search_matches("Personal secrets", query) || search_matches("My secrets", query);
        let entries: Vec<_> = contents
            .entries
            .iter()
            .filter(|entry| {
                is_personal_secret(entry)
                    && (category_matches || entry_matches_search(entry, query))
            })
            .collect();
        if !category_matches && entries.is_empty() {
            return div().into_any_element();
        }
        let theme = cx.theme().clone();
        let selection = VaultSelection::PersonalSecrets;
        let selected = self.selected_vault_item.as_ref() == Some(&selection);
        v_flex()
            .gap_1()
            .child(
                h_flex()
                    .id("personal-secrets-category")
                    .w_full()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .py_2()
                    .rounded_lg()
                    .cursor_pointer()
                    .when(selected, |element| {
                        element
                            .bg(theme.primary)
                            .text_color(theme.primary_foreground)
                            .font_semibold()
                    })
                    .when(!selected, |element| {
                        element.hover(|style| style.bg(theme.sidebar_accent))
                    })
                    .child("Personal secrets")
                    .child(
                        div()
                            .min_w(px(24.))
                            .px_2()
                            .py(px(2.))
                            .rounded_full()
                            .bg(if selected {
                                theme.primary_foreground.opacity(0.16)
                            } else {
                                theme.background.opacity(0.65)
                            })
                            .text_sm()
                            .text_color(if selected {
                                theme.primary_foreground
                            } else {
                                theme.muted_foreground
                            })
                            .child(entries.len().to_string()),
                    )
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.show_personal_panel(PersonalPanel::Overview, cx);
                    })),
            )
            .into_any_element()
    }

    fn render_access_sidebar(
        &self,
        contents: &VaultContents,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let category_matches = search_matches("Access", query) || search_matches("Security", query);
        let permissions: Vec<_> = contents
            .permissions
            .iter()
            .filter(|permission| category_matches || permission_matches_search(permission, query))
            .collect();
        if !category_matches && permissions.is_empty() {
            return div();
        }
        let access_selection = VaultSelection::Category(factorseal::DocumentKind::Authorization);
        let access_selected = self.selected_vault_item.as_ref() == Some(&access_selection);
        v_flex().gap_1().child(
            h_flex()
                .id("vault-access-category")
                .w_full()
                .items_center()
                .justify_between()
                .px_3()
                .py_2()
                .rounded_lg()
                .cursor_pointer()
                .when(access_selected, |element| {
                    element
                        .bg(theme.primary)
                        .text_color(theme.primary_foreground)
                        .font_semibold()
                })
                .when(!access_selected, |element| {
                    element.hover(|style| style.bg(theme.sidebar_accent))
                })
                .child("Access")
                .child(
                    div()
                        .min_w(px(24.))
                        .px_2()
                        .py(px(2.))
                        .rounded_full()
                        .bg(if access_selected {
                            theme.primary_foreground.opacity(0.16)
                        } else {
                            theme.background.opacity(0.65)
                        })
                        .text_sm()
                        .text_color(if access_selected {
                            theme.primary_foreground
                        } else {
                            theme.muted_foreground
                        })
                        .child(permissions.len().to_string()),
                )
                .on_click(cx.listener(move |view, _, _, cx| {
                    view.select_vault_item(access_selection.clone(), cx);
                })),
        )
    }

    fn render_system_integrations(
        &self,
        contents: &VaultContents,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let group_matches = search_matches("System integrations", query);
        let child_query = if group_matches { "" } else { query };
        let has_matches = [
            (
                factorseal::DocumentKind::LinuxSecretService,
                "System keyring",
            ),
            (
                factorseal::DocumentKind::LocalKeyring,
                "Application keyrings",
            ),
        ]
        .into_iter()
        .any(|(kind, title)| category_is_visible(contents, kind, title, child_query));
        if !has_matches {
            return div();
        }
        let expanded = self.system_integrations_expanded || !query.is_empty();
        v_flex()
            .gap_2()
            .child(
                h_flex()
                    .id("system-integrations-toggle")
                    .w_full()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .mt_2()
                    .mb_1()
                    .cursor_pointer()
                    .text_xs()
                    .font_semibold()
                    .text_color(theme.muted_foreground)
                    .hover(|style| style.text_color(theme.foreground))
                    .child("System integrations")
                    .child(if expanded { "⌄" } else { "›" })
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.toggle_system_integrations(cx);
                    })),
            )
            .when(expanded, |section| {
                section
                    .child(self.render_sidebar_section(
                        contents,
                        factorseal::DocumentKind::LinuxSecretService,
                        "System keyring",
                        2,
                        child_query,
                        cx,
                    ))
                    .child(self.render_sidebar_section(
                        contents,
                        factorseal::DocumentKind::LocalKeyring,
                        "Application keyrings",
                        3,
                        child_query,
                        cx,
                    ))
            })
    }

    fn render_vault_search(&self, has_query: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        div().flex_none().pr_5().child(
            Input::new(&self.vault_search)
                .bg(theming::input_background(cx))
                .prefix(search_icon(theme.muted_foreground))
                .when(has_query, |input| {
                    input.suffix(
                        div()
                            .id("clear-vault-search")
                            .p_1()
                            .rounded_sm()
                            .cursor_pointer()
                            .text_color(theme.muted_foreground)
                            .hover(|style| {
                                style.bg(theme.sidebar_accent).text_color(theme.foreground)
                            })
                            .child(close_icon(theme.muted_foreground))
                            .on_click(cx.listener(|view, _, window, cx| {
                                let search = view.vault_search.clone();
                                search.update(cx, |search, cx| {
                                    search.set_value("", window, cx);
                                });
                            })),
                    )
                })
                .small(),
        )
    }

    fn render_vault_sidebar(
        &self,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let theme = cx.theme().clone();
        let query = self.vault_search.read(cx).value().trim().to_lowercase();
        let secret_spec_matches = search_matches("SecretSpec", &query);
        let secret_spec_query = if secret_spec_matches {
            ""
        } else {
            query.as_str()
        };
        let secret_spec_visible = category_is_visible(
            contents,
            factorseal::DocumentKind::SecretSpecProject,
            "Projects",
            secret_spec_query,
        ) || category_is_visible(
            contents,
            factorseal::DocumentKind::SecretSpecProviderCache,
            "Provider cache",
            secret_spec_query,
        );
        let access_visible = search_matches("Security", &query)
            || search_matches("Access", &query)
            || contents
                .permissions
                .iter()
                .any(|permission| permission_matches_search(permission, &query));
        let group_label = |label: &'static str| {
            div()
                .px_3()
                .mt_2()
                .mb_1()
                .text_xs()
                .font_semibold()
                .text_color(theme.muted_foreground)
                .child(label)
        };
        v_flex()
            .id("vault-sidebar")
            .size_full()
            .gap_4()
            .child(self.render_vault_search(!query.is_empty(), cx))
            .child(
                div()
                    .id("vault-sidebar-results")
                    .flex_1()
                    .min_h_0()
                    .child(
                        v_flex()
                            .gap_5()
                            .pr_5()
                            .child(self.render_personal_secrets_sidebar(contents, &query, cx))
                            .when(secret_spec_visible, |sidebar| {
                                sidebar.child(
                                    v_flex()
                                        .gap_2()
                                        .child(group_label("SecretSpec"))
                                        .child(self.render_sidebar_section(
                                            contents,
                                            factorseal::DocumentKind::SecretSpecProject,
                                            "Projects",
                                            0,
                                            secret_spec_query,
                                            cx,
                                        ))
                                        .child(self.render_sidebar_section(
                                            contents,
                                            factorseal::DocumentKind::SecretSpecProviderCache,
                                            "Provider cache",
                                            1,
                                            secret_spec_query,
                                            cx,
                                        )),
                                )
                            })
                            .when(access_visible, |sidebar| {
                                sidebar.child(
                                    v_flex()
                                        .gap_2()
                                        .child(group_label("Security"))
                                        .child(self.render_access_sidebar(contents, &query, cx)),
                                )
                            })
                            .child(self.render_system_integrations(contents, &query, cx)),
                    )
                    .overflow_y_scrollbar(),
            )
    }

    fn render_detail_rows(details: Vec<(&'static str, String)>, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let mut rows = v_flex();
        for (label, value) in details {
            rows = rows.child(
                h_flex()
                    .w_full()
                    .items_start()
                    .justify_between()
                    .gap_4()
                    .py_3()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(div().text_color(theme.muted_foreground).child(label))
                    .child(div().min_w_0().text_right().font_medium().child(value)),
            );
        }
        rows
    }

    fn empty_item_rows(has_any: bool, query: &str, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        v_flex()
            .items_center()
            .gap_2()
            .px_5()
            .py_6()
            .child(div().font_semibold().child(if has_any {
                "No matching items"
            } else {
                "No items yet"
            }))
            .when(has_any && !query.is_empty(), |empty| {
                empty.child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child("Try a different search."),
                )
            })
    }

    fn render_entry_rows(
        entries: &[&factorseal::VaultEntryMetadata],
        has_any: bool,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let mut rows = v_flex()
            .w_full()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .overflow_hidden();
        for (index, entry) in entries.iter().enumerate() {
            let (label, detail) = vault_entry_label(entry);
            let selection = VaultSelection::Entry((*entry).clone());
            rows = rows.child(
                h_flex()
                    .id(("secret-row", index))
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .px_4()
                    .py_3()
                    .when(index > 0, |row| row.border_t_1().border_color(theme.border))
                    .cursor_pointer()
                    .hover(|style| style.bg(theme.muted))
                    .child(
                        v_flex()
                            .min_w_0()
                            .gap_1()
                            .child(div().font_semibold().child(label))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child(detail),
                            ),
                    )
                    .child(
                        div()
                            .flex_none()
                            .text_color(theme.muted_foreground)
                            .child("›"),
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.select_vault_item(selection.clone(), cx);
                    })),
            );
        }
        if entries.is_empty() {
            rows = rows.child(Self::empty_item_rows(has_any, query, cx));
        }
        rows
    }

    fn render_permission_rows(
        permissions: &[&factorseal::Permission],
        has_any: bool,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let mut rows = v_flex()
            .w_full()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .overflow_hidden();
        for (index, permission) in permissions.iter().enumerate() {
            let application = permission
                .application
                .project
                .as_deref()
                .unwrap_or(&permission.principal.application_id)
                .to_owned();
            let selection = VaultSelection::Permission((*permission).clone());
            rows = rows.child(
                h_flex()
                    .id(("permission-row", index))
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .px_4()
                    .py_3()
                    .when(index > 0, |row| row.border_t_1().border_color(theme.border))
                    .cursor_pointer()
                    .hover(|style| style.bg(theme.muted))
                    .child(
                        v_flex()
                            .min_w_0()
                            .gap_1()
                            .child(div().font_semibold().child(application))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child(permission_operation_label(permission.operation)),
                            ),
                    )
                    .child(
                        div()
                            .flex_none()
                            .text_color(theme.muted_foreground)
                            .child("›"),
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.select_vault_item(selection.clone(), cx);
                    })),
            );
        }
        if permissions.is_empty() {
            rows = rows.child(Self::empty_item_rows(has_any, query, cx));
        }
        rows
    }

    fn render_category_instructions(guidance: &CategoryGuidance, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let mut instructions = v_flex().gap_2();
        for (index, instruction) in guidance.instructions.iter().enumerate() {
            instructions = instructions.child(
                h_flex()
                    .w_full()
                    .items_start()
                    .gap_3()
                    .p_3()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.popover)
                    .child(
                        h_flex()
                            .flex_none()
                            .w(px(24.))
                            .h(px(24.))
                            .items_center()
                            .justify_center()
                            .rounded_full()
                            .bg(theme.primary)
                            .text_color(theme.primary_foreground)
                            .text_sm()
                            .font_semibold()
                            .child(format!("{}.", index + 1)),
                    )
                    .child(div().flex_1().child(*instruction)),
            );
        }
        instructions
    }

    fn render_category_detail(
        &self,
        kind: factorseal::DocumentKind,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let guidance = category_guidance(kind);
        let query = self.vault_search.read(cx).value().trim().to_lowercase();
        let (item_count, item_rows) = if kind == factorseal::DocumentKind::Authorization {
            let permissions: Vec<_> = contents
                .permissions
                .iter()
                .filter(|permission| permission_matches_search(permission, &query))
                .collect();
            (
                contents.permissions.len(),
                Self::render_permission_rows(
                    &permissions,
                    !contents.permissions.is_empty(),
                    &query,
                    cx,
                ),
            )
        } else {
            let all_entries: Vec<_> = contents
                .entries
                .iter()
                .filter(|entry| {
                    entry.document_kind == kind
                        && visible_vault_entry(entry)
                        && !(kind == factorseal::DocumentKind::LocalKeyring
                            && is_personal_secret(entry))
                })
                .collect();
            let entries: Vec<_> = all_entries
                .iter()
                .copied()
                .filter(|entry| entry_matches_search(entry, &query))
                .collect();
            (
                all_entries.len(),
                Self::render_entry_rows(&entries, !all_entries.is_empty(), &query, cx),
            )
        };
        let instructions = Self::render_category_instructions(&guidance, cx);
        let integration_error = if kind == factorseal::DocumentKind::LinuxSecretService {
            contents.secret_service_error.clone()
        } else {
            None
        };
        div().size_full().child(
            v_flex()
                .id("vault-category-detail")
                .size_full()
                .gap_4()
                .p_6()
                .overflow_y_scroll()
                .child(
                    h_flex()
                        .w_full()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(div().text_xl().font_semibold().child(guidance.title))
                        .child(
                            div()
                                .flex_none()
                                .px_3()
                                .py_1()
                                .rounded_full()
                                .bg(theme.muted)
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(format!(
                                    "{item_count} {}",
                                    if item_count == 1 { "item" } else { "items" }
                                )),
                        ),
                )
                .child(
                    div()
                        .text_color(theme.muted_foreground)
                        .child(guidance.description),
                )
                .when_some(integration_error, |element, error| {
                    element.child(error_banner(error, theme.danger))
                })
                .child(div().font_semibold().child("Items"))
                .child(item_rows)
                .child(div().font_semibold().child("How to use it"))
                .child(instructions)
                .when_some(category_documentation(kind), |element, (id, label, url)| {
                    element.child(
                        h_flex()
                            .pt_1()
                            .child(Link::new(id).href(url).child(format!("{label} ↗"))),
                    )
                }),
        )
    }

    fn render_personal_overview(
        contents: &VaultContents,
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let entries: Vec<_> = contents
            .entries
            .iter()
            .filter(|entry| is_personal_secret(entry))
            .filter(|entry| entry_matches_search(entry, query))
            .collect();
        let has_any = contents.entries.iter().any(is_personal_secret);
        Self::render_entry_rows(&entries, has_any, query, cx)
    }

    fn render_personal_new_item(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        v_flex()
            .gap_4()
            .p_5()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .child(div().font_semibold().child("New personal secret"))
            .child(field_label(
                "Name",
                Input::new(&self.personal_name).bg(theming::input_background(cx)),
            ))
            .child(field_label(
                "Secret value",
                Input::new(&self.personal_value)
                    .bg(theming::input_background(cx))
                    .mask_toggle(),
            ))
            .when_some(self.personal_error.clone(), |panel, error| {
                panel.child(error_banner(error, theme.danger))
            })
            .child(
                h_flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("cancel-personal-secret")
                            .label("Cancel")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.show_personal_panel(PersonalPanel::Overview, cx);
                            })),
                    )
                    .child(
                        Button::new("save-personal-secret")
                            .primary()
                            .label("Save item")
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.save_personal_secret(window, cx);
                            })),
                    ),
            )
    }

    #[allow(clippy::too_many_lines)]
    fn render_transfer_detail(&self, is_import: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let description = if is_import {
            "Restore a FactorSeal backup or bring personal items from another password manager."
        } else {
            "Create an encrypted FactorSeal backup or migrate personal items to another password manager."
        };
        let format = self.transfer_format;
        let replace_control = {
            let view = cx.entity().downgrade();
            Checkbox::new("replace-import-conflicts")
                .checked(self.transfer_replace_existing)
                .label("Replace vault items with the same name or address")
                .disabled(self.transfer_busy)
                .on_click(move |checked, _, cx| {
                    let _ = view.update(cx, |view, cx| {
                        view.transfer_replace_existing = *checked;
                        view.transfer_notice = None;
                        cx.notify();
                    });
                })
        };
        let plaintext_control = {
            let view = cx.entity().downgrade();
            Checkbox::new("confirm-plaintext-export")
                .checked(self.transfer_plaintext_confirmed)
                .label("I understand this file will contain readable secrets")
                .disabled(self.transfer_busy)
                .on_click(move |checked, _, cx| {
                    let _ = view.update(cx, |view, cx| {
                        view.transfer_plaintext_confirmed = *checked;
                        view.transfer_notice = None;
                        cx.notify();
                    });
                })
        };
        let mut form =
            v_flex().w_full().min_w_0().gap_5().child(
                h_flex().gap_2().flex_wrap().children(
                    TransferFormat::ALL
                        .into_iter()
                        .enumerate()
                        .map(|(index, candidate)| {
                            Button::new(("transfer-format", index))
                                .selected(format == candidate)
                                .disabled(self.transfer_busy)
                                .label(candidate.label())
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.select_transfer_format(candidate, cx);
                                }))
                        }),
                ),
            );
        if format.is_native() {
            form = form.child(
                v_flex()
                    .gap_3()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.popover)
                    .child(
                        div()
                            .font_semibold()
                            .child("Encrypted FactorSeal archive"),
                    )
                    .child(
                        div()
                            .w_full()
                            .whitespace_normal()
                            .text_color(theme.muted_foreground)
                            .child(if is_import {
                                "Enter the separate passphrase used when this backup was created. Restored data is encrypted again using this device's TPM."
                            } else {
                                "Includes durable vault items, but not provider caches, application authorizations, history, or device keys. Choose a separate passphrase for this portable backup."
                            }),
                    )
                    .child(field_label("Archive passphrase", Input::new(&self.archive_passphrase).bg(theming::input_background(cx)).mask_toggle()))
                    .when(!is_import, |panel| {
                        panel.child(
                            field_label("Confirm archive passphrase", Input::new(&self.archive_passphrase_confirmation).bg(theming::input_background(cx)).mask_toggle()),
                        )
                    }),
            );
        } else {
            form = form.child(
                v_flex()
                    .gap_3()
                    .p_5()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.popover)
                    .child(div().font_semibold().child(format.label()))
                    .child(
                        div()
                            .w_full()
                            .whitespace_normal()
                            .text_color(theme.muted_foreground)
                            .child(if is_import {
                                "Only Personal secrets are imported. Login fields, URLs, one-time-password seeds, notes, and supported metadata are mapped into FactorSeal."
                            } else {
                                "Only Personal secrets are exported. Password-manager interchange files are plaintext and are not protected by FactorSeal after they are written."
                            }),
                    )
                    .when(!is_import, |panel| panel.child(plaintext_control)),
            );
        }
        if is_import {
            form = form.child(replace_control);
        }
        form = form
            .when_some(self.transfer_notice.clone(), |form, notice| match notice {
                TransferNotice::Success(message) => form.child(
                    div()
                        .w_full()
                        .px_4()
                        .py_3()
                        .rounded_lg()
                        .bg(theme.secondary)
                        .child(message),
                ),
                TransferNotice::Error(message) => form.child(error_banner(message, theme.danger)),
            })
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_end()
                    .gap_3()
                    .when(self.transfer_busy, |row| {
                        row.child(
                            h_flex()
                                .gap_2()
                                .text_color(theme.muted_foreground)
                                .child(Spinner::new().small())
                                .child(if is_import {
                                    "Importing and securing…"
                                } else {
                                    "Preparing export…"
                                }),
                        )
                    })
                    .child(
                        Button::new(if is_import {
                            "start-secret-import"
                        } else {
                            "start-secret-export"
                        })
                        .primary()
                        .disabled(self.transfer_busy)
                        .label(if is_import {
                            "Choose file and import"
                        } else {
                            "Choose location and export"
                        })
                        .on_click(cx.listener(
                            move |view, _, window, cx| {
                                view.start_transfer(is_import, window, cx);
                            },
                        )),
                    ),
            );

        div().size_full().child(
            v_flex()
                .w_full()
                .min_w_0()
                .max_w(px(820.))
                .gap_4()
                .p_6()
                .child(div().text_color(theme.muted_foreground).child(description))
                .child(form),
        )
    }

    fn render_personal_secrets_detail(
        &self,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let query = self.vault_search.read(cx).value().trim().to_lowercase();
        let body = match self.personal_panel {
            PersonalPanel::Overview => Self::render_personal_overview(contents, &query, cx),
            PersonalPanel::NewItem => self.render_personal_new_item(cx),
        };
        v_flex()
            .size_full()
            .gap_4()
            .p_6()
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(div().text_xl().font_semibold().child("Personal secrets"))
                    .child(
                        Button::new("new-personal-secret")
                            .small()
                            .primary()
                            .label("New item")
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.show_personal_panel(PersonalPanel::NewItem, cx);
                            })),
                    ),
            )
            .child(
                div().text_color(theme.muted_foreground).child(
                    "Credentials and private information you manage directly in FactorSeal.",
                ),
            )
            .child(body)
    }

    fn render_vault_detail(&self, contents: &VaultContents, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let entry_count = contents
            .entries
            .iter()
            .filter(|entry| visible_vault_entry(entry))
            .count();
        match &self.selected_vault_item {
            None => v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_4()
                .p_8()
                .child(brand_mark(64., theme.foreground))
                .child(
                    div()
                        .text_2xl()
                        .font_semibold()
                        .child("Welcome to your vault"),
                )
                .child(
                    div()
                        .max_w(px(420.))
                        .text_center()
                        .text_color(theme.muted_foreground)
                        .child(if entry_count == 0 {
                            "Choose a secret type on the left to get started."
                        } else {
                            "Choose an item on the left to see its details."
                        }),
                ),
            Some(VaultSelection::PersonalSecrets) => {
                self.render_personal_secrets_detail(contents, cx)
            }
            Some(VaultSelection::Import) => self.render_transfer_detail(true, cx),
            Some(VaultSelection::Export) => self.render_transfer_detail(false, cx),
            Some(VaultSelection::Category(kind)) => {
                self.render_category_detail(*kind, contents, cx)
            }
            Some(VaultSelection::Entry(entry)) => {
                let (title, _) = vault_entry_label(entry);
                v_flex()
                    .size_full()
                    .gap_4()
                    .p_6()
                    .child(div().text_xl().font_semibold().child(title))
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .child("Secret value hidden"),
                    )
                    .child(Self::render_detail_rows(vault_entry_details(entry), cx))
            }
            Some(VaultSelection::Permission(permission)) => {
                let application = permission
                    .application
                    .project
                    .as_deref()
                    .unwrap_or(&permission.principal.application_id)
                    .to_owned();
                let state = match permission.state {
                    factorseal::PermissionState::Pending { .. } => "Pending",
                    factorseal::PermissionState::Granted { .. } => "Granted",
                };
                let mut details = vec![
                    ("Type", "Application access".to_owned()),
                    (
                        "Operation",
                        permission_operation_label(permission.operation).to_owned(),
                    ),
                    ("State", state.to_owned()),
                    (
                        "Application ID",
                        permission.principal.application_id.clone(),
                    ),
                ];
                if let Some(project) = &permission.application.project {
                    details.push(("Project", project.clone()));
                }
                v_flex()
                    .size_full()
                    .gap_4()
                    .p_6()
                    .child(div().text_xl().font_semibold().child(application))
                    .child(Self::render_detail_rows(details, cx))
            }
        }
    }

    fn render_vault_breadcrumb(&self, cx: &mut Context<Self>) -> Div {
        let title = match self.selected_vault_item.as_ref() {
            Some(VaultSelection::Import) => Some("Import"),
            Some(VaultSelection::Export) => Some("Export"),
            _ => None,
        };
        let theme = cx.theme();
        if let Some(title) = title {
            h_flex()
                .items_center()
                .gap_2()
                .text_2xl()
                .font_semibold()
                .child(
                    div()
                        .id("vault-breadcrumb")
                        .cursor_pointer()
                        .hover(|style| style.text_color(theme.muted_foreground))
                        .child("Your vault")
                        .on_click(cx.listener(|view, _, _, cx| {
                            view.show_vault_browser(cx);
                        })),
                )
                .child(div().text_color(theme.muted_foreground).child("←"))
                .child(title)
        } else {
            h_flex().text_2xl().font_semibold().child("Your vault")
        }
    }

    fn render_unsealed(
        &self,
        contents: &VaultContents,
        errors: (Option<&str>, Option<&str>),
        browser_height: gpui::Pixels,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let (contents_error, error) = errors;
        let transfer_selected = matches!(
            self.selected_vault_item.as_ref(),
            Some(VaultSelection::Import | VaultSelection::Export)
        );
        let header_title = self.render_vault_breadcrumb(cx);
        v_flex()
            .gap_5()
            .child(
                h_flex()
                    .w_full()
                    .items_end()
                    .justify_between()
                    .gap_4()
                    .child(
                        v_flex().gap_1().child(header_title).child(
                            div()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child("On this device. Available to authorized applications."),
                        ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("import-vault")
                                    .small()
                                    .selected(
                                        self.selected_vault_item.as_ref()
                                            == Some(&VaultSelection::Import),
                                    )
                                    .label("Import")
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.select_vault_item(VaultSelection::Import, cx);
                                    })),
                            )
                            .child(
                                Button::new("export-vault")
                                    .small()
                                    .selected(
                                        self.selected_vault_item.as_ref()
                                            == Some(&VaultSelection::Export),
                                    )
                                    .label("Export")
                                    .on_click(cx.listener(|view, _, _, cx| {
                                        view.select_vault_item(VaultSelection::Export, cx);
                                    })),
                            ),
                    ),
            )
            .child(
                h_flex()
                    .w_full()
                    .h(browser_height)
                    .rounded_xl()
                    .border_1()
                    .border_color(theme.border)
                    .overflow_hidden()
                    .bg(theme.popover)
                    .when(!transfer_selected, |workspace| {
                        workspace.child(
                            div()
                                .w(px(232.))
                                .flex_none()
                                .h_full()
                                .pl_5()
                                .py_5()
                                .bg(theme.sidebar)
                                .border_r_1()
                                .border_color(theme.sidebar_border)
                                .child(self.render_vault_sidebar(contents, cx)),
                        )
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .child(self.render_vault_detail(contents, cx)),
                    ),
            )
            .when_some(contents_error.map(str::to_owned), |element, error| {
                element.child(
                    div()
                        .text_color(theme.danger)
                        .child(format!("Could not load vault contents: {error}")),
                )
            })
            .when_some(error.map(str::to_owned), |element, error| {
                element.child(div().text_color(theme.danger).child(error))
            })
    }

    fn render_header_status(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let theme = cx.theme();
        match &self.snapshot {
            Snapshot::Unsealed {
                idle_deadline,
                absolute_deadline,
                owned,
                ..
            } => {
                let tooltip = format!(
                    "Idle deadline: {idle_deadline}\nAbsolute deadline: {absolute_deadline}"
                );
                Some(
                    h_flex()
                        .id("unsealed-control")
                        .flex_none()
                        .items_center()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.border)
                        .overflow_hidden()
                        .child(
                            h_flex()
                                .id("unsealed-status")
                                .items_center()
                                .gap_2()
                                .px_3()
                                .py_2()
                                .text_color(theme.muted_foreground)
                                .text_sm()
                                .font_semibold()
                                .child(div().w(px(8.)).h(px(8.)).rounded_full().bg(theme.success))
                                .child("Vault is unsealed")
                                .tooltip(move |window, cx| {
                                    Tooltip::new(tooltip.clone()).build(window, cx)
                                }),
                        )
                        .child(
                            div()
                                .id("seal-vault")
                                .flex()
                                .items_center()
                                .px_3()
                                .py_2()
                                .border_l_1()
                                .border_color(theme.border)
                                .bg(theme.muted)
                                .text_sm()
                                .font_semibold()
                                .child("Seal now")
                                .when(*owned, |action| {
                                    action
                                        .cursor_pointer()
                                        .hover(|style| style.bg(theme.sidebar_accent))
                                        .on_click(cx.listener(|view, _, _, cx| view.seal(cx)))
                                })
                                .when(!*owned, |action| action.text_color(theme.muted_foreground)),
                        )
                        .into_any_element(),
                )
            }
            _ => None,
        }
    }

    fn render_uninitialized(&self, runtime_error: Option<&str>, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let mut methods = h_flex().gap_2().flex_wrap();
        #[cfg(target_os = "linux")]
        let available = [SetupMethod::Password];
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        let available = [
            SetupMethod::Password,
            SetupMethod::Biometric,
            SetupMethod::PasswordAndBiometric,
            SetupMethod::PasswordOrBiometric,
        ];
        let has_multiple_methods = available.len() > 1;
        for (index, method) in available.into_iter().enumerate() {
            methods = methods.child(
                Button::new(("setup-method", index))
                    .label(method.label())
                    .selected(self.setup_method == method)
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.choose_setup_method(method, window, cx);
                    })),
            );
        }

        vault_card(theme)
            .child(
                v_flex()
                    .items_center()
                    .gap_3()
                    .pb_2()
                    .child(brand_mark(72., theme.foreground))
                    .child(
                        div()
                            .text_2xl()
                            .font_semibold()
                            .child("Create your vault"),
                    )
                    .child(
                        div()
                            .text_center()
                            .text_color(theme.muted_foreground)
                            .text_sm()
                            .child("A local home for your secrets, applications, and projects."),
                    ),
            )
            .child(
                div()
                    .w_full()
                    .px_4()
                    .py_3()
                    .rounded_lg()
                    .bg(theme.muted)
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(setup_protection_description()),
            )
            .when(has_multiple_methods, |element| element.child(methods))
            .when(cfg!(target_os = "linux"), |element| {
                element
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(
                                "Unlock with a password on Linux. Biometric unlock is not available on this platform.",
                            ),
                    )
                    .child(
                        Link::new("security-link")
                            .href("https://factorseal.dev/security")
                            .child("How device protection works"),
                    )
            })
            .when(self.setup_method.needs_password(), |element| {
                element
                    .child(field_label("Password", Input::new(&self.password).bg(theming::input_background(cx)).mask_toggle().large()))
                    .child(field_label("Confirm password", Input::new(&self.password_confirmation).bg(theming::input_background(cx)).mask_toggle().large()))
            })
            .when_some(self.setup_error.clone(), |element, error| {
                element.child(error_banner(error, theme.danger))
            })
            .when_some(runtime_error.map(str::to_owned), |element, error| {
                element.child(error_banner(error, theme.danger))
            })
            .child(
                Button::new("initialize-vault")
                    .primary()
                    .large()
                    .w_full()
                    .label("Create vault")
                    .on_click(cx.listener(|view, _, window, cx| view.initialize(window, cx))),
            )
    }

    fn render_body(&self, browser_height: gpui::Pixels, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        match &self.snapshot {
            Snapshot::Uninitialized { error } => self.render_uninitialized(error.as_deref(), cx),
            Snapshot::Initializing => vault_card(&theme)
                .items_center()
                .text_center()
                .child(brand_mark(56., theme.foreground))
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_2xl().font_semibold().child("Creating vault…"))
                .child(
                    div()
                        .text_color(theme.muted_foreground)
                        .text_sm()
                        .child("Protecting your vault with this device's hardware."),
                ),
            Snapshot::Sealed { metadata, error } => {
                self.render_sealed(metadata, error.as_deref(), cx)
            }
            Snapshot::Unlocking { group, .. } => {
                vault_card(&theme)
                    .items_center()
                    .text_center()
                    .child(brand_mark(56., theme.foreground))
                    .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                    .child(
                        div()
                            .text_2xl()
                            .font_semibold()
                            .child("Unlocking your vault…"),
                    )
                    .child(
                        div().text_sm().text_color(theme.muted_foreground).child(
                            "FactorSeal’s secure unlock process normally takes a few seconds.",
                        ),
                    )
                    .when(
                        group.requires(factorseal::UnlockFactorKind::Biometric),
                        |element| {
                            element.child(
                                div().text_sm().text_color(theme.muted_foreground).child(
                                    "Complete the device authorization prompt if one appears.",
                                ),
                            )
                        },
                    )
            }
            Snapshot::Sealing { .. } => vault_card(&theme)
                .items_center()
                .text_center()
                .child(brand_mark(56., theme.foreground))
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_2xl().font_semibold().child("Sealing vault…"))
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child("Closing access and removing vault keys from memory."),
                ),
            Snapshot::Unsealed {
                contents,
                contents_error,
                error,
                ..
            } => self.render_unsealed(
                contents,
                (contents_error.as_deref(), error.as_deref()),
                browser_height,
                cx,
            ),
            Snapshot::Error(error) => vault_card(&theme)
                .items_center()
                .child(brand_mark(56., theme.foreground))
                .child(div().text_2xl().font_semibold().child("Vault unavailable"))
                .child(
                    div()
                        .text_center()
                        .text_color(theme.danger)
                        .child(error.clone()),
                ),
        }
    }
}

impl Render for DesktopView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let header_status = self.render_header_status(cx);
        let security_label = self.security_label();
        let unsealed = matches!(self.snapshot, Snapshot::Unsealed { .. });
        let body_max_width = match &self.snapshot {
            Snapshot::Unsealed { .. } => 1200.,
            Snapshot::Uninitialized { .. } => 520.,
            _ => 440.,
        };
        let available_browser_height = window.viewport_size().height - px(272.);
        let browser_height = if available_browser_height < px(320.) {
            px(320.)
        } else {
            available_browser_height
        };
        v_flex()
            .size_full()
            .px_6()
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .text_size(theme.font_size)
            .child(
                h_flex()
                    .w_full()
                    .flex_none()
                    .h(px(80.))
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(brand_mark(36., theme.foreground))
                            .child(div().text_size(px(23.)).font_semibold().child("FactorSeal")),
                    )
                    .when_some(header_status, gpui::ParentElement::child),
            )
            .child(
                div()
                    .id("desktop-content-scroll")
                    .flex_1()
                    .min_h_0()
                    .w_full()
                    .child(
                        div()
                            .w_full()
                            .min_h_full()
                            .py_8()
                            .flex()
                            .justify_center()
                            .when(!unsealed, gpui::Styled::items_center)
                            .child(
                                div()
                                    .w_full()
                                    .max_w(px(body_max_width))
                                    .flex_none()
                                    .child(self.render_body(browser_height, cx)),
                            ),
                    )
                    .overflow_y_scrollbar(),
            )
            .child(
                h_flex()
                    .w_full()
                    .flex_none()
                    .h(px(48.))
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .border_t_1()
                    .border_color(theme.border)
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(branding::TAGLINE)
                    .child(
                        Link::new("footer-security-link")
                            .href("https://factorseal.dev/security")
                            .child(security_label),
                    ),
            )
    }
}

fn forget_desktop_window(handle: AnyWindowHandle, cx: &mut App) -> bool {
    let desktop = cx.global_mut::<DesktopWindow>();
    if desktop.handle != Some(handle) {
        return false;
    }
    desktop.handle = None;
    desktop.visible = false;
    if let Ok(mut view) = desktop.view.lock() {
        view.take();
    }
    true
}

fn apply_desktop_snapshot(snapshot: &Snapshot, cx: &mut App) {
    let window_height = desired_window_height(snapshot, cx);
    let (handle, view_holder) = {
        let desktop = cx.global_mut::<DesktopWindow>();
        desktop.snapshot = snapshot.clone();
        desktop.refresh_generation = desktop.refresh_generation.wrapping_add(1);
        (desktop.handle, Arc::clone(&desktop.view))
    };

    if let Some(handle) = handle {
        let _ = handle.update(cx, |_, window, _| {
            window.resize(size(px(1040.), window_height));
        });
    }
    if let Ok(holder) = view_holder.lock()
        && let Some(view) = holder.as_ref()
    {
        view.update(cx, |view, cx| view.apply_snapshot(snapshot.clone(), cx));
    }
    cx.global_mut::<DesktopStatus>().unsealed = matches!(snapshot, Snapshot::Unsealed { .. });
    refresh_tray(cx);
    if matches!(snapshot, Snapshot::Unsealed { .. }) {
        crate::timing::finish_unlock("ui_updated", "ok");
    }
}

fn refresh_desktop_snapshot(runtime: Arc<DesktopRuntime>, cx: &mut App) {
    let generation = {
        let desktop = cx.global_mut::<DesktopWindow>();
        desktop.refresh_generation = desktop.refresh_generation.wrapping_add(1);
        desktop.refresh_generation
    };
    cx.spawn(async move |cx| {
        let snapshot = smol::unblock(move || runtime.inspect()).await;
        cx.update(|cx| {
            if cx.global::<DesktopWindow>().refresh_generation == generation {
                apply_desktop_snapshot(&snapshot, cx);
            }
        });
    })
    .detach();
}

fn open_desktop(_: &OpenDesktop, cx: &mut App) {
    let existing = cx.global::<DesktopWindow>().handle;
    if let Some(handle) = existing {
        if handle
            .update(cx, |_, window, _| {
                window.set_visible(true);
                window.activate_window();
            })
            .is_ok()
        {
            cx.global_mut::<DesktopWindow>().visible = true;
            refresh_tray(cx);
            let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
            refresh_desktop_snapshot(runtime, cx);
            return;
        }
        forget_desktop_window(handle, cx);
    }

    let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
    {
        let desktop = cx.global::<DesktopWindow>();
        let view = Arc::clone(&desktop.view);
        let snapshot = desktop.snapshot.clone();
        match open_desktop_window(Arc::clone(&runtime), snapshot, view, true, cx) {
            Ok(handle) => {
                let desktop = cx.global_mut::<DesktopWindow>();
                desktop.handle = Some(handle);
                desktop.visible = true;
            }
            Err(error) => {
                eprintln!("failed to open FactorSeal Desktop: {error}");
                return;
            }
        }
    }
    refresh_tray(cx);
    refresh_desktop_snapshot(runtime, cx);
}

fn close_desktop(_: &CloseDesktop, cx: &mut App) {
    let handle = cx.global::<DesktopWindow>().handle;
    let Some(handle) = handle else {
        return;
    };
    cx.global_mut::<DesktopWindow>().visible = false;
    refresh_tray(cx);
    cx.defer(move |cx| {
        if let Err(error) = handle.update(cx, |_, window, _| window.set_visible(false)) {
            forget_desktop_window(handle, cx);
            refresh_tray(cx);
            eprintln!("failed to hide FactorSeal Desktop window: {error}");
        }
    });
}

fn toggle_desktop(_: &ToggleDesktop, cx: &mut App) {
    if cx.global::<DesktopWindow>().visible {
        close_desktop(&CloseDesktop, cx);
    } else {
        open_desktop(&OpenDesktop, cx);
    }
}

fn seal_vault(_: &SealVault, cx: &mut App) {
    if let Some(runtime) = cx.try_global::<RuntimeGlobal>()
        && let Err(error) = runtime.0.seal()
    {
        eprintln!("failed to seal FactorSeal vault: {error}");
    }
}

fn quit(_: &Quit, cx: &mut App) {
    cx.global_mut::<DesktopStatus>().quitting = true;
    if let Some(runtime) = cx.try_global::<RuntimeGlobal>() {
        let _ = runtime.0.seal();
    }
    let tray = cx.try_global::<DesktopTray>().map(|tray| tray.0.clone());
    if let Some(tray) = tray
        && let Err(error) = tray.close(cx)
    {
        eprintln!("failed to close FactorSeal tray: {error}");
    }
    cx.quit();
}

fn tray_menu(cx: &mut App) -> Vec<MenuItem> {
    let status = cx.global::<DesktopStatus>();
    let window_visible = cx.global::<DesktopWindow>().visible;
    let desktop_label = if window_visible {
        "Close Desktop"
    } else if status.unsealed {
        "Open Desktop"
    } else {
        "Unseal"
    };
    let mut items = if window_visible {
        vec![MenuItem::action(desktop_label, CloseDesktop)]
    } else {
        vec![MenuItem::action(desktop_label, OpenDesktop)]
    };
    if status.unsealed {
        items.push(MenuItem::action("Seal", SealVault));
    }
    items.push(MenuItem::separator());
    items.push(MenuItem::action("Quit", Quit));
    items
}

fn refresh_tray(cx: &mut App) {
    let tray = cx.try_global::<DesktopTray>().map(|tray| tray.0.clone());
    if let Some(tray) = tray
        && let Err(error) = tray.refresh_menu(cx)
    {
        eprintln!("failed to refresh FactorSeal tray menu: {error}");
    }
}

fn factorseal_icon(dark_background: bool, cx: &App) -> gpui_tray::Result<Icon> {
    // Generated from the same optical master as the Linux symbolic icons.
    let bytes: &[u8] = if dark_background {
        include_bytes!("../../assets/logo/factorseal-tray-paper.png")
    } else {
        include_bytes!("../../assets/logo/factorseal-tray-ink.png")
    };
    let image = gpui::Image::from_bytes(gpui::ImageFormat::Png, bytes.to_vec());
    Icon::from_gpui(&image, cx)
}

fn install_tray(cx: &mut App) {
    let dark_background = gpui_component::Theme::global(cx).is_dark();
    let tray = factorseal_icon(dark_background, cx).and_then(|icon| {
        Tray::builder()
            .icon(icon)
            .title("FactorSeal")
            .tooltip("FactorSeal vault")
            .on_activate(ToggleDesktop)
            .menu(tray_menu)
            .build(cx)
    });
    match tray {
        Ok(tray) => cx.set_global(DesktopTray(tray)),
        Err(error) => eprintln!("FactorSeal tray unavailable: {error}"),
    }
}

pub(crate) fn refresh_tray_icon(cx: &mut App) {
    let tray = cx.try_global::<DesktopTray>().map(|tray| tray.0.clone());
    let Some(tray) = tray else {
        return;
    };
    let dark_background = gpui_component::Theme::global(cx).is_dark();
    match factorseal_icon(dark_background, cx) {
        Ok(icon) => {
            if let Err(error) = tray.set_icon(Some(icon), cx) {
                eprintln!("failed to refresh FactorSeal tray bitmap: {error}");
            }
        }
        Err(error) => eprintln!("failed to render FactorSeal tray bitmap: {error}"),
    }
}

fn open_desktop_window(
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    view_holder: Arc<std::sync::Mutex<Option<gpui::Entity<DesktopView>>>>,
    visible: bool,
    cx: &mut App,
) -> anyhow::Result<AnyWindowHandle> {
    let initial_height = desired_window_height(&snapshot, cx);
    let bounds = Bounds::centered(None, size(px(1040.0), initial_height), cx);
    let handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(size(px(640.), px(480.))),
            titlebar: Some(gpui::TitlebarOptions {
                title: Some("FactorSeal Desktop".into()),
                ..Default::default()
            }),
            app_id: Some("dev.factorseal.Desktop".to_owned()),
            show: visible,
            ..Default::default()
        },
        move |window, cx| {
            window.on_window_should_close(cx, |window, cx| {
                if cx.global::<DesktopStatus>().no_tray {
                    quit(&Quit, cx);
                    return true;
                }
                if cx.global::<DesktopStatus>().quitting {
                    return true;
                }
                window.set_visible(false);
                cx.global_mut::<DesktopWindow>().visible = false;
                refresh_tray(cx);
                false
            });
            let view = cx.new(|cx| DesktopView::new(Arc::clone(&runtime), snapshot, window, cx));
            if let Ok(mut holder) = view_holder.lock() {
                *holder = Some(view.clone());
            }
            cx.new(|cx| Root::new(view, window, cx))
        },
    )?;
    Ok(handle.into())
}

pub(crate) fn setup(
    config: RuntimeConfig,
    background: bool,
    no_tray: bool,
    activations: smol::channel::Receiver<()>,
    cx: &mut App,
) {
    gpui_component::init(cx);
    theming::initialize(cx);
    cx.on_action(open_desktop);
    cx.on_action(close_desktop);
    cx.on_action(toggle_desktop);
    cx.on_action(seal_vault);
    cx.on_action(quit);

    let (runtime, receiver) = DesktopRuntime::new(config);
    let initial = runtime.inspect();
    cx.set_global(RuntimeGlobal(Arc::clone(&runtime)));
    cx.set_global(DesktopStatus {
        unsealed: matches!(initial, Snapshot::Unsealed { .. }),
        quitting: false,
        no_tray,
    });

    let view_holder = Arc::new(std::sync::Mutex::new(None));
    cx.set_global(DesktopWindow {
        view: Arc::clone(&view_holder),
        handle: None,
        visible: false,
        snapshot: initial.clone(),
        refresh_generation: 0,
    });
    let handle = open_desktop_window(
        Arc::clone(&runtime),
        initial,
        Arc::clone(&view_holder),
        !background,
        cx,
    )
    .expect("failed to open FactorSeal window");
    {
        let desktop = cx.global_mut::<DesktopWindow>();
        desktop.handle = Some(handle);
        desktop.visible = !background;
    }
    if !no_tray {
        install_tray(cx);
    }

    let task = cx.spawn(async move |cx| {
        while let Ok(snapshot) = receiver.recv().await {
            cx.update(|cx| {
                apply_desktop_snapshot(&snapshot, cx);
            });
        }
    });
    cx.set_global(EventTask { _task: task });
    cx.spawn(async move |cx| {
        while activations.recv().await.is_ok() {
            cx.update(|cx| open_desktop(&OpenDesktop, cx));
        }
    })
    .detach();
    if !background {
        cx.activate(true);
    }
}

#[cfg(test)]
mod tests {
    use factorseal::{DocumentKind, SecretSpecAddress, SecretSpecCoordinates};

    use super::{
        category_documentation, category_guidance, hardware_backend_label, password_strength_error,
        secret_spec_address_label,
    };

    #[test]
    fn formats_hardware_backend_names_for_people() {
        assert_eq!(hardware_backend_label("tpm"), "TPM");
        assert_eq!(hardware_backend_label("windows-tpm"), "Windows TPM");
        assert_eq!(hardware_backend_label("future-backend"), "future-backend");
    }

    #[test]
    fn rejects_guessable_passwords() {
        assert!(password_strength_error("P@ssword1").is_some());
        assert!(password_strength_error("factorseal").is_some());
    }

    #[test]
    fn accepts_strong_passphrases() {
        assert!(password_strength_error("opal nebula lantern saffron velocity").is_none());
    }

    #[test]
    fn formats_project_entries_without_secret_values() {
        let convention = SecretSpecAddress::convention("demo", "production", "TOKEN").unwrap();
        assert_eq!(
            secret_spec_address_label(&convention),
            ("TOKEN".to_owned(), "Profile: production".to_owned())
        );

        let native = SecretSpecAddress::native(SecretSpecCoordinates {
            item: "GitHub".to_owned(),
            field: Some("token".to_owned()),
            vault: None,
            section: Some("Deploy".to_owned()),
            version: None,
        })
        .unwrap();
        assert_eq!(
            secret_spec_address_label(&native),
            (
                "GitHub".to_owned(),
                "Field: token · Section: Deploy".to_owned()
            )
        );
    }

    #[test]
    fn provides_usage_guidance_for_empty_vault_categories() {
        let project = category_guidance(DocumentKind::SecretSpecProject);
        assert_eq!(project.title, "Projects");
        assert!(
            project
                .instructions
                .iter()
                .any(|instruction| instruction.contains("secretspec init"))
        );
        assert_eq!(
            category_documentation(DocumentKind::SecretSpecProject)
                .expect("project documentation")
                .2,
            "https://secretspec.dev/quick-start/"
        );

        assert_eq!(
            category_documentation(DocumentKind::SecretSpecProviderCache)
                .expect("cache documentation")
                .2,
            "https://secretspec.dev/concepts/providers/caching/"
        );

        let access = category_guidance(DocumentKind::Authorization);
        assert_eq!(access.title, "Access");
        assert!(
            access
                .instructions
                .iter()
                .any(|instruction| instruction.contains("permissions watch"))
        );
    }
}
