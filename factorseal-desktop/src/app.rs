use self::shortcuts::OpenSettings;
use crate::secret_input::SecretInputState;
mod access;
mod approval_window;
mod breadcrumb;
mod browser;
mod devices;
mod entry_access;
mod error_notice;
mod generator;
mod item_editor;
#[cfg(target_os = "linux")]
mod niri;
mod personal_actions;
mod personal_detail;
mod personal_history;
mod personal_templates;
mod placement;
mod qr_codes;
mod section_pages;
mod shortcuts;
#[cfg(feature = "apple-credential-exchange")]
mod system_transfer;
mod totp;
mod vault_layout;
mod website_icons;
mod wifi;
mod window_activation;
#[cfg(target_os = "windows")]
mod windows_screen;

/// Work for the access popup. Only the Linux Secret Service adapter sends the
/// keyring variants; pending permissions come from polling on every platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum AccessEvent {
    Finished(factorseal::SecretServiceAccessContext),
    Input(factorseal::SecretServiceInputRequest),
    Unlock {
        context: factorseal::SecretServiceAccessContext,
        objects: Vec<String>,
    },
    Request(factorseal::SecretServiceAccessRequest),
    Permissions(Vec<factorseal::Permission>),
}
use std::{cell::Cell, rc::Rc, sync::Arc};

use gpui::{
    AnyWindowHandle, App, Bounds, ColorExt as _, Context, Div, Global, HighlightStyle, Hsla,
    KeyBinding, MenuItem, Render, ScrollHandle, StyledText, Subscription, Task, Window,
    WindowBounds, WindowOptions, actions, div, prelude::*, px, rems, size, svg,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, IconName, Root, Selectable as _, Side, Sizable as _, Size,
    StyledExt as _, WindowExt as _,
    button::{Button, ButtonVariants as _},
    checkbox::Checkbox,
    clipboard::Clipboard,
    dialog::{Cancel as CancelDialog, Confirm as ConfirmDialog, DialogFooter},
    h_flex,
    input::{self, Input, InputEvent, InputState, Textarea, TextareaState},
    menu::{DropdownMenu as _, PopupMenuItem},
    scroll::ScrollableElement as _,
    spinner::Spinner,
    tooltip::Tooltip,
    v_flex,
};
use gpui_tray::{Icon, Tray};
use zeroize::Zeroizing;

use crate::appearance::TypeScale as _;
use crate::controls::{ClickStyle as _, button};
use crate::runtime::{
    DesktopRuntime, PERSONAL_SECRET_NAMESPACE, RuntimeConfig, Snapshot, TransferKey,
    TransferSummary, UnlockStep, VaultContents,
};
use crate::{
    branding::{self, Glyph},
    controls,
    settings::Page,
    theming,
};
use factorseal::transfer::{
    PersonalField, PersonalFieldType, PersonalSecret, PersonalSecretKind, PersonalSection,
    TransferFormat, read_transfer_file, write_private_file,
};

actions!(
    factorseal_desktop,
    [
        OpenDesktop,
        CloseDesktop,
        ToggleDesktop,
        SealVault,
        Quit,
        FocusSearch,
        UndoPersonalChange,
        RedoPersonalChange
    ]
);

struct DesktopTray(Tray);

impl Global for DesktopTray {}

struct DesktopWindow {
    view: Arc<std::sync::Mutex<Option<gpui::Entity<DesktopView>>>>,
    handle: Option<AnyWindowHandle>,
    visible: bool,
    /// When the window last lost the focus. Clicking the tray icon makes the
    /// taskbar active first on Windows, so a window that was in front is no
    /// longer focused when the click arrives.
    deactivated_at: Option<std::time::Instant>,
    snapshot: Snapshot,
    refresh_generation: u64,
}

impl Global for DesktopWindow {}

/// How long after losing the focus the window still counts as in front for
/// a tray icon click.
const TRAY_CLICK_FOCUS_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

struct RuntimeGlobal(Arc<DesktopRuntime>);

impl Global for RuntimeGlobal {}

pub(crate) fn set_next_lease(lease: crate::runtime::LeasePolicy, cx: &App) {
    if let Some(runtime) = cx.try_global::<RuntimeGlobal>() {
        runtime.0.set_next_lease(lease);
    }
}

struct DesktopStatus {
    unsealed: bool,
    quitting: bool,
    no_tray: bool,
}

impl Global for DesktopStatus {}

struct EventTask {
    _task: Task<()>,
}

#[cfg(target_os = "linux")]
pub(crate) type SecretServiceHost = factorseal::SecretServiceHost;

/// Placeholder where no Secret Service is hosted.
#[cfg(not(target_os = "linux"))]
pub(crate) struct SecretServiceHost;

#[cfg(target_os = "linux")]
struct SecretServiceGlobal(Option<Arc<SecretServiceHost>>);

#[cfg(target_os = "linux")]
impl Global for SecretServiceGlobal {}

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

enum TransferOperation {
    Prepared(crate::runtime::PreparedImport),
    Exported(TransferCompletion),
}

impl Global for EventTask {}

fn brand_mark(size: f32, color: Hsla) -> impl IntoElement {
    svg()
        .path(if size < 32. {
            branding::MICRO_MARK_ASSET
        } else {
            branding::MARK_ASSET
        })
        .size(rems(size / 16.))
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

fn sidebar_item(id: impl Into<gpui::ElementId>, selected: bool, cx: &App) -> gpui::Stateful<Div> {
    let theme = cx.theme();
    h_flex()
        .id(id)
        .w_full()
        .items_center()
        .justify_between()
        .px_3()
        .py_1p5()
        .rounded_lg()
        .fill_control(selected, cx)
        .when(selected, |element| {
            element
                .bg(theme.primary)
                .text_color(theme.primary_foreground)
                .font_semibold()
        })
}

fn sidebar_label(icon: impl Into<gpui_component::Icon>, label: &'static str) -> Div {
    h_flex()
        .min_w_0()
        .gap_2()
        .child(icon.into().flex_none())
        .child(div().min_w_0().truncate().child(label))
}

fn field_label(label: &'static str, field: impl IntoElement) -> Div {
    v_flex()
        .gap_2()
        .child(div().text_body().font_medium().child(label))
        .child(field)
}

fn segmented<T: Copy + PartialEq + 'static>(
    id: &'static str,
    options: impl IntoIterator<Item = (T, &'static str)>,
    selected: T,
    disabled: bool,
    on_select: impl Fn(&T, &mut Window, &mut App) + 'static,
    theme: &gpui_component::theme::Theme,
) -> Div {
    let on_select = Rc::new(on_select);
    let raised = if theme.is_dark() {
        theme.secondary
    } else {
        theme.background
    };
    h_flex()
        .self_start()
        .max_w_full()
        .flex_wrap()
        .p_1()
        .gap_1()
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .bg(theme.muted)
        .when(disabled, |track| track.opacity(0.5))
        .children(
            options
                .into_iter()
                .enumerate()
                .map(|(index, (value, label))| {
                    let on_select = on_select.clone();
                    let chosen = value == selected;
                    button((id, index))
                        .ghost()
                        .label(label)
                        .selected(chosen)
                        .disabled(disabled)
                        .border_1()
                        .when(chosen, |segment| {
                            segment
                                .bg(raised)
                                .border_color(theme.border)
                                .text_color(theme.foreground)
                                .shadow_sm()
                        })
                        .when(!chosen, |segment| {
                            segment
                                .border_color(theme.transparent)
                                .text_color(theme.muted_foreground)
                        })
                        .on_click(move |_, window, cx| on_select(&value, window, cx))
                }),
        )
}

fn search_icon(color: Hsla) -> impl IntoElement {
    svg()
        .path(branding::SEARCH_ASSET)
        .size(rems(0.875))
        .text_color(color)
}

fn close_icon(color: Hsla) -> impl IntoElement {
    svg()
        .path(branding::CLOSE_ASSET)
        .size(rems(0.875))
        .text_color(color)
}

fn personal_kind_icon(kind: PersonalSecretKind) -> gpui_component::Icon {
    match kind {
        PersonalSecretKind::Login => IconName::Globe.into(),
        PersonalSecretKind::SecureNote => IconName::File.into(),
        PersonalSecretKind::Card => Glyph::Card.into(),
        PersonalSecretKind::Identity => IconName::CircleUser.into(),
        PersonalSecretKind::SshKey => IconName::SquareTerminal.into(),
        PersonalSecretKind::ApiCredential => Glyph::Key.into(),
        PersonalSecretKind::Passport => IconName::BookOpen.into(),
        PersonalSecretKind::BankAccount => IconName::Building2.into(),
        PersonalSecretKind::Document => IconName::Folder.into(),
        PersonalSecretKind::Generic => IconName::Ellipsis.into(),
    }
}

fn personal_field_icon(id: &str, field_type: &PersonalFieldType) -> gpui_component::Icon {
    match id {
        "username" | "cardholderName" | "owner" | "fullname" | "firstName" | "lastName"
        | "initial" => return IconName::User.into(),
        "password" | "passphrase" | "credential" | "token" => return Glyph::Key.into(),
        "code" | "cvv" | "pin" | "telephonePin" | "accountNo" | "iban" => {
            return Glyph::Lock.into();
        }
        "type" | "brand" => return Glyph::Tag.into(),
        "expiry" | "expMonth" | "expYear" | "expiry_date" | "expires" => {
            return IconName::Calendar.into();
        }
        "bank" | "bankName" | "company" | "department" => return IconName::Building2.into(),
        "website" => return IconName::Globe.into(),
        _ => {}
    }
    match field_type {
        PersonalFieldType::Text => IconName::CaseSensitive.into(),
        PersonalFieldType::Concealed | PersonalFieldType::SshKey => Glyph::Key.into(),
        PersonalFieldType::Url => IconName::Globe.into(),
        PersonalFieldType::Email => Glyph::Mail.into(),
        PersonalFieldType::Phone => Glyph::Phone.into(),
        PersonalFieldType::Date | PersonalFieldType::MonthYear => IconName::Calendar.into(),
        PersonalFieldType::Totp => Glyph::Clock.into(),
        PersonalFieldType::Multiline => IconName::File.into(),
        PersonalFieldType::Boolean => IconName::CircleCheck.into(),
        PersonalFieldType::CardNumber => Glyph::Card.into(),
        PersonalFieldType::Address => IconName::Map.into(),
        PersonalFieldType::Reference | PersonalFieldType::Unknown(_) => IconName::Asterisk.into(),
    }
}

const CUSTOM_FIELD_KINDS: [PersonalFieldType; 9] = [
    PersonalFieldType::Concealed,
    PersonalFieldType::Text,
    PersonalFieldType::Url,
    PersonalFieldType::Email,
    PersonalFieldType::Phone,
    PersonalFieldType::Date,
    PersonalFieldType::MonthYear,
    PersonalFieldType::Totp,
    PersonalFieldType::Multiline,
];

fn field_kind_picker(
    id: impl Into<gpui::ElementId>,
    selected: &PersonalFieldType,
    pick: impl Fn(PersonalFieldType, &mut App) + 'static,
) -> impl IntoElement {
    let selected = selected.clone();
    let pick = Rc::new(pick);
    button(id)
        .ghost()
        .xsmall()
        .icon(IconName::ChevronDown)
        .dropdown_menu(move |mut menu, _, _| {
            menu = menu.check_side(Side::Right);
            for kind in CUSTOM_FIELD_KINDS {
                let pick = Rc::clone(&pick);
                let picked = kind.clone();
                menu = menu.item(
                    PopupMenuItem::new(kind.label())
                        .icon(personal_field_icon("", &kind))
                        .checked(kind == selected)
                        .on_click(move |_, _, cx| pick(picked.clone(), cx)),
                );
            }
            menu
        })
}

fn personal_entry_kind(entry: &factorseal::VaultEntryMetadata) -> PersonalSecretKind {
    PersonalSecretKind::ALL
        .into_iter()
        .find(|kind| entry.display_type.as_deref() == Some(kind.label()))
        .unwrap_or_default()
}

fn error_banner(message: String, color: Hsla) -> Div {
    div().w_full().child(crate::motion::enter(
        gpui::ElementId::Name(message.clone().into()),
        div()
            .w_full()
            .px_4()
            .py_3()
            .rounded_lg()
            .bg(color.opacity(0.1))
            .text_color(color)
            // An ID exposes the message to accessibility clients.
            .child(gpui::Text::new("error-message".into(), message.into())),
    ))
}

fn field_message(message: String, color: Hsla) -> Div {
    div().text_caption().text_color(color).child(message)
}

fn password_strength_error(password: &str) -> Option<String> {
    factorseal::security::validate_new_password(password.as_bytes()).err()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupField {
    Password,
    Confirmation,
    Form,
}

fn setup_password_error(password: &str, confirmation: &str) -> Option<(SetupField, String)> {
    if password.is_empty() {
        return Some((
            SetupField::Password,
            "Choose a non-empty password.".to_owned(),
        ));
    }
    if let Some(error) = password_strength_error(password) {
        return Some((SetupField::Password, error));
    }
    (password != confirmation).then(|| {
        (
            SetupField::Confirmation,
            "The passwords do not match.".to_owned(),
        )
    })
}

const fn unlock_step_description(step: UnlockStep, biometric: bool) -> &'static str {
    match step {
        UnlockStep::Verifying if biometric => {
            "Complete the device authorization prompt if one appears."
        }
        UnlockStep::Verifying => "Checking your password with this device’s hardware.",
        UnlockStep::Starting => "Starting the vault service.",
        UnlockStep::Loading => "Loading your secrets.",
    }
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

fn setup_protection_description(cx: &App) -> Div {
    if cfg!(target_os = "linux") {
        h_flex()
            .gap_1()
            .flex_wrap()
            .child("Your password and this device's")
            .child(link(
                "tpm-explanation-link",
                "TPM",
                "https://trustedcomputinggroup.org/about/what-is-a-trusted-platform-module-tpm/",
                cx,
            ))
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

fn personal_item_id(entry: &factorseal::VaultEntryMetadata) -> Option<&str> {
    match entry.address.as_local() {
        Some((id, None)) if is_personal_secret(entry) => Some(id),
        _ => None,
    }
}

fn list_row_text(
    title: impl Into<gpui::SharedString>,
    detail: Option<&'static str>,
    theme: &gpui_component::theme::Theme,
) -> Div {
    v_flex()
        .flex_1()
        .min_w_0()
        .child(
            div()
                .min_w_0()
                .font_semibold()
                .truncate()
                .child(title.into()),
        )
        .when_some(detail, |text, detail| {
            text.child(
                div()
                    .text_caption()
                    .text_color(theme.muted_foreground)
                    .truncate()
                    .child(detail),
            )
        })
}

fn icon_tile(size: f32, theme: &gpui_component::theme::Theme) -> Div {
    h_flex()
        .flex_none()
        .size(rems(size))
        .items_center()
        .justify_center()
        .rounded_lg()
        .bg(if theme.is_dark() {
            theme.foreground.opacity(0.1)
        } else {
            theme.secondary
        })
}

fn personal_icon_tile(
    kind: PersonalSecretKind,
    size: f32,
    theme: &gpui_component::theme::Theme,
) -> Div {
    icon_tile(size, theme).child(
        personal_kind_icon(kind)
            .size(rems(size / 2.))
            .text_color(theme.foreground),
    )
}

fn sorted_personal_entries<'a>(
    entries: &'a [factorseal::VaultEntryMetadata],
    query: &str,
) -> Vec<&'a factorseal::VaultEntryMetadata> {
    let mut entries: Vec<_> = entries
        .iter()
        .filter(|entry| is_personal_secret(entry) && entry_matches_search(entry, query))
        .collect();
    entries.sort_by_cached_key(|entry| {
        (
            std::cmp::Reverse(entry.favorite),
            vault_entry_label(entry).0.to_lowercase(),
        )
    });
    entries
}

fn desired_vault_browser_height(contents: &VaultContents) -> gpui::Pixels {
    let document_count = contents
        .entries
        .iter()
        .filter(|entry| visible_vault_entry(entry))
        .count();
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

fn personal_entry_icon(
    entry: &factorseal::VaultEntryMetadata,
    icon: Option<Arc<gpui::RenderImage>>,
    size: f32,
    theme: &gpui_component::theme::Theme,
) -> Div {
    match icon {
        Some(icon) => icon_tile(size, theme)
            .when(theme.is_dark(), |tile| {
                tile.bg(theme.foreground.opacity(0.9))
            })
            .child(gpui::img(icon).size(rems(size / 2.))),
        None => personal_icon_tile(personal_entry_kind(entry), size, theme),
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
            entry.display_name.as_deref().unwrap_or(item).to_owned(),
            entry
                .display_type
                .as_deref()
                .unwrap_or("Personal secret")
                .to_owned(),
        );
    }
    if entry.document_kind == factorseal::DocumentKind::NetworkManagerWifi {
        return (
            entry.display_name.as_deref().unwrap_or(item).to_owned(),
            wifi_credential_label(field).to_owned(),
        );
    }
    if entry.document_kind == factorseal::DocumentKind::LinuxSecretService {
        (
            entry
                .display_name
                .clone()
                .unwrap_or_else(|| "System keyring item".to_owned()),
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

fn wifi_credential_label(field: Option<&str>) -> &str {
    match field.and_then(|field| field.rsplit('/').next()) {
        Some("psk") => "Wi-Fi password",
        Some("password" | "password-raw") => "Enterprise password",
        Some("pin") => "Token PIN",
        Some("private-key-password") => "Private key password",
        Some("phase2-private-key-password") => "Inner authentication private key password",
        Some("ca-cert-password") => "CA certificate token password",
        Some("phase2-ca-cert-password") => "Inner authentication CA certificate token password",
        Some("client-cert-password") => "Client certificate token password",
        Some("phase2-client-cert-password") => {
            "Inner authentication client certificate token password"
        }
        _ => "Wi-Fi credential",
    }
}

fn category_badge(integration_error: bool, count: usize) -> String {
    match (integration_error, count) {
        (true, 0) => "!".to_owned(),
        (true, count) => format!("! {count}"),
        (false, count) => count.to_string(),
    }
}

fn sidebar_category_icon(kind: factorseal::DocumentKind) -> gpui_component::Icon {
    match kind {
        factorseal::DocumentKind::SecretSpecProject => IconName::Folder.into(),
        factorseal::DocumentKind::SecretSpecProviderCache => IconName::MemoryStick.into(),
        factorseal::DocumentKind::NetworkManagerWifi => IconName::Globe.into(),
        factorseal::DocumentKind::LinuxSecretService => Glyph::Key.into(),
        factorseal::DocumentKind::LocalKeyring => IconName::LayoutDashboard.into(),
        _ => IconName::Inbox.into(),
    }
}

fn vault_category_label(kind: factorseal::DocumentKind) -> &'static str {
    match kind {
        factorseal::DocumentKind::SecretSpecProject => "Project secret",
        factorseal::DocumentKind::LinuxSecretService => "System keyring",
        factorseal::DocumentKind::NetworkManagerWifi => "Wi-Fi password",
        factorseal::DocumentKind::LocalKeyring => "Application keyring",
        factorseal::DocumentKind::SecretSpecProviderCache => "Provider cache",
        factorseal::DocumentKind::Authorization => "Access",
        _ => "Vault item",
    }
}

fn search_matches(value: &str, query: &str) -> bool {
    query.is_empty() || value.to_lowercase().contains(query)
}

fn search_match_range(value: &str, query: &str) -> Option<std::ops::Range<usize>> {
    if query.is_empty() {
        return None;
    }
    value.char_indices().find_map(|(start, _)| {
        let mut wanted = query.chars().peekable();
        for (offset, character) in value[start..].char_indices() {
            if !character
                .to_lowercase()
                .all(|lower| wanted.next() == Some(lower))
            {
                return None;
            }
            if wanted.peek().is_none() {
                return Some(start..start + offset + character.len_utf8());
            }
        }
        None
    })
}

fn entry_matches_search(entry: &factorseal::VaultEntryMetadata, query: &str) -> bool {
    let (label, detail) = vault_entry_label(entry);
    search_matches(&label, query)
        || search_matches(&detail, query)
        || entry
            .display_username
            .as_deref()
            .is_some_and(|username| search_matches(username, query))
}

fn category_entries(
    entries: &[factorseal::VaultEntryMetadata],
    kind: factorseal::DocumentKind,
) -> impl Iterator<Item = &factorseal::VaultEntryMetadata> {
    entries.iter().filter(move |entry| {
        entry.document_kind == kind
            && visible_vault_entry(entry)
            && !(kind == factorseal::DocumentKind::LocalKeyring && is_personal_secret(entry))
    })
}

const SEARCH_CATEGORIES: [(factorseal::DocumentKind, &str); 5] = [
    (factorseal::DocumentKind::SecretSpecProject, "Projects"),
    (
        factorseal::DocumentKind::SecretSpecProviderCache,
        "Provider cache",
    ),
    (
        factorseal::DocumentKind::NetworkManagerWifi,
        "Wi-Fi passwords",
    ),
    (
        factorseal::DocumentKind::LinuxSecretService,
        "System keyring",
    ),
    (
        factorseal::DocumentKind::LocalKeyring,
        "Application keyrings",
    ),
];

fn search_results<'a>(
    entries: &'a [factorseal::VaultEntryMetadata],
    query: &str,
) -> Vec<(&'static str, Vec<&'a factorseal::VaultEntryMetadata>)> {
    let personal_title = "Personal secrets";
    let personal_query = if search_matches(personal_title, query) {
        ""
    } else {
        query
    };
    std::iter::once((
        personal_title,
        sorted_personal_entries(entries, personal_query),
    ))
    .chain(SEARCH_CATEGORIES.into_iter().map(|(kind, title)| {
        let title_matches = search_matches(title, query);
        (
            title,
            category_entries(entries, kind)
                .filter(|entry| title_matches || entry_matches_search(entry, query))
                .collect(),
        )
    }))
    .filter(|(_, entries)| !entries.is_empty())
    .collect()
}

fn search_result_entries<'a>(
    entries: &'a [factorseal::VaultEntryMetadata],
    query: &str,
) -> Vec<&'a factorseal::VaultEntryMetadata> {
    search_results(entries, query)
        .into_iter()
        .flat_map(|(_, entries)| entries)
        .collect()
}

fn highlighted_text(text: String, query: &str, color: Hsla) -> StyledText {
    let highlights = search_match_range(&text, query).map(|range| {
        (
            range,
            HighlightStyle {
                background_color: Some(color),
                ..HighlightStyle::default()
            },
        )
    });
    StyledText::new(text).with_highlights(highlights)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn link(
    id: impl Into<gpui::ElementId>,
    label: impl Into<gpui::SharedString>,
    href: &'static str,
    cx: &App,
) -> gpui::Stateful<Div> {
    let label = label.into();
    link_showing(id, label.clone(), label, href, cx)
}

fn link_showing(
    id: impl Into<gpui::ElementId>,
    name: impl Into<gpui::SharedString>,
    shown: impl Into<gpui::SharedString>,
    href: &'static str,
    cx: &App,
) -> gpui::Stateful<Div> {
    let color = cx.theme().link;
    div()
        .id(id)
        .role(gpui::Role::Link)
        .aria_label(name)
        .text_color(color)
        .text_decoration_1()
        .text_decoration_color(color.opacity(0.5))
        .hover(move |this| {
            this.text_color(color.opacity(0.8))
                .text_decoration_1()
                .text_decoration_color(color)
        })
        .active(move |this| {
            this.text_color(color.opacity(0.6))
                .text_decoration_1()
                .text_decoration_color(color)
        })
        .text_focus(cx)
        .on_mouse_down(gpui::MouseButton::Left, |_, _, cx| cx.stop_propagation())
        .on_click(move |_, _, cx| cx.open_url(href))
        .child(shown.into())
}

/// An authenticated executable path as a person reads it. Windows reports
/// caller images in the verbatim form (`\\?\C:\...`, `\\?\UNC\host\...`),
/// and that exact string is part of the caller identity grants are bound
/// to, so only the display drops the prefix.
fn display_executable(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = path.strip_prefix(r"\\?\")
        && rest.as_bytes().get(1) == Some(&b':')
    {
        return rest.to_owned();
    }
    path.to_owned()
}

fn permission_access_type(scope: Option<factorseal::DocumentKind>) -> &'static str {
    match scope {
        Some(factorseal::DocumentKind::LinuxSecretService) => "System keyring",
        Some(factorseal::DocumentKind::NetworkManagerWifi) => "Wi-Fi passwords",
        Some(factorseal::DocumentKind::SecretSpecProviderCache) => "SecretSpec provider",
        Some(factorseal::DocumentKind::SecretSpecProject) => "SecretSpec project",
        Some(factorseal::DocumentKind::LocalKeyring) => "Application keyring",
        Some(_) => "Vault access",
        None => "Legacy access · type unknown",
    }
}

fn vault_entry_details(entry: &factorseal::VaultEntryMetadata) -> Vec<(&'static str, String)> {
    if is_personal_secret(entry) {
        return vec![(
            "Type",
            entry
                .display_type
                .as_deref()
                .unwrap_or("Personal secret")
                .to_owned(),
        )];
    }
    let mut details = vec![
        ("Type", vault_category_label(entry.document_kind).to_owned()),
        (
            "Namespace",
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

struct GuidanceStep {
    text: &'static str,
    command: Option<&'static str>,
}

const fn step(text: &'static str) -> GuidanceStep {
    GuidanceStep {
        text,
        command: None,
    }
}

const fn command_step(text: &'static str, command: &'static str) -> GuidanceStep {
    GuidanceStep {
        text,
        command: Some(command),
    }
}

struct CategoryGuidance {
    title: &'static str,
    description: &'static str,
    instructions: &'static [GuidanceStep],
}

#[allow(clippy::too_many_lines)]
fn category_guidance(kind: factorseal::DocumentKind) -> CategoryGuidance {
    match kind {
        factorseal::DocumentKind::NetworkManagerWifi => CategoryGuidance {
            title: "Wi-Fi passwords",
            description: "Personal and enterprise Wi-Fi credentials stored for NetworkManager.",
            instructions: const {
                &[
                    step(
                        "Keep FactorSeal running while connecting to Wi-Fi. Unlock the vault when asked to make saved passwords available.",
                    ),
                    step(
                        "In your network connection editor, choose to store the password for this user. Enter the password in FactorSeal when connecting.",
                    ),
                    step(
                        "Use Move existing Wi-Fi passwords to copy and verify saved credentials, update their storage settings, and remove matching old keyring copies.",
                    ),
                    step(
                        "Enterprise connections also support certificate passwords and PINs. Credentials marked to ask every time are not saved.",
                    ),
                ]
            },
        },
        factorseal::DocumentKind::SecretSpecProject => CategoryGuidance {
            title: "Projects",
            description: "Secrets declared by your SecretSpec projects and profiles.",
            instructions: const {
                &[
                    command_step(
                        "Run this in your project directory, then declare the secrets your application needs in secretspec.toml.",
                        "secretspec init",
                    ),
                    command_step(
                        "Store a value.",
                        "secretspec set TOKEN --provider factorseal://default",
                    ),
                    command_step(
                        "Start your application.",
                        "secretspec run --provider factorseal://default -- your-command",
                    ),
                ]
            },
        },
        factorseal::DocumentKind::LinuxSecretService => CategoryGuidance {
            title: "System keyring",
            description: "Passwords saved through Linux's standard Secret Service appear here.",
            instructions: const {
                &[
                    step(
                        "Use the normal keyring API in your application. FactorSeal provides org.freedesktop.secrets while unsealed.",
                    ),
                    command_step(
                        "On NixOS, add this to your configuration.",
                        "services.factorseal.mode = \"desktop\";",
                    ),
                    step(
                        "Disable competing Secret Service providers such as GNOME Keyring so only one service owns the bus name.",
                    ),
                ]
            },
        },
        factorseal::DocumentKind::LocalKeyring => CategoryGuidance {
            title: "Application keyrings",
            description: "Durable, namespace-isolated credentials stored through FactorSeal's Rust API.",
            instructions: const {
                &[
                    step(
                        "Create a NativeVaultClient connected to the running FactorSeal endpoint.",
                    ),
                    command_step("Import the Keyring trait.", "use factorseal::Keyring;"),
                    step(
                        "Call set, get, or delete with an application-owned namespace and WireSecretAddress.",
                    ),
                ]
            },
        },
        factorseal::DocumentKind::Authorization => CategoryGuidance {
            title: "Access",
            description: "Review applications requesting or holding access to FactorSeal secrets.",
            instructions: const {
                &[
                    command_step("List permissions.", "factorseal permissions list"),
                    command_step(
                        "Review requests as they come in.",
                        "factorseal permissions watch --prompt",
                    ),
                    command_step(
                        "Approve a request with the permission ID it shows. Use deny or revoke the same way.",
                        "factorseal permissions approve PERMISSION_ID",
                    ),
                ]
            },
        },
        factorseal::DocumentKind::SecretSpecProviderCache => CategoryGuidance {
            title: "Provider cache",
            description: "Expiring local copies that make remote SecretSpec providers faster.",
            instructions: const {
                &[
                    command_step(
                        "Add this under [providers] in secretspec.toml.",
                        "factorseal = \"factorseal://default\"",
                    ),
                    command_step(
                        "Add this to an authoritative provider alias.",
                        "cache = { provider = \"factorseal\", max_age = \"8h\" }",
                    ),
                    command_step(
                        "Use that alias normally. Run this when you need to clear its local copies.",
                        "secretspec cache clear",
                    ),
                ]
            },
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
        factorseal::DocumentKind::NetworkManagerWifi => Some((
            "wifi-passwords-documentation",
            "Read the Wi-Fi setup and migration guide",
            "https://github.com/cachix/factorseal/blob/main/docs/network-manager.md",
        )),
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
    Devices,
    TransferCredentials,
    BackupVault,
    Category(factorseal::DocumentKind),
    Entry(Box<factorseal::VaultEntryMetadata>),
}

impl VaultSelection {
    fn page_title(&self) -> Option<&'static str> {
        match self {
            Self::Devices => Some("Devices"),
            Self::TransferCredentials => Some("Transfer credentials"),
            Self::BackupVault => Some("Back up vault"),
            _ => None,
        }
    }

    fn page(&self) -> Page {
        match self {
            Self::PersonalSecrets => Page::PersonalSecrets,
            Self::Entry(entry) if is_personal_secret(entry) => Page::PersonalSecrets,
            Self::Entry(entry) => Page::Category(entry.document_kind),
            Self::Devices => Page::Devices,
            Self::TransferCredentials => Page::TransferCredentials,
            Self::BackupVault => Page::BackupVault,
            Self::Category(kind) => Page::Category(*kind),
        }
    }

    fn parent(&self, panel: PersonalPanel) -> Option<Self> {
        match self {
            Self::PersonalSecrets if panel == PersonalPanel::NewItem => Some(Self::PersonalSecrets),
            Self::Entry(entry) if is_personal_secret(entry) => Some(Self::PersonalSecrets),
            Self::Entry(entry) => Some(Self::Category(entry.document_kind)),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VaultPanes {
    All,
    Sidebar,
    Main,
}

fn vault_panes(single_pane: bool, open: bool) -> VaultPanes {
    match (single_pane, open) {
        (false, _) => VaultPanes::All,
        (true, false) => VaultPanes::Sidebar,
        (true, true) => VaultPanes::Main,
    }
}

fn restored_selection(
    page: &Page,
    open_item: Option<&str>,
    entries: &[factorseal::VaultEntryMetadata],
) -> VaultSelection {
    match page {
        Page::PersonalSecrets => entries
            .iter()
            .find(|entry| open_item.is_some() && personal_item_id(entry) == open_item)
            .map_or(VaultSelection::PersonalSecrets, |entry| {
                VaultSelection::Entry(Box::new(entry.clone()))
            }),
        Page::Devices => VaultSelection::Devices,
        Page::TransferCredentials => VaultSelection::TransferCredentials,
        Page::BackupVault => VaultSelection::BackupVault,
        Page::Category(kind) => VaultSelection::Category(*kind),
    }
}

#[derive(Debug, PartialEq)]
enum VaultPage<'a> {
    Welcome,
    Personal(PersonalPanel),
    Section,
    Category(factorseal::DocumentKind),
    Entry(&'a factorseal::SecretAddress),
}

fn vault_page(selection: Option<&VaultSelection>, panel: PersonalPanel) -> VaultPage<'_> {
    match selection {
        None => VaultPage::Welcome,
        Some(VaultSelection::PersonalSecrets) => VaultPage::Personal(panel),
        Some(
            VaultSelection::Devices
            | VaultSelection::TransferCredentials
            | VaultSelection::BackupVault,
        ) => VaultPage::Section,
        Some(VaultSelection::Category(kind)) => VaultPage::Category(*kind),
        Some(VaultSelection::Entry(entry)) => VaultPage::Entry(&entry.address),
    }
}

fn shows_empty_detail(
    selection: Option<&VaultSelection>,
    panel: PersonalPanel,
    searching: bool,
) -> bool {
    match selection {
        Some(VaultSelection::PersonalSecrets) => panel == PersonalPanel::Overview,
        Some(VaultSelection::Category(_)) => searching,
        _ => false,
    }
}

fn screen_key(settings_open: bool, snapshot: &Snapshot) -> &'static str {
    if settings_open {
        return "settings";
    }
    match snapshot {
        Snapshot::Uninitialized { .. } => "setup",
        Snapshot::Initializing => "creating",
        Snapshot::Sealed { .. } | Snapshot::Unlocking { .. } => "sealed",
        Snapshot::Sealing { .. } => "sealing",
        Snapshot::Unsealed { .. } => "unsealed",
        Snapshot::Error(_) => "error",
    }
}

fn list_selection(selection: Option<&VaultSelection>) -> Option<VaultSelection> {
    match selection {
        Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => {
            Some(VaultSelection::PersonalSecrets)
        }
        Some(VaultSelection::Entry(entry)) => Some(VaultSelection::Category(entry.document_kind)),
        Some(VaultSelection::PersonalSecrets) => Some(VaultSelection::PersonalSecrets),
        Some(VaultSelection::Category(kind)) => Some(VaultSelection::Category(*kind)),
        _ => None,
    }
}

fn entry_element_id(
    prefix: &'static str,
    entry: &factorseal::VaultEntryMetadata,
) -> gpui::ElementId {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entry.partition.hash(&mut hasher);
    entry.address.hash(&mut hasher);
    (prefix, hasher.finish()).into()
}

fn is_selected_entry(
    selection: Option<&VaultSelection>,
    entry: &factorseal::VaultEntryMetadata,
) -> bool {
    matches!(selection, Some(VaultSelection::Entry(selected))
        if selected.address == entry.address && selected.partition == entry.partition)
}

#[allow(clippy::struct_excessive_bools)]
struct DesktopView {
    #[cfg(target_os = "linux")]
    wifi_migration: wifi::State,
    settings_open: bool,
    issue_report_busy: bool,
    issue_report_notice: Option<&'static str>,
    issue_description: Option<gpui::Entity<TextareaState>>,
    issue_report_error: Rc<Cell<Option<&'static str>>>,
    settings: gpui::Entity<crate::settings_view::SettingsView>,
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    selected_group: Option<factorseal::UnlockGroup>,
    password: gpui::Entity<SecretInputState>,
    password_confirmation: gpui::Entity<SecretInputState>,
    vault_search: gpui::Entity<InputState>,
    item_name: gpui::Entity<InputState>,
    item_editor: Option<item_editor::Editor>,
    item_leave: item_editor::Leave,
    navigation: vault_layout::Navigation,
    opening: u64,
    qr_scan: Option<qr_codes::QrScan>,
    qr_generation: u64,
    qr_capturing: bool,
    archive_passphrase: gpui::Entity<SecretInputState>,
    archive_passphrase_confirmation: gpui::Entity<SecretInputState>,
    setup_method: SetupMethod,
    setup_error: Option<(SetupField, String)>,
    password_revealed: bool,
    focus_password: bool,
    selected_vault_item: Option<VaultSelection>,
    open_item_before_seal: Option<String>,
    vault_sidebar_scroll: ScrollHandle,
    personal_panel: PersonalPanel,
    personal_detail: personal_detail::PersonalDetail,
    personal_history: personal_history::History<personal_history::Change>,
    personal_toast: u64,
    change_toast: Option<personal_detail::ChangeToast>,
    copied_personal_field: Option<personal_actions::CopiedField>,
    generator: gpui::Entity<generator::PasswordGenerator>,
    generator_target: Option<generator::GeneratorTarget>,
    generator_anchor: generator::GeneratorAnchor,
    generator_focus: gpui::FocusHandle,
    password_strength: Option<crate::password_generator::Strength>,
    password_rating: Option<Task<()>>,
    clipboard_notice: Option<u64>,
    clipboard_notice_leaving: bool,
    error_details_open: bool,
    error_details_copied: bool,
    devices: factorseal::desktop_worker::sync::network::View,
    devices_busy: bool,
    devices_syncing: bool,
    devices_loaded: bool,
    devices_cancel_queued: bool,
    device_pairing: Option<devices::PairingScreen>,
    pairing_focus: gpui::FocusHandle,
    selected_device: usize,
    section_opened: bool,
    devices_notice: Option<String>,
    device_name: gpui::Entity<InputState>,
    device_renaming: bool,
    pairing_ticket: gpui::Entity<SecretInputState>,
    transfer_format: TransferFormat,
    transfer_is_import: bool,
    transfer_use_recipient: bool,
    transfer_key_file: Option<std::path::PathBuf>,
    transfer_busy: bool,
    transfer_replace_existing: bool,
    transfer_plaintext_confirmed: bool,
    transfer_notice: Option<TransferNotice>,
    #[cfg(feature = "apple-credential-exchange")]
    system_transfer: system_transfer::State,
    search_cursor: usize,
    search_scroll: ScrollHandle,
    system_integrations_expanded: bool,
    shortcuts: shortcuts::State,
    website_icons: website_icons::WebsiteIcons,
    _subscriptions: Vec<Subscription>,
}

impl DesktopView {
    fn report_from_settings(
        &mut self,
        _: &gpui::Entity<crate::settings_view::SettingsView>,
        _: &crate::settings_view::ReportIssue,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.report_issue(window, cx);
    }

    fn report_issue(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.issue_report_busy {
            return;
        }
        let description = self
            .issue_description
            .get_or_insert_with(|| {
                cx.new(|cx| {
                    TextareaState::new(window, cx)
                        .rows(7)
                        .placeholder("What happened, and what did you expect?")
                })
            })
            .clone();
        self.issue_report_error.set(None);
        let error = Rc::clone(&self.issue_report_error);
        let view = cx.weak_entity();
        window.open_dialog(cx, move |dialog, _, cx| {
            let send_view = view.clone();
            let cancel_view = view.clone();
            dialog
                .title("Report an issue")
                .width(px(560.))
                .close_button(false)
                .overlay_closable(false)
                .child(
                    v_flex()
                        .gap_2()
                        .child(div().text_body().child("Describe the issue and how to reproduce it."))
                        .child(controls::hover_field(
                            "issue-description-field",
                            Textarea::new(&description)
                                .aria_label("Issue description")
                                .h(rems(176. / 16.)),
                        ))
                        .child(div().text_caption().text_color(cx.theme().muted_foreground)
                            .child("Up to 4,000 characters. Leave out passwords and other secrets.")),
                )
                .when_some(error.get(), |dialog, error| dialog.child(error_banner(error.to_owned(), cx.theme().danger)))
                .footer(
                    DialogFooter::new()
                        .child(button("cancel-issue-report").icon(IconName::Close).label("Cancel")
                            .on_click(|_, window, cx| window.dispatch_action(Box::new(CancelDialog), cx)))
                        .child(button("send-issue-report").primary().icon(Glyph::Upload).label("Send report")
                            .on_click(|_, window, cx| window.dispatch_action(Box::new(ConfirmDialog { secondary: false }), cx))),
                )
                .on_ok(move |_, window, cx| {
                    send_view.update(cx, |view, cx| view.submit_issue(window, cx)).unwrap_or(true)
                })
                .on_cancel(move |_, _, cx| {
                    let _ = cancel_view.update(cx, |view, _| view.issue_description = None);
                    true
                })
        });
        if let Some(description) = &self.issue_description {
            description.update(cx, |input, cx| input.focus(window, cx));
        }
        cx.notify();
    }

    fn submit_issue(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> bool {
        if self.issue_report_busy {
            return false;
        }
        let Some(input) = &self.issue_description else {
            return false;
        };
        let description = input.read(cx).value().to_string();
        if let Err(error) = factorseal::diagnostics::validate_issue_description(&description) {
            self.issue_report_error.set(Some(error));
            cx.notify();
            return false;
        }
        if !crate::crash_reporting::configured() {
            self.issue_report_error.set(Some(
                "Issue submission is unavailable. You can export diagnostics from Settings.",
            ));
            cx.notify();
            return false;
        }
        self.issue_report_busy = true;
        self.set_issue_report_notice("Sending issue report…", cx);
        cx.spawn(async move |view, cx| {
            let result =
                smol::unblock(move || crate::crash_reporting::submit_issue(&description)).await;
            let queued = result.is_ok();
            let notice = if let Ok(id) = result {
                let mut sent = false;
                for _ in 0..20 {
                    let id = id.clone();
                    sent = smol::unblock(move || crate::crash_reporting::issue_sent(&id))
                        .await
                        .unwrap_or(false);
                    if sent {
                        break;
                    }
                    smol::Timer::after(std::time::Duration::from_millis(500)).await;
                }
                if sent {
                    "Issue report sent to Sentry with recent diagnostic logs."
                } else {
                    "Issue report queued for Sentry. Desktop will retry automatically."
                }
            } else {
                "Could not queue the issue report. Try again or export diagnostics from Settings."
            };
            let _ = view.update(cx, |view, cx| {
                view.issue_report_busy = false;
                view.set_issue_report_notice(notice, cx);
                if queued {
                    view.issue_description = None;
                }
                cx.notify();
            });
        })
        .detach();
        true
    }

    fn set_issue_report_notice(&mut self, notice: &'static str, cx: &mut Context<Self>) {
        self.issue_report_notice = Some(notice);
        if self.is_unsealed() {
            self.show_toast(notice, None, false, cx);
        }
        cx.notify();
    }

    fn render_footer(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let security_label = self.security_label();
        v_flex()
            .w_full()
            .flex_none()
            .when_some(self.issue_report_notice, |view, notice| {
                view.child(
                    div()
                        .py_2()
                        .text_caption()
                        .text_color(theme.muted_foreground)
                        .child(notice),
                )
            })
            .child(
                h_flex()
                    .w_full()
                    .flex_none()
                    .h(rems(48. / 16.))
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .border_t_1()
                    .border_color(theme.border)
                    .text_caption()
                    .text_color(theme.muted_foreground)
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .child(self.render_report_issue_button(cx))
                            .child(branding::TAGLINE),
                    )
                    .child(link(
                        "footer-security-link",
                        security_label,
                        "https://factorseal.dev/security",
                        cx,
                    )),
            )
    }

    fn render_report_issue_button(&self, cx: &mut Context<Self>) -> Button {
        button("report-issue")
            .icon(gpui_component::Icon::default().path(branding::BUG_ASSET))
            .accessibility_label("Report an issue")
            .ghost()
            .small()
            .disabled(self.issue_report_busy)
            .tooltip("Report an issue")
            .on_click(cx.listener(|view, _, window, cx| {
                view.report_issue(window, cx);
            }))
    }

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

    #[allow(clippy::too_many_lines)]
    fn new(
        runtime: Arc<DesktopRuntime>,
        snapshot: Snapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        Self::poll_devices(Arc::clone(&runtime), cx);
        let settings = cx.new(|cx| crate::settings_view::SettingsView::new(window, cx));
        let settings_changed = cx.observe(&settings, |view, _, cx| {
            view.refresh_website_icons(cx);
            cx.notify();
        });
        let settings_report = cx.subscribe_in(&settings, window, Self::report_from_settings);
        let selected_group = snapshot
            .metadata()
            .map(|metadata| metadata.preferred_unlock_group().clone());
        let password =
            cx.new(|cx| SecretInputState::new(window, cx).placeholder("FactorSeal password"));
        let password_confirmation =
            cx.new(|cx| SecretInputState::new(window, cx).placeholder("Confirm password"));
        let vault_search = cx.new(|cx| InputState::new(window, cx).placeholder("Search secrets"));
        let item_name = cx.new(|cx| InputState::new(window, cx).placeholder("Name"));
        let archive_passphrase =
            cx.new(|cx| SecretInputState::new(window, cx).placeholder("Archive passphrase"));
        let archive_passphrase_confirmation = cx
            .new(|cx| SecretInputState::new(window, cx).placeholder("Confirm archive passphrase"));
        let [password_events, confirmation_events] =
            Self::password_subscriptions(&password, &password_confirmation, window, cx);
        let password_change = cx.subscribe_in(
            &password,
            window,
            |view, password, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change)
                    && matches!(view.snapshot, Snapshot::Uninitialized { .. })
                {
                    if password.read(cx).value().is_empty() {
                        view.password_rating = None;
                        view.password_strength = None;
                        cx.notify();
                    } else {
                        view.rate_password_later(cx);
                    }
                }
            },
        );
        let generator = cx.new(generator::PasswordGenerator::new);
        let use_generated_password = cx.subscribe_in(
            &generator,
            window,
            |view, _, event: &generator::UsePassword, window, cx| {
                view.use_generated_password(&event.0, window, cx);
            },
        );
        let vault_search_change = cx.subscribe_in(
            &vault_search,
            window,
            |view, _, event: &InputEvent, window, cx| match event {
                InputEvent::Change => view.on_vault_search_changed(cx),
                InputEvent::PressEnter { .. } if view.showing_search_results(cx) => {
                    view.open_search_result(cx);
                }
                InputEvent::PressEnter { .. } => view.focus_list(0, window, cx),
                _ => {}
            },
        );
        let window_activation = cx.observe_window_activation(window, |view, window, cx| {
            if window.is_window_active() {
                if matches!(view.snapshot, Snapshot::Sealed { .. }) {
                    view.focus_password = true;
                    cx.notify();
                }
            } else if cx.has_global::<DesktopWindow>() {
                // Recorded for the tray icon's toggle.
                cx.global_mut::<DesktopWindow>().deactivated_at = Some(std::time::Instant::now());
            }
        });
        Self {
            settings_open: false,
            issue_report_busy: false,
            issue_report_notice: None,
            issue_description: None,
            issue_report_error: Rc::new(Cell::new(None)),
            settings,
            runtime,
            snapshot,
            selected_group,
            password,
            password_confirmation,
            vault_search,
            item_name,
            item_editor: None,
            item_leave: item_editor::Leave::default(),
            navigation: vault_layout::Navigation::default(),
            opening: 0,
            qr_scan: None,
            qr_generation: 0,
            qr_capturing: false,
            archive_passphrase,
            archive_passphrase_confirmation,
            setup_method: SetupMethod::default(),
            setup_error: None,
            password_revealed: false,
            focus_password: true,
            selected_vault_item: None,
            open_item_before_seal: None,
            vault_sidebar_scroll: ScrollHandle::new(),
            personal_panel: PersonalPanel::Overview,
            personal_detail: personal_detail::PersonalDetail::default(),
            personal_history: personal_history::History::default(),
            personal_toast: 0,
            change_toast: None,
            copied_personal_field: None,
            generator,
            generator_target: None,
            generator_anchor: generator::GeneratorAnchor::default(),
            generator_focus: cx.focus_handle(),
            password_strength: None,
            password_rating: None,
            clipboard_notice: None,
            clipboard_notice_leaving: false,
            error_details_open: false,
            error_details_copied: false,
            devices: factorseal::desktop_worker::sync::network::View::default(),
            devices_busy: false,
            devices_syncing: false,
            devices_loaded: false,
            devices_cancel_queued: false,
            device_pairing: None,
            pairing_focus: cx.focus_handle(),
            selected_device: 0,
            section_opened: false,
            devices_notice: None,
            device_name: Self::device_name_input(window, cx),
            device_renaming: false,
            pairing_ticket: cx
                .new(|cx| SecretInputState::new(window, cx).placeholder("Paste pairing code")),
            transfer_format: TransferFormat::default(),
            transfer_is_import: false,
            transfer_use_recipient: false,
            transfer_key_file: None,
            transfer_busy: false,
            transfer_replace_existing: false,
            transfer_plaintext_confirmed: false,
            transfer_notice: None,
            #[cfg(feature = "apple-credential-exchange")]
            system_transfer: system_transfer::State::default(),
            system_integrations_expanded: true,
            search_cursor: 0,
            search_scroll: ScrollHandle::new(),
            shortcuts: shortcuts::State::new(window, cx),
            website_icons: website_icons::WebsiteIcons::new(crate::runtime::open_icon_helper),
            #[cfg(target_os = "linux")]
            wifi_migration: wifi::State::default(),
            _subscriptions: vec![
                password_events,
                confirmation_events,
                password_change,
                vault_search_change,
                settings_changed,
                settings_report,
                use_generated_password,
                window_activation,
            ],
        }
    }

    fn is_unsealed(&self) -> bool {
        matches!(self.snapshot, Snapshot::Unsealed { .. })
    }

    fn current_page(&self) -> Option<Page> {
        self.selected_vault_item.as_ref().map(VaultSelection::page)
    }

    fn restore_page(&mut self, cx: &mut Context<Self>) {
        let open_item = self.open_item_before_seal.take();
        if let Snapshot::Unsealed { contents, .. } = &self.snapshot
            && let Some(page) = crate::appearance::current(cx).page.clone()
        {
            let selection = restored_selection(&page, open_item.as_deref(), &contents.entries);
            self.select_vault_item(selection, cx);
        }
    }

    fn password_subscriptions(
        password: &gpui::Entity<SecretInputState>,
        password_confirmation: &gpui::Entity<SecretInputState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> [gpui::Subscription; 2] {
        [
            cx.subscribe_in(
                password,
                window,
                |view, _, event: &InputEvent, window, cx| match event {
                    InputEvent::PressEnter {
                        secondary: false, ..
                    } => match view.snapshot {
                        Snapshot::Sealed { .. } => view.unlock(window, cx),
                        Snapshot::Uninitialized { .. }
                            if view.password_confirmation.read(cx).value().is_empty() =>
                        {
                            view.password_confirmation
                                .update(cx, |input, cx| input.focus(window, cx));
                        }
                        Snapshot::Uninitialized { .. } => view.initialize(window, cx),
                        _ => {}
                    },
                    InputEvent::Change => view.clear_password_error(cx),
                    _ => {}
                },
            ),
            cx.subscribe_in(
                password_confirmation,
                window,
                |view, _, event: &InputEvent, window, cx| match event {
                    InputEvent::PressEnter {
                        secondary: false, ..
                    } => view.initialize(window, cx),
                    InputEvent::Change => view.clear_password_error(cx),
                    _ => {}
                },
            ),
        ]
    }

    fn device_name_input(window: &mut Window, cx: &mut Context<Self>) -> gpui::Entity<InputState> {
        cx.new(|cx| {
            let name = crate::appearance::current(cx)
                .device_name
                .clone()
                .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
            InputState::new(window, cx).default_value(name)
        })
    }

    fn choose_setup_method(
        &mut self,
        method: SetupMethod,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.clear_secret_inputs(cx);
        self.setup_method = method;
        self.setup_error = None;
        cx.notify();
    }

    fn rate_password_later(&mut self, cx: &mut Context<Self>) {
        self.password_rating = Some(cx.spawn(async move |view, cx| {
            smol::Timer::after(crate::password_generator::RATING_PAUSE).await;
            let _ = view.update(cx, Self::rate_password);
        }));
    }

    fn rate_password(&mut self, cx: &mut Context<Self>) {
        let password = self.password.read(cx).value();
        self.password_strength =
            (!password.is_empty()).then(|| crate::password_generator::Strength::of(&password));
        cx.notify();
    }

    fn initialize(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Uninitialized { .. }) {
            return;
        }
        let mut password = self.password.read(cx).value();
        let confirmation = self.password_confirmation.read(cx).value();
        if self.setup_method.needs_password()
            && let Some(error) = setup_password_error(&password, &confirmation)
        {
            self.setup_error = Some(error);
            self.rate_password(cx);
            return;
        }
        let policy = match self.setup_method.policy() {
            Ok(policy) => policy,
            Err(error) => {
                self.setup_error = Some((SetupField::Form, error.to_string()));
                cx.notify();
                return;
            }
        };
        self.password
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.password_confirmation
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.password_strength = None;
        self.password_rating = None;
        match self.runtime.initialize(
            policy,
            Zeroizing::new(std::mem::take(&mut *password).into_bytes()),
        ) {
            Ok(()) => {
                self.setup_error = None;
                self.reset_error_details();
                self.snapshot = Snapshot::Initializing;
            }
            Err(error) => self.setup_error = Some((SetupField::Form, error.to_owned())),
        }
        cx.notify();
    }

    fn clear_password_error(&mut self, cx: &mut Context<Self>) {
        match &mut self.snapshot {
            Snapshot::Uninitialized { .. } if self.setup_error.is_some() => {
                self.setup_error = None;
            }
            Snapshot::Sealed { error, .. } if error.is_some() => *error = None,
            _ => return,
        }
        cx.notify();
    }

    fn toggle_password_reveal(&mut self, cx: &mut Context<Self>) {
        self.set_password_revealed(!self.password_revealed, cx);
    }

    fn set_password_revealed(&mut self, revealed: bool, cx: &mut Context<Self>) {
        self.password_revealed = revealed;
        for input in [&self.password, &self.password_confirmation] {
            input.update(cx, |input, cx| input.set_masked(!revealed, cx));
        }
        cx.notify();
    }

    fn render_password_field(
        &self,
        id: &'static str,
        input: &gpui::Entity<SecretInputState>,
        cx: &Context<Self>,
    ) -> Div {
        let revealed = self.password_revealed;
        h_flex()
            .w_full()
            .gap_2()
            .child(div().flex_1().child(input.clone()))
            .child(
                button(id)
                    .ghost()
                    .flex_none()
                    .icon(if revealed {
                        IconName::EyeOff
                    } else {
                        IconName::Eye
                    })
                    .tooltip(if revealed {
                        "Hide password"
                    } else {
                        "Show password"
                    })
                    .on_click(cx.listener(|view, _, _, cx| view.toggle_password_reveal(cx))),
            )
    }

    fn on_vault_search_changed(&mut self, cx: &mut Context<Self>) {
        if !self.leave_item_editor(Self::on_vault_search_changed, cx) {
            return;
        }
        self.shortcuts.cursor = 0;
        self.clear_personal_detail();
        self.settings_open = false;
        self.selected_vault_item = list_selection(self.selected_vault_item.as_ref());
        self.search_cursor = 0;
        self.search_scroll.set_offset(gpui::Point::default());
        cx.notify();
    }

    fn search_query(&self, cx: &App) -> String {
        self.vault_search.read(cx).value().trim().to_lowercase()
    }

    fn showing_search_results(&self, cx: &App) -> bool {
        matches!(self.snapshot, Snapshot::Unsealed { .. })
            && !self.settings_open
            && self
                .selected_vault_item
                .as_ref()
                .is_none_or(|selection| selection.page_title().is_none())
            && !self.search_query(cx).is_empty()
    }

    fn search_result_at_cursor(&self, cx: &App) -> Option<factorseal::VaultEntryMetadata> {
        let Snapshot::Unsealed { contents, .. } = &self.snapshot else {
            return None;
        };
        let results = search_result_entries(&contents.entries, &self.search_query(cx));
        results
            .get(self.search_cursor.min(results.len().saturating_sub(1)))
            .map(|entry| (*entry).clone())
    }

    fn move_search_cursor(&mut self, forward: bool, cx: &mut Context<Self>) -> bool {
        let Snapshot::Unsealed { contents, .. } = &self.snapshot else {
            return false;
        };
        if !self.showing_search_results(cx) {
            return false;
        }
        let count = search_result_entries(&contents.entries, &self.search_query(cx)).len();
        self.search_cursor = shortcuts::step(self.search_cursor, count, forward);
        self.search_scroll.scroll_to_item(self.search_cursor);
        cx.notify();
        true
    }

    fn open_search_result(&mut self, cx: &mut Context<Self>) {
        if !self.showing_search_results(cx) {
            return;
        }
        if let Some(entry) = self.search_result_at_cursor(cx) {
            self.select_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
        }
    }

    fn clear_vault_search(&self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.vault_search.read(cx).value().is_empty() {
            self.vault_search.update(cx, |search, cx| {
                search.set_value("", window, cx);
            });
        }
    }

    fn escape_vault_search(&self, window: &mut Window, cx: &mut Context<Self>) {
        if self.vault_search.read(cx).value().is_empty() {
            window.blur(cx);
        } else {
            self.clear_vault_search(window, cx);
        }
    }

    fn focus_vault_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        self.settings_open = false;
        self.vault_search.update(cx, |search, cx| {
            search.focus(window, cx);
            search.select_all(window, cx);
        });
        cx.notify();
    }

    fn clear_personal_detail(&mut self) {
        self.personal_detail.clear();
        self.personal_history.clear();
        self.change_toast = None;
    }

    fn clear_secret_inputs(&mut self, cx: &mut Context<Self>) {
        self.opening = self.opening.wrapping_add(1);
        self.clear_personal_detail();
        self.copied_personal_field = None;
        self.close_generator(cx);
        self.password_strength = None;
        self.password_rating = None;
        self.set_password_revealed(false, cx);
        for input in [
            &self.password,
            &self.password_confirmation,
            &self.archive_passphrase,
            &self.archive_passphrase_confirmation,
        ] {
            input.update(cx, SecretInputState::clear);
        }
        self.item_editor = None;
        self.item_leave = item_editor::Leave::default();
    }

    fn refresh_website_icons(&mut self, cx: &mut Context<Self>) {
        let entries = match &self.snapshot {
            Snapshot::Unsealed { contents, .. } => Some(contents.entries.as_slice()),
            _ => None,
        };
        let enabled = crate::appearance::current(cx).website_icons;
        let (batch, dropped) = self.website_icons.refresh(enabled, entries);
        for image in dropped {
            cx.defer(move |cx| cx.drop_image(image, None));
        }
        let Some(batch) = batch else {
            return;
        };
        for host in batch.hosts {
            let helper = Arc::clone(&batch.helper);
            let generation = batch.generation;
            cx.spawn(async move |view, cx| {
                let (host, icon) = smol::unblock(move || {
                    let icon = helper.fetch(&host);
                    (host, icon)
                })
                .await;
                let _ = view.update(cx, |view, cx| {
                    if view.website_icons.finish(generation, &host, icon.as_ref()) {
                        cx.notify();
                    }
                    view.refresh_website_icons(cx);
                });
            })
            .detach();
        }
    }

    fn apply_snapshot(&mut self, snapshot: Snapshot, cx: &mut Context<Self>) {
        let refreshed_item = match (&snapshot, &self.selected_vault_item) {
            (Snapshot::Unsealed { contents, .. }, Some(VaultSelection::Entry(entry)))
                if is_personal_secret(entry) =>
            {
                Some(
                    contents
                        .entries
                        .iter()
                        .find(|current| {
                            is_personal_secret(current) && current.address == entry.address
                        })
                        .cloned(),
                )
            }
            _ => None,
        };
        if !matches!(snapshot, Snapshot::Unsealed { .. }) {
            #[cfg(feature = "apple-credential-exchange")]
            if matches!(self.snapshot, Snapshot::Unsealed { .. }) {
                self.cancel_system_transfer();
            }
            self.clear_secret_inputs(cx);
            self.pairing_ticket.update(cx, SecretInputState::clear);
            self.devices.state.invitation = None;
            self.devices.state.request = None;
            self.devices_notice = None;
        }
        if self.selected_group.is_none() {
            self.selected_group = snapshot
                .metadata()
                .map(|metadata| metadata.preferred_unlock_group().clone());
        }
        let was_unsealed = self.is_unsealed();
        let unsealed = matches!(snapshot, Snapshot::Unsealed { .. });
        let was_open = was_unsealed || matches!(self.snapshot, Snapshot::Sealing { .. });
        if was_open && !unsealed && self.selected_vault_item.is_some() {
            self.open_item_before_seal = match &self.selected_vault_item {
                Some(VaultSelection::Entry(entry)) => personal_item_id(entry).map(str::to_owned),
                _ => None,
            };
            let page = self.current_page();
            crate::appearance::remember(|settings| settings.page.clone_from(&page), cx);
        }
        if !unsealed {
            self.selected_vault_item = None;
        }
        self.focus_password |= matches!(
            snapshot,
            Snapshot::Sealed { .. } | Snapshot::Uninitialized { .. }
        );
        self.snapshot = snapshot;
        self.refresh_website_icons(cx);
        if unsealed && !was_unsealed && self.selected_vault_item.is_none() {
            self.restore_page(cx);
        }
        if let Some(refreshed_item) = refreshed_item {
            match refreshed_item {
                Some(entry)
                    if self.selected_vault_item.as_ref()
                        != Some(&VaultSelection::Entry(Box::new(entry.clone()))) =>
                {
                    self.select_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
                }
                None => self.show_personal_panel(PersonalPanel::Overview, cx),
                _ => {}
            }
        }
        cx.notify();
    }

    fn select_vault_item(&mut self, selection: VaultSelection, cx: &mut Context<Self>) {
        if self.transfer_busy
            && matches!(
                selection,
                VaultSelection::TransferCredentials | VaultSelection::BackupVault
            )
        {
            return;
        }
        let retry = selection.clone();
        if !self.leave_item_editor(move |view, cx| view.select_vault_item(retry, cx), cx) {
            return;
        }
        self.forget_qr_scan();
        match selection {
            VaultSelection::Entry(entry) if is_personal_secret(&entry) => {
                self.open_personal_entry(*entry, cx);
            }
            selection => self.show_vault_item(selection, cx),
        }
    }

    fn show_vault_item(&mut self, selection: VaultSelection, cx: &mut Context<Self>) {
        self.clear_secret_inputs(cx);
        if matches!(
            selection,
            VaultSelection::TransferCredentials | VaultSelection::BackupVault
        ) {
            self.transfer_notice = None;
            self.transfer_key_file = None;
            self.transfer_plaintext_confirmed = false;
            self.transfer_replace_existing = false;
            self.transfer_is_import = false;
            self.transfer_format = if selection == VaultSelection::BackupVault {
                TransferFormat::FactorSeal
            } else {
                TransferFormat::CxfAge
            };
        }
        self.settings_open = false;
        self.section_opened = false;
        self.selected_vault_item = Some(selection);
        self.remember_page(cx);
        cx.notify();
    }

    fn remember_page(&self, cx: &mut Context<Self>) {
        if self.is_unsealed() {
            let page = self.current_page();
            crate::appearance::remember(|settings| settings.page.clone_from(&page), cx);
        }
    }

    fn show_vault_browser(&mut self, cx: &mut Context<Self>) {
        if !self.leave_item_editor(Self::show_vault_browser, cx) {
            return;
        }
        self.clear_secret_inputs(cx);
        self.settings_open = false;
        self.selected_vault_item = None;
        self.remember_page(cx);
        cx.notify();
    }

    fn show_vault_parent(&mut self, cx: &mut Context<Self>) {
        if self.on_section_page() && self.section_opened && self.shortcuts.compact {
            self.section_opened = false;
            cx.notify();
            return;
        }
        let parent = if self.settings_open {
            None
        } else {
            self.selected_vault_item
                .as_ref()
                .and_then(|selection| selection.parent(self.personal_panel))
        };
        match parent {
            Some(VaultSelection::PersonalSecrets) => {
                self.show_personal_panel(PersonalPanel::Overview, cx);
            }
            Some(parent) => self.select_vault_item(parent, cx),
            None => self.show_vault_browser(cx),
        }
    }

    fn select_transfer_format(&mut self, format: TransferFormat, cx: &mut Context<Self>) {
        if !self.leave_item_editor(move |view, cx| view.select_transfer_format(format, cx), cx) {
            return;
        }
        if self.transfer_busy {
            return;
        }
        self.clear_secret_inputs(cx);
        self.transfer_format = format;
        self.transfer_key_file = None;
        self.transfer_plaintext_confirmed = false;
        self.transfer_notice = None;
        cx.notify();
    }

    fn select_transfer_direction(&mut self, is_import: bool, cx: &mut Context<Self>) {
        if self.transfer_busy
            || is_import == self.transfer_is_import
            || !self.leave_item_editor(
                move |view, cx| view.select_transfer_direction(is_import, cx),
                cx,
            )
        {
            return;
        }
        self.clear_secret_inputs(cx);
        self.transfer_is_import = is_import;
        if !is_import && self.transfer_format == TransferFormat::OnePasswordPux {
            self.transfer_format = TransferFormat::CxfAge;
        }
        self.transfer_key_file = None;
        self.transfer_replace_existing = false;
        self.transfer_plaintext_confirmed = false;
        self.transfer_notice = None;
        cx.notify();
    }

    fn choose_transfer_key_file(&mut self, is_import: bool, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        self.transfer_busy = true;
        cx.spawn(async move |view, cx| {
            let chosen = rfd::AsyncFileDialog::new()
                .set_title(if is_import {
                    "Choose private age identity"
                } else {
                    "Choose public age recipient"
                })
                .pick_file()
                .await;
            let _ = view.update(cx, |view, cx| {
                view.transfer_busy = false;
                if let Some(chosen) = chosen {
                    view.transfer_key_file = Some(chosen.path().to_owned());
                    view.transfer_notice = None;
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    #[allow(clippy::too_many_lines)]
    fn start_transfer(&mut self, is_import: bool, window: &mut Window, cx: &mut Context<Self>) {
        if self.transfer_busy {
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            self.transfer_notice = Some(TransferNotice::Error(
                "Unseal the vault before transferring secrets.".to_owned(),
            ));
            cx.notify();
            return;
        };
        let metadata = metadata.clone();
        let format = self.transfer_format;
        let use_recipient = format == TransferFormat::CxfAge && self.transfer_use_recipient;
        let needs_passphrase = format.is_encrypted() && !use_recipient;
        let key_file = if use_recipient {
            self.transfer_key_file.clone()
        } else {
            None
        };
        if use_recipient && key_file.is_none() {
            self.transfer_notice = Some(TransferNotice::Error(
                if is_import {
                    "Choose the private age identity file."
                } else {
                    "Choose the recipient's public age key file."
                }
                .to_owned(),
            ));
            cx.notify();
            return;
        }
        let passphrase = self.archive_passphrase.read(cx).value();
        let confirmation = self.archive_passphrase_confirmation.read(cx).value();
        if needs_passphrase && passphrase.is_empty() {
            self.transfer_notice = Some(TransferNotice::Error(
                if format.is_native() {
                    "Enter the backup passphrase."
                } else {
                    "Enter the transfer passphrase."
                }
                .to_owned(),
            ));
            cx.notify();
            return;
        }
        if !is_import && needs_passphrase && passphrase != confirmation {
            self.transfer_notice = Some(TransferNotice::Error(
                "The passphrases do not match.".to_owned(),
            ));
            cx.notify();
            return;
        }
        if !is_import
            && needs_passphrase
            && let Some(error) = password_strength_error(&passphrase)
        {
            self.transfer_notice = Some(TransferNotice::Error(error));
            cx.notify();
            return;
        }
        if !is_import && !format.is_encrypted() && !self.transfer_plaintext_confirmed {
            self.transfer_notice = Some(TransferNotice::Error(
                "Confirm that you understand the export will contain plaintext secrets.".to_owned(),
            ));
            cx.notify();
            return;
        }

        let passphrase = Zeroizing::new(passphrase.as_bytes().to_vec());
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
            let dialog = rfd::AsyncFileDialog::new()
                .set_title(match (format.is_native(), is_import) {
                    (true, true) => "Choose backup to restore",
                    (true, false) => "Save vault backup",
                    (false, true) => "Choose credentials to import",
                    (false, false) => "Save credential transfer",
                })
                .add_filter(format.label(), &[format.extension()]);
            let chosen = if is_import {
                dialog.pick_file().await
            } else {
                dialog
                    .set_file_name(format!("factorseal-{}.{}", if format.is_native() { "backup" } else { "credentials" }, format.extension()))
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
            let commit_runtime = Arc::clone(&runtime);
            let commit_metadata = metadata.clone();
            let result = smol::unblock(move || {
                let key = key_file.as_deref().map_or(
                    TransferKey::Passphrase(&passphrase),
                    TransferKey::HybridFile,
                );
                if !is_import
                    && key_file.as_deref().is_some_and(|key| {
                        std::fs::canonicalize(key)
                            .ok()
                            .zip(std::fs::canonicalize(&operation_path).ok())
                            .is_some_and(|(key, destination)| key == destination)
                    })
                {
                    return Err(
                        "Choose an export destination different from the age key file.".to_owned(),
                    );
                }
                if is_import {
                    let bytes =
                        read_transfer_file(&operation_path).map_err(|error| error.to_string())?;
                    DesktopRuntime::prepare_import(&bytes, format, key).map(TransferOperation::Prepared)
                } else {
                    let output = if format.is_native() {
                        runtime.export_native_archive(&metadata, &passphrase)?
                    } else {
                        runtime.export_password_manager(&metadata, format, key)?
                    };
                    write_private_file(&operation_path, &output)
                        .map_err(|error| error.to_string())?;
                    Ok(TransferOperation::Exported(TransferCompletion {
                        summary: None,
                        contents: None,
                        path: operation_path,
                    }))
                }
            })
            .await;
            let result = match result {
                Ok(TransferOperation::Prepared(prepared)) => {
                    let preview = format!(
                        "{} items are ready to {}. {} contain data without full functional support.\n\nExisting items will be {}. Keep the old vault until you have verified important logins and verification codes.",
                        prepared.len(), if format.is_native() { "restore" } else { "import" }, prepared.preserved_only(),
                        if replace_existing { "replaced" } else { "kept" },
                    );
                    let decision = rfd::AsyncMessageDialog::new()
                        .set_title(if format.is_native() { "Review restore" } else { "Review import" })
                        .set_description(preview)
                        .set_buttons(rfd::MessageButtons::OkCancel)
                        .show().await;
                    if decision != rfd::MessageDialogResult::Ok {
                        let _ = view.update(cx, |view, cx| {
                            view.transfer_busy = false;
                            view.transfer_notice = None;
                            cx.notify();
                        });
                        return;
                    }
                    smol::unblock(move || {
                        let (summary, contents) = commit_runtime.commit_import(&commit_metadata, prepared, replace_existing)?;
                        Ok(TransferCompletion { summary: Some(summary), contents: Some(contents), path })
                    }).await
                }
                Ok(TransferOperation::Exported(completion)) => Ok(completion),
                Err(error) => Err(error),
            };
            let _ = view.update(cx, |view, cx| {
                view.finish_transfer(is_import, format.is_native(), result);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_transfer(
        &mut self,
        is_import: bool,
        is_backup: bool,
        result: Result<TransferCompletion, String>,
    ) {
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
                    let mut message = format!(
                        "{} {} items: {} added, {} replaced, {} kept existing.",
                        if is_backup { "Restored" } else { "Imported" },
                        summary.processed(),
                        summary.added,
                        summary.replaced,
                        summary.kept_existing
                    );
                    if summary.preserved_only > 0 {
                        use std::fmt::Write as _;
                        let _ = write!(
                            message,
                            " {} source items contain data preserved without full functional support. Keep the old vault until you have verified important credentials.",
                            summary.preserved_only
                        );
                    }
                    message
                } else if is_import {
                    if is_backup {
                        "Restore complete."
                    } else {
                        "Import complete."
                    }
                    .to_owned()
                } else {
                    format!(
                        "{} saved to {}.",
                        if is_backup {
                            "Backup"
                        } else {
                            "Credential transfer"
                        },
                        completion.path.display()
                    )
                };
                self.transfer_notice = Some(TransferNotice::Success(message));
            }
            Err(error) => {
                self.transfer_notice = Some(TransferNotice::Error(format!(
                    "{} failed: {error}",
                    match (is_backup, is_import) {
                        (true, true) => "Restore",
                        (true, false) => "Backup",
                        (false, true) => "Import",
                        (false, false) => "Export",
                    }
                )));
            }
        }
    }

    fn show_personal_panel(&mut self, panel: PersonalPanel, cx: &mut Context<Self>) {
        if !self.leave_item_editor(move |view, cx| view.show_personal_panel(panel, cx), cx) {
            return;
        }
        self.forget_qr_scan();
        self.clear_secret_inputs(cx);
        self.personal_panel = panel;
        self.settings_open = false;
        self.selected_vault_item = Some(VaultSelection::PersonalSecrets);
        self.remember_page(cx);
        cx.notify();
    }

    fn show_import(&mut self, cx: &mut Context<Self>) {
        self.select_vault_item(VaultSelection::TransferCredentials, cx);
        if self.selected_vault_item == Some(VaultSelection::TransferCredentials) {
            self.select_transfer_direction(true, cx);
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
        self.clear_secret_inputs(cx);
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
            let value = self.password.read(cx).value();
            if value.is_empty() {
                self.snapshot = Snapshot::Sealed {
                    metadata,
                    error: Some(error_notice::MISSING_UNLOCK_PASSWORD.to_owned()),
                };
                cx.notify();
                return;
            }
            Zeroizing::new(value.as_bytes().to_vec())
        } else {
            Zeroizing::new(Vec::new())
        };
        self.password.update(cx, |input, cx| {
            input.set_value("", window, cx);
        });
        self.reset_error_details();
        if let Err(error) = self
            .runtime
            .unlock(metadata.clone(), group.clone(), password)
        {
            self.snapshot = Snapshot::Sealed {
                metadata,
                error: Some(error.to_owned()),
            };
        } else {
            window.blur(cx);
            self.snapshot = Snapshot::Unlocking {
                metadata,
                group,
                step: UnlockStep::default(),
            };
        }
        cx.notify();
    }

    fn seal(&mut self, cx: &mut Context<Self>) {
        self.save_item_editor_on_exit(cx);
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
        let unlocking = matches!(self.snapshot, Snapshot::Unlocking { .. });
        let has_multiple_groups = metadata.unlock_policy().groups().len() > 1;
        let mut choices = h_flex().gap_2().flex_wrap();
        for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
            let selected = self.selected_group.as_ref() == Some(group);
            let chosen = group.clone();
            choices = choices.child(
                button(("unlock-group", index))
                    .label(group.to_string())
                    .selected(selected)
                    .disabled(unlocking)
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

        let title = if unlocking {
            "Unlocking your vault…"
        } else {
            "Vault is sealed"
        };
        let description = match &self.snapshot {
            Snapshot::Unlocking { group, step, .. } => unlock_step_description(
                *step,
                group.requires(factorseal::UnlockFactorKind::Biometric),
            ),
            _ => "Unlock to make your secrets available to authorized applications.",
        };
        let password_field = if unlocking {
            // Preserve the form's height without leaving an editable secret field.
            div()
                .w_full()
                .h_8()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .bg(theme.muted)
                .opacity(0.5)
        } else {
            self.render_password_field("reveal-password", &self.password, cx)
        };

        vault_card(&theme)
            .child(
                v_flex()
                    .items_center()
                    .gap_3()
                    .pb_2()
                    .child(crate::unlock_animation::vault_mark(&theme, unlocking))
                    .child(div().text_title().font_semibold().child(title))
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .text_center()
                            .text_lead()
                            .min_h(rems(40. / 16.))
                            .child(description),
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
            .when(needs_password, |element| element.child(password_field))
            .when_some(error, |element, error| {
                element.child(self.render_error_notice(error, false, cx))
            })
            .child(
                button("unlock-vault")
                    .primary()
                    .large()
                    .w_full()
                    .loading(unlocking)
                    .disabled(unlocking)
                    .label(if unlocking {
                        "Unlocking…"
                    } else if needs_password {
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
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<Div> {
        let theme = cx.theme().clone();
        let entry_count = category_entries(&contents.entries, kind).count();
        let category_selection = VaultSelection::Category(kind);
        let category_selected = !self.showing_search_results(cx)
            && self.current_list().as_ref() == Some(&category_selection);
        let integration_error = kind == factorseal::DocumentKind::LinuxSecretService
            && contents.secret_service_error.is_some();
        sidebar_item(("vault-category", category_index), category_selected, cx)
            .child(
                sidebar_label(sidebar_category_icon(kind), title)
                    .when(integration_error && !category_selected, |element| {
                        element.text_color(theme.danger)
                    }),
            )
            .child(
                div()
                    .min_w(rems(24. / 16.))
                    .px_2()
                    .py(rems(2. / 16.))
                    .text_center()
                    .rounded_full()
                    .bg(if category_selected {
                        theme.primary_foreground.opacity(0.16)
                    } else {
                        theme.background.opacity(0.65)
                    })
                    .text_body()
                    .text_color(if category_selected {
                        theme.primary_foreground
                    } else if integration_error {
                        theme.danger
                    } else {
                        theme.muted_foreground
                    })
                    .child(category_badge(integration_error, entry_count)),
            )
            .on_click(cx.listener(move |view, _, window, cx| {
                view.select_vault_item(category_selection.clone(), cx);
                view.clear_vault_search(window, cx);
            }))
    }

    fn render_personal_secrets_sidebar(
        &self,
        contents: &VaultContents,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let entry_count = contents
            .entries
            .iter()
            .filter(|entry| is_personal_secret(entry))
            .count();
        let theme = cx.theme().clone();
        let selected = !self.showing_search_results(cx)
            && self.current_list() == Some(VaultSelection::PersonalSecrets);
        v_flex()
            .gap_1()
            .child(
                sidebar_item("personal-secrets-category", selected, cx)
                    .child(sidebar_label(IconName::User, "Personal secrets"))
                    .child(
                        div()
                            .min_w(rems(24. / 16.))
                            .px_2()
                            .py(rems(2. / 16.))
                            .rounded_full()
                            .bg(if selected {
                                theme.primary_foreground.opacity(0.16)
                            } else {
                                theme.background.opacity(0.65)
                            })
                            .text_body()
                            .text_color(if selected {
                                theme.primary_foreground
                            } else {
                                theme.muted_foreground
                            })
                            .child(entry_count.to_string()),
                    )
                    .on_click(cx.listener(|view, _, window, cx| {
                        view.show_personal_panel(PersonalPanel::Overview, cx);
                        view.clear_vault_search(window, cx);
                    })),
            )
            .into_any_element()
    }

    fn render_system_integrations(&self, contents: &VaultContents, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let expanded = self.system_integrations_expanded;
        v_flex()
            .child(
                h_flex()
                    .id("system-integrations-toggle")
                    .w_full()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .mt_2()
                    .mb_1()
                    .quiet_text_control(cx)
                    .text_caption()
                    .font_semibold()
                    .text_color(theme.muted_foreground)
                    .child("System integrations")
                    .child(gpui::AnimationExt::with_animation(
                        gpui_component::Icon::new(IconName::ChevronRight).small(),
                        ("system-integrations-chevron", u64::from(expanded)),
                        gpui::Animation::new(std::time::Duration::from_millis(160))
                            .with_easing(gpui_component::animation::ease_out_cubic),
                        move |icon, delta| {
                            let turn = if expanded { delta } else { 1. - delta };
                            icon.rotate(gpui::radians(std::f32::consts::FRAC_PI_2 * turn))
                        },
                    ))
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.toggle_system_integrations(cx);
                    })),
            )
            .child(
                div()
                    .id("system-integrations-items")
                    .overflow_hidden()
                    .transitions(|transitions| transitions.h(crate::motion::change()))
                    .map(|items| {
                        if expanded {
                            items.h_auto()
                        } else {
                            items.h_0()
                        }
                    })
                    .when(expanded, |items| {
                        items.child(
                            v_flex()
                                .gap_1()
                                .pt_1()
                                .child(self.render_sidebar_section(
                                    contents,
                                    factorseal::DocumentKind::NetworkManagerWifi,
                                    "Wi-Fi passwords",
                                    4,
                                    cx,
                                ))
                                .child(self.render_sidebar_section(
                                    contents,
                                    factorseal::DocumentKind::LinuxSecretService,
                                    "System keyring",
                                    2,
                                    cx,
                                ))
                                .child(self.render_sidebar_section(
                                    contents,
                                    factorseal::DocumentKind::LocalKeyring,
                                    "Application keyrings",
                                    3,
                                    cx,
                                )),
                        )
                    }),
            )
    }

    fn render_vault_search(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let has_query = !self.vault_search.read(cx).value().is_empty();
        div()
            .id("vault-search")
            .flex_none()
            .px_3()
            .capture_action(cx.listener(|view, _: &input::Escape, window, cx| {
                cx.stop_propagation();
                view.escape_vault_search(window, cx);
            }))
            .capture_action(cx.listener(|view, _: &input::MoveUp, _, cx| {
                if view.move_search_cursor(false, cx) {
                    cx.stop_propagation();
                }
            }))
            .capture_action(cx.listener(|view, _: &input::MoveDown, _, cx| {
                if view.move_search_cursor(true, cx) {
                    cx.stop_propagation();
                }
            }))
            .child(controls::hover_field(
                "vault-search-field",
                Input::new(&self.vault_search)
                    .bg(theming::input_background(cx))
                    .prefix(search_icon(theme.muted_foreground))
                    .when(has_query, |input| {
                        input.suffix(
                            div()
                                .id("clear-vault-search")
                                .p_1()
                                .rounded_sm()
                                .fill_control(false, cx)
                                .text_color(theme.muted_foreground)
                                .child(close_icon(theme.muted_foreground))
                                .on_click(cx.listener(|view, _, window, cx| {
                                    view.clear_vault_search(window, cx);
                                })),
                        )
                    }),
            ))
    }

    fn render_vault_sidebar(
        &self,
        contents: &VaultContents,
        full_width: bool,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let theme = cx.theme().clone();
        let group_label = |label: &'static str| {
            div()
                .px_3()
                .mt_2()
                .mb_1()
                .text_caption()
                .font_semibold()
                .text_color(theme.muted_foreground)
                .child(label)
        };
        v_flex()
            .id("vault-sidebar")
            .key_context(shortcuts::SIDEBAR_CONTEXT)
            .map(|sidebar| {
                if full_width {
                    sidebar.flex_1().min_w_0()
                } else {
                    sidebar.w(rems(232. / 16.)).flex_none().border_r_1()
                }
            })
            .h_full()
            .gap_3()
            .bg(theme.sidebar)
            .border_color(theme.sidebar_border)
            .child(Self::render_sidebar_brand(cx))
            .child(self.render_vault_search(cx))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .relative()
                    .child(
                        div()
                            .id("vault-sidebar-results")
                            .size_full()
                            .track_scroll(&self.vault_sidebar_scroll)
                            .overflow_y_scroll()
                            .child(
                                v_flex()
                                    .gap_3()
                                    .px_3()
                                    .child(self.render_personal_secrets_sidebar(contents, cx))
                                    .child(
                                        v_flex()
                                            .gap_1()
                                            .child(group_label("SecretSpec"))
                                            .child(self.render_sidebar_section(
                                                contents,
                                                factorseal::DocumentKind::SecretSpecProject,
                                                "Projects",
                                                0,
                                                cx,
                                            ))
                                            .child(self.render_sidebar_section(
                                                contents,
                                                factorseal::DocumentKind::SecretSpecProviderCache,
                                                "Provider cache",
                                                1,
                                                cx,
                                            )),
                                    )
                                    .child(self.render_system_integrations(contents, cx)),
                            ),
                    )
                    .vertical_scrollbar(&self.vault_sidebar_scroll),
            )
            .child(self.render_sidebar_nav(cx))
            .child(self.render_sidebar_footer(cx))
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

    fn empty_state(
        mark: impl IntoElement,
        title: &'static str,
        line: &'static str,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        v_flex()
            .w_full()
            .items_center()
            .gap_3()
            .px_5()
            .py_8()
            .child(mark)
            .child(div().text_lead().font_semibold().child(title))
            .child(
                div()
                    .max_w(rems(420. / 16.))
                    .text_center()
                    .text_color(theme.muted_foreground)
                    .child(line),
            )
    }

    fn empty_list_icon(cx: &mut Context<Self>) -> gpui_component::Icon {
        gpui_component::Icon::new(IconName::Inbox)
            .size(rems(40. / 16.))
            .text_color(cx.theme().muted_foreground)
    }

    fn render_empty_vault_actions(&self, cx: &mut Context<Self>) -> Div {
        h_flex()
            .flex_wrap()
            .justify_center()
            .gap_2()
            .pt_1()
            .child(
                button("empty-vault-new-item")
                    .primary()
                    .icon(IconName::Plus)
                    .label("New item")
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.show_personal_panel(PersonalPanel::NewItem, cx);
                    })),
            )
            .child(
                button("empty-vault-import")
                    .disabled(self.transfer_busy)
                    .icon(Glyph::Upload)
                    .label("Import credentials")
                    .on_click(cx.listener(|view, _, _, cx| view.show_import(cx))),
            )
    }

    fn empty_item_rows(cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        v_flex()
            .items_center()
            .gap_2()
            .px_5()
            .py_6()
            .child(div().font_semibold().child("No matching items"))
            .child(
                div()
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child("Try a different search."),
            )
    }

    fn render_entry_rows(
        &self,
        entries: &[&factorseal::VaultEntryMetadata],
        query: &str,
        cx: &mut Context<Self>,
    ) -> Div {
        let highlighted = self
            .shortcuts
            .list_focused
            .then(|| self.shortcuts.cursor.min(entries.len().saturating_sub(1)));
        let mut rows = v_flex()
            .w_full()
            .when(!entries.is_empty(), |rows| {
                rows.track_focus(&self.shortcuts.list)
            })
            .key_context(shortcuts::LIST_CONTEXT);
        for (index, entry) in entries.iter().enumerate() {
            let selected = is_selected_entry(self.selected_vault_item.as_ref(), entry);
            rows = rows.child(self.render_entry_row(entry, query, cx).when(
                highlighted == Some(index),
                |row| {
                    row.keyboard_cursor(selected, cx)
                        .child(self.reveal_when_moved(index == 0))
                },
            ));
        }
        if entries.is_empty() {
            rows = rows.child(Self::empty_item_rows(cx));
        }
        rows
    }

    fn render_entry_row(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        query: &str,
        cx: &mut Context<Self>,
    ) -> gpui::Stateful<Div> {
        let theme = cx.theme().clone();
        let highlight = theme.warning.opacity(0.35);
        let (label, detail) = vault_entry_label(entry);
        let selected = is_selected_entry(self.selected_vault_item.as_ref(), entry);
        let personal = is_personal_secret(entry);
        let detail = if personal {
            entry.display_username.clone().unwrap_or(detail)
        } else {
            detail
        };
        let selection = VaultSelection::Entry(Box::new(entry.clone()));
        Self::list_row(entry_element_id("secret-row", entry), selected, cx)
            .when(personal, |row| {
                row.child(personal_entry_icon(
                    entry,
                    self.website_icons.icon(entry),
                    2.,
                    &theme,
                ))
            })
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .child(
                        h_flex()
                            .min_w_0()
                            .gap_1()
                            .items_center()
                            .when(entry.favorite, |title| {
                                title.child(
                                    gpui_component::Icon::new(IconName::StarFill)
                                        .flex_none()
                                        .text_color(theme.muted_foreground),
                                )
                            })
                            .child(
                                div()
                                    .min_w_0()
                                    .font_semibold()
                                    .truncate()
                                    .child(highlighted_text(label, query, highlight)),
                            ),
                    )
                    .child(
                        div()
                            .text_caption()
                            .text_color(theme.muted_foreground)
                            .truncate()
                            .child(highlighted_text(detail, query, highlight)),
                    ),
            )
            .on_click(cx.listener(move |view, _, _, cx| {
                view.select_vault_item(selection.clone(), cx);
            }))
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
                    .child(
                        h_flex()
                            .flex_none()
                            .w(rems(24. / 16.))
                            .h(rems(24. / 16.))
                            .items_center()
                            .justify_center()
                            .rounded_full()
                            .bg(theme.primary)
                            .text_color(theme.primary_foreground)
                            .text_body()
                            .font_semibold()
                            .child(format!("{}.", index + 1)),
                    )
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_2()
                            .child(instruction.text)
                            .when_some(instruction.command, |element, command| {
                                element.child(
                                    h_flex()
                                        .w_full()
                                        .items_center()
                                        .gap_2()
                                        .py_1()
                                        .pl_3()
                                        .pr_1()
                                        .rounded(theme.radius)
                                        .bg(theme.muted)
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .font_family(theme.mono_font_family.clone())
                                                .text_body()
                                                .child(command),
                                        )
                                        .child(
                                            Clipboard::new(("guidance-command", index))
                                                .value(command)
                                                .tooltip("Copy"),
                                        ),
                                )
                            }),
                    ),
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

        let instructions = Self::render_category_instructions(&guidance, cx);
        let integration_error = if kind == factorseal::DocumentKind::LinuxSecretService {
            contents.secret_service_error.clone()
        } else {
            None
        };
        v_flex()
            .w_full()
            .gap_4()
            .p_6()
            .child(
                div()
                    .text_color(theme.muted_foreground)
                    .child(guidance.description),
            )
            .when_some(integration_error, |element, error| {
                element.child(error_banner(error, theme.danger))
            })
            .child(self.render_wifi_migration(kind, cx))
            .child(div().font_semibold().child("How to use it"))
            .child(instructions)
            .when_some(category_documentation(kind), |element, (id, label, url)| {
                element.child(h_flex().pt_1().child(link_showing(
                    id,
                    label,
                    format!("{label} ↗"),
                    url,
                    cx,
                )))
            })
    }

    fn render_cxf_key_options(&self, is_import: bool, cx: &mut Context<Self>) -> Div {
        let mut panel = v_flex().gap_3().child(segmented(
            "transfer-key-mode",
            [(false, "Passphrase"), (true, "Post-quantum key")],
            self.transfer_use_recipient,
            self.transfer_busy,
            cx.listener(|view, hybrid: &bool, _, cx| {
                view.clear_secret_inputs(cx);
                view.transfer_use_recipient = *hybrid;
                view.transfer_key_file = None;
                view.transfer_notice = None;
                cx.notify();
            }),
            cx.theme(),
        ));
        if self.transfer_use_recipient {
            panel = panel
                .child(div().whitespace_normal().child(if is_import {
                    "Choose the private age identity matching the recipient used for this export. The key file must be unencrypted and private to your account."
                } else {
                    "Choose the recipient's public age post-quantum key. Only the matching private key can decrypt this export. Compatible with age 1.3 and later."
                }))
                .child(
                    button("choose-transfer-key")
                        .icon(IconName::FolderOpen)
                        .label(if is_import { "Choose private key file" } else { "Choose public key file" })
                        .disabled(self.transfer_busy)
                        .on_click(cx.listener(move |view, _, _, cx| view.choose_transfer_key_file(is_import, cx))),
                )
                .when_some(self.transfer_key_file.as_ref(), |panel, path| {
                    panel.child(div().whitespace_normal().child(path.file_name().unwrap_or_default().to_string_lossy().into_owned()))
                });
        }
        panel
    }

    #[allow(clippy::too_many_lines)]
    fn render_transfer_detail(&self, is_backup: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let is_import = self.transfer_is_import;
        let description = match (is_backup, is_import) {
            (true, true) => "Restore saved vault items from a FactorSeal backup.",
            (true, false) => {
                "Save an encrypted backup of your Personal secrets, project secrets, and system-keyring items."
            }
            (false, true) => {
                "Bring Personal credentials from another password manager or an encrypted transfer file."
            }
            (false, false) => "Move Personal credentials to another device or password manager.",
        };
        let format = self.transfer_format;
        let use_recipient = format == TransferFormat::CxfAge && self.transfer_use_recipient;
        let replace_control = {
            let view = cx.entity().downgrade();
            Checkbox::new("replace-import-conflicts")
                .checked(self.transfer_replace_existing)
                .label("Replace existing items")
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
        let mut form = v_flex()
            .w_full()
            .min_w_0()
            .gap_5()
            .child(div().text_color(theme.muted_foreground).child(description));
        if !is_backup {
            #[cfg(feature = "apple-credential-exchange")]
            if crate::apple_exchange::available() {
                form = form.child(self.render_system_transfer(is_import, cx));
            }
            form = form.child(
                v_flex()
                    .gap_2()
                    .child(div().text_body().font_semibold().child("File type"))
                    .child(segmented(
                        "transfer-format",
                        TransferFormat::ALL
                            .into_iter()
                            .filter(|candidate| {
                                !candidate.is_native()
                                    && (is_import || *candidate != TransferFormat::OnePasswordPux)
                            })
                            .map(|candidate| {
                                (
                                    candidate,
                                    if candidate == TransferFormat::CxfAge {
                                        "Encrypted transfer"
                                    } else {
                                        candidate.label()
                                    },
                                )
                            }),
                        format,
                        self.transfer_busy,
                        cx.listener(|view, candidate: &TransferFormat, _, cx| {
                            view.select_transfer_format(*candidate, cx);
                        }),
                        &theme,
                    )),
            );
        }
        if format.is_encrypted() {
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
                            .child(if is_backup { "Encrypted backup" } else { "Encrypted credential file" }),
                    )
                    .child(
                        div()
                            .w_full()
                            .whitespace_normal()
                            .text_color(theme.muted_foreground)
                            .child(if format == TransferFormat::CxfAge {
                                "Uses the open CXF credential format with age encryption. The receiving manager needs CXF support and may require a separate decryption step."
                            } else if is_import {
                                "Enter the passphrase used when this backup was created. Restored data is protected by this device's vault keys."
                            } else {
                                "Includes durable vault items, but not provider caches, application authorizations, history, or device keys. Choose a separate passphrase for this portable backup."
                            }),
                    )
                    .when(format == TransferFormat::CxfAge, |panel| panel.child(self.render_cxf_key_options(is_import, cx)))
                    .when(!use_recipient, |panel| panel.child(field_label(if is_backup { "Backup passphrase" } else { "Transfer passphrase" }, self.archive_passphrase.clone())))
                    .when(!is_import && !use_recipient, |panel| {
                        panel.child(
                            field_label("Confirm passphrase", self.archive_passphrase_confirmation.clone()),
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
                                "Personal items retain typed fields and sections. Unknown source data is kept with the encrypted item. 1PUX files are imported as separate document items."
                            } else {
                                "Only Personal secrets are exported. Password-manager interchange files are plaintext and are not protected by FactorSeal after they are written."
                            }),
                    )
                    .when(!is_import, |panel| {
                        panel.child(
                            controls::toggle_frame("confirm-plaintext-export-frame", plaintext_control)
                                .disabled(self.transfer_busy)
                                .without_focus_ring(),
                        )
                    }),
            );
        }
        if is_import {
            form = form.child(
                controls::toggle_frame("replace-import-conflicts-frame", replace_control)
                    .disabled(self.transfer_busy)
                    .without_focus_ring(),
            );
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
                                    if is_backup {
                                        "Restore in progress…"
                                    } else {
                                        "Import in progress…"
                                    }
                                } else if is_backup {
                                    "Preparing backup…"
                                } else {
                                    "Preparing export…"
                                }),
                        )
                    })
                    .child(
                        button(if is_import {
                            "start-secret-import"
                        } else {
                            "start-secret-export"
                        })
                        .primary()
                        .icon(if is_import {
                            Glyph::Upload
                        } else {
                            Glyph::Download
                        })
                        .loading(self.transfer_busy)
                        .disabled(self.transfer_busy)
                        .label(if is_import {
                            "Choose file and review"
                        } else if is_backup {
                            "Save backup"
                        } else {
                            "Save transfer file"
                        })
                        .on_click(cx.listener(
                            move |view, _, window, cx| {
                                view.start_transfer(is_import, window, cx);
                            },
                        )),
                    ),
            );

        form
    }

    fn render_personal_secrets_detail(&self, cx: &mut Context<Self>) -> Div {
        self.render_new_item_page(cx)
    }

    #[allow(clippy::too_many_lines)]
    fn render_vault_detail(&self, contents: &VaultContents, cx: &mut Context<Self>) -> Div {
        if shows_empty_detail(
            self.selected_vault_item.as_ref(),
            self.personal_panel,
            self.showing_search_results(cx),
        ) {
            let has_items = if self.showing_search_results(cx) {
                !search_results(&contents.entries, &self.search_query(cx)).is_empty()
            } else {
                contents.entries.iter().any(is_personal_secret)
            };
            if self.shortcuts.compact || !has_items {
                return div();
            }
            let icon = Self::empty_list_icon(cx);
            return v_flex()
                .size_full()
                .justify_center()
                .child(Self::empty_state(
                    icon,
                    "No item selected",
                    "Choose an item from the list to see its details.",
                    cx,
                ));
        }
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
                        .text_title()
                        .font_semibold()
                        .child("Welcome to your vault"),
                )
                .child(
                    div()
                        .max_w(rems(420. / 16.))
                        .text_center()
                        .text_color(theme.muted_foreground)
                        .text_lead()
                        .child(if entry_count == 0 {
                            "Add your first secret or import from another password manager."
                        } else {
                            "Choose a category on the left to see its items."
                        }),
                )
                .map(|welcome| {
                    if entry_count == 0 {
                        welcome.child(self.render_empty_vault_actions(cx))
                    } else {
                        welcome.child(
                            button("welcome-new-item")
                                .primary()
                                .icon(IconName::Plus)
                                .label("New item")
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.show_personal_panel(PersonalPanel::NewItem, cx);
                                })),
                        )
                    }
                })
                .child(self.render_browser(cx)),
            Some(VaultSelection::PersonalSecrets) => self.render_personal_secrets_detail(cx),
            Some(
                VaultSelection::Devices
                | VaultSelection::TransferCredentials
                | VaultSelection::BackupVault,
            ) => div(),
            Some(VaultSelection::Category(kind)) => {
                self.render_category_detail(*kind, contents, cx)
            }
            Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => {
                self.render_personal_item(entry, cx)
            }
            Some(VaultSelection::Entry(entry)) => {
                let (title, _) = vault_entry_label(entry);
                v_flex()
                    .size_full()
                    .gap_4()
                    .p_6()
                    .child(div().text_heading().font_semibold().child(title))
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .child("Secret value hidden"),
                    )
                    .child(Self::render_detail_rows(vault_entry_details(entry), cx))
                    .child(Self::render_entry_access(entry, contents, cx))
            }
        }
    }

    fn revoke_access(&mut self, id: String, cx: &mut Context<Self>) {
        let Some(metadata) = self.snapshot.metadata().cloned() else {
            return;
        };
        let runtime = Arc::clone(&self.runtime);
        cx.spawn(async move |this, cx| {
            let revoked_id = id.clone();
            let result =
                smol::unblock(move || runtime.revoke_permission(&metadata, revoked_id)).await;
            let _ = this.update(cx, |view, cx| {
                match result {
                    Ok(()) => {
                        if let Snapshot::Unsealed { contents, .. } = &mut view.snapshot {
                            contents
                                .permissions
                                .retain(|permission| permission.id != id);
                        }
                    }
                    Err(message) => {
                        if let Snapshot::Unsealed { error, .. } = &mut view.snapshot {
                            *error = Some(message);
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn setup_error_for(&self, field: SetupField) -> Option<String> {
        self.setup_error
            .as_ref()
            .filter(|(error_field, _)| *error_field == field)
            .map(|(_, message)| message.clone())
    }

    fn render_setup_field(&self, field: SetupField, cx: &Context<Self>) -> Div {
        let (label, id, input) = match field {
            SetupField::Confirmation => (
                "Confirm password",
                "reveal-password-confirmation",
                &self.password_confirmation,
            ),
            SetupField::Password | SetupField::Form => {
                ("Password", "reveal-password", &self.password)
            }
        };
        field_label(label, self.render_password_field(id, input, cx))
            .when(field == SetupField::Password, |element| {
                element.when_some(self.password_strength, |element, strength| {
                    element.child(generator::strength_meter(strength, cx))
                })
            })
            .when_some(self.setup_error_for(field), |element, error| {
                element.child(field_message(error, cx.theme().danger))
            })
    }

    fn render_uninitialized(&self, runtime_error: Option<&str>, cx: &mut Context<Self>) -> Div {
        let runtime_notice = runtime_error.map(|error| self.render_error_notice(error, true, cx));
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
                button(("setup-method", index))
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
                            .text_title()
                            .font_semibold()
                            .child("Create your vault"),
                    )
                    .child(
                        div()
                            .text_center()
                            .text_color(theme.muted_foreground)
                            .text_lead()
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
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child(setup_protection_description(cx)),
            )
            .when(has_multiple_methods, |element| element.child(methods))
            .when(cfg!(target_os = "linux"), |element| {
                element
                    .child(
                        div()
                            .text_body()
                            .text_color(theme.muted_foreground)
                            .child(
                                "Unlock with a password on Linux. Biometric unlock is not available on this platform.",
                            ),
                    )
                    .child(h_flex().child(link(
                        "security-link",
                        "How device protection works",
                        "https://factorseal.dev/security",
                        cx,
                    )))
            })
            .when(self.setup_method.needs_password(), |element| {
                element
                    .child(self.render_setup_field(SetupField::Password, cx))
                    .child(self.render_setup_field(SetupField::Confirmation, cx))
            })
            .when_some(self.setup_error_for(SetupField::Form), |element, error| {
                element.child(error_banner(error, theme.danger))
            })
            .children(runtime_notice)
            .child(
                button("initialize-vault")
                    .primary()
                    .large()
                    .w_full()
                    .label("Create vault")
                    .on_click(cx.listener(|view, _, window, cx| view.initialize(window, cx))),
            )
    }

    fn render_settings_button(cx: &mut Context<Self>) -> Button {
        button("open-settings")
            .icon(gpui_component::Icon::new(IconName::Settings).text_color(cx.theme().foreground))
            .label("Settings")
            .on_click(cx.listener(|view, _, _, cx| view.open_settings(cx)))
    }

    fn open_settings(&mut self, cx: &mut Context<Self>) {
        if !self.leave_item_editor(Self::open_settings, cx) {
            return;
        }
        if let Some(VaultSelection::Entry(entry)) = &self.selected_vault_item
            && is_personal_secret(entry)
        {
            self.show_personal_panel(PersonalPanel::Overview, cx);
        }
        if !self.settings_open {
            self.section_opened = false;
        }
        self.settings_open = true;
        cx.notify();
    }

    fn render_body(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        match &self.snapshot {
            Snapshot::Uninitialized { error } => self.render_uninitialized(error.as_deref(), cx),
            Snapshot::Initializing => vault_card(&theme)
                .items_center()
                .text_center()
                .child(brand_mark(56., theme.foreground))
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_title().font_semibold().child("Creating vault…"))
                .child(
                    div()
                        .text_color(theme.muted_foreground)
                        .text_body()
                        .child("Protecting your vault with this device's hardware."),
                ),
            Snapshot::Sealed { metadata, error } => {
                self.render_sealed(metadata, error.as_deref(), cx)
            }
            Snapshot::Unlocking { metadata, .. } => self.render_sealed(metadata, None, cx),
            Snapshot::Sealing { .. } => vault_card(&theme)
                .items_center()
                .text_center()
                .child(brand_mark(56., theme.foreground))
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_title().font_semibold().child("Sealing vault…"))
                .child(
                    div()
                        .text_body()
                        .text_color(theme.muted_foreground)
                        .child("Closing access and removing vault keys from memory."),
                ),
            Snapshot::Unsealed { .. } => div(),
            Snapshot::Error(error) => vault_card(&theme)
                .items_center()
                .child(brand_mark(56., theme.foreground))
                .child(
                    div()
                        .text_title()
                        .font_semibold()
                        .child("Vault unavailable"),
                )
                .child(self.render_error_notice(error, true, cx)),
        }
    }
}

impl DesktopView {
    fn body_max_width(&self) -> f32 {
        if self.settings_open {
            1200.
        } else {
            match &self.snapshot {
                Snapshot::Uninitialized { .. } => 520.,
                _ => 440.,
            }
        }
    }
}

impl DesktopView {
    fn render_content(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let body_max_width = self.body_max_width();
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
                    .when(!self.settings_open, gpui::Styled::items_center)
                    .child(
                        div()
                            .w_full()
                            .max_w(rems(body_max_width / 16.))
                            .flex_none()
                            .child(crate::motion::enter(
                                screen_key(self.settings_open, &self.snapshot),
                                self.render_body(cx),
                            )),
                    ),
            )
            .overflow_y_scrollbar()
    }

    fn render_framed(&self, compact: bool, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        v_flex()
            .size_full()
            .px_6()
            .child(
                h_flex()
                    .w_full()
                    .flex_none()
                    .min_h(rems(80. / 16.))
                    .py_3()
                    .flex_wrap()
                    .items_center()
                    .justify_between()
                    .gap_4()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(self.render_breadcrumb(compact, cx))
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .flex_none()
                            .when(!self.settings_open, |element| {
                                element.child(Self::render_settings_button(cx))
                            }),
                    ),
            )
            .map(|frame| {
                if self.settings_open {
                    frame.child(
                        v_flex()
                            .flex_1()
                            .min_h_0()
                            .w_full()
                            .when(compact && self.section_opened, |settings| {
                                settings.child(self.render_vault_back(false, cx))
                            })
                            .child(
                                h_flex()
                                    .flex_1()
                                    .min_h_0()
                                    .w_full()
                                    .child(self.render_section_layout(compact, cx)),
                            ),
                    )
                } else {
                    frame.child(self.render_content(cx))
                }
            })
            .child(self.render_footer(cx))
    }
}

impl Render for DesktopView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.ensure_new_item_editor(window, cx);
        self.apply_qr_scan(window, cx);
        self.fill_from_one_time_link(window, cx);
        self.animate_item_editor(window, cx);
        self.open_leave_dialog(window, cx);
        let dialog_layer = Root::render_dialog_layer(window, cx);
        let notification_layer = Root::render_notification_layer(window, cx);
        window.set_rem_size(crate::appearance::rem_size(cx));
        if self.focus_password && !self.settings_open {
            self.focus_password = false;
            let needs_password = match &self.snapshot {
                Snapshot::Sealed { metadata, .. } => self
                    .selected_group
                    .as_ref()
                    .unwrap_or(metadata.preferred_unlock_group())
                    .requires(factorseal::UnlockFactorKind::Password),
                Snapshot::Uninitialized { .. } => self.setup_method.needs_password(),
                _ => false,
            };
            if needs_password {
                self.password
                    .update(cx, |input, cx| input.focus(window, cx));
            }
        }
        let theme = cx.theme().clone();
        let scale = crate::appearance::scale(cx);
        let compact = window.viewport_size().width < px(960.) * scale;
        let single_pane = window.viewport_size().width < px(720.) * scale;
        self.shortcuts.compact = compact;
        self.shortcuts.narrow = window.viewport_size().width < px(1200.) * scale;
        self.shortcuts.list_focused = self.shortcuts.list.is_focused(window);
        if matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            let (page, depth) = self.navigation_page(compact, single_pane, cx);
            self.navigation.visit(page, depth);
        }
        let device_pairing = self
            .visible_pairing()
            .map(|screen| self.render_device_pairing(screen, cx));
        let content = match &self.snapshot {
            Snapshot::Unsealed {
                contents,
                contents_error,
                error,
                ..
            } => crate::motion::enter(
                screen_key(false, &self.snapshot),
                self.render_unsealed(
                    contents,
                    (contents_error.as_deref(), error.as_deref()),
                    compact,
                    single_pane,
                    cx,
                ),
            )
            .into_any_element(),
            _ => self.render_framed(compact, cx).into_any_element(),
        };
        self.bind_shortcuts(div(), cx)
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .text_body()
            .child(content)
            .children(self.render_notices(cx))
            .children(device_pairing)
            .when(window.has_active_dialog(cx), |root| {
                root.child(crate::motion::fade(
                    "dialog-scrim",
                    div().absolute().inset_0().bg(theme.overlay),
                ))
            })
            .children(dialog_layer)
            .children(notification_layer)
    }
}

fn forget_desktop_window(handle: AnyWindowHandle, cx: &mut App) -> bool {
    if cx.global::<DesktopWindow>().handle != Some(handle) {
        return false;
    }
    #[cfg(feature = "apple-credential-exchange")]
    system_transfer::cancel(cx);
    let desktop = cx.global_mut::<DesktopWindow>();
    desktop.handle = None;
    desktop.visible = false;
    if let Ok(mut view) = desktop.view.lock() {
        view.take();
    }
    true
}

fn apply_desktop_snapshot(snapshot: &Snapshot, cx: &mut App) {
    #[cfg(feature = "apple-credential-exchange")]
    crate::apple_exchange::set_unlocked(matches!(snapshot, Snapshot::Unsealed { .. }));
    let view_holder = {
        let desktop = cx.global_mut::<DesktopWindow>();
        desktop.snapshot = snapshot.clone();
        desktop.refresh_generation = desktop.refresh_generation.wrapping_add(1);
        Arc::clone(&desktop.view)
    };
    if let Ok(holder) = view_holder.lock()
        && let Some(view) = holder.as_ref()
    {
        view.update(cx, |view, cx| view.apply_snapshot(snapshot.clone(), cx));
    }
    cx.global_mut::<DesktopStatus>().unsealed = matches!(snapshot, Snapshot::Unsealed { .. });
    refresh_tray(cx);
    sync_secret_service(snapshot, cx);
    access::update(snapshot, cx);
    if matches!(snapshot, Snapshot::Unsealed { .. }) {
        crate::timing::finish_unlock("ui_updated", "ok");
    }
    load_deferred_permissions(snapshot, cx);
}

fn load_deferred_permissions(snapshot: &Snapshot, cx: &mut App) {
    let Snapshot::Unsealed {
        metadata, contents, ..
    } = snapshot
    else {
        return;
    };
    if !contents.permissions_loading {
        return;
    }
    let metadata = metadata.clone();
    let generation = cx.global::<DesktopWindow>().refresh_generation;
    let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
    cx.spawn(async move |cx| {
        let started = std::time::Instant::now();
        let result = smol::unblock(move || runtime.load_permissions(&metadata)).await;
        cx.update(|cx| {
            let desktop = cx.global_mut::<DesktopWindow>();
            // A seal, another unlock, or a refresh supersedes this request.
            if desktop.refresh_generation != generation {
                return;
            }
            if let Snapshot::Unsealed { contents, .. } = &mut desktop.snapshot {
                contents.complete_permissions(result.clone());
            }
            let view_holder = Arc::clone(&desktop.view);
            if let Ok(holder) = view_holder.lock()
                && let Some(view) = holder.as_ref()
            {
                view.update(cx, |view, cx| {
                    // Patch only permissions, retaining edits and selection
                    // made since the first unlocked snapshot was displayed.
                    if let Snapshot::Unsealed { contents, .. } = &mut view.snapshot {
                        contents.complete_permissions(result.clone());
                        cx.notify();
                    }
                });
            }
            crate::timing::record(
                "desktop_inventory",
                "permissions_ready",
                started,
                if result.is_ok() { "ok" } else { "error" },
            );
        });
    })
    .detach();
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

// Actions may arrive through a borrowed window. Defer all window operations
// until dispatch finishes, including explicit menu actions and tray toggles.
fn open_desktop(_: &OpenDesktop, cx: &mut App) {
    cx.defer(show_desktop);
}

fn open_settings(_: &OpenSettings, cx: &mut App) {
    cx.defer(|cx| {
        show_desktop(cx);
        let view = cx
            .global::<DesktopWindow>()
            .view
            .lock()
            .ok()
            .and_then(|view| view.clone());
        if let Some(view) = view {
            view.update(cx, DesktopView::open_settings);
        }
    });
}

fn close_desktop(_: &CloseDesktop, cx: &mut App) {
    cx.defer(hide_desktop);
}

fn toggle_desktop(_: &ToggleDesktop, cx: &mut App) {
    cx.defer(toggle_desktop_window);
}

fn show_desktop(cx: &mut App) {
    // Activate the app to bring its window to the foreground on macOS.
    #[cfg(target_os = "macos")]
    cx.activate(true);

    let existing = cx.global::<DesktopWindow>().handle;
    if let Some(handle) = existing {
        if window_activation::desktop(handle, cx).is_ok() {
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
                factorseal::diagnostics::event("desktop", "open_window", "error");
                eprintln!("failed to open FactorSeal Desktop: {error}");
                return;
            }
        }
    }
    refresh_tray(cx);
    refresh_desktop_snapshot(runtime, cx);
}

fn hide_desktop(cx: &mut App) {
    #[cfg(feature = "apple-credential-exchange")]
    system_transfer::cancel(cx);
    flush_desktop_personal_changes(cx);
    let handle = cx.global::<DesktopWindow>().handle;
    let Some(handle) = handle else {
        return;
    };
    cx.global_mut::<DesktopWindow>().visible = false;
    dismiss_secret_service_prompts(cx);
    refresh_tray(cx);
    if let Err(error) = handle.update(cx, |_, window, cx| {
        remember_desktop(window, cx);
        window.set_visible(false);
    }) {
        forget_desktop_window(handle, cx);
        refresh_tray(cx);
        factorseal::diagnostics::event("desktop", "hide_window", "error");
        eprintln!("failed to hide FactorSeal Desktop window: {error}");
    }
}

fn toggle_desktop_window(cx: &mut App) {
    let desktop = cx.global::<DesktopWindow>();
    let visible = desktop.visible;
    let handle = desktop.handle;
    let just_deactivated = desktop
        .deactivated_at
        .is_some_and(|at| at.elapsed() < TRAY_CLICK_FOCUS_GRACE);
    let focused = just_deactivated
        || handle.is_some_and(|handle| {
            handle
                .update(cx, |_, window, _| window.is_window_active())
                .unwrap_or(false)
        });
    if visible && focused {
        hide_desktop(cx);
    } else {
        show_desktop(cx);
    }
}

fn flush_desktop_personal_changes(cx: &mut App) {
    let holder = cx
        .try_global::<DesktopWindow>()
        .map(|desktop| Arc::clone(&desktop.view));
    if let Some(holder) = holder
        && let Ok(holder) = holder.lock()
        && let Some(view) = holder.as_ref()
    {
        view.update(cx, |view, cx| {
            view.save_item_editor_on_exit(cx);
        });
    }
}

fn step_desktop_personal_history(direction: personal_history::Direction, cx: &mut App) {
    let Some(desktop) = cx.try_global::<DesktopWindow>() else {
        return;
    };
    let Some(handle) = desktop.handle else {
        return;
    };
    let Some(view) = desktop.view.lock().ok().and_then(|view| view.clone()) else {
        return;
    };
    let _ = handle.update(cx, |_, window, cx| {
        if window.is_window_active() {
            view.update(cx, |view, cx| view.step_personal_history(direction, cx));
        }
    });
}

fn undo_personal_change(_: &UndoPersonalChange, cx: &mut App) {
    cx.defer(|cx| step_desktop_personal_history(personal_history::Direction::Undo, cx));
}

fn redo_personal_change(_: &RedoPersonalChange, cx: &mut App) {
    cx.defer(|cx| step_desktop_personal_history(personal_history::Direction::Redo, cx));
}

fn seal_vault(_: &SealVault, cx: &mut App) {
    flush_desktop_personal_changes(cx);
    if let Some(runtime) = cx.try_global::<RuntimeGlobal>()
        && let Err(error) = runtime.0.seal()
    {
        factorseal::diagnostics::event("desktop", "seal_vault", "error");
        eprintln!("failed to seal FactorSeal vault: {error}");
    }
}

fn remember_desktop(window: &Window, cx: &mut App) {
    let placement = placement::of(window);
    let holder = Arc::clone(&cx.global::<DesktopWindow>().view);
    let page = holder.lock().ok().and_then(|holder| {
        holder
            .as_ref()
            .map(|view| view.read(cx))
            .and_then(|view| view.is_unsealed().then(|| view.current_page()))
    });
    crate::appearance::remember(
        |settings| {
            settings.window = Some(placement);
            if let Some(page) = &page {
                settings.page.clone_from(page);
            }
        },
        cx,
    );
}

fn focus_search(_: &FocusSearch, cx: &mut App) {
    cx.defer(focus_desktop_search);
}

fn focus_desktop_search(cx: &mut App) {
    let desktop = cx.global::<DesktopWindow>();
    let Some(handle) = desktop.handle else {
        return;
    };
    let Some(view) = desktop.view.lock().ok().and_then(|view| view.clone()) else {
        return;
    };
    handle
        .update(cx, |_, window, cx| {
            if window.is_window_active() {
                view.update(cx, |view, cx| view.focus_vault_search(window, cx));
            }
        })
        .ok();
}

fn quit(_: &Quit, cx: &mut App) {
    flush_desktop_personal_changes(cx);
    let desktop = cx.global::<DesktopWindow>();
    if desktop.visible
        && let Some(handle) = desktop.handle
    {
        let _ = handle.update(cx, |_, window, cx| remember_desktop(window, cx));
    }
    cx.global_mut::<DesktopStatus>().quitting = true;
    if let Some(runtime) = cx.try_global::<RuntimeGlobal>() {
        let _ = runtime.0.seal();
    }
    let tray = cx.try_global::<DesktopTray>().map(|tray| tray.0.clone());
    if let Some(tray) = tray
        && let Err(error) = tray.close(cx)
    {
        factorseal::diagnostics::event("desktop", "close_tray", "error");
        eprintln!("failed to close FactorSeal tray: {error}");
    }
    factorseal::diagnostics::finish(true);
    cx.quit();
}

fn tray_label() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let revision = env!("FACTORSEAL_GIT_REVISION");
    if cfg!(debug_assertions) {
        if revision.is_empty() {
            format!("FactorSeal {version} (dev)")
        } else {
            format!("FactorSeal {version} (dev · {revision})")
        }
    } else {
        format!("FactorSeal {version}")
    }
}

fn tray_menu(cx: &mut App) -> Vec<MenuItem> {
    let status = cx.global::<DesktopStatus>();
    vec![
        MenuItem::action("Open FactorSeal", OpenDesktop),
        MenuItem::separator(),
        MenuItem::action("Seal", SealVault).disabled(!status.unsealed),
        MenuItem::action("Settings…", OpenSettings),
        MenuItem::action("Quit", Quit),
    ]
}

fn refresh_tray(cx: &mut App) {
    let tray = cx.try_global::<DesktopTray>().map(|tray| tray.0.clone());
    if let Some(tray) = tray
        && let Err(error) = tray.refresh_menu(cx)
    {
        factorseal::diagnostics::event("desktop", "refresh_tray_menu", "error");
        eprintln!("failed to refresh FactorSeal tray menu: {error}");
    }
}

fn factorseal_icon(dark_background: bool, cx: &App) -> gpui_tray::Result<Icon> {
    #[cfg(target_os = "macos")]
    let image = {
        let _ = dark_background;
        let svg = include_str!("../../assets/logo/factorseal-mark-micro.svg")
            .replace("<svg ", "<svg width=\"18\" height=\"18\" ")
            .replace("currentColor", "#000000");
        gpui::Image::from_bytes(gpui::ImageFormat::Svg, svg.into_bytes())
    };
    #[cfg(not(target_os = "macos"))]
    let image = {
        let bytes: &[u8] = if dark_background {
            include_bytes!("../../assets/logo/factorseal-tray-paper.png")
        } else {
            include_bytes!("../../assets/logo/factorseal-tray-ink.png")
        };
        gpui::Image::from_bytes(gpui::ImageFormat::Png, bytes.to_vec())
    };
    let icon = Icon::from_gpui(&image, cx);
    #[cfg(target_os = "macos")]
    let icon = icon.scale_factor(2.0).template(true);
    icon.build()
}

fn install_tray(cx: &mut App) {
    let dark_background = gpui_component::Theme::global(cx).is_dark();
    let tray = factorseal_icon(dark_background, cx).and_then(|icon| {
        Tray::builder()
            .icon(icon)
            .tooltip(tray_label())
            .on_activate(ToggleDesktop)
            .menu(tray_menu)
            .build(cx)
    });
    match tray {
        Ok(tray) => cx.set_global(DesktopTray(tray)),
        Err(error) => {
            factorseal::diagnostics::event("desktop", "install_tray", "error");
            eprintln!("FactorSeal tray unavailable: {error}");
        }
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
            if let Err(error) = tray.set_icon(icon, cx) {
                factorseal::diagnostics::event("desktop", "refresh_tray_icon", "error");
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
    let handle = cx.open_window(
        WindowOptions {
            window_bounds: Some(placement::initial(initial_height, cx)),
            window_min_size: Some(placement::MINIMUM_SIZE),
            titlebar: Some(gpui::TitlebarOptions {
                title: Some("FactorSeal".into()),
                ..Default::default()
            }),
            app_id: Some("dev.factorseal.Desktop".to_owned()),
            show: visible,
            ..Default::default()
        },
        move |window, cx| {
            #[cfg(target_os = "macos")]
            window_activation::configure_desktop(window);
            window.on_window_should_close(cx, |window, cx| {
                remember_desktop(window, cx);
                if cx.global::<DesktopStatus>().no_tray {
                    quit(&Quit, cx);
                    return true;
                }
                if cx.global::<DesktopStatus>().quitting {
                    return true;
                }
                window.set_visible(false);
                cx.global_mut::<DesktopWindow>().visible = false;
                dismiss_secret_service_prompts(cx);
                refresh_tray(cx);
                false
            });
            let view = cx.new(|cx| {
                let mut view = DesktopView::new(Arc::clone(&runtime), snapshot, window, cx);
                view.restore_page(cx);
                view
            });
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
    access_requests: smol::channel::Receiver<AccessEvent>,
    secret_service: Option<Arc<SecretServiceHost>>,
    cx: &mut App,
) {
    gpui_component::init(cx);
    theming::initialize(cx);
    crate::appearance::use_launch_lease(config.lease, cx);
    cx.on_action(open_desktop);
    cx.on_action(open_settings);
    cx.on_action(close_desktop);
    cx.on_action(toggle_desktop);
    cx.on_action(seal_vault);
    cx.on_action(quit);
    cx.on_action(focus_search);
    cx.bind_keys([
        KeyBinding::new("secondary-f", FocusSearch, None),
        KeyBinding::new("secondary-f", FocusSearch, Some("Input")),
    ]);
    shortcuts::bind_keys(cx);
    cx.on_action(undo_personal_change);
    cx.on_action(redo_personal_change);

    let browser_root = config.root.clone();
    let (runtime, receiver) = DesktopRuntime::new(config);
    let initial = runtime.inspect();
    cx.set_global(RuntimeGlobal(Arc::clone(&runtime)));
    #[cfg(target_os = "linux")]
    cx.set_global(SecretServiceGlobal(secret_service));
    #[cfg(not(target_os = "linux"))]
    drop(secret_service);
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
        deactivated_at: None,
        snapshot: initial.clone(),
        refresh_generation: 0,
    });
    sync_secret_service(&initial, cx);
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
    #[cfg(feature = "apple-credential-exchange")]
    system_transfer::setup(cx);
    browser::setup(&browser_root, Arc::clone(&runtime), cx);

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
    access::setup(access_requests, cx);
    if !background {
        cx.activate(true);
    }
}

/// Keep the hosted Secret Service in step with the vault: publish the vault
/// while it is unsealed and lock the collection otherwise. Clients waiting on
/// an unlock prompt complete once the vault is published.
fn sync_secret_service(snapshot: &Snapshot, cx: &mut App) {
    #[cfg(target_os = "linux")]
    {
        let Some(host) = cx.global::<SecretServiceGlobal>().0.clone() else {
            return;
        };
        let result = match snapshot {
            Snapshot::Unsealed { .. } => {
                if host.is_installed() {
                    Ok(())
                } else {
                    let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
                    host.install(Box::new(runtime.vault_client()))
                }
            }
            Snapshot::Unlocking { .. } | Snapshot::Initializing => Ok(()),
            Snapshot::Sealed { .. }
            | Snapshot::Sealing { .. }
            | Snapshot::Uninitialized { .. }
            | Snapshot::Error(_) => {
                // Queue behind any install that has not published its agent yet.
                host.uninstall()
            }
        };
        if let Err(error) = result {
            eprintln!("factorseal-desktop: system keyring integration: {error}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (snapshot, cx);
    }
}

/// A hidden window cannot answer an unlock prompt. Complete pending prompts
/// as dismissed so waiting clients get an answer instead of a hang.
fn dismiss_secret_service_prompts(cx: &mut App) {
    if access::is_open(cx) {
        return;
    }
    #[cfg(target_os = "linux")]
    if !cx.global::<DesktopStatus>().unsealed
        && let Some(host) = &cx.global::<SecretServiceGlobal>().0
        && let Err(error) = host.dismiss_prompts()
    {
        eprintln!("factorseal-desktop: system keyring integration: {error}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cx;
    }
}

#[cfg(test)]
mod tests {
    use factorseal::{DocumentKind, SecretSpecAddress, SecretSpecCoordinates};

    use super::{
        category_badge, category_documentation, category_guidance, display_executable,
        hardware_backend_label, password_strength_error, secret_spec_address_label,
    };

    #[test]
    fn executables_are_shown_without_the_verbatim_prefix() {
        assert_eq!(
            display_executable(r"\\?\C:\Program Files\FactorSeal\factorseal.exe"),
            r"C:\Program Files\FactorSeal\factorseal.exe"
        );
        assert_eq!(
            display_executable(r"\\?\UNC\server\share\factorseal.exe"),
            r"\\server\share\factorseal.exe"
        );
        assert_eq!(
            display_executable("/usr/bin/factorseal"),
            "/usr/bin/factorseal"
        );
        // A verbatim path that is not a drive path keeps its prefix.
        assert_eq!(
            display_executable(r"\\?\Volume{1}\factorseal.exe"),
            r"\\?\Volume{1}\factorseal.exe"
        );
    }

    fn personal_entries(items: &[(&str, bool)]) -> Vec<factorseal::VaultEntryMetadata> {
        items
            .iter()
            .map(|(name, favorite)| factorseal::VaultEntryMetadata {
                access_project: None,
                display_name: Some((*name).into()),
                display_type: Some("Login".into()),
                display_username: None,
                display_website: None,
                updated_at: None,
                favorite: *favorite,
                document_kind: DocumentKind::LocalKeyring,
                partition: super::PERSONAL_SECRET_NAMESPACE.to_vec(),
                address: factorseal::SecretAddress::new(format!("id-{name}"), None).unwrap(),
            })
            .collect()
    }

    fn sorted_names(entries: &[factorseal::VaultEntryMetadata], query: &str) -> Vec<String> {
        super::sorted_personal_entries(entries, query)
            .iter()
            .map(|entry| super::vault_entry_label(entry).0)
            .collect()
    }

    #[test]
    fn open_entries_are_remembered_and_reopened() {
        use super::{Page, VaultSelection, restored_selection};

        let entry = |partition: &[u8], document_kind| factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: None,
            display_type: None,
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind,
            partition: partition.to_vec(),
            address: factorseal::SecretAddress::new("item".to_owned(), None).unwrap(),
        };
        let personal = entry(super::PERSONAL_SECRET_NAMESPACE, DocumentKind::LocalKeyring);
        let open = VaultSelection::Entry(Box::new(personal.clone()));
        assert_eq!(open.page(), Page::PersonalSecrets);
        assert_eq!(
            restored_selection(&open.page(), None, std::slice::from_ref(&personal)),
            VaultSelection::PersonalSecrets
        );
        assert_eq!(
            restored_selection(&open.page(), Some("item"), std::slice::from_ref(&personal)),
            open
        );
        assert_eq!(
            restored_selection(&open.page(), Some("item"), &[]),
            VaultSelection::PersonalSecrets
        );
        assert_eq!(
            VaultSelection::Entry(Box::new(entry(b"app", DocumentKind::LocalKeyring))).page(),
            Page::Category(DocumentKind::LocalKeyring)
        );
        for selection in [
            VaultSelection::PersonalSecrets,
            VaultSelection::Devices,
            VaultSelection::TransferCredentials,
            VaultSelection::BackupVault,
            VaultSelection::Category(DocumentKind::SecretSpecProject),
        ] {
            assert_eq!(restored_selection(&selection.page(), None, &[]), selection);
        }
    }

    #[test]
    fn personal_inventory_pins_favorites_then_sorts_by_name_ignoring_case() {
        let entries = personal_entries(&[
            ("delta", false),
            ("Banana", false),
            ("Zulu", true),
            ("apple", false),
            ("charlie", true),
        ]);
        assert_eq!(
            sorted_names(&entries, ""),
            ["charlie", "Zulu", "apple", "Banana", "delta"]
        );
        assert_eq!(sorted_names(&entries, "an"), ["Banana"]);
        assert_eq!(sorted_names(&entries, "absent").len(), 0);
    }

    #[test]
    fn personal_inventory_shows_and_searches_item_types() {
        for kind in super::PersonalSecretKind::ALL {
            let entry = factorseal::VaultEntryMetadata {
                access_project: None,
                display_name: Some("Example".into()),
                display_type: Some(kind.label().into()),
                display_username: None,
                display_website: None,
                updated_at: None,
                favorite: false,
                document_kind: DocumentKind::LocalKeyring,
                partition: super::PERSONAL_SECRET_NAMESPACE.to_vec(),
                address: factorseal::SecretAddress::new("internal-id", None).unwrap(),
            };
            assert_eq!(
                super::vault_entry_label(&entry),
                ("Example".into(), kind.label().into())
            );
            assert!(super::entry_matches_search(
                &entry,
                &kind.label().to_lowercase()
            ));
            assert_eq!(
                super::vault_entry_details(&entry),
                vec![("Type", kind.label().into())]
            );
        }
    }

    #[test]
    fn personal_entries_resolve_their_item_type() {
        let entry = |display_type: Option<&str>| factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some("Example".into()),
            display_type: display_type.map(Into::into),
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: DocumentKind::LocalKeyring,
            partition: super::PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: factorseal::SecretAddress::new("internal-id", None).unwrap(),
        };
        for kind in super::PersonalSecretKind::ALL {
            assert_eq!(super::personal_entry_kind(&entry(Some(kind.label()))), kind);
        }
        for display_type in [None, Some("Unknown type")] {
            assert_eq!(
                super::personal_entry_kind(&entry(display_type)),
                super::PersonalSecretKind::Generic
            );
        }
    }

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
    fn setup_errors_point_at_the_field_to_fix() {
        let strong = "opal nebula lantern saffron velocity";
        let field = |password, confirmation| {
            super::setup_password_error(password, confirmation).map(|(field, _)| field)
        };
        assert_eq!(field("", ""), Some(super::SetupField::Password));
        assert_eq!(
            field("factorseal", "factorseal"),
            Some(super::SetupField::Password)
        );
        assert_eq!(field(strong, ""), Some(super::SetupField::Confirmation));
        assert_eq!(field(strong, strong), None);
    }

    #[test]
    fn unlock_progress_follows_each_step() {
        use super::{UnlockStep, unlock_step_description};
        let steps = [
            UnlockStep::Verifying,
            UnlockStep::Starting,
            UnlockStep::Loading,
        ]
        .map(|step| unlock_step_description(step, false));
        assert!(steps.iter().all(|line| !line.is_empty()));
        assert_eq!(
            steps
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            steps.len()
        );
        assert_ne!(
            unlock_step_description(UnlockStep::Verifying, true),
            steps[0]
        );
        assert_eq!(unlock_step_description(UnlockStep::Loading, true), steps[2]);
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
                .any(|instruction| instruction.command == Some("secretspec init"))
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
        assert!(access.instructions.iter().any(
            |instruction| instruction.command == Some("factorseal permissions watch --prompt")
        ));
    }

    #[test]
    fn category_badge_keeps_the_count_next_to_an_error() {
        assert_eq!(category_badge(false, 3), "3");
        assert_eq!(category_badge(true, 3), "! 3");
        assert_eq!(category_badge(true, 0), "!");
    }

    #[test]
    fn guidance_steps_keep_commands_out_of_their_text() {
        for kind in [
            DocumentKind::NetworkManagerWifi,
            DocumentKind::SecretSpecProject,
            DocumentKind::LinuxSecretService,
            DocumentKind::LocalKeyring,
            DocumentKind::Authorization,
            DocumentKind::SecretSpecProviderCache,
        ] {
            for step in category_guidance(kind).instructions {
                if let Some(command) = step.command {
                    assert_ne!(command.len(), 0);
                    assert!(!step.text.contains(command), "{}", step.text);
                }
            }
        }
    }

    fn entry(
        kind: DocumentKind,
        partition: &[u8],
        address: &str,
    ) -> factorseal::VaultEntryMetadata {
        factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: None,
            display_type: None,
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: kind,
            partition: partition.to_vec(),
            address: factorseal::SecretAddress::new(address, None).unwrap(),
        }
    }

    fn named_entry(
        kind: DocumentKind,
        partition: &[u8],
        item: &str,
        name: &str,
    ) -> factorseal::VaultEntryMetadata {
        factorseal::VaultEntryMetadata {
            display_name: Some(name.into()),
            display_type: Some("Login".into()),
            ..entry(kind, partition, item)
        }
    }

    #[test]
    fn finds_search_matches_without_regard_to_case() {
        assert_eq!(super::search_match_range("GitHub", "git"), Some(0..3));
        assert_eq!(super::search_match_range("My GitHub", "hub"), Some(6..9));
        assert_eq!(
            super::search_match_range("Ünïcode Key", "key"),
            Some(10..13)
        );
        assert_eq!(super::search_match_range("ÜNÏ", "ünï"), Some(0..5));
        assert_eq!(super::search_match_range("GitHub", "gitlab"), None);
        assert_eq!(super::search_match_range("GitHub", ""), None);
    }

    fn search_result_names(
        entries: &[factorseal::VaultEntryMetadata],
        query: &str,
    ) -> Vec<(&'static str, Vec<String>)> {
        super::search_results(entries, query)
            .into_iter()
            .map(|(title, entries)| {
                (
                    title,
                    entries
                        .iter()
                        .map(|entry| entry.display_name.clone().unwrap())
                        .collect(),
                )
            })
            .collect()
    }

    fn search_entries() -> [factorseal::VaultEntryMetadata; 4] {
        [
            named_entry(DocumentKind::NetworkManagerWifi, b"wifi", "home", "Home"),
            named_entry(
                DocumentKind::LocalKeyring,
                super::PERSONAL_SECRET_NAMESPACE,
                "github",
                "GitHub",
            ),
            named_entry(
                DocumentKind::NetworkManagerWifi,
                b"wifi",
                "office",
                "GitHub office",
            ),
            named_entry(DocumentKind::LocalKeyring, b"kwallet", "git", "Git cache"),
        ]
    }

    #[test]
    fn groups_search_results_from_every_category() {
        let entries = search_entries();
        assert_eq!(
            search_result_names(&entries, "git"),
            [
                ("Personal secrets", vec!["GitHub".to_owned()]),
                ("Wi-Fi passwords", vec!["GitHub office".to_owned()]),
                ("Application keyrings", vec!["Git cache".to_owned()]),
            ]
        );
        assert_eq!(super::search_result_entries(&entries, "git").len(), 3);
        assert_eq!(super::search_results(&entries, "absent").len(), 0);
    }

    #[test]
    fn matches_whole_groups_by_their_shown_title() {
        let entries = search_entries();
        assert_eq!(
            search_result_names(&entries, "wi-fi"),
            [(
                "Wi-Fi passwords",
                vec!["Home".to_owned(), "GitHub office".to_owned()]
            )]
        );
        assert_eq!(
            search_result_names(&entries, "keyring"),
            [("Application keyrings", vec!["Git cache".to_owned()])]
        );
        assert_eq!(
            search_result_names(&entries, "personal"),
            [("Personal secrets", vec!["GitHub".to_owned()])]
        );
    }

    #[test]
    fn list_column_follows_the_selected_entry() {
        use super::VaultSelection;

        let personal = entry(
            DocumentKind::LocalKeyring,
            super::PERSONAL_SECRET_NAMESPACE,
            "personal",
        );
        let project = entry(DocumentKind::SecretSpecProject, b"project", "token");
        let selected = VaultSelection::Entry(Box::new(personal.clone()));
        assert_eq!(
            super::list_selection(Some(&selected)),
            Some(VaultSelection::PersonalSecrets)
        );
        assert_eq!(
            super::list_selection(Some(&VaultSelection::Entry(Box::new(project.clone())))),
            Some(VaultSelection::Category(DocumentKind::SecretSpecProject))
        );
        assert_eq!(
            super::list_selection(Some(&VaultSelection::Category(
                DocumentKind::NetworkManagerWifi
            ))),
            Some(VaultSelection::Category(DocumentKind::NetworkManagerWifi))
        );
        for page in [
            VaultSelection::Devices,
            VaultSelection::TransferCredentials,
            VaultSelection::BackupVault,
        ] {
            assert_eq!(super::list_selection(Some(&page)), None);
        }
        assert_eq!(super::list_selection(None), None);

        assert!(super::is_selected_entry(Some(&selected), &personal));
        assert!(!super::is_selected_entry(Some(&selected), &project));
        let mut moved = personal.clone();
        moved.partition = b"other".to_vec();
        assert!(!super::is_selected_entry(Some(&selected), &moved));
        assert!(!super::is_selected_entry(
            Some(&VaultSelection::PersonalSecrets),
            &personal
        ));
    }

    #[test]
    fn category_lists_leave_out_personal_secrets_and_the_keyring_index() {
        let entries = [
            entry(
                DocumentKind::LocalKeyring,
                super::PERSONAL_SECRET_NAMESPACE,
                "personal",
            ),
            entry(DocumentKind::LocalKeyring, b"app", "app-token"),
            entry(
                DocumentKind::LinuxSecretService,
                b"login",
                "secret-service-index",
            ),
            entry(DocumentKind::LinuxSecretService, b"login", "mail"),
        ];
        let addresses = |kind| {
            super::category_entries(&entries, kind)
                .map(|entry| entry.address.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            addresses(DocumentKind::LocalKeyring),
            [entries[1].address.clone()]
        );
        assert_eq!(
            addresses(DocumentKind::LinuxSecretService),
            [entries[3].address.clone()]
        );
        assert_eq!(addresses(DocumentKind::SecretSpecProject).len(), 0);
    }

    #[test]
    fn narrow_windows_show_one_vault_pane_at_a_time() {
        use super::{VaultPanes, vault_panes};

        assert_eq!(vault_panes(false, false), VaultPanes::All);
        assert_eq!(vault_panes(false, true), VaultPanes::All);
        assert_eq!(vault_panes(true, false), VaultPanes::Sidebar);
        assert_eq!(vault_panes(true, true), VaultPanes::Main);
    }

    #[test]
    fn back_from_an_item_returns_to_its_list() {
        use super::{PersonalPanel, VaultSelection};

        let overview = PersonalPanel::Overview;
        let entry = |document_kind, partition: &[u8]| {
            VaultSelection::Entry(Box::new(factorseal::VaultEntryMetadata {
                access_project: None,
                display_name: Some("Item".into()),
                display_type: None,
                display_username: None,
                display_website: None,
                favorite: false,
                updated_at: None,
                document_kind,
                partition: partition.to_vec(),
                address: factorseal::SecretAddress::new("item", None).unwrap(),
            }))
        };
        assert_eq!(
            entry(DocumentKind::LocalKeyring, super::PERSONAL_SECRET_NAMESPACE).parent(overview),
            Some(VaultSelection::PersonalSecrets)
        );
        assert_eq!(
            entry(DocumentKind::NetworkManagerWifi, b"wifi").parent(overview),
            Some(VaultSelection::Category(DocumentKind::NetworkManagerWifi))
        );
        assert_eq!(VaultSelection::PersonalSecrets.parent(overview), None);
        assert_eq!(
            VaultSelection::Category(DocumentKind::NetworkManagerWifi).parent(overview),
            None
        );
    }

    #[test]
    fn back_from_the_new_item_form_returns_to_personal_secrets() {
        use super::{PersonalPanel, VaultSelection};

        assert_eq!(
            VaultSelection::PersonalSecrets.parent(PersonalPanel::NewItem),
            Some(VaultSelection::PersonalSecrets)
        );
    }

    #[test]
    fn list_help_and_blank_panes_stay_out_of_search() {
        use super::{PersonalPanel, VaultSelection, shows_empty_detail};

        let personal = Some(&VaultSelection::PersonalSecrets);
        let projects = Some(&VaultSelection::Category(DocumentKind::SecretSpecProject));
        for searching in [false, true] {
            assert!(shows_empty_detail(
                personal,
                PersonalPanel::Overview,
                searching
            ));
            assert!(!shows_empty_detail(
                personal,
                PersonalPanel::NewItem,
                searching
            ));
            assert!(!shows_empty_detail(
                None,
                PersonalPanel::Overview,
                searching
            ));
            assert!(!shows_empty_detail(
                Some(&VaultSelection::Devices),
                PersonalPanel::Overview,
                searching
            ));
        }
        assert!(!shows_empty_detail(
            projects,
            PersonalPanel::Overview,
            false
        ));
        assert!(shows_empty_detail(projects, PersonalPanel::Overview, true));
    }

    #[test]
    fn vault_pages_follow_the_selected_item_not_its_details() {
        use super::{PersonalPanel, VaultPage, VaultSelection, vault_page};

        let entry = |updated_at| factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some("Mail".into()),
            display_type: Some("Login".into()),
            display_username: None,
            display_website: None,
            favorite: false,
            updated_at,
            document_kind: DocumentKind::LocalKeyring,
            partition: super::PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: factorseal::SecretAddress::new("mail".to_owned(), None).unwrap(),
        };
        let before = VaultSelection::Entry(Box::new(entry(Some(1))));
        let after = VaultSelection::Entry(Box::new(entry(Some(2))));
        assert_eq!(
            vault_page(Some(&before), PersonalPanel::Overview),
            vault_page(Some(&after), PersonalPanel::NewItem),
        );

        let personal = Some(&VaultSelection::PersonalSecrets);
        assert_ne!(
            vault_page(personal, PersonalPanel::Overview),
            vault_page(personal, PersonalPanel::NewItem),
        );

        assert_eq!(
            vault_page(Some(&VaultSelection::Devices), PersonalPanel::NewItem),
            VaultPage::Section,
        );
        assert_eq!(vault_page(None, PersonalPanel::NewItem), VaultPage::Welcome);
    }

    #[test]
    fn every_action_is_declared_once() {
        let mut names = std::collections::HashSet::new();
        for action in gpui::generate_list_of_all_registered_actions() {
            assert!(
                names.insert(action.name),
                "{} is declared twice",
                action.name
            );
        }
    }

    #[test]
    fn settings_replace_every_vault_screen() {
        use crate::runtime::Snapshot;

        assert_eq!(super::screen_key(true, &Snapshot::Initializing), "settings");
        assert_eq!(
            super::screen_key(false, &Snapshot::Initializing),
            "creating"
        );
        assert_ne!(
            super::screen_key(false, &Snapshot::Uninitialized { error: None }),
            super::screen_key(false, &Snapshot::Error("lost".into())),
        );
    }
}
