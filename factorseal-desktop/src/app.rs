use std::sync::Arc;

use gpui::{
    App, Bounds, Context, Div, Global, MenuItem, Render, Subscription, Task, Window, WindowBounds,
    WindowOptions, actions, div, prelude::*, px, size,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Root, Selectable as _, Sizable as _, Size, StyledExt as _,
    button::{Button, ButtonVariants as _},
    h_flex,
    input::{Input, InputEvent, InputState},
    link::Link,
    spinner::Spinner,
    tooltip::Tooltip,
    v_flex,
};
use gpui_tray::{Icon, Tray};
use zeroize::Zeroizing;

use crate::runtime::{DesktopRuntime, RuntimeConfig, Snapshot};
use crate::theming;

actions!(factorseal_desktop, [OpenDesktop, SealVault, Quit]);

struct DesktopTray(Tray);

impl Global for DesktopTray {}

struct RuntimeGlobal(Arc<DesktopRuntime>);

impl Global for RuntimeGlobal {}

struct DesktopStatus {
    unsealed: bool,
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

impl Global for EventTask {}

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

struct DesktopView {
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    selected_group: Option<factorseal::UnlockGroup>,
    password: gpui::Entity<InputState>,
    password_confirmation: gpui::Entity<InputState>,
    setup_method: SetupMethod,
    setup_error: Option<String>,
    _subscriptions: Vec<Subscription>,
}

impl DesktopView {
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
        let password_submit = cx.subscribe_in(
            &password,
            window,
            |view, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { secondary: false })
                    && matches!(view.snapshot, Snapshot::Sealed { .. })
                {
                    view.unlock(window, cx);
                }
            },
        );
        Self {
            runtime,
            snapshot,
            selected_group,
            password,
            password_confirmation,
            setup_method: SetupMethod::default(),
            setup_error: None,
            _subscriptions: vec![password_submit],
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
        self.snapshot = snapshot;
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
        if !owned {
            self.snapshot = Snapshot::Unsealed {
                metadata,
                idle_deadline,
                absolute_deadline,
                owned,
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
        let theme = cx.theme();
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

        v_flex()
            .gap_4()
            .p_5()
            .bg(theme.muted)
            .border_1()
            .border_color(theme.border)
            .child(format!(
                "Protected by {}",
                hardware_backend_label(metadata.hardware_backend())
            ))
            .when(has_multiple_groups, |element| {
                element
                    .child(div().text_color(theme.muted_foreground).child(
                        "Choose one configured unlock method. Native biometric approval is performed by FactorSeal Desktop.",
                    ))
                    .child(choices)
            })
            .when(needs_password, |element| {
                element.child(Input::new(&self.password).mask_toggle())
            })
            .when_some(error.map(str::to_owned), |element, error| {
                element.child(div().text_color(theme.danger).child(error))
            })
            .child(
                Button::new("unlock-vault")
                    .primary()
                    .label(if needs_password {
                        "Unlock vault"
                    } else {
                        "Continue with biometrics"
                    })
                    .on_click(cx.listener(|view, _, window, cx| view.unlock(window, cx))),
            )
    }

    fn render_unsealed(
        metadata: &factorseal::VaultMetadata,
        owned: bool,
        error: Option<&str>,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme();
        v_flex()
            .gap_3()
            .p_5()
            .bg(theme.muted)
            .border_1()
            .border_color(theme.border)
            .child(format!(
                "Hardware backend: {}",
                hardware_backend_label(metadata.hardware_backend())
            ))
            .child(if owned {
                "FactorSeal Desktop is hosting the authenticated vault service."
            } else {
                "Another FactorSeal agent is hosting this vault."
            })
            .when_some(error.map(str::to_owned), |element, error| {
                element.child(div().text_color(theme.danger).child(error))
            })
            .child(
                Button::new("seal-vault")
                    .label("Seal now")
                    .disabled(!owned)
                    .on_click(cx.listener(|view, _, _, cx| view.seal(cx))),
            )
    }

    fn render_header_status(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        let theme = cx.theme();
        match &self.snapshot {
            Snapshot::Sealed { .. } => Some(
                div()
                    .id("sealed-status")
                    .flex_none()
                    .px_3()
                    .py_1()
                    .rounded_full()
                    .bg(theme.muted)
                    .text_color(theme.muted_foreground)
                    .font_semibold()
                    .child("Vault is sealed")
                    .into_any_element(),
            ),
            Snapshot::Unsealed {
                idle_deadline,
                absolute_deadline,
                ..
            } => {
                let tooltip = format!(
                    "Idle deadline: {idle_deadline}\nAbsolute deadline: {absolute_deadline}"
                );
                Some(
                    div()
                        .id("unsealed-status")
                        .flex_none()
                        .px_3()
                        .py_1()
                        .rounded_full()
                        .bg(theme.success.opacity(0.12))
                        .text_color(theme.success)
                        .font_semibold()
                        .child("Vault is unsealed")
                        .tooltip(move |window, cx| Tooltip::new(tooltip.clone()).build(window, cx))
                        .into_any_element(),
                )
            }
            _ => None,
        }
    }

    fn render_uninitialized(&self, runtime_error: Option<&str>, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let protection_description = if cfg!(target_os = "linux") {
            h_flex()
                .gap_1()
                .flex_wrap()
                .child("FactorSeal will bind an encrypted vault key to this device's")
                .child(
                    Link::new("tpm-explanation-link")
                        .href("https://trustedcomputinggroup.org/about/what-is-a-trusted-platform-module-tpm/")
                        .child("TPM"),
                )
                .child("so it can only be unsealed on this device. Your password is also required to decrypt it.")
        } else {
            h_flex().child("Choose how this device should authorize access to your secrets.")
        };
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

        v_flex()
            .gap_4()
            .p_5()
            .bg(theme.muted)
            .border_1()
            .border_color(theme.border)
            .child(
                div()
                    .text_xl()
                    .font_semibold()
                    .child("Create your personal vault"),
            )
            .child(protection_description)
            .when(has_multiple_methods, |element| element.child(methods))
            .when(cfg!(target_os = "linux"), |element| {
                element
                    .child(div().text_color(theme.muted_foreground).child(
                        "Fingerprint unlock cannot currently be implemented securely on Linux. The system fingerprint APIs can confirm a match, but cannot release the hardware-bound secret FactorSeal needs.",
                    ))
                    .child(
                        Link::new("security-link")
                            .href("https://factorseal.dev/security")
                            .child("Learn more at factorseal.dev/security"),
                    )
            })
            .when(self.setup_method.needs_password(), |element| {
                element
                    .child(Input::new(&self.password).mask_toggle())
                    .child(Input::new(&self.password_confirmation).mask_toggle())
            })
            .when_some(self.setup_error.clone(), |element, error| {
                element.child(div().text_color(theme.danger).child(error))
            })
            .when_some(runtime_error.map(str::to_owned), |element, error| {
                element.child(div().text_color(theme.danger).child(error))
            })
            .child(
                Button::new("initialize-vault")
                    .primary()
                    .label("Create vault")
                    .on_click(cx.listener(|view, _, window, cx| view.initialize(window, cx))),
            )
    }

    fn render_body(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        match &self.snapshot {
            Snapshot::Uninitialized { error } => self.render_uninitialized(error.as_deref(), cx),
            Snapshot::Initializing => v_flex()
                .gap_3()
                .p_5()
                .bg(theme.muted)
                .border_1()
                .border_color(theme.border)
                .child(div().text_xl().font_semibold().child("Creating vault…"))
                .child("Protecting the vault root with this device's hardware."),
            Snapshot::Sealed { metadata, error } => {
                self.render_sealed(metadata, error.as_deref(), cx)
            }
            Snapshot::Unlocking { metadata, group } => v_flex()
                .gap_4()
                .p_5()
                .items_center()
                .bg(theme.muted)
                .border_1()
                .border_color(theme.border)
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_xl().font_semibold().child("Unsealing vault…"))
                .child(format!("Unlock method: {group}"))
                .child(format!(
                    "Hardware backend: {}",
                    hardware_backend_label(metadata.hardware_backend())
                ))
                .child("Complete the native authorization prompt if one appears."),
            Snapshot::Sealing { metadata } => v_flex()
                .gap_4()
                .p_5()
                .items_center()
                .bg(theme.muted)
                .border_1()
                .border_color(theme.border)
                .child(Spinner::new().with_size(Size::Large).color(theme.primary))
                .child(div().text_xl().font_semibold().child("Sealing vault…"))
                .child(format!(
                    "Discarding keys protected by {}.",
                    hardware_backend_label(metadata.hardware_backend())
                )),
            Snapshot::Unsealed {
                metadata,
                owned,
                error,
                ..
            } => Self::render_unsealed(metadata, *owned, error.as_deref(), cx),
            Snapshot::Error(error) => v_flex()
                .gap_3()
                .p_5()
                .bg(theme.muted)
                .border_1()
                .border_color(theme.danger)
                .child(div().text_xl().font_semibold().child("Vault unavailable"))
                .child(div().text_color(theme.danger).child(error.clone())),
        }
    }
}

impl Render for DesktopView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let header_status = self.render_header_status(cx);
        v_flex()
            .size_full()
            .p_6()
            .gap_5()
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .text_size(theme.font_size)
            .child(
                h_flex()
                    .w_full()
                    .items_start()
                    .justify_between()
                    .child(div().text_2xl().font_semibold().child("FactorSeal Desktop"))
                    .when_some(header_status, gpui::ParentElement::child),
            )
            .child(
                div()
                    .flex_1()
                    .w_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(div().w_full().max_w(px(560.)).child(self.render_body(cx))),
            )
    }
}

fn open_desktop(_: &OpenDesktop, cx: &mut App) {
    for handle in cx.windows() {
        let _ = handle.update(cx, |_, window, _| window.activate_window());
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
    let mut items = if status.unsealed {
        vec![
            MenuItem::action("Open Desktop", OpenDesktop),
            MenuItem::action("Seal", SealVault),
        ]
    } else {
        vec![MenuItem::action("Unseal", OpenDesktop)]
    };
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

fn factorseal_icon() -> gpui_tray::Result<Icon> {
    const SIZE: u32 = 32;
    let mut rgba = vec![0_u8; (SIZE * SIZE * 4) as usize];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let offset = ((y * SIZE + x) * 4) as usize;
            let center = (9..=22).contains(&x) && (7..=24).contains(&y);
            let shoulder = (6..=25).contains(&x) && (4..=11).contains(&y);
            if center || shoulder {
                let border = x <= 7 || x >= 24 || y <= 5 || y >= 23;
                let color = if border {
                    [31, 41, 55, 255]
                } else {
                    [59, 130, 246, 255]
                };
                rgba[offset..offset + 4].copy_from_slice(&color);
            }
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE)
}

pub(crate) fn setup(
    config: RuntimeConfig,
    background: bool,
    activations: smol::channel::Receiver<()>,
    cx: &mut App,
) {
    gpui_component::init(cx);
    theming::initialize(cx);
    cx.on_action(open_desktop);
    cx.on_action(seal_vault);
    cx.on_action(quit);

    let (runtime, receiver) = DesktopRuntime::new(config);
    let initial = runtime.inspect();
    cx.set_global(RuntimeGlobal(Arc::clone(&runtime)));
    cx.set_global(DesktopStatus {
        unsealed: matches!(initial, Snapshot::Unsealed { .. }),
    });

    match factorseal_icon().and_then(|icon| {
        Tray::builder()
            .icon(icon)
            .title("FactorSeal")
            .tooltip("FactorSeal vault")
            .menu(tray_menu)
            .build(cx)
    }) {
        Ok(tray) => cx.set_global(DesktopTray(tray)),
        Err(error) => eprintln!("FactorSeal tray unavailable: {error}"),
    }

    let bounds = Bounds::centered(None, size(px(760.0), px(520.0)), cx);
    let view_holder = Arc::new(std::sync::Mutex::new(None));
    let view_for_window = Arc::clone(&view_holder);
    cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            show: !background,
            app_id: Some("dev.factorseal.Desktop".to_owned()),
            ..Default::default()
        },
        {
            let runtime = Arc::clone(&runtime);
            let initial = initial.clone();
            move |window, cx| {
                let view = cx.new(|cx| DesktopView::new(Arc::clone(&runtime), initial, window, cx));
                if let Ok(mut holder) = view_for_window.lock() {
                    *holder = Some(view.clone());
                }
                cx.new(|cx| Root::new(view, window, cx))
            }
        },
    )
    .expect("failed to open FactorSeal window");

    let task = cx.spawn(async move |cx| {
        while let Ok(snapshot) = receiver.recv().await {
            if cx
                .update(|cx| {
                    if let Ok(holder) = view_holder.lock()
                        && let Some(view) = holder.as_ref()
                    {
                        view.update(cx, |view, cx| view.apply_snapshot(snapshot.clone(), cx));
                    }
                    let status = cx.global_mut::<DesktopStatus>();
                    status.unsealed = matches!(snapshot, Snapshot::Unsealed { .. });
                    refresh_tray(cx);
                })
                .is_err()
            {
                break;
            }
        }
    });
    cx.set_global(EventTask { _task: task });
    cx.spawn(async move |cx| {
        while activations.recv().await.is_ok() {
            if cx.update(|cx| open_desktop(&OpenDesktop, cx)).is_err() {
                break;
            }
        }
    })
    .detach();
    if background {
        for handle in cx.windows() {
            let _ = handle.update(cx, |_, window, _| window.minimize_window());
        }
    } else {
        cx.activate(true);
    }
}

#[cfg(test)]
mod tests {
    use super::{hardware_backend_label, password_strength_error};

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
}
