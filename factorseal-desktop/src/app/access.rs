//! A separate, compact review window for a pending system-keyring lookup.
use super::*;
use factorseal::{SecretServiceAccessContext, SecretServiceAccessRequest};

#[derive(Default)]
struct AccessWindow(Option<(AnyWindowHandle, gpui::Entity<AccessView>)>, bool);
impl Global for AccessWindow {}

struct InputEditor {
    value: gpui::Entity<SecretInputState>,
    initialized: bool,
    focused: bool,
}

#[derive(Default)]
struct RequestDetails {
    expanded: bool,
}

struct AccessView {
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    requests: Vec<SecretServiceAccessRequest>,
    inputs: Vec<factorseal::SecretServiceInputRequest>,
    editor: InputEditor,
    explicit_unlock: bool,
    grants: Vec<factorseal::Permission>,
    reviewed_grants: Vec<factorseal::Permission>,
    approving: bool,
    reviewing: bool,
    duration: Option<u64>,
    details: RequestDetails,
    password: gpui::Entity<SecretInputState>,
    group: Option<factorseal::UnlockGroup>,
    error: Option<String>,
    _submit: Subscription,
    _secret_submit: Subscription,
}

pub(super) fn setup(receiver: smol::channel::Receiver<AccessEvent>, cx: &mut App) {
    cx.set_global(AccessWindow::default());
    cx.spawn(async move |cx| {
        loop {
            smol::Timer::after(std::time::Duration::from_millis(500)).await;
            let state = cx.update(|cx| {
                let snapshot = &cx.global::<DesktopWindow>().snapshot;
                match snapshot {
                    Snapshot::Unsealed { metadata, .. } => Some((
                        Arc::clone(&cx.global::<RuntimeGlobal>().0),
                        metadata.clone(),
                    )),
                    _ => None,
                }
            });
            let Some((runtime, metadata)) = state else {
                continue;
            };
            if let Ok(permissions) =
                smol::unblock(move || runtime.load_permissions(&metadata)).await
            {
                cx.update(|cx| {
                    if !cx.global::<DesktopStatus>().unsealed {
                        return;
                    }
                    if let Snapshot::Unsealed { contents, .. } =
                        &mut cx.global_mut::<DesktopWindow>().snapshot
                    {
                        contents.permissions.clone_from(&permissions);
                        contents.permissions_loading = false;
                    }
                    let holder = Arc::clone(&cx.global::<DesktopWindow>().view);
                    if let Ok(holder) = holder.lock()
                        && let Some(view) = holder.as_ref()
                    {
                        view.update(cx, |view, cx| {
                            if let Snapshot::Unsealed { contents, .. } = &mut view.snapshot
                                && contents.permissions != permissions
                            {
                                contents.permissions.clone_from(&permissions);
                                contents.permissions_loading = false;
                                cx.notify();
                            }
                        });
                    }
                    let pending: Vec<_> = permissions
                        .into_iter()
                        .filter(|permission| {
                            matches!(
                                permission.state,
                                factorseal::PermissionState::Pending { .. }
                            )
                        })
                        .collect();
                    if let Some((_, view)) = cx.global::<AccessWindow>().0.clone() {
                        view.update(cx, |view, cx| {
                            view.grants = pending;
                            cx.notify();
                        });
                    } else if !pending.is_empty() {
                        open(AccessEvent::Permissions(pending), cx);
                    }
                });
            }
        }
    })
    .detach();
    cx.spawn(async move |cx| {
        loop {
            smol::Timer::after(std::time::Duration::from_millis(500)).await;
            cx.update(|cx| {
                if let Some((_, view)) = cx.global::<AccessWindow>().0.clone() {
                    let expired = view.update(cx, |view, cx| {
                        view.requests.retain(|request| !request.is_expired());
                        view.prune_inputs(cx);
                        if view.requests.is_empty() && view.inputs.is_empty() {
                            view.reviewing = false;
                        }
                        cx.notify();
                        view.requests.is_empty()
                            && view.inputs.is_empty()
                            && view.grants.is_empty()
                            && !view.explicit_unlock
                            && !view.approving
                            && !view.reviewing
                    });
                    if expired {
                        close(cx);
                    }
                }
            });
        }
    })
    .detach();
    cx.spawn(async move |cx| {
        while let Ok(event) = receiver.recv().await {
            cx.update(|cx| open(event, cx));
        }
    })
    .detach();
}

pub(super) fn is_open(cx: &App) -> bool {
    cx.try_global::<AccessWindow>()
        .is_some_and(|state| state.0.is_some())
}

fn close(cx: &mut App) {
    if let Some((handle, view)) = cx.global_mut::<AccessWindow>().0.take() {
        let denial = view.update(cx, |view, cx| {
            view.requests.clear();
            view.inputs.clear();
            view.editor.value.update(cx, SecretInputState::clear);
            view.password.update(cx, SecretInputState::clear);
            (
                Arc::clone(&view.runtime),
                view.snapshot.metadata().cloned(),
                std::mem::take(&mut view.grants),
            )
        });
        if let (runtime, Some(metadata), grants) = denial {
            cx.spawn(async move |_| {
                smol::unblock(move || {
                    for grant in grants {
                        let _ = runtime.deny_permission(&metadata, grant.id);
                    }
                })
                .await;
            })
            .detach();
        }
        let _ = handle.update(cx, |_, window, _| window.remove_window());
    }
}

pub(super) fn update(snapshot: &Snapshot, cx: &mut App) {
    let Some((_, view)) = cx
        .try_global::<AccessWindow>()
        .and_then(|state| state.0.clone())
    else {
        return;
    };
    let done = view.update(cx, |view, cx| {
        if matches!(view.snapshot, Snapshot::Unsealed { .. })
            && matches!(snapshot, Snapshot::Sealed { .. })
        {
            return true;
        }
        view.snapshot = snapshot.clone();
        view.error = match snapshot {
            Snapshot::Sealed { error, .. } | Snapshot::Unsealed { error, .. } => error.clone(),
            Snapshot::Error(error) => Some(error.clone()),
            _ => None,
        };
        cx.notify();
        matches!(snapshot, Snapshot::Unsealed { .. })
            && view.grants.is_empty()
            && view.inputs.is_empty()
            && !view.approving
            && !view.reviewing
            && !view
                .requests
                .iter()
                .any(SecretServiceAccessRequest::is_pending)
    });
    if done {
        close(cx);
    }
}

#[allow(clippy::too_many_lines)]
fn open(event: AccessEvent, cx: &mut App) {
    if let AccessEvent::Finished(context) = event {
        if let Some((_, view)) = cx.global::<AccessWindow>().0.clone() {
            let done = view.update(cx, |view, _| {
                view.requests.retain(|request| {
                    let same = same_request(&request.context, &context);
                    !same
                });
                view.reviewing
                    && view.requests.is_empty()
                    && view.inputs.is_empty()
                    && view.grants.is_empty()
                    && !view.approving
            });
            if done {
                close(cx);
            }
        }
        return;
    }
    if let Some((handle, view)) = cx.global::<AccessWindow>().0.clone() {
        view.update(cx, |view, cx| {
            view.add(event);
            cx.notify();
        });
        let layered = cx.global::<AccessWindow>().1;
        let _ = handle.update(cx, |_, window, _| {
            // Layer surfaces already stay above the desktop and retain keyboard
            // focus. Only ordinary dialogs need the Wayland remapping workaround.
            if layered {
                return;
            }
            if !window.is_window_active() {
                window.set_visible(false);
            }
            window.set_visible(true);
            window.activate_window();
        });
        return;
    }
    let runtime = Arc::clone(&cx.global::<RuntimeGlobal>().0);
    let snapshot = cx.global::<DesktopWindow>().snapshot.clone();
    let mut entity = None;
    let mut event = Some(event);
    let mut build = |window: &mut Window, cx: &mut App| {
        window.on_window_should_close(cx, |_, cx| {
            if approval_in_progress(cx) {
                return false;
            }
            cx.defer(|cx| {
                close(cx);
                dismiss_secret_service_prompts(cx);
            });
            false
        });
        let view = cx.new(|cx| {
            let password =
                cx.new(|cx| SecretInputState::new(window, cx).placeholder("FactorSeal password"));
            password.update(cx, |input, cx| input.focus(window, cx));
            let submit = cx.subscribe_in(
                &password,
                window,
                |view: &mut AccessView, _, event: &InputEvent, window, cx| {
                    if matches!(
                        event,
                        InputEvent::PressEnter {
                            secondary: false,
                            ..
                        }
                    ) {
                        view.allow(window, cx);
                    }
                },
            );
            let secret = cx.new(|cx| SecretInputState::new(window, cx).placeholder("Secret value"));
            let secret_submit = cx.subscribe_in(
                &secret,
                window,
                |view: &mut AccessView, _, event: &InputEvent, window, cx| {
                    if matches!(
                        event,
                        InputEvent::PressEnter {
                            secondary: false,
                            ..
                        }
                    ) {
                        view.allow(window, cx);
                    }
                },
            );
            let group = snapshot
                .metadata()
                .map(|metadata| metadata.preferred_unlock_group().clone());
            let mut view = AccessView {
                runtime: Arc::clone(&runtime),
                snapshot: snapshot.clone(),
                password,
                editor: InputEditor {
                    value: secret,
                    initialized: false,
                    focused: false,
                },
                inputs: Vec::new(),
                group,
                requests: Vec::new(),
                explicit_unlock: false,
                grants: Vec::new(),
                reviewed_grants: Vec::new(),
                approving: false,
                reviewing: false,
                duration: None,
                details: RequestDetails::default(),
                error: None,
                _submit: submit,
                _secret_submit: secret_submit,
            };
            view.add(event.take().expect("window builder runs once"));
            view
        });
        entity = Some(view.clone());
        cx.new(|cx| Root::new(view, window, cx))
    };
    let mut layered = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let mut opened = cx.open_window(window_options(layered, cx), &mut build);
    if opened.is_err() && layered {
        // GNOME and other compositors without layer-shell still get the normal
        // access dialog. The builder has not run when platform creation fails.
        layered = false;
        opened = cx.open_window(window_options(false, cx), &mut build);
    }
    match opened {
        Ok(handle) => {
            let state = cx.global_mut::<AccessWindow>();
            state.0 = Some((handle.into(), entity.unwrap()));
            state.1 = layered;
        }
        Err(error) => eprintln!("FactorSeal: could not open access window: {error}"),
    }
}

fn window_options(layered: bool, cx: &App) -> WindowOptions {
    use gpui::layer_shell::{KeyboardInteractivity, Layer, LayerShellOptions};
    let bounds = Bounds::centered(None, size(px(500.), px(640.)), cx);
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(420.), px(420.))),
        titlebar: (!layered).then(|| gpui::TitlebarOptions {
            title: Some("FactorSeal — Secret access".into()),
            ..Default::default()
        }),
        app_id: Some("dev.factorseal.Access".to_owned()),
        kind: if layered {
            gpui::WindowKind::LayerShell(LayerShellOptions {
                namespace: "dev.factorseal.Access".to_owned(),
                layer: Layer::Overlay,
                // No anchors: center the requested size without reserving space
                // or changing the layout of the user's tiled windows.
                keyboard_interactivity: KeyboardInteractivity::Exclusive,
                ..Default::default()
            })
        } else {
            gpui::WindowKind::Dialog
        },
        ..Default::default()
    }
}

fn approval_in_progress(cx: &App) -> bool {
    cx.global::<AccessWindow>()
        .0
        .as_ref()
        .is_some_and(|(_, view)| view.read(cx).approving)
}

fn deny(cx: &mut App) {
    if approval_in_progress(cx) {
        return;
    }
    if let Some((_, view)) = cx.global::<AccessWindow>().0.clone() {
        view.update(cx, |view, _| {
            for request in &mut view.requests {
                request.deny();
            }
            for request in &mut view.inputs {
                request.deny();
            }
        });
    }
    close(cx);
    dismiss_secret_service_prompts(cx);
}

impl AccessView {
    fn prune_inputs(&mut self, cx: &mut Context<Self>) -> bool {
        let changed = prune_queue(
            &mut self.inputs,
            factorseal::SecretServiceInputRequest::is_expired,
        );
        if changed {
            self.editor.value.update(cx, SecretInputState::clear);
            self.editor.initialized = false;
            self.editor.focused = false;
            cx.notify();
        }
        changed
    }

    fn add(&mut self, event: AccessEvent) {
        match event {
            AccessEvent::Finished(_) => unreachable!("completion does not open a popup"),
            AccessEvent::Request(request) => self.requests.push(request),
            AccessEvent::Input(request) => self.inputs.push(request),
            AccessEvent::Unlock => self.explicit_unlock = true,
            AccessEvent::Permissions(grants) => {
                for grant in grants {
                    if !self.grants.iter().any(|existing| existing.id == grant.id) {
                        self.grants.push(grant);
                    }
                }
            }
        }
    }

    fn grant(&mut self, cx: &mut Context<Self>) {
        let grants = reviewed_pending(&self.reviewed_grants, &self.grants);
        if grants.is_empty() {
            return;
        }
        let Some(metadata) = self.snapshot.metadata().cloned() else {
            return;
        };
        let group = self
            .group
            .clone()
            .unwrap_or_else(|| metadata.preferred_unlock_group().clone());
        let password = self.password.read(cx).value();
        if group.requires(factorseal::UnlockFactorKind::Password) && password.is_empty() {
            self.error = Some("Enter your password to authorize this grant.".to_owned());
            cx.notify();
            return;
        }
        let password = Zeroizing::new(password.as_bytes().to_vec());
        self.password.update(cx, SecretInputState::clear);
        let runtime = Arc::clone(&self.runtime);
        let ids: Vec<_> = grants.iter().map(|grant| grant.id.clone()).collect();
        let duration = self.duration;
        self.approving = true;
        self.error = None;
        cx.spawn(async move |this, cx| {
            let result = smol::unblock(move || {
                runtime.approve_permissions(&metadata, &grants, group, password, duration)
            })
            .await;
            let _ = this.update(cx, |view, cx| {
                view.approving = false;
                match result {
                    Ok(()) => {
                        view.grants.retain(|grant| !ids.contains(&grant.id));
                        if view.grants.is_empty()
                            && view.inputs.is_empty()
                            && !view
                                .requests
                                .iter()
                                .any(SecretServiceAccessRequest::is_pending)
                        {
                            cx.defer(close);
                        }
                    }
                    Err(error) => view.error = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }

    fn allow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.approving || matches!(self.snapshot, Snapshot::Unlocking { .. }) {
            return;
        }
        if self.prune_inputs(cx) {
            // A newly selected request must be rendered before it can be saved.
            return;
        }
        if !self.inputs.is_empty() && matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            if !self.editor.initialized || self.editor.value.read(cx).allocation_failed() {
                return;
            }
            let value = self.editor.value.read(cx).value();
            match factorseal::WireSecret::new(value.as_bytes().to_vec()) {
                Ok(value) => {
                    let mut request = self.inputs.remove(0);
                    request.save(value);
                    self.editor.value.update(cx, SecretInputState::clear);
                    self.password.update(cx, SecretInputState::clear);
                    self.editor.initialized = false;
                    self.editor.focused = false;
                    if self.inputs.is_empty()
                        && self.grants.is_empty()
                        && !self
                            .requests
                            .iter()
                            .any(SecretServiceAccessRequest::is_pending)
                    {
                        cx.defer(close);
                    }
                }
                Err(error) => self.error = Some(error.to_string()),
            }
            cx.notify();
            return;
        }
        if !self.grants.is_empty() && matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            self.grant(cx);
            return;
        }
        if let Snapshot::Sealed { metadata, .. } = &self.snapshot {
            let metadata = metadata.clone();
            let group = self
                .group
                .clone()
                .unwrap_or_else(|| metadata.preferred_unlock_group().clone());
            let password = self.password.read(cx).value();
            if group.requires(factorseal::UnlockFactorKind::Password) && password.is_empty() {
                self.error = Some("Enter your FactorSeal password.".to_owned());
                cx.notify();
                return;
            }
            let password = if group.requires(factorseal::UnlockFactorKind::Password) {
                Zeroizing::new(password.as_bytes().to_vec())
            } else {
                Zeroizing::new(Vec::new())
            };
            self.reviewing = !self.requests.is_empty() || !self.inputs.is_empty();
            if let Err(error) = self
                .runtime
                .unlock(metadata.clone(), group.clone(), password)
            {
                self.error = Some(error.to_owned());
                cx.notify();
                return;
            }
            self.snapshot = Snapshot::Unlocking { metadata, group };
        } else if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        for request in &mut self.requests {
            request.allow();
        }
        self.error = None;
        if matches!(self.snapshot, Snapshot::Unsealed { .. }) && !self.reviewing {
            cx.defer(close);
        }
        if !self.reviewing {
            window.blur(cx);
        }
        cx.notify();
    }
}

fn reviewed_pending<T: Clone + PartialEq>(reviewed: &[T], pending: &[T]) -> Vec<T> {
    reviewed
        .iter()
        .filter(|request| pending.contains(request))
        .cloned()
        .collect()
}

fn same_request(left: &SecretServiceAccessContext, right: &SecretServiceAccessContext) -> bool {
    if left.attributes.contains_key("factorseal_request_id")
        || right.attributes.contains_key("factorseal_request_id")
    {
        return left.process_id.is_some()
            && left.process_id == right.process_id
            && left.executable == right.executable
            && left.attributes.get("factorseal_request_id")
                == right.attributes.get("factorseal_request_id");
    }
    !left.sender.is_empty() && left.sender == right.sender && left.attributes == right.attributes
}

/// Returns whether the editor's active request changed, requiring a wipe.
fn prune_queue<T>(queue: &mut Vec<T>, expired: impl Fn(&T) -> bool) -> bool {
    let mut first = true;
    let mut active_changed = false;
    queue.retain(|request| {
        let remove = expired(request);
        if first {
            active_changed = remove;
            first = false;
        }
        !remove
    });
    active_changed
}

/// The conventional service path is a caller-supplied label, not proof of identity.
fn project_coordinates(context: &SecretServiceAccessContext) -> Option<(&str, &str, &str)> {
    let service = context.attributes.get("service")?;
    let mut parts = service.strip_prefix("secretspec/")?.splitn(3, '/');
    let (project, profile, secret) = (parts.next()?, parts.next()?, parts.next()?);
    (!project.is_empty() && !profile.is_empty() && !secret.is_empty())
        .then_some((project, profile, secret))
}

fn application_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn detail(
    label: impl Into<gpui::SharedString>,
    value: impl Into<gpui::SharedString>,
    cx: &App,
) -> Div {
    h_flex()
        .items_start()
        .gap_3()
        .child(
            div()
                .w(px(105.))
                .flex_none()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(label.into()),
        )
        .child(div().flex_1().min_w_0().text_sm().child(value.into()))
}

impl Render for AccessView {
    #[allow(clippy::too_many_lines)]
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.reviewed_grants = if self.inputs.is_empty() {
            self.grants.clone()
        } else {
            Vec::new()
        };
        window.set_rem_size(crate::appearance::rem_size(cx));
        if !self.editor.initialized
            && let Some(request) = self.inputs.first_mut()
        {
            if let Some(initial) = request.initial.take() {
                match std::str::from_utf8(initial.expose()) {
                    Ok(value) => self
                        .editor
                        .value
                        .update(cx, |input, cx| input.set_value(value, window, cx)),
                    Err(_) => {
                        self.error = Some("This dialog supports text secrets only.".to_owned());
                    }
                }
            }
            self.editor.initialized = true;
        }
        if !self.editor.focused
            && !self.inputs.is_empty()
            && matches!(self.snapshot, Snapshot::Unsealed { .. })
        {
            self.editor
                .value
                .update(cx, |input, cx| input.focus(window, cx));
            self.editor.focused = true;
        }
        let theme = cx.theme().clone();
        let busy = self.approving || matches!(self.snapshot, Snapshot::Unlocking { .. });
        let unsealed = matches!(self.snapshot, Snapshot::Unsealed { .. });
        let metadata = self.snapshot.metadata();
        let needs_password = (!unsealed || !self.grants.is_empty())
            && self
                .group
                .as_ref()
                .is_some_and(|group| group.requires(factorseal::UnlockFactorKind::Password));
        let mut requests = v_flex().gap_4();
        let mut technical = v_flex().gap_4();
        for context in self
            .requests
            .iter()
            .filter(|_| self.inputs.is_empty())
            .map(|request| &request.context)
            .chain(self.inputs.iter().take(1).map(|request| &request.context))
        {
            let mut card = v_flex().p_4().gap_3().rounded_lg().bg(theme.muted);
            if let Some((project, profile, secret)) = project_coordinates(context) {
                card = card
                    .child(div().text_lg().font_semibold().child(project.to_owned()))
                    .child(detail("Secret", format!("{secret} · {profile}"), cx));
            } else if let Some(project) = context.attributes.get("project") {
                card = card.child(div().text_lg().font_semibold().child(project.clone()));
                if let Some(secret) = context.attributes.get("secret") {
                    card = card.child(detail("Secret", secret.clone(), cx));
                }
            } else {
                card = card.child(div().font_semibold().child("System keyring"));
            }
            if let Some(folder) = context.attributes.get("base_dir") {
                card = card.child(detail("Project folder", folder.clone(), cx));
            }
            if let Some(executable) = &context.executable {
                card = card.child(detail("Requested by", application_name(executable), cx));
                technical =
                    technical.child(detail("Executable", executable.display().to_string(), cx));
            }
            // Once permissions arrive, their authenticated scope becomes the review summary.
            if self.grants.is_empty() || !self.inputs.is_empty() {
                requests = requests.child(card);
            }
            let mut info = v_flex().gap_3();
            if let Some(directory) = &context.working_directory {
                info = info.child(detail(
                    "Working directory",
                    directory.display().to_string(),
                    cx,
                ));
            }
            info = info.child(detail(
                "D-Bus sender / process",
                format!(
                    "{} / {}",
                    context.sender,
                    context
                        .process_id
                        .map_or_else(|| "unavailable".to_owned(), |pid| pid.to_string())
                ),
                cx,
            ));
            for (key, value) in &context.attributes {
                info = info.child(detail(format!("Lookup · {key}"), value.clone(), cx));
            }
            technical = technical.child(info);
        }
        for grant in self.grants.iter().filter(|_| self.inputs.is_empty()) {
            let mut card = v_flex()
                .p_4()
                .gap_3()
                .rounded_lg()
                .bg(theme.muted)
                .child(
                    div().text_lg().font_semibold().child(
                        grant
                            .application
                            .project
                            .clone()
                            .unwrap_or_else(|| "Secret access".to_owned()),
                    ),
                )
                .child(detail(
                    "Access via",
                    permission_access_type(grant.scope),
                    cx,
                ))
                .child(detail(
                    "Allow",
                    permission_operation_label(grant.operation),
                    cx,
                ));
            for (label, value) in [
                ("Profile", &grant.application.profile),
                ("Project folder", &grant.application.base_dir),
            ] {
                if let Some(value) = value {
                    card = card.child(detail(label, value.clone(), cx));
                }
            }
            card = card.child(detail(
                "Requested by",
                application_name(std::path::Path::new(&grant.principal.application_id)),
                cx,
            ));
            technical = technical.child(detail(
                "Executable",
                grant.principal.application_id.clone(),
                cx,
            ));
            if let Some(reason) = &grant.application.reason {
                technical = technical.child(detail("Request", reason.clone(), cx));
            }
            requests = requests.child(card);
            technical = technical.child(detail(
                "Executable digest",
                hex_digest(&grant.principal.executable_digest),
                cx,
            ));
        }
        requests = requests.child(
            Button::new("access-technical-details").ghost().small()
                .label(if self.details.expanded { "Hide technical details −" } else { "Technical details +" })
                .on_click(cx.listener(|view, _, _, cx| {
                    view.details.expanded = !view.details.expanded;
                    cx.notify();
                })),
        ).when(self.details.expanded, |element| {
            element.child(technical).child(div().text_xs().text_color(theme.muted_foreground)
                .child("Project labels come from the requesting app. Process identity is verified by the operating system."))
        });
        let mut groups = h_flex().gap_2().flex_wrap();
        if let Some(metadata) = metadata {
            for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
                let selected = self.group.as_ref() == Some(group);
                let group = group.clone();
                groups = groups.child(
                    Button::new(("access-factor", index))
                        .label(group.to_string())
                        .selected(selected)
                        .disabled(busy)
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.group = Some(group.clone());
                            cx.notify();
                        })),
                );
            }
        }
        v_flex().size_full().border_1().border_color(theme.border)
            .capture_key_down(cx.listener(|_, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" {
                    cx.stop_propagation();
                    cx.defer(deny);
                }
            }))
            .bg(theme.background).text_color(theme.foreground).font_family(theme.font_family.clone()).text_size(theme.font_size)
            .child(v_flex().p_6().gap_2().child(h_flex().gap_2().items_center().child(brand_mark(22., theme.foreground)).child(div().text_sm().text_color(theme.muted_foreground).child("FactorSeal")))
                .child(div().text_xl().font_semibold().child(if self.inputs.is_empty() { "Allow project access" } else { "Save a secret" })))
            .child(div().id("access-request-details").flex_1().min_h_0().px_6().overflow_y_scrollbar().pb_4().child(requests))
            .child(v_flex().p_6().gap_3().border_t_1().border_color(theme.border)
                .child(div().text_xs().text_color(theme.muted_foreground).child(if !self.inputs.is_empty() { "Saves this value once. No access grant is created." } else if self.grants.is_empty() { "Unlock your vault to continue here." } else { "Applies to this app, project, folder, and operation. Manage it in Access Grants." }))
                .when(metadata.is_some_and(|metadata| metadata.unlock_policy().groups().len() > 1), |element| element.child(groups))
                .when(!self.grants.is_empty() && self.inputs.is_empty(), |element| element.child(field_label("Allow access for", h_flex().gap_2()
                    .child(Button::new("grant-hour").label("1 hour").selected(self.duration == Some(3600)).disabled(busy).on_click(cx.listener(|view, _, _, cx| { view.duration = Some(3600); cx.notify(); })))
                    .child(Button::new("grant-persistent").label("Until revoked").selected(self.duration.is_none()).disabled(busy).on_click(cx.listener(|view, _, _, cx| { view.duration = None; cx.notify(); }))))))
                .when(!self.inputs.is_empty() && !busy, |element| element.child(field_label("Secret value", self.editor.value.clone())))
                .when(needs_password && !busy, |element| element.child(field_label("Vault password", self.password.clone())))
                .when_some(self.error.clone(), |element, error| element.child(error_banner(error, theme.danger)))
                .when(matches!(self.snapshot, Snapshot::Uninitialized { .. }), |element| element.child(div().text_sm().child("Set up your vault in FactorSeal Desktop before allowing access.")))
                .child(h_flex().justify_end().gap_2()
                    .child(Button::new("deny-access").ghost().label(if self.inputs.is_empty() { "Deny" } else { "Cancel" }).disabled(self.approving).on_click(cx.listener(|_, _, _, cx| {
                        cx.defer(|cx| {
                            deny(cx);
                        });
                    })))
                    .child(Button::new("allow-access").primary().disabled((self.reviewing && self.grants.is_empty() && self.inputs.is_empty() && unsealed) || busy || !matches!(self.snapshot, Snapshot::Sealed { .. } | Snapshot::Unsealed { .. }))
                        .label(if self.approving { "Authorizing…" } else if busy { "Unlocking…" } else if !self.inputs.is_empty() && unsealed { "Save secret" } else if !self.grants.is_empty() { "Grant access" } else if unsealed && self.reviewing { "Checking access…" } else if unsealed { "Continue" } else { "Unlock to continue" })
                        .on_click(cx.listener(|view, _, window, cx| view.allow(window, cx))))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_excludes_requests_arriving_after_review() {
        assert_eq!(
            reviewed_pending(&["reviewed"], &["reviewed", "new"]),
            vec!["reviewed"]
        );
        assert!(reviewed_pending(&["expired"], &["new"]).is_empty());
    }

    #[test]
    fn completing_one_ipc_request_does_not_dismiss_another() {
        let mut first = SecretServiceAccessContext {
            process_id: Some(42),
            ..Default::default()
        };
        first
            .attributes
            .insert("factorseal_request_id".into(), "1".into());
        let mut second = first.clone();
        second
            .attributes
            .insert("factorseal_request_id".into(), "2".into());
        assert!(!same_request(&first, &second));
        assert!(same_request(&first, &first));
        second.attributes = first.attributes.clone();
        second.process_id = Some(43);
        assert!(!same_request(&first, &second));
    }

    #[test]
    fn expiration_never_reuses_the_editor_for_the_next_request() {
        let mut queue = vec![("first", true), ("second", false)];
        assert!(prune_queue(&mut queue, |request| request.1));
        assert_eq!(queue, vec![("second", false)]);
        queue.push(("third", true));
        assert!(!prune_queue(&mut queue, |request| request.1));
        assert_eq!(queue, vec![("second", false)]);
    }

    #[test]
    fn project_details_only_parse_conventional_secretspec_paths() {
        let mut context = SecretServiceAccessContext::default();
        for (service, expected) in [
            (
                "secretspec/my-project/production/DATABASE_URL",
                Some(("my-project", "production", "DATABASE_URL")),
            ),
            ("custom-service", None),
            ("secretspec/project/", None),
            ("secretspec//default/TOKEN", None),
        ] {
            context
                .attributes
                .insert("service".to_owned(), service.to_owned());
            assert_eq!(project_coordinates(&context), expected);
        }
    }
}
