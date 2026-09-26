//! A separate, compact review window for a pending system-keyring lookup.
use super::*;
use factorseal::{SecretServiceAccessContext, SecretServiceAccessRequest};
use std::collections::BTreeMap;

/// How long the popup ignores approval after it appears or its requests
/// change, so a click or Enter meant for another window cannot approve.
const ARM_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

#[derive(Default)]
struct AccessWindow(Option<(AnyWindowHandle, gpui::Entity<AccessView>)>, bool);
impl Global for AccessWindow {}

struct InputEditor {
    value: gpui::Entity<SecretInputState>,
    initialized: bool,
    focused: bool,
}

/// The popup can take keyboard focus while the user is typing in another app,
/// even while it stays hidden behind that app. Its fields take no focus and
/// nothing is approved until the user clicks inside it, and approval waits
/// [`ARM_DELAY`] after the popup appears or its requests change.
struct InputGuard {
    armed: bool,
    changed_at: std::time::Instant,
}

impl InputGuard {
    fn new() -> Self {
        Self {
            armed: false,
            changed_at: std::time::Instant::now(),
        }
    }

    fn changed(&mut self) {
        self.changed_at = std::time::Instant::now();
    }

    fn allows_approval(&self) -> bool {
        self.armed && self.changed_at.elapsed() >= ARM_DELAY
    }
}

#[derive(Default)]
struct RequestDetails {
    expanded: bool,
    scroll: gpui::ScrollHandle,
}

#[allow(clippy::struct_excessive_bools)]
struct AccessView {
    runtime: Arc<DesktopRuntime>,
    snapshot: Snapshot,
    requests: Vec<SecretServiceAccessRequest>,
    inputs: Vec<factorseal::SecretServiceInputRequest>,
    editor: InputEditor,
    explicit_unlock: bool,
    unlocks: Vec<(SecretServiceAccessContext, Vec<String>)>,
    grants: Vec<factorseal::Permission>,
    reviewed_grants: Vec<factorseal::Permission>,
    approving: bool,
    reviewing: bool,
    // The person's pick; `None` until they click one. See `grant_choice`.
    choice: Option<GrantChoice>,
    details: RequestDetails,
    expired: bool,
    password: gpui::Entity<SecretInputState>,
    group: Option<factorseal::UnlockGroup>,
    error: Option<String>,
    guard: InputGuard,
    _submit: Subscription,
    _secret_submit: Subscription,
}

pub(super) fn setup(receiver: smol::channel::Receiver<AccessEvent>, cx: &mut App) {
    cx.set_global(AccessWindow::default());
    watch_permissions(cx);
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
                            && !view.expired
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

fn watch_permissions(cx: &mut App) {
    cx.spawn(async move |cx| {
        let mut generation = None;
        let mut after_revision = None;
        loop {
            let state = cx.update(|cx| {
                let desktop = cx.global::<DesktopWindow>();
                match &desktop.snapshot {
                    Snapshot::Unsealed { metadata, .. } => Some((
                        Arc::clone(&cx.global::<RuntimeGlobal>().0),
                        metadata.clone(),
                        desktop.refresh_generation,
                    )),
                    _ => None,
                }
            });
            let Some((runtime, metadata, current_generation)) = state else {
                generation = None;
                after_revision = None;
                smol::Timer::after(std::time::Duration::from_millis(500)).await;
                continue;
            };
            if generation != Some(current_generation) {
                generation = Some(current_generation);
                after_revision = None;
            }
            let result =
                smol::unblock(move || runtime.watch_permissions(&metadata, after_revision)).await;
            if let Ok((revision, permissions)) = result {
                let accepted = cx.update(|cx| {
                    // A seal, another unlock or a refresh supersedes this wait.
                    if !cx.global::<DesktopStatus>().unsealed
                        || cx.global::<DesktopWindow>().refresh_generation != current_generation
                    {
                        return false;
                    }
                    if after_revision == Some(revision) {
                        return true;
                    }
                    if let Snapshot::Unsealed { contents, .. } =
                        &mut cx.global_mut::<DesktopWindow>().snapshot
                    {
                        contents.permissions.clone_from(&permissions);
                        contents.permissions_loading = false;
                        contents.permissions_error = None;
                    }
                    let holder = Arc::clone(&cx.global::<DesktopWindow>().view);
                    if let Ok(holder) = holder.lock()
                        && let Some(view) = holder.as_ref()
                    {
                        view.update(cx, |view, cx| {
                            if let Snapshot::Unsealed { contents, .. } = &mut view.snapshot
                                && (contents.permissions != permissions
                                    || contents.permissions_loading
                                    || contents.permissions_error.is_some())
                            {
                                contents.permissions.clone_from(&permissions);
                                contents.permissions_loading = false;
                                contents.permissions_error = None;
                                cx.notify();
                            }
                        });
                    }
                    show_pending(&permissions, cx);
                    true
                });
                after_revision = accepted.then_some(revision);
            } else {
                // Retry a fresh, complete inventory after a seal, transport
                // failure or a concurrent mutation between permission pages.
                after_revision = None;
                smol::Timer::after(std::time::Duration::from_millis(500)).await;
            }
        }
    })
    .detach();
}

fn show_pending(permissions: &[factorseal::Permission], cx: &mut App) {
    let pending: Vec<_> = permissions
        .iter()
        .filter(|permission| awaited(permission))
        .cloned()
        .collect();
    if let Some((_, view)) = cx.global::<AccessWindow>().0.clone() {
        view.update(cx, |view, cx| {
            let expired = !view.approving
                && pending.is_empty()
                && (view.expired || stopped_waiting(&view.grants, permissions));
            if expired && !view.expired {
                view.password.update(cx, SecretInputState::clear);
            }
            view.expired = expired;
            view.set_pending(pending);
            cx.notify();
        });
    } else if !pending.is_empty() {
        open(AccessEvent::Permissions(pending), cx);
    }
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
            && !view.expired
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
            view.guard.changed();
            cx.notify();
        });
        let layered = cx.global::<AccessWindow>().1;
        let _ = handle.update(cx, |_, window, _| {
            // Layer surfaces already stay above the desktop and retain keyboard
            // focus. Only ordinary dialogs need the Wayland remapping workaround.
            if layered {
                return;
            }
            window_activation::show(window, true);
            // Activation can be refused (Windows keeps focus with the app the
            // user is typing in), so also flag the window in the taskbar.
            window_activation::request_attention(window);
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
            let mut view = AccessView::new(Arc::clone(&runtime), snapshot.clone(), window, cx);
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
            if !layered {
                // A new window opened behind the focused app gets no focus of
                // its own on Windows; flag it so the request is not missed.
                let _ = handle.update(cx, |_, window, _| {
                    window_activation::request_attention(window);
                });
            }
            let state = cx.global_mut::<AccessWindow>();
            state.0 = Some((handle.into(), entity.unwrap()));
            state.1 = layered;
        }
        Err(error) => eprintln!("FactorSeal: could not open access window: {error}"),
    }
}

fn window_options(layered: bool, cx: &App) -> WindowOptions {
    super::approval_window::options(
        layered,
        "FactorSeal — Secret access",
        "dev.factorseal.Access",
        crate::appearance::rem_size(cx) * 37.,
        cx,
    )
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
    fn new(
        runtime: Arc<DesktopRuntime>,
        snapshot: Snapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let password = cx.new(|cx| {
            SecretInputState::new(window, cx)
                .placeholder("FactorSeal password")
                .accessibility_id("factorseal.access.password")
        });
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
        let secret = cx.new(|cx| {
            SecretInputState::new(window, cx)
                .placeholder("Secret value")
                .accessibility_id("factorseal.access.secret-value")
        });
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
        AccessView {
            runtime,
            snapshot,
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
            unlocks: Vec::new(),
            grants: Vec::new(),
            reviewed_grants: Vec::new(),
            approving: false,
            reviewing: false,
            choice: None,
            details: RequestDetails::default(),
            expired: false,
            error: None,
            guard: InputGuard::new(),
            _submit: submit,
            _secret_submit: secret_submit,
        }
    }

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
            AccessEvent::Unlock { context, objects } => {
                self.explicit_unlock = true;
                self.unlocks.push((context, objects));
            }
            AccessEvent::Permissions(grants) => {
                self.expired = false;
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
        let (duration, single_use) = grant_choice(&grants, self.choice).lifetime();
        if single_use && !single_write_allowed(&grants) {
            self.error = Some("The requests changed. Choose how long to allow access.".to_owned());
            cx.notify();
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
        self.approving = true;
        self.error = None;
        cx.spawn(async move |this, cx| {
            let result = smol::unblock(move || {
                runtime
                    .approve_permissions(&metadata, &grants, group, password, duration, single_use)
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

    /// Replace the polled pending permissions, restarting the approval delay
    /// when the set changes under the user.
    fn set_pending(&mut self, pending: Vec<factorseal::Permission>) {
        if self
            .grants
            .iter()
            .map(|grant| &grant.id)
            .ne(pending.iter().map(|grant| &grant.id))
        {
            self.guard.changed();
        }
        self.grants = pending;
    }

    /// Accept keyboard input once the user clicks inside the popup.
    fn arm(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.guard.armed {
            return;
        }
        self.guard.armed = true;
        // The secret editor takes focus in render once armed.
        if self.inputs.is_empty() {
            self.password
                .update(cx, |input, cx| input.focus(window, cx));
        }
        cx.notify();
    }

    fn allow(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if !self.guard.allows_approval() {
            return;
        }
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
            self.snapshot = Snapshot::Unlocking {
                metadata,
                group,
                step: UnlockStep::default(),
            };
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

fn context_project(context: &SecretServiceAccessContext) -> Option<String> {
    project_coordinates(context)
        .map(|(project, _, _)| project)
        .or_else(|| context.attributes.get("project").map(String::as_str))
        .map(display_reason)
}

fn access_title(has_input: bool, has_grants: bool, explicit_unlock: bool) -> &'static str {
    if has_input {
        "Save a secret"
    } else if has_grants {
        "Allow secret access"
    } else if explicit_unlock {
        "Unlock system keyring"
    } else {
        "Review secret access"
    }
}

fn unlock_target_label(path: &str) -> String {
    match path {
        "/org/freedesktop/secrets/collection/factorseal"
        | "/org/freedesktop/secrets/aliases/default" => {
            "Default keyring (application did not specify an individual secret)".to_owned()
        }
        _ => format!("Locked item: {path}"),
    }
}

fn application_name(path: &std::path::Path) -> String {
    path.file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}

fn requester_label(grants: &[&factorseal::Permission]) -> Option<String> {
    single(grants.iter().map(|grant| &grant.principal)).map(|principal| {
        if grants.iter().all(|grant| is_secretspec_request(grant)) {
            "SecretSpec".to_owned()
        } else {
            visible_text(&principal.application_id)
        }
    })
}

fn header_requester(grants: &[&factorseal::Permission], other_requests: bool) -> Option<String> {
    if other_requests {
        None
    } else {
        requester_label(grants)
    }
}

const REASON_LIMIT: usize = 200;

fn hidden_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00AD}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061C}'
                | '\u{06DD}'
                | '\u{070F}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08E2}'
                | '\u{115F}'..='\u{1160}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{3164}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{110BD}'
                | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

fn visible_text(text: &str) -> String {
    let visible: String = text
        .chars()
        .filter_map(|character| {
            if character.is_whitespace() {
                Some(' ')
            } else {
                (!hidden_character(character)).then_some(character)
            }
        })
        .collect();
    visible.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn display_reason(reason: &str) -> String {
    let words = visible_text(reason);
    if words.chars().count() > REASON_LIMIT {
        let cut: String = words.chars().take(REASON_LIMIT).collect();
        format!("{}…", cut.trim_end())
    } else {
        words
    }
}

const fn secretspec_scope(scope: Option<factorseal::DocumentKind>) -> bool {
    matches!(
        scope,
        Some(
            factorseal::DocumentKind::SecretSpecProviderCache
                | factorseal::DocumentKind::SecretSpecProject
        )
    )
}

fn grant_secret_label(grant: &factorseal::Permission) -> Option<String> {
    if let Some(
        factorseal::PermissionTarget::Entry { address, .. }
        | factorseal::PermissionTarget::ProjectEntry { address, .. },
    ) = grant.target.as_deref()
        && let factorseal::SecretAddress::SecretSpec {
            address: factorseal::SecretSpecAddress::Convention { profile, key, .. },
        } = address
        && grant.application.profile.as_ref() == Some(profile)
    {
        return Some(visible_text(key));
    }
    entry_access::entry_label(grant).map(|label| visible_text(&label))
}

fn request_summary(operation: &str, project: Option<&str>) -> String {
    project.map_or_else(
        || format!("wants to {operation} secrets"),
        |project| format!("wants to {operation} secrets for {project}"),
    )
}

fn quoted_reasons(reasons: &[String]) -> Option<String> {
    let quoted: Vec<_> = reasons
        .iter()
        .map(|reason| display_reason(reason))
        .filter(|reason| !reason.is_empty())
        .map(|reason| format!("“{reason}”"))
        .collect();
    (!quoted.is_empty()).then(|| quoted.join(" "))
}

const fn awaited(permission: &factorseal::Permission) -> bool {
    matches!(
        permission.state,
        factorseal::PermissionState::Pending { awaited: true, .. }
    )
}

fn stopped_waiting(
    shown: &[factorseal::Permission],
    permissions: &[factorseal::Permission],
) -> bool {
    shown.iter().any(|grant| {
        permissions.iter().any(|permission| {
            permission.id == grant.id
                && matches!(
                    permission.state,
                    factorseal::PermissionState::Pending { awaited: false, .. }
                )
        })
    })
}

fn single<T: PartialEq>(values: impl IntoIterator<Item = T>) -> Option<T> {
    let mut values = values.into_iter();
    let first = values.next()?;
    values.all(|value| value == first).then_some(first)
}

fn is_secretspec_request(grant: &factorseal::Permission) -> bool {
    grant.scope == Some(factorseal::DocumentKind::SecretSpecProviderCache)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrantChoice {
    ThisWriteOnly,
    Hour,
    UntilRevoked,
}

impl GrantChoice {
    // The approval's duration, and whether it is single-use.
    fn lifetime(self) -> (Option<u64>, bool) {
        match self {
            Self::ThisWriteOnly => (None, true),
            Self::Hour => (Some(3600), false),
            Self::UntilRevoked => (None, false),
        }
    }
}

// The vault takes a single-use approval only for a SecretSpec write.
fn single_write_allowed(grants: &[factorseal::Permission]) -> bool {
    !grants.is_empty() && grants.iter().all(factorseal::Permission::allows_single_use)
}

// A plain SecretSpec write asks for no more than that write unless the
// person picks a longer lifetime; a cache write, which SecretSpec repeats
// whenever the entry expires, defaults to an hour (see
// `Permission::defaults_to_single_use`). Keep an explicit choice even if new
// requests make it incompatible; granting then requires a fresh choice.
fn grant_choice(grants: &[factorseal::Permission], choice: Option<GrantChoice>) -> GrantChoice {
    match choice {
        Some(choice) => choice,
        None if !grants.is_empty()
            && grants
                .iter()
                .all(factorseal::Permission::defaults_to_single_use) =>
        {
            GrantChoice::ThisWriteOnly
        }
        None => GrantChoice::Hour,
    }
}

// A SecretSpec grant binds the provider, not the program that ran
// `secretspec`, so say who it covers in those terms.
fn grant_scope_note(grants: &[factorseal::Permission]) -> &'static str {
    if grants.iter().any(is_secretspec_request) {
        "Applies only to the listed entries, folder, and operation, for any program that runs SecretSpec in that folder. Manage access on each secret."
    } else {
        "Applies only to the listed entries, app, folder, and operation. Manage access on each secret."
    }
}

// Outermost launcher first, e.g. `pwsh.exe → secretspec.exe`. The chain is
// declared by the caller (see
// `VaultApplicationContext::declared_launch_chain`), so the label says it
// is not verified.
fn launch_chain_label(chain: &[String]) -> Option<String> {
    (!chain.is_empty()).then(|| {
        let names: Vec<_> = chain
            .iter()
            .rev()
            .map(|executable| visible_text(&application_name(std::path::Path::new(executable))))
            .collect();
        format!("{} (not verified)", names.join(" → "))
    })
}

fn detail(
    label: impl Into<gpui::SharedString>,
    value: impl Into<gpui::SharedString>,
    cx: &App,
) -> Div {
    let (label, value) = (label.into(), value.into());
    h_flex()
        .items_start()
        .gap_3()
        .child(
            div()
                .w(px(105.))
                .flex_none()
                .text_body()
                .text_color(cx.theme().muted_foreground)
                .child(visible_text(&label)),
        )
        .child(
            div()
                .flex_1()
                .min_w_0()
                .text_body()
                .child(visible_text(&value)),
        )
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
        if self.guard.armed
            && !self.editor.focused
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
        let choice = grant_choice(&self.grants, self.choice);
        if !self.grants.is_empty() {
            self.choice = Some(choice);
        }
        let unsealed = matches!(self.snapshot, Snapshot::Unsealed { .. });
        let metadata = self.snapshot.metadata();
        let mut projects: Vec<_> = if self.inputs.is_empty() {
            self.requests
                .iter()
                .map(|request| context_project(&request.context))
                .chain(
                    self.grants
                        .iter()
                        .map(|grant| grant.application.project.as_deref().map(display_reason)),
                )
                .chain(
                    self.unlocks
                        .iter()
                        .map(|(context, _)| context_project(context)),
                )
                .collect()
        } else {
            self.inputs
                .iter()
                .take(1)
                .map(|request| context_project(&request.context))
                .collect()
        };
        projects.sort();
        projects.dedup();
        let project_title = match projects.as_slice() {
            [Some(project)] if !project.is_empty() => Some(project.clone()),
            _ => None,
        };
        let title = project_title.as_ref().map_or_else(
            || {
                access_title(
                    !self.inputs.is_empty(),
                    !self.grants.is_empty(),
                    self.explicit_unlock,
                )
                .to_owned()
            },
            |project| {
                if self.inputs.is_empty() {
                    format!("Secret access for {project}")
                } else {
                    format!("Save a secret for {project}")
                }
            },
        );
        let pending_grants = || self.grants.iter().filter(|_| self.inputs.is_empty());
        let shown_grants: Vec<_> = pending_grants().collect();
        let other_requests = !self.requests.is_empty() || !self.unlocks.is_empty();
        let requester = header_requester(&shown_grants, other_requests).map(|name| {
            let operation = single(pending_grants().map(|grant| grant.operation))
                .map_or("use", |operation| permission_operation_label(operation))
                .to_lowercase();
            (name, request_summary(&operation, project_title.as_deref()))
        });
        let mut reasons: Vec<_> = pending_grants()
            .filter(|grant| secretspec_scope(grant.scope))
            .filter_map(|grant| grant.application.reason.clone())
            .collect();
        reasons.sort();
        reasons.dedup();
        let needs_password = (!unsealed || !self.grants.is_empty())
            && self
                .group
                .as_ref()
                .is_some_and(|group| group.requires(factorseal::UnlockFactorKind::Password));
        let mut requests = v_flex().gap_4();
        let mut technical = v_flex().gap_4();
        if self.inputs.is_empty() {
            let mut grouped: BTreeMap<(&str, &str), (Vec<&str>, &SecretServiceAccessContext)> =
                BTreeMap::new();
            for request in &self.requests {
                if let Some((project, profile, secret)) = project_coordinates(&request.context) {
                    let entry = grouped
                        .entry((project, profile))
                        .or_insert_with(|| (Vec::new(), &request.context));
                    if !entry.0.contains(&secret) {
                        entry.0.push(secret);
                    }
                }
            }
            for ((project, profile), (mut secrets, context)) in grouped {
                secrets.sort_unstable();
                let mut card = v_flex().p_4().gap_3().rounded_lg().bg(theme.muted).child(
                    div()
                        .text_body()
                        .text_color(theme.muted_foreground)
                        .child("Secrets"),
                );
                for secret in secrets {
                    card = card.child(
                        div()
                            .text_heading()
                            .font_semibold()
                            .child(visible_text(secret)),
                    );
                }
                if project_title.is_none() {
                    card = card.child(detail("Project", display_reason(project), cx));
                }
                card = card.child(detail("Profile", display_reason(profile), cx));
                if let Some(folder) = context.attributes.get("base_dir") {
                    card = card.child(detail("Folder", folder.clone(), cx));
                }
                requests = requests.child(card);
            }
        }
        for (context, objects) in self
            .requests
            .iter()
            .filter(|_| self.inputs.is_empty())
            .filter(|request| project_coordinates(&request.context).is_none())
            .map(|request| &request.context)
            .chain(self.inputs.iter().take(1).map(|request| &request.context))
            .map(|context| (context, None))
            .chain(
                self.unlocks
                    .iter()
                    .filter(|_| self.inputs.is_empty())
                    .map(|(context, objects)| (context, Some(objects))),
            )
        {
            let mut card = v_flex().p_4().gap_3().rounded_lg().bg(theme.muted);
            if let Some((project, profile, secret)) = project_coordinates(context) {
                card = card
                    .child(
                        div()
                            .text_heading()
                            .font_semibold()
                            .child(display_reason(project)),
                    )
                    .child(detail(
                        "Secret",
                        format!("{secret} · {}", display_reason(profile)),
                        cx,
                    ));
            } else if let Some(project) = context.attributes.get("project") {
                card = card.child(
                    div()
                        .text_heading()
                        .font_semibold()
                        .child(display_reason(project)),
                );
                if let Some(secret) = context.attributes.get("secret") {
                    card = card.child(detail("Secret", secret.clone(), cx));
                }
            } else {
                card = card.child(div().font_semibold().child("System keyring"));
            }
            if let Some(objects) = objects {
                card = card.child(detail("Requested action", "Unlock system keyring", cx));
                if objects.is_empty() {
                    card = card.child(detail(
                        "Requested items",
                        "Not supplied by the application",
                        cx,
                    ));
                }
                for object in objects {
                    card = card.child(detail("Requested item", unlock_target_label(object), cx));
                }
                card = card.child(div().text_body().child(
                    "Item names and contents stay encrypted until unlock. Unlocking does not grant permission to read secrets.",
                ));
            } else if project_coordinates(context).is_none()
                && !context.attributes.contains_key("project")
            {
                for (key, value) in &context.attributes {
                    card = card.child(detail(key.clone(), value.clone(), cx));
                }
            }
            if let Some(folder) = context.attributes.get("base_dir") {
                card = card.child(detail("Project folder", folder.clone(), cx));
            }
            if let Some(executable) = &context.executable {
                card = card.child(detail("Requested by", application_name(executable), cx));
                technical =
                    technical.child(detail("Executable", executable.display().to_string(), cx));
            }
            if context.executable.is_none() {
                card = card.child(detail(
                    "Requested by",
                    if context.sender.is_empty() {
                        "Unknown application".to_owned()
                    } else {
                        format!("Application identity unavailable ({})", context.sender)
                    },
                    cx,
                ));
            }
            // Keep the requested items visible alongside the authenticated grant scope.
            requests = requests.child(card);
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
        let mut grant_groups: Vec<Vec<&factorseal::Permission>> = Vec::new();
        for grant in self.grants.iter().filter(|_| self.inputs.is_empty()) {
            let group = grant_groups.iter_mut().find(|group| {
                let first = group[0];
                first.principal == grant.principal
                    && first.application == grant.application
                    && first.scope == grant.scope
                    && first.operation == grant.operation
                    && entry_access::entry_label(first).is_some()
                    && entry_access::entry_label(grant).is_some()
            });
            if let Some(group) = group {
                group.push(grant);
            } else {
                grant_groups.push(vec![grant]);
            }
        }
        for group in grant_groups {
            let grant = group[0];
            let mut labels: Vec<_> = group
                .iter()
                .filter_map(|grant| grant_secret_label(grant))
                .collect();
            labels.sort();
            labels.dedup();
            let mut card = v_flex().p_4().gap_3().rounded_lg().bg(theme.muted).child(
                div()
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child("Secrets"),
            );
            if labels.is_empty() {
                card = card.child(div().text_heading().font_semibold().child("Secret access"));
            }
            for label in labels {
                card = card.child(div().text_heading().font_semibold().child(label));
            }
            if let Some(project) = &grant.application.project
                && project_title.is_none()
            {
                card = card.child(detail("Project", display_reason(project), cx));
            }
            technical = technical
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
            if requester.is_none() {
                card = card.child(div().text_body().child(format!(
                    "{} {}.",
                    requester_label(&group).unwrap_or_default(),
                    request_summary(
                        &permission_operation_label(grant.operation).to_lowercase(),
                        None
                    ),
                )));
            }
            if let Some(chain) = launch_chain_label(&grant.application.declared_launch_chain) {
                card = card.child(detail("Launched from", chain, cx));
            }
            for (label, value) in [
                (
                    "Profile",
                    grant.application.profile.as_deref().map(display_reason),
                ),
                ("Folder", grant.application.base_dir.clone()),
            ] {
                if let Some(value) = value {
                    card = card.child(detail(label, value, cx));
                }
            }
            if let Some(distro) = &grant.application.declared_wsl_origin {
                // Caller-declared, not authenticated -- see
                // `VaultApplicationContext::declared_wsl_origin`. Shown
                // prominently because it changes what this approval actually
                // grants: a short-lived lease regardless of the duration
                // chosen below, since this caller has none of the
                // executable-identity assurance a native one has. The
                // expiry row says so, so the duration buttons don't
                // overstate the grant.
                card = card
                    .child(detail("WSL distro", distro.clone(), cx))
                    .child(detail(
                        "Access expires",
                        format!(
                            "After {} minutes, whichever duration you choose",
                            factorseal::MAX_WSL_GRANT_SECONDS / 60
                        ),
                        cx,
                    ));
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
            for executable in grant.application.declared_launch_chain.iter().rev() {
                technical = technical.child(detail(
                    "Launcher (not verified)",
                    visible_text(executable),
                    cx,
                ));
            }
            if let Some(reason) = &grant.application.reason {
                technical = technical.child(detail("Request", display_reason(reason), cx));
            }
            requests = requests.child(card);
            technical = technical.child(detail(
                "Executable digest",
                hex_digest(&grant.principal.executable_digest),
                cx,
            ));
        }
        requests = requests
            .child(
                button("access-technical-details")
                    .ghost()
                    .small()
                    .label(if self.details.expanded {
                        "Hide technical details −"
                    } else {
                        "Technical details +"
                    })
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.details.expanded = !view.details.expanded;
                        if view.details.expanded {
                            view.details.scroll.scroll_to_bottom();
                        }
                        cx.notify();
                    })),
            )
            .when(self.details.expanded, |element| {
                element.child(
                    technical
                        .p_4()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.border)
                        .child(div().text_caption().text_color(theme.muted_foreground).child(
                            "Project labels and launchers come from the requesting app. The executable's identity is verified by the operating system, and access is granted to it.",
                        )),
                )
            });
        let header = match &requester {
            Some((name, summary)) => v_flex()
                .gap_3()
                .child(
                    h_flex()
                        .gap_3()
                        .items_center()
                        .child(
                            div()
                                .size_10()
                                .flex_none()
                                .flex()
                                .items_center()
                                .justify_center()
                                .rounded_lg()
                                .bg(theme.muted)
                                .child(
                                    gpui_component::Icon::new(IconName::SquareTerminal)
                                        .size_5()
                                        .text_color(theme.foreground),
                                ),
                        )
                        .child(
                            v_flex()
                                .min_w_0()
                                .child(div().text_heading().font_semibold().child(name.clone()))
                                .child(
                                    div()
                                        .text_body()
                                        .text_color(theme.muted_foreground)
                                        .child(summary.clone()),
                                ),
                        ),
                )
                .when_some(quoted_reasons(&reasons), |element, reasons| {
                    element.child(
                        v_flex()
                            .gap_1()
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(theme.border)
                            .child(
                                div()
                                    .text_caption()
                                    .text_color(theme.muted_foreground)
                                    .child("Reason given by the app"),
                            )
                            .child(
                                div()
                                    .text_body()
                                    .italic()
                                    .line_clamp(3)
                                    .text_ellipsis()
                                    .child(reasons),
                            ),
                    )
                }),
            None => div().text_heading().font_semibold().child(title),
        };
        let expired = self.expired
            && self.grants.is_empty()
            && self.requests.is_empty()
            && self.inputs.is_empty();
        let header = if expired {
            v_flex()
                .gap_2()
                .child(
                    div()
                        .text_heading()
                        .font_semibold()
                        .child("This request expired"),
                )
                .child(
                    div()
                        .text_body()
                        .text_color(theme.muted_foreground)
                        .child("The app stopped waiting. Run it again to ask for access."),
                )
        } else {
            header
        };

        let mut groups = h_flex().gap_2().flex_wrap();
        if let Some(metadata) = metadata {
            for (index, group) in metadata.unlock_policy().groups().iter().enumerate() {
                let selected = self.group.as_ref() == Some(group);
                let group = group.clone();
                groups = groups.child(
                    button(("access-factor", index))
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
        crate::motion::enter("access-request", v_flex().size_full().border_1().border_color(theme.border)
            .capture_any_mouse_down(cx.listener(|view, _, window, cx| view.arm(window, cx)))
            .capture_key_down(cx.listener(|_, event: &gpui::KeyDownEvent, _, cx| {
                if event.keystroke.key == "escape" {
                    cx.stop_propagation();
                    cx.defer(deny);
                }
            }))
            .bg(theme.background).text_color(theme.foreground).font_family(theme.font_family.clone()).text_body()
            .child(v_flex().p_6().gap_2().child(h_flex().gap_2().items_center().child(brand_mark(22., theme.foreground)).child(div().text_body().text_color(theme.muted_foreground).child("FactorSeal")))
                .child(header))
            .child(div().flex_1().min_h_0().relative()
                .when(!expired, |details| details.child(div().id("access-request-details").size_full().px_6().pb_4().overflow_y_scroll().track_scroll(&self.details.scroll).child(requests))
                .vertical_scrollbar(&self.details.scroll)))
            .when(!expired, |window| window.child(v_flex().p_6().gap_3().border_t_1().border_color(theme.border)
                .child(div().text_caption().text_color(theme.muted_foreground).child(if !self.inputs.is_empty() { "Saves this value once. No access grant is created." } else if self.grants.is_empty() { "Unlock your vault to continue here." } else { grant_scope_note(&self.grants) }))
                .when(metadata.is_some_and(|metadata| metadata.unlock_policy().groups().len() > 1), |element| element.child(groups))
                .when((!self.grants.is_empty() || !self.requests.is_empty()) && self.inputs.is_empty(), |element| element.child(field_label("Allow access for", h_flex().gap_2()
                    .when(single_write_allowed(&self.grants), |row| row.child(button("grant-once").label("This write only").selected(choice == GrantChoice::ThisWriteOnly).disabled(busy).on_click(cx.listener(|view, _, _, cx| { view.choice = Some(GrantChoice::ThisWriteOnly); cx.notify(); }))))
                    .child(button("grant-hour").label("1 hour").selected(choice == GrantChoice::Hour).disabled(busy).on_click(cx.listener(|view, _, _, cx| { view.choice = Some(GrantChoice::Hour); cx.notify(); })))
                    .child(button("grant-persistent").label("Until revoked").selected(choice == GrantChoice::UntilRevoked).disabled(busy).on_click(cx.listener(|view, _, _, cx| { view.choice = Some(GrantChoice::UntilRevoked); cx.notify(); }))))))
                .when(!self.inputs.is_empty() && !busy, |element| element.child(field_label("Secret value", self.editor.value.clone())))
                .when(needs_password && !busy, |element| element.child(field_label("Vault password", self.password.clone())))
                .when_some(self.error.clone(), |element, error| element.child(error_banner(error, theme.danger)))
                .when(matches!(self.snapshot, Snapshot::Uninitialized { .. }), |element| element.child(div().text_body().child("Set up your vault in FactorSeal Desktop before allowing access.")))
                .child(h_flex().items_center().justify_end().gap_2()
                    .child(button("deny-access").ghost().label(if self.inputs.is_empty() { "Deny" } else { "Cancel" }).disabled(self.approving).on_click(cx.listener(|_, _, _, cx| {
                        cx.defer(|cx| {
                            deny(cx);
                        });
                    })))
                    .child(button("allow-access").primary().disabled((self.reviewing && self.grants.is_empty() && self.inputs.is_empty() && unsealed) || busy || !matches!(self.snapshot, Snapshot::Sealed { .. } | Snapshot::Unsealed { .. }))
                        .label(if self.approving { "Authorizing…" } else if busy { "Unlocking…" } else if !self.inputs.is_empty() && unsealed { "Save secret" } else if !self.grants.is_empty() { "Grant access" } else if unsealed && self.reviewing { "Checking access…" } else if unsealed { "Continue" } else { "Unlock to continue" })
                        .on_click(cx.listener(|view, _, window, cx| view.allow(window, cx)))))))
            .when(expired, |window| window.child(h_flex().p_6().justify_end().border_t_1().border_color(theme.border)
                .child(button("close-expired-access").primary().label("Close").on_click(|_, _, cx| cx.defer(close))))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_guard_needs_a_click_and_a_settled_popup() {
        let settled = std::time::Instant::now()
            .checked_sub(ARM_DELAY * 2)
            .expect("monotonic clock is past the delay");
        let mut guard = InputGuard::new();
        assert!(!guard.allows_approval(), "opening does not arm");
        guard.changed_at = settled;
        assert!(
            !guard.allows_approval(),
            "a settled popup still needs a click"
        );
        guard.armed = true;
        assert!(guard.allows_approval());
        guard.changed();
        assert!(!guard.allows_approval(), "new requests restart the delay");
    }

    /// Opens the popup over a vault-less snapshot with a password unlock
    /// group, which shows the password field without a real vault.
    fn open_popup(
        cx: &mut gpui::TestAppContext,
    ) -> (gpui::Entity<AccessView>, &mut gpui::VisualTestContext) {
        cx.update(|cx| {
            gpui_component::init(cx);
            crate::appearance::initialize_for_test(cx);
        });
        let (runtime, _) = DesktopRuntime::new(crate::runtime::RuntimeConfig {
            root: std::env::temp_dir().join("factorseal-access-popup-test"),
            socket: None,
            lease: crate::runtime::LeasePolicy {
                idle_timeout: std::time::Duration::from_mins(1),
                maximum_lifetime: std::time::Duration::from_mins(1),
            },
            secret_service: false,
        });
        let mut popup = None;
        let (_, cx) = cx.add_window_view(|window, cx| {
            let view = cx.new(|cx| {
                let mut view =
                    AccessView::new(runtime, Snapshot::Uninitialized { error: None }, window, cx);
                view.group = Some(
                    factorseal::UnlockGroup::new([factorseal::UnlockFactorKind::Password])
                        .expect("a password-only group is valid"),
                );
                view
            });
            popup = Some(view.clone());
            Root::new(view, window, cx)
        });
        (popup.expect("the window builder ran"), cx)
    }

    fn password(view: &gpui::Entity<AccessView>, cx: &mut gpui::VisualTestContext) -> String {
        view.read_with(cx, |view, cx| view.password.read(cx).value().to_string())
    }

    #[gpui::test]
    fn typing_meant_for_another_app_does_not_reach_the_password(cx: &mut gpui::TestAppContext) {
        let (view, cx) = open_popup(cx);
        cx.run_until_parked();
        cx.simulate_input("typed in a terminal");
        assert_eq!(
            password(&view, cx),
            "",
            "the field takes no focus on its own"
        );
        assert!(view.read_with(cx, |view, _| !view.guard.armed));
    }

    #[gpui::test]
    fn a_click_arms_the_popup_and_focuses_the_password(cx: &mut gpui::TestAppContext) {
        let (view, cx) = open_popup(cx);
        cx.run_until_parked();
        cx.simulate_click(
            gpui::point(gpui::px(20.), gpui::px(20.)),
            gpui::Modifiers::none(),
        );
        cx.simulate_input("vault password");
        assert!(view.read_with(cx, |view, _| view.guard.armed));
        assert_eq!(password(&view, cx), "vault password");
    }

    #[test]
    fn unlock_dialog_describes_collection_and_item_requests() {
        assert_eq!(access_title(false, false, true), "Unlock system keyring");
        assert_eq!(access_title(false, true, true), "Allow secret access");
        assert_eq!(access_title(true, true, true), "Save a secret");
        for path in [
            "/org/freedesktop/secrets/collection/factorseal",
            "/org/freedesktop/secrets/aliases/default",
        ] {
            assert!(unlock_target_label(path).contains("did not specify an individual secret"));
        }
        let item = "/org/freedesktop/secrets/collection/factorseal/item/example";
        assert_eq!(unlock_target_label(item), format!("Locked item: {item}"));
    }

    #[test]
    fn secretspec_requests_name_secretspec_and_where_it_was_launched_from() {
        let path = |name: &str| {
            std::env::temp_dir()
                .join("bin")
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let caller = factorseal::CallerIdentity::new(
            factorseal::CallerPlatform::Windows,
            "S-1-5-21-1",
            path("factorseal.exe"),
            [7; 32],
            None,
        )
        .expect("a valid caller");
        let mut grant = factorseal::Permission {
            target: None,
            id: "p".to_owned(),
            scope: Some(factorseal::DocumentKind::SecretSpecProviderCache),
            operation: factorseal::PermissionOperation::Put,
            principal: factorseal::PermissionPrincipal::from(&caller),
            application: factorseal::VaultApplicationContext::new(
                Some("demo".to_owned()),
                None,
                None,
                None,
            )
            .expect("a valid context"),
            state: factorseal::PermissionState::Pending {
                created_at: 1,
                expires_at: 2,
                challenge: [0; 32],
                awaited: false,
                expiring_write: false,
            },
        };
        assert_eq!(requester_label(&[&grant]).as_deref(), Some("SecretSpec"));
        assert!(
            grant_scope_note(std::slice::from_ref(&grant))
                .contains("any program that runs SecretSpec")
        );
        grant.scope = Some(factorseal::DocumentKind::LinuxSecretService);
        assert_eq!(
            requester_label(&[&grant]).as_deref(),
            Some(path("factorseal.exe").as_str())
        );
        assert!(grant_scope_note(std::slice::from_ref(&grant)).contains("entries, app, folder"));

        // A SecretSpec write defaults to this write only. An incompatible
        // request must not silently broaden that choice to an hour.
        grant.scope = Some(factorseal::DocumentKind::SecretSpecProviderCache);
        let write = grant.clone();
        assert_eq!(
            grant_choice(std::slice::from_ref(&write), None),
            GrantChoice::ThisWriteOnly
        );
        assert_eq!(GrantChoice::ThisWriteOnly.lifetime(), (None, true));
        // A cache write repeats on every expiry, so it defaults to an hour,
        // but can still be approved for one write.
        let mut cache_write = write.clone();
        cache_write.state = factorseal::PermissionState::Pending {
            created_at: 1,
            expires_at: 2,
            challenge: [0; 32],
            expiring_write: true,
            awaited: false,
        };
        assert_eq!(
            grant_choice(std::slice::from_ref(&cache_write), None),
            GrantChoice::Hour
        );
        assert!(single_write_allowed(std::slice::from_ref(&cache_write)));
        assert_eq!(
            grant_choice(
                std::slice::from_ref(&cache_write),
                Some(GrantChoice::ThisWriteOnly)
            ),
            GrantChoice::ThisWriteOnly
        );
        let mut read = write.clone();
        read.operation = factorseal::PermissionOperation::Get;
        assert!(!single_write_allowed(std::slice::from_ref(&read)));
        assert_eq!(
            grant_choice(std::slice::from_ref(&read), None),
            GrantChoice::Hour
        );
        let mixed = [write.clone(), read];
        assert_eq!(
            grant_choice(&mixed, Some(GrantChoice::ThisWriteOnly)),
            GrantChoice::ThisWriteOnly
        );
        assert_eq!(
            grant_choice(
                std::slice::from_ref(&write),
                Some(GrantChoice::UntilRevoked)
            ),
            GrantChoice::UntilRevoked
        );
        grant.scope = Some(factorseal::DocumentKind::LinuxSecretService);

        assert_eq!(launch_chain_label(&[]), None);
        assert_eq!(
            launch_chain_label(&[path("secretspec.exe"), path("pwsh.exe"),]).as_deref(),
            Some("pwsh.exe → secretspec.exe (not verified)")
        );
    }

    #[test]
    fn approval_excludes_requests_arriving_after_review() {
        assert_eq!(
            reviewed_pending(&["reviewed"], &["reviewed", "new"]),
            vec!["reviewed"]
        );
        assert_eq!(reviewed_pending(&["expired"], &["new"]), Vec::<&str>::new());
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

    #[test]
    fn project_names_from_apps_lose_hidden_characters() {
        let mut context = SecretServiceAccessContext::default();
        context.attributes.insert(
            "service".to_owned(),
            "secretspec/demo\u{202E}ppa/default/TOKEN".to_owned(),
        );
        assert_eq!(context_project(&context).as_deref(), Some("demoppa"));
        context.attributes.clear();
        context
            .attributes
            .insert("project".to_owned(), "my\u{200B}  \tapp".to_owned());
        assert_eq!(context_project(&context).as_deref(), Some("my app"));
    }

    fn secretspec_grant(executable: &str, profile: Option<&str>) -> factorseal::Permission {
        factorseal::Permission {
            target: Some(Box::new(factorseal::PermissionTarget::ProjectEntry {
                namespace: b"demo-app".to_vec(),
                address: factorseal::SecretAddress::SecretSpec {
                    address: factorseal::SecretSpecAddress::Convention {
                        project: "demo-app".to_owned(),
                        profile: "default".to_owned(),
                        key: "DATABASE_URL".to_owned(),
                    },
                },
                project: "demo-app".to_owned(),
                base_dir: None,
            })),
            id: "grant".to_owned(),
            scope: Some(factorseal::DocumentKind::SecretSpecProviderCache),
            operation: factorseal::PermissionOperation::Get,
            principal: factorseal::PermissionPrincipal {
                platform: factorseal::CallerPlatform::Linux,
                user_id: "uid:1000".to_owned(),
                application_id: executable.to_owned(),
                executable_digest: [0; 32],
                signer_id: None,
            },
            application: factorseal::VaultApplicationContext::new(
                Some("demo-app".to_owned()),
                profile.map(str::to_owned),
                None,
                Some("Run migrations".to_owned()),
            )
            .unwrap(),
            state: factorseal::PermissionState::Pending {
                created_at: 1,
                expires_at: 2,
                challenge: [0; 32],
                awaited: false,
                expiring_write: false,
            },
        }
    }

    #[test]
    fn the_requester_header_only_shows_when_grants_are_all_that_is_asked() {
        let grant = secretspec_grant("/nix/store/abc-factorseal/bin/factorseal", None);
        assert_eq!(
            header_requester(&[&grant], false).as_deref(),
            Some("SecretSpec")
        );
        assert_eq!(header_requester(&[&grant], true), None);
    }

    #[test]
    fn requests_from_different_executables_get_no_shared_name() {
        let first = secretspec_grant("/usr/bin/tool", None);
        let mut second = secretspec_grant("/usr/bin/tool", None);
        assert_eq!(
            requester_label(&[&first, &second]).as_deref(),
            Some("SecretSpec")
        );
        second.principal.executable_digest = [1; 32];
        assert_eq!(requester_label(&[&first, &second]), None);
        second.principal = first.principal.clone();
        second.principal.application_id = "/opt/tool".to_owned();
        assert_eq!(requester_label(&[&first, &second]), None);
    }

    #[test]
    fn app_reasons_lose_hidden_characters_and_stay_short() {
        assert_eq!(
            display_reason("Run\u{202E}gnp.exe\u{200B} db\u{0007}\t\nmigrations"),
            "Rungnp.exe db migrations"
        );
        assert_eq!(display_reason("\u{2066}\u{FEFF}\u{E0041}"), "");
        let long = display_reason(&"word ".repeat(100));
        assert_eq!(long.chars().count(), REASON_LIMIT);
        assert!(long.ends_with("word…") || long.ends_with('…'));
        assert_eq!(quoted_reasons(&["\u{200B}".to_owned()]), None);
    }

    #[test]
    fn app_names_paths_and_keys_lose_hidden_characters_but_not_their_end() {
        let path = format!(
            "/home/user/{}/tool\u{202E}\n\nFolder /trusted",
            "a".repeat(300)
        );
        let visible = visible_text(&path);
        assert!(visible.ends_with("tool Folder /trusted"));
        assert!(!visible.contains(['\n', '\u{202E}']));
        assert_eq!(
            launch_chain_label(&["secretspec\u{202e}.exe".to_owned()]).as_deref(),
            Some("secretspec.exe (not verified)")
        );
        let mut grant = secretspec_grant("/usr/bin/tool\u{2066}\nSecretSpec", None);
        grant.scope = Some(factorseal::DocumentKind::LinuxSecretService);
        assert_eq!(
            requester_label(&[&grant]).as_deref(),
            Some("/usr/bin/tool SecretSpec")
        );
    }

    #[test]
    fn a_shown_request_expires_when_its_app_stops_waiting() {
        let mut waiting = secretspec_grant("/usr/bin/tool", None);
        waiting.state = factorseal::PermissionState::Pending {
            created_at: 1,
            expires_at: 300,
            challenge: [0; 32],
            awaited: true,
            expiring_write: false,
        };
        assert!(awaited(&waiting));
        let mut given_up = waiting.clone();
        given_up.state = factorseal::PermissionState::Pending {
            created_at: 1,
            expires_at: 300,
            challenge: [0; 32],
            awaited: false,
            expiring_write: false,
        };
        assert!(!awaited(&given_up));
        let shown = std::slice::from_ref(&waiting);
        assert!(stopped_waiting(shown, std::slice::from_ref(&given_up)));
        assert!(!stopped_waiting(shown, std::slice::from_ref(&waiting)));
        assert!(!stopped_waiting(shown, &[]));
    }

    #[test]
    fn approval_shows_the_profile_once() {
        assert_eq!(
            grant_secret_label(&secretspec_grant("factorseal", Some("default"))).as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(
            grant_secret_label(&secretspec_grant("factorseal", Some("production"))).as_deref(),
            Some("DATABASE_URL · Profile: default")
        );
    }

    #[test]
    fn approval_summary_names_the_project_when_there_is_one() {
        assert_eq!(
            request_summary("read", Some("demo-app")),
            "wants to read secrets for demo-app"
        );
        assert_eq!(request_summary("write", None), "wants to write secrets");
        assert_eq!(single(["a", "a"]), Some("a"));
        assert_eq!(single(["a", "b"]), None);
        assert_eq!(single(Vec::<&str>::new()), None);
    }

    #[test]
    fn approval_reason_stays_on_one_flowing_line() {
        assert_eq!(quoted_reasons(&[]), None);
        assert_eq!(
            quoted_reasons(&["Run\n\n  database\tmigrations\n".to_owned()]).as_deref(),
            Some("“Run database migrations”")
        );
        assert_eq!(
            quoted_reasons(&["Deploy".to_owned(), "Seed".to_owned()]).as_deref(),
            Some("“Deploy” “Seed”")
        );
    }
}
