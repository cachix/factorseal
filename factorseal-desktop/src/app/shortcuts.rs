use gpui::{
    AnyElement, FocusHandle, Focusable as _, KeyBinding, Keystroke, Pixels, ScrollHandle, canvas,
    point,
};
use gpui_component::{
    IndexPath, InteractiveElementExt as _,
    command::{Command, CommandGroup, CommandItem, CommandState},
    kbd::Kbd,
};

use super::*;

pub(super) const CONTEXT: &str = "FactorsealDesktop";
pub(super) const LIST_CONTEXT: &str = "FactorsealList";
pub(super) const SIDEBAR_CONTEXT: &str = "FactorsealSidebar";
const SIDEBAR_INPUT_CONTEXT: &str = "FactorsealSidebar > Input";
const OUTSIDE_DIALOG_CONTEXT: &str = "FactorsealDesktop && !Dialog";
const OUTSIDE_TEXT_CONTEXT: &str = "FactorsealDesktop && !Dialog && !Input && !FactorsealSecret";
const OUTSIDE_SECRET_CONTEXT: &str = "FactorsealDesktop && !FactorsealSecret";
const PALETTE_KEYS: &str = "secondary-k";
const SHORTCUTS_KEYS: &str = "secondary-/";

actions!(
    factorseal_desktop,
    [
        OpenPalette,
        SelectNext,
        SelectPrevious,
        OpenSelected,
        CopyPassword,
        CopyUsername,
        GoBack,
        ShowShortcuts,
        NewLogin,
        BackUpVault,
        OpenSettings,
        EditItem,
        SaveItem,
        PasteQrCode,
    ]
);

const ACTIONS_SECTION: usize = 0;
const ITEMS_SECTION: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaletteAction {
    SealNow,
    NewLogin,
    BackUpVault,
    Settings,
    Shortcuts,
}

const PALETTE_ACTIONS: [PaletteAction; 5] = [
    PaletteAction::NewLogin,
    PaletteAction::BackUpVault,
    PaletteAction::Settings,
    PaletteAction::Shortcuts,
    PaletteAction::SealNow,
];

impl PaletteAction {
    fn confirmed(index: IndexPath) -> Option<Self> {
        if index.section == ACTIONS_SECTION {
            PALETTE_ACTIONS.get(index.row).copied()
        } else {
            None
        }
    }

    fn item(self) -> CommandItem {
        let (label, icon, action): (&str, gpui_component::Icon, Box<dyn gpui::Action>) = match self
        {
            Self::SealNow => ("Seal now", Glyph::Lock.into(), Box::new(SealVault)),
            Self::NewLogin => ("New login", IconName::Plus.into(), Box::new(NewLogin)),
            Self::BackUpVault => (
                "Back up vault",
                IconName::HardDrive.into(),
                Box::new(BackUpVault),
            ),
            Self::Settings => (
                "Settings",
                IconName::Settings.into(),
                Box::new(OpenSettings),
            ),
            Self::Shortcuts => (
                "Keyboard shortcuts",
                Glyph::Keyboard.into(),
                Box::new(ShowShortcuts),
            ),
        };
        CommandItem::new().label(label).icon(icon).action(action)
    }
}

const BROWSABLE_KINDS: [factorseal::DocumentKind; 5] = [
    factorseal::DocumentKind::SecretSpecProject,
    factorseal::DocumentKind::SecretSpecProviderCache,
    factorseal::DocumentKind::NetworkManagerWifi,
    factorseal::DocumentKind::LinuxSecretService,
    factorseal::DocumentKind::LocalKeyring,
];

pub(super) fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new(PALETTE_KEYS, OpenPalette, Some(CONTEXT)),
        KeyBinding::new("secondary-c", CopyPassword, Some(OUTSIDE_TEXT_CONTEXT)),
        KeyBinding::new(
            "secondary-shift-c",
            CopyUsername,
            Some(OUTSIDE_TEXT_CONTEXT),
        ),
        KeyBinding::new("secondary-l", SealVault, Some(CONTEXT)),
        KeyBinding::new("secondary-e", EditItem, Some(OUTSIDE_TEXT_CONTEXT)),
        KeyBinding::new("secondary-s", SaveItem, Some(CONTEXT)),
        KeyBinding::new("secondary-v", PasteQrCode, Some(OUTSIDE_TEXT_CONTEXT)),
        KeyBinding::new(SHORTCUTS_KEYS, ShowShortcuts, Some(CONTEXT)),
        KeyBinding::new("escape", GoBack, Some(OUTSIDE_SECRET_CONTEXT)),
        KeyBinding::new("down", SelectNext, Some(OUTSIDE_DIALOG_CONTEXT)),
        KeyBinding::new("up", SelectPrevious, Some(OUTSIDE_DIALOG_CONTEXT)),
        KeyBinding::new("down", SelectNext, Some(SIDEBAR_INPUT_CONTEXT)),
        KeyBinding::new("enter", OpenSelected, Some(LIST_CONTEXT)),
    ]);
    cx.bind_keys(history_keys());
}

fn history_keys() -> [KeyBinding; 2] {
    [
        KeyBinding::new(
            "secondary-z",
            UndoPersonalChange,
            Some(OUTSIDE_TEXT_CONTEXT),
        ),
        KeyBinding::new(
            "secondary-shift-z",
            RedoPersonalChange,
            Some(OUTSIDE_TEXT_CONTEXT),
        ),
    ]
}

pub(super) struct State {
    root: FocusHandle,
    pub(super) list: FocusHandle,
    pub(super) cursor: usize,
    pub(super) list_focused: bool,
    pub(super) compact: bool,
    pub(super) narrow: bool,
    reveal: Rc<Cell<bool>>,
    pub(super) overlay: Rc<Cell<bool>>,
    list_scroll: ScrollHandle,
    detail_scroll: ScrollHandle,
    _keep_focus: Subscription,
    _close_on_seal: Subscription,
}

impl State {
    pub(super) fn new(window: &mut Window, cx: &mut Context<DesktopView>) -> Self {
        let root = cx.focus_handle();
        root.focus(window, cx);
        Self {
            root,
            list: cx.focus_handle().tab_stop(true),
            cursor: 0,
            list_focused: false,
            compact: false,
            narrow: false,
            reveal: Rc::new(Cell::new(false)),
            overlay: Rc::new(Cell::new(false)),
            list_scroll: ScrollHandle::new(),
            detail_scroll: ScrollHandle::new(),
            _keep_focus: cx.on_focus_lost(window, |view, window, cx| {
                if view.visible_pairing().is_some() {
                    view.pairing_focus.focus(window, cx);
                } else {
                    view.shortcuts.root.focus(window, cx);
                }
            }),
            _close_on_seal: cx.observe_in(&cx.entity(), window, |view, _, window, cx| {
                view.close_overlay_when_sealed(window, cx);
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CopyTarget {
    Password,
    Username,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum BackStep {
    CloseSettings,
    PersonalOverview,
    Select(VaultSelection),
    VaultBrowser,
}

fn back_step(
    settings_open: bool,
    selection: Option<&VaultSelection>,
    panel: PersonalPanel,
    draft_started: bool,
) -> Option<BackStep> {
    if settings_open {
        return Some(BackStep::CloseSettings);
    }
    match selection? {
        VaultSelection::Entry(entry) if is_personal_secret(entry) => {
            Some(BackStep::PersonalOverview)
        }
        VaultSelection::Entry(entry) => Some(BackStep::Select(VaultSelection::Category(
            entry.document_kind,
        ))),
        VaultSelection::PersonalSecrets if panel == PersonalPanel::NewItem => {
            (!draft_started).then_some(BackStep::PersonalOverview)
        }
        _ => Some(BackStep::VaultBrowser),
    }
}

pub(super) fn step(cursor: usize, len: usize, forward: bool) -> usize {
    if len == 0 {
        0
    } else if forward {
        (cursor + 1).min(len - 1)
    } else {
        cursor.min(len - 1).saturating_sub(1)
    }
}

fn revealed_offset(
    viewport: Bounds<Pixels>,
    row: Bounds<Pixels>,
    offset: Pixels,
    first: bool,
) -> Pixels {
    if first && row.bottom() - offset <= viewport.bottom() {
        px(0.)
    } else if row.top() < viewport.top() {
        offset + viewport.top() - row.top()
    } else if row.bottom() > viewport.bottom() {
        offset + viewport.bottom() - row.bottom()
    } else {
        offset
    }
}

fn copy_field_index(item: &PersonalSecret, target: CopyTarget) -> Option<usize> {
    let fields: Vec<_> = item
        .sections
        .iter()
        .flat_map(|section| &section.fields)
        .collect();
    let by_id = |id: &str| fields.iter().position(|field| field.id == id);
    match target {
        CopyTarget::Password => by_id("password").or_else(|| {
            fields
                .iter()
                .position(|field| field.field_type == PersonalFieldType::Concealed)
        }),
        CopyTarget::Username => by_id("username").or_else(|| {
            fields
                .iter()
                .position(|field| field.field_type == PersonalFieldType::Email)
        }),
    }
}

fn list_entries<'a>(
    contents: &'a VaultContents,
    list: Option<&VaultSelection>,
) -> Vec<&'a factorseal::VaultEntryMetadata> {
    match list {
        Some(VaultSelection::PersonalSecrets) => sorted_personal_entries(&contents.entries, ""),
        Some(VaultSelection::Category(kind)) => {
            category_entries(&contents.entries, *kind).collect()
        }
        _ => Vec::new(),
    }
}

fn palette_entries(contents: &VaultContents) -> Vec<factorseal::VaultEntryMetadata> {
    sorted_personal_entries(&contents.entries, "")
        .into_iter()
        .chain(
            BROWSABLE_KINDS
                .iter()
                .flat_map(|kind| category_entries(&contents.entries, *kind)),
        )
        .cloned()
        .collect()
}

fn tracked_scroll(id: &'static str, scroll: &ScrollHandle, content: impl IntoElement) -> Div {
    div()
        .size_full()
        .relative()
        .child(
            div()
                .id(id)
                .size_full()
                .flex()
                .flex_col()
                .track_scroll(scroll)
                .overflow_y_scroll()
                .lock_scroll_axis()
                .child(div().min_w_0().flex_none().min_h_full().child(content)),
        )
        .vertical_scrollbar(scroll)
}

fn palette_actions() -> CommandGroup {
    CommandGroup::new()
        .label("Actions")
        .items(PALETTE_ACTIONS.map(PaletteAction::item))
}

fn overlay_outlives_vault(overlay_open: bool, vault_open: bool) -> bool {
    overlay_open && !vault_open
}

fn palette_items(entries: &[factorseal::VaultEntryMetadata]) -> CommandGroup {
    CommandGroup::new()
        .label("Items")
        .items(entries.iter().map(|entry| {
            let (label, detail) = vault_entry_label(entry);
            let row_label = label.clone();
            let icon = if is_personal_secret(entry) {
                personal_kind_icon(personal_entry_kind(entry))
            } else {
                sidebar_category_icon(entry.document_kind)
            };
            CommandItem::new()
                .label(label)
                .keywords([
                    detail.clone(),
                    vault_category_label(entry.document_kind).to_owned(),
                ])
                .child(move |_, cx| {
                    h_flex()
                        .min_w_0()
                        .gap_2()
                        .child(
                            icon.clone()
                                .size_4()
                                .text_color(cx.theme().muted_foreground),
                        )
                        .child(div().truncate().child(row_label.clone()))
                        .child(
                            div()
                                .flex_none()
                                .text_body()
                                .text_color(cx.theme().muted_foreground)
                                .child(detail.clone()),
                        )
                })
        }))
}

impl DesktopView {
    pub(super) fn bind_shortcuts(&self, element: Div, cx: &mut Context<Self>) -> Div {
        element
            .key_context(CONTEXT)
            .track_focus(&self.shortcuts.root)
            .capture_action(cx.listener(Self::paste_qr_action))
            .on_action(cx.listener(Self::paste_qr_code))
            .on_action(cx.listener(Self::open_palette))
            .on_action(cx.listener(Self::select_next))
            .on_action(cx.listener(Self::select_previous))
            .on_action(cx.listener(Self::open_selected))
            .on_action(cx.listener(Self::copy_password))
            .on_action(cx.listener(Self::copy_username))
            .on_action(cx.listener(Self::seal_now))
            .on_action(cx.listener(Self::go_back))
            .on_action(cx.listener(Self::show_shortcuts))
            .on_action(cx.listener(Self::new_login))
            .on_action(cx.listener(Self::back_up_vault))
            .on_action(cx.listener(Self::open_settings_action))
            .on_action(cx.listener(Self::edit_item))
            .on_action(cx.listener(Self::save_item))
    }

    pub(super) fn scroll_list(&self, list: impl IntoElement) -> Div {
        tracked_scroll("vault-list", &self.shortcuts.list_scroll, list)
    }

    pub(super) fn scroll_detail(&self, detail: impl IntoElement) -> Div {
        tracked_scroll("vault-detail", &self.shortcuts.detail_scroll, detail)
    }

    pub(super) fn reveal_when_moved(&self, first: bool) -> impl IntoElement {
        let pending = Rc::clone(&self.shortcuts.reveal);
        let scroll = self.shortcuts.list_scroll.clone();
        canvas(
            move |row, window, _| {
                if !pending.replace(false) {
                    return;
                }
                let offset = scroll.offset();
                let revealed = revealed_offset(scroll.bounds(), row, offset.y, first);
                if revealed != offset.y {
                    window.on_next_frame(move |window, _| {
                        scroll.set_offset(point(offset.x, revealed));
                        window.refresh();
                    });
                }
            },
            |_, (), _, _| {},
        )
        .absolute()
        .inset_0()
    }

    pub(super) fn unsealed_contents(&self) -> Option<&VaultContents> {
        match &self.snapshot {
            Snapshot::Unsealed { contents, .. } => Some(contents),
            _ => None,
        }
    }

    fn vault_query(&self, cx: &App) -> String {
        self.vault_search.read(cx).value().trim().to_lowercase()
    }

    fn visible_list(&self, cx: &App) -> Vec<factorseal::VaultEntryMetadata> {
        if self.showing_search_results(cx) {
            return Vec::new();
        }
        let list = self.shown_list(self.shortcuts.compact);
        self.unsealed_contents().map_or_else(Vec::new, |contents| {
            list_entries(contents, list.as_ref())
                .into_iter()
                .cloned()
                .collect()
        })
    }

    pub(super) fn follow_opened_entry(&mut self, address: &factorseal::SecretAddress, cx: &App) {
        let search_position = self
            .unsealed_contents()
            .filter(|_| self.showing_search_results(cx))
            .and_then(|contents| {
                search_result_entries(&contents.entries, &self.vault_query(cx))
                    .iter()
                    .position(|entry| entry.address == *address)
            });
        if let Some(position) = search_position {
            self.search_cursor = position;
        }
        if let Some(position) = self
            .visible_list(cx)
            .iter()
            .position(|entry| entry.address == *address)
        {
            self.shortcuts.cursor = position;
        }
    }

    fn list_len(&self, cx: &App) -> usize {
        self.visible_list(cx)
            .len()
            .max(self.shown_section_rows(cx).len())
    }

    fn shown_section_rows(&self, cx: &App) -> Vec<section_pages::SectionRow> {
        if self.shortcuts.compact && self.section_opened {
            Vec::new()
        } else {
            self.section_rows(cx)
        }
    }

    pub(super) fn focus_list(
        &mut self,
        cursor: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let len = self.list_len(cx);
        if len == 0 {
            return;
        }
        self.shortcuts.cursor = cursor.min(len - 1);
        self.shortcuts.reveal.set(true);
        self.shortcuts.list.focus(window, cx);
        cx.notify();
    }

    fn personal_draft_started(&self, cx: &App) -> bool {
        self.item_editor
            .as_ref()
            .is_some_and(item_editor::Editor::is_new)
            && self.item_editor_changed(cx)
    }

    fn drafting_new_item(&self) -> bool {
        self.selected_vault_item == Some(VaultSelection::PersonalSecrets)
            && self.personal_panel == PersonalPanel::NewItem
    }

    fn open_palette(&mut self, _: &OpenPalette, window: &mut Window, cx: &mut Context<Self>) {
        let Some(contents) = self.unsealed_contents() else {
            cx.propagate();
            return;
        };
        if window.has_active_dialog(cx) {
            return;
        }
        let entries = Rc::new(palette_entries(contents));
        let state = cx.new(|cx| CommandState::new(window, cx));
        let view = cx.weak_entity();
        let focus_on_mount = Rc::new(Cell::new(true));
        let overlay = Rc::clone(&self.shortcuts.overlay);
        overlay.set(true);
        window.open_dialog(cx, move |dialog, _, _| {
            let state = state.clone();
            let entries = Rc::clone(&entries);
            let view = view.clone();
            let focus_on_mount = Rc::clone(&focus_on_mount);
            let overlay = Rc::clone(&overlay);
            dialog
                .on_close(move |_, _, _| overlay.set(false))
                .close_button(false)
                .p_0()
                .width(px(560.))
                .content(move |content, window, cx| {
                    if focus_on_mount.replace(false) {
                        let state = state.clone();
                        window.defer(cx, move |window, cx| {
                            state.read(cx).focus_handle(cx).focus(window, cx);
                        });
                    }
                    let confirmed_entries = Rc::clone(&entries);
                    let view = view.clone();
                    let radius = cx.theme().radius_lg;
                    content.child(
                        Command::new(&state)
                            .bordered(false)
                            .rounded(radius)
                            .max_h(rems(28.))
                            .placeholder("Search items and actions")
                            .empty(|_, _, cx| {
                                div()
                                    .p_4()
                                    .text_body()
                                    .text_color(cx.theme().muted_foreground)
                                    .child("No matching items")
                            })
                            .group(palette_actions())
                            .group(palette_items(&entries))
                            .on_confirm(move |index: IndexPath, window, cx| {
                                window.close_dialog(cx);
                                let _ = view.update(cx, |view, cx| {
                                    view.palette_confirmed(index, &confirmed_entries, window, cx);
                                });
                            }),
                    )
                })
        });
    }

    fn palette_confirmed(
        &mut self,
        index: IndexPath,
        entries: &[factorseal::VaultEntryMetadata],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.shortcuts.overlay.set(false);
        match PaletteAction::confirmed(index) {
            Some(PaletteAction::Shortcuts) => self.show_shortcuts(&ShowShortcuts, window, cx),
            Some(PaletteAction::NewLogin) => self.focus_new_item_name(window, cx),
            Some(_) => {}
            None => {
                if index.section == ITEMS_SECTION
                    && let Some(entry) = entries.get(index.row).cloned()
                {
                    self.open_entry(entry, cx);
                }
            }
        }
    }

    pub(super) fn close_overlay_when_sealed(&mut self, window: &mut Window, cx: &mut App) {
        if overlay_outlives_vault(
            self.shortcuts.overlay.get(),
            self.unsealed_contents().is_some(),
        ) {
            self.shortcuts.overlay.set(false);
            window.close_dialog(cx);
        }
    }

    fn focus_new_item_name(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.drafting_new_item() {
            self.ensure_new_item_editor(window, cx);
            self.item_name.update(cx, |name, cx| name.focus(window, cx));
        }
    }

    fn open_entry(&mut self, entry: factorseal::VaultEntryMetadata, cx: &mut Context<Self>) {
        self.settings_open = false;
        self.select_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
    }

    fn move_selection(&mut self, forward: bool, window: &mut Window, cx: &mut Context<Self>) {
        if self.move_search_cursor(forward, cx) {
            return;
        }
        let len = self.list_len(cx);
        let search_focused = self
            .vault_search
            .read(cx)
            .focus_handle(cx)
            .is_focused(window);
        if self.shortcuts.list.is_focused(window) {
            self.shortcuts.cursor = step(self.shortcuts.cursor, len, forward);
            self.shortcuts.reveal.set(true);
            cx.notify();
        } else if len > 0 && (search_focused || self.shortcuts.root.is_focused(window)) {
            self.focus_list(if forward { 0 } else { usize::MAX }, window, cx);
        } else {
            cx.propagate();
        }
    }

    fn select_next(&mut self, _: &SelectNext, window: &mut Window, cx: &mut Context<Self>) {
        self.move_selection(true, window, cx);
    }

    fn select_previous(&mut self, _: &SelectPrevious, window: &mut Window, cx: &mut Context<Self>) {
        self.move_selection(false, window, cx);
    }

    fn open_selected(&mut self, _: &OpenSelected, _: &mut Window, cx: &mut Context<Self>) {
        let entries = self.visible_list(cx);
        let sections = self.shown_section_rows(cx);
        let cursor = self
            .shortcuts
            .cursor
            .min(entries.len().max(sections.len()).saturating_sub(1));
        if let Some(entry) = entries.into_iter().nth(cursor) {
            self.open_entry(entry, cx);
        } else if let Some(row) = sections.get(cursor) {
            self.open_section(*row, cx);
        } else {
            cx.propagate();
        }
    }

    fn copy_field(&mut self, target: CopyTarget, cx: &mut Context<Self>) {
        if !self.is_unsealed() {
            cx.propagate();
            return;
        }
        let index = match &self.selected_vault_item {
            Some(VaultSelection::Entry(entry)) if is_personal_secret(entry) => self
                .personal_detail
                .item()
                .and_then(|item| copy_field_index(item, target))
                .filter(|index| self.personal_detail.has_value(*index)),
            _ => None,
        };
        match index {
            Some(index) => self.copy_saved_personal_field(index, cx),
            None => cx.propagate(),
        }
    }

    fn copy_password(&mut self, _: &CopyPassword, _: &mut Window, cx: &mut Context<Self>) {
        self.copy_field(CopyTarget::Password, cx);
    }

    fn copy_username(&mut self, _: &CopyUsername, _: &mut Window, cx: &mut Context<Self>) {
        self.copy_field(CopyTarget::Username, cx);
    }

    fn seal_now(&mut self, _: &SealVault, _: &mut Window, cx: &mut Context<Self>) {
        if self.unsealed_contents().is_some() {
            self.seal(cx);
        }
    }

    fn go_back(&mut self, _: &GoBack, window: &mut Window, cx: &mut Context<Self>) {
        if !self.settings_open && self.unsealed_contents().is_none() {
            cx.propagate();
            return;
        }
        if self.generator_target.is_some() {
            self.close_generator(cx);
            return;
        }
        if self.visible_pairing().is_some() {
            self.cancel_device_pairing(cx);
            return;
        }
        let search_focused = self
            .vault_search
            .read(cx)
            .focus_handle(cx)
            .is_focused(window);
        if search_focused && !self.vault_query(cx).is_empty() {
            self.vault_search
                .update(cx, |search, cx| search.set_value("", window, cx));
            return;
        }
        if self.item_editor.is_some() {
            self.cancel_item_editor(cx);
            return;
        }
        if !self.shortcuts.root.is_focused(window) && !self.shortcuts.list.is_focused(window) {
            self.shortcuts.root.focus(window, cx);
            return;
        }
        if self.shortcuts.compact && self.on_section_page() && self.section_opened {
            self.section_opened = false;
            let cursor = self.shortcuts.cursor;
            self.focus_list(cursor, window, cx);
            return;
        }
        let opened = match &self.selected_vault_item {
            Some(VaultSelection::Entry(entry)) => Some((**entry).clone()),
            _ => None,
        };
        match back_step(
            self.settings_open,
            self.selected_vault_item.as_ref(),
            self.personal_panel,
            self.personal_draft_started(cx),
        ) {
            Some(BackStep::CloseSettings) => {
                self.settings_open = false;
                cx.notify();
            }
            Some(BackStep::PersonalOverview) => {
                self.show_personal_panel(PersonalPanel::Overview, cx);
            }
            Some(BackStep::Select(selection)) => self.select_vault_item(selection, cx),
            Some(BackStep::VaultBrowser) => self.show_vault_browser(cx),
            None => {
                cx.propagate();
                return;
            }
        }
        if let Some(opened) = opened {
            let position = self
                .visible_list(cx)
                .iter()
                .position(|entry| entry.address == opened.address);
            if let Some(position) = position {
                self.focus_list(position, window, cx);
            }
        }
    }

    fn new_login(&mut self, _: &NewLogin, window: &mut Window, cx: &mut Context<Self>) {
        if self.unsealed_contents().is_none() {
            return;
        }
        self.settings_open = false;
        if !(self.drafting_new_item() && self.personal_draft_started(cx)) {
            self.show_personal_panel(PersonalPanel::NewItem, cx);
        }
        self.focus_new_item_name(window, cx);
        cx.notify();
    }

    fn back_up_vault(&mut self, _: &BackUpVault, _: &mut Window, cx: &mut Context<Self>) {
        if self.unsealed_contents().is_none() {
            return;
        }
        self.settings_open = false;
        self.select_vault_item(VaultSelection::BackupVault, cx);
    }

    fn open_settings_action(&mut self, _: &OpenSettings, _: &mut Window, cx: &mut Context<Self>) {
        self.open_settings(cx);
    }

    fn paste_qr_code(&mut self, _: &PasteQrCode, _: &mut Window, cx: &mut Context<Self>) {
        self.paste_qr(false, cx);
    }

    fn edit_item(&mut self, _: &EditItem, window: &mut Window, cx: &mut Context<Self>) {
        let viewing = matches!(&self.selected_vault_item, Some(VaultSelection::Entry(entry))
            if is_personal_secret(entry));
        if !viewing || self.settings_open || self.personal_detail.item().is_none() {
            cx.propagate();
            return;
        }
        self.begin_edit(item_editor::EditStart::Top, window, cx);
    }

    fn save_item(&mut self, _: &SaveItem, _: &mut Window, cx: &mut Context<Self>) {
        if self.item_editor.is_none() {
            cx.propagate();
            return;
        }
        self.save_item_editor(cx);
    }

    fn show_shortcuts(&mut self, _: &ShowShortcuts, window: &mut Window, cx: &mut Context<Self>) {
        if window.has_active_dialog(cx) {
            return;
        }
        let keys = |action: &dyn gpui::Action, window: &Window| {
            Kbd::binding_for_action(action, Some(CONTEXT), window)
                .map(IntoElement::into_any_element)
        };
        let typed = |keystroke: &str| {
            Keystroke::parse(keystroke)
                .ok()
                .map(|keystroke| Kbd::new(keystroke).into_any_element())
        };
        let overlay = Rc::clone(&self.shortcuts.overlay);
        overlay.set(self.unsealed_contents().is_some());
        window.open_dialog(cx, move |dialog, window, cx| {
            let rows: [(&str, Vec<Option<AnyElement>>); 11] = [
                ("Search items and actions", vec![keys(&OpenPalette, window)]),
                ("Search the vault", vec![keys(&FocusSearch, window)]),
                ("Move through a list", vec![typed("up"), typed("down")]),
                ("Open the selected item", vec![typed("enter")]),
                ("Copy password", vec![keys(&CopyPassword, window)]),
                ("Copy username", vec![keys(&CopyUsername, window)]),
                ("Edit item", vec![keys(&EditItem, window)]),
                ("Save changes", vec![keys(&SaveItem, window)]),
                ("Seal now", vec![keys(&SealVault, window)]),
                ("Go back", vec![keys(&GoBack, window)]),
                ("Keyboard shortcuts", vec![keys(&ShowShortcuts, window)]),
            ];
            let theme = cx.theme();
            let overlay = Rc::clone(&overlay);
            dialog
                .on_close(move |_, _, _| overlay.set(false))
                .title("Keyboard shortcuts")
                .width(px(440.))
                .child(v_flex().children(rows.into_iter().enumerate().map(
                    |(index, (label, keys))| {
                        h_flex()
                            .w_full()
                            .items_center()
                            .justify_between()
                            .gap_4()
                            .py_2()
                            .when(index > 0, |row| row.border_t_1().border_color(theme.border))
                            .child(div().text_body().child(label))
                            .child(h_flex().gap_1().children(keys.into_iter().flatten()))
                    },
                )))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: factorseal::DocumentKind, partition: &[u8]) -> factorseal::VaultEntryMetadata {
        named(kind, partition, "item", None)
    }

    fn named(
        kind: factorseal::DocumentKind,
        partition: &[u8],
        name: &str,
        updated_at: Option<u64>,
    ) -> factorseal::VaultEntryMetadata {
        factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some(name.into()),
            display_type: Some("Login".into()),
            display_username: None,
            display_website: None,
            favorite: false,
            updated_at,
            document_kind: kind,
            partition: partition.to_vec(),
            address: factorseal::SecretAddress::new(name, None).unwrap(),
        }
    }

    #[test]
    fn lists_and_palette_follow_what_the_screen_shows() {
        let contents = VaultContents {
            entries: vec![
                named(
                    factorseal::DocumentKind::LocalKeyring,
                    PERSONAL_SECRET_NAMESPACE,
                    "older",
                    Some(1),
                ),
                named(
                    factorseal::DocumentKind::NetworkManagerWifi,
                    b"wifi",
                    "home",
                    None,
                ),
                named(
                    factorseal::DocumentKind::LocalKeyring,
                    PERSONAL_SECRET_NAMESPACE,
                    "newer",
                    Some(2),
                ),
            ],
            ..VaultContents::default()
        };
        let names = |entries: Vec<&factorseal::VaultEntryMetadata>| {
            entries
                .into_iter()
                .map(|entry| entry.display_name.clone().unwrap())
                .collect::<Vec<_>>()
        };
        let personal = Some(&VaultSelection::PersonalSecrets);
        assert_eq!(names(list_entries(&contents, personal)), ["newer", "older"]);
        let wifi = VaultSelection::Category(factorseal::DocumentKind::NetworkManagerWifi);
        assert_eq!(names(list_entries(&contents, Some(&wifi))), ["home"]);
        assert_eq!(
            list_entries(&contents, Some(&VaultSelection::Devices)).len(),
            0
        );
        assert_eq!(list_entries(&contents, None).len(), 0);
        assert_eq!(
            palette_entries(&contents)
                .into_iter()
                .map(|entry| entry.display_name.unwrap())
                .collect::<Vec<_>>(),
            ["newer", "older", "home"]
        );
    }

    #[test]
    fn escape_steps_back_one_level_at_a_time() {
        let personal = entry(
            factorseal::DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
        );
        let wifi = entry(factorseal::DocumentKind::NetworkManagerWifi, b"wifi");
        assert_eq!(
            back_step(
                true,
                Some(&VaultSelection::Devices),
                PersonalPanel::Overview,
                false
            ),
            Some(BackStep::CloseSettings)
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::Entry(Box::new(personal))),
                PersonalPanel::Overview,
                false
            ),
            Some(BackStep::PersonalOverview)
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::Entry(Box::new(wifi))),
                PersonalPanel::Overview,
                false
            ),
            Some(BackStep::Select(VaultSelection::Category(
                factorseal::DocumentKind::NetworkManagerWifi
            )))
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::PersonalSecrets),
                PersonalPanel::NewItem,
                false
            ),
            Some(BackStep::PersonalOverview)
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::PersonalSecrets),
                PersonalPanel::NewItem,
                true
            ),
            None
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::PersonalSecrets),
                PersonalPanel::Overview,
                false
            ),
            Some(BackStep::VaultBrowser)
        );
        assert_eq!(
            back_step(
                false,
                Some(&VaultSelection::BackupVault),
                PersonalPanel::Overview,
                false
            ),
            Some(BackStep::VaultBrowser)
        );
        assert_eq!(back_step(false, None, PersonalPanel::Overview, false), None);
    }

    #[test]
    fn undo_and_redo_leave_text_fields_to_their_own_editing() {
        let contexts = |names: &[&str]| {
            names
                .iter()
                .map(|name| gpui::KeyContext::parse(name).unwrap())
                .collect::<Vec<_>>()
        };
        for binding in history_keys() {
            let predicate = binding.predicate().unwrap();
            let matches = |names: &[&str]| predicate.depth_of(&contexts(names)).is_some();
            assert!(matches(&[CONTEXT]));
            assert!(matches(&[CONTEXT, LIST_CONTEXT]));
            assert!(!matches(&[CONTEXT, "Input"]));
            assert!(!matches(&[CONTEXT, "FactorsealSecret"]));
            assert!(!matches(&[CONTEXT, "Dialog"]));
        }
    }

    #[test]
    fn arrow_keys_leave_open_dialogs_alone() {
        let binding = KeyBinding::new("down", SelectNext, Some(OUTSIDE_DIALOG_CONTEXT));
        let predicate = binding.predicate().unwrap();
        let matches = |names: &[&str]| {
            let contexts: Vec<_> = names
                .iter()
                .map(|name| gpui::KeyContext::parse(name).unwrap())
                .collect();
            predicate.depth_of(&contexts).is_some()
        };
        assert!(matches(&[CONTEXT]));
        assert!(matches(&[CONTEXT, LIST_CONTEXT]));
        assert!(!matches(&[CONTEXT, "Dialog"]));
    }

    #[test]
    fn arrow_keys_stay_inside_the_list() {
        assert_eq!(step(0, 3, true), 1);
        assert_eq!(step(2, 3, true), 2);
        assert_eq!(step(1, 3, false), 0);
        assert_eq!(step(0, 3, false), 0);
        assert_eq!(step(7, 3, false), 1);
        assert_eq!(step(0, 0, true), 0);
        assert_eq!(step(0, 0, false), 0);
    }

    #[test]
    fn the_selected_row_scrolls_just_into_view() {
        let viewport = Bounds::new(point(px(0.), px(100.)), size(px(400.), px(300.)));
        let row = |top: f32| Bounds::new(point(px(0.), px(top)), size(px(400.), px(48.)));
        let revealed = |top: f32, offset: f32, first: bool| {
            revealed_offset(viewport, row(top), px(offset), first)
        };
        assert_eq!(revealed(200., -50., false), px(-50.));
        assert_eq!(revealed(100., -50., false), px(-50.));
        assert_eq!(revealed(352., -50., false), px(-50.));
        assert_eq!(revealed(380., -50., false), px(-78.));
        assert_eq!(revealed(60., -100., false), px(-60.));
        assert_eq!(revealed(60., -100., true), px(0.));
        assert_eq!(revealed(380., 0., true), px(-28.));
    }

    #[test]
    fn the_palette_knows_each_action_by_what_it_is() {
        let at = |section: usize, row: usize| {
            PaletteAction::confirmed(IndexPath::new(row).section(section))
        };
        assert_ne!(PALETTE_ACTIONS[0], PaletteAction::SealNow);
        for (row, action) in PALETTE_ACTIONS.into_iter().enumerate() {
            assert_eq!(at(ACTIONS_SECTION, row), Some(action));
        }
        let shortcuts = PALETTE_ACTIONS
            .iter()
            .position(|action| *action == PaletteAction::Shortcuts)
            .unwrap();
        assert_eq!(
            at(ACTIONS_SECTION, shortcuts),
            Some(PaletteAction::Shortcuts)
        );
        assert_eq!(at(ACTIONS_SECTION, PALETTE_ACTIONS.len()), None);
        assert_eq!(at(ITEMS_SECTION, shortcuts), None);
    }

    #[test]
    fn the_palette_and_sheet_close_when_the_vault_seals() {
        assert!(overlay_outlives_vault(true, false));
        assert!(!overlay_outlives_vault(true, true));
        assert!(!overlay_outlives_vault(false, false));
        assert!(!overlay_outlives_vault(false, true));
    }

    #[test]
    fn copy_shortcuts_find_the_password_and_username() {
        let mut login = PersonalSecret::new(PersonalSecretKind::Login, "GitHub".into());
        login.sections.push(PersonalSection {
            id: "account".into(),
            label: "Account".into(),
            fields: vec![
                PersonalField::new("username", "Username", PersonalFieldType::Text, "alice"),
                PersonalField::new("password", "Password", PersonalFieldType::Concealed, "pw"),
            ],
        });
        assert_eq!(copy_field_index(&login, CopyTarget::Password), Some(1));
        assert_eq!(copy_field_index(&login, CopyTarget::Username), Some(0));

        let mut api = PersonalSecret::new(PersonalSecretKind::ApiCredential, "API".into());
        api.sections.push(PersonalSection {
            id: "details".into(),
            label: "Details".into(),
            fields: vec![
                PersonalField::new("email", "Email", PersonalFieldType::Email, "a@b.c"),
                PersonalField::new(
                    "credential",
                    "Credential",
                    PersonalFieldType::Concealed,
                    "k",
                ),
            ],
        });
        assert_eq!(copy_field_index(&api, CopyTarget::Password), Some(1));
        assert_eq!(copy_field_index(&api, CopyTarget::Username), Some(0));

        let note = PersonalSecret::new(PersonalSecretKind::SecureNote, "Note".into());
        assert_eq!(copy_field_index(&note, CopyTarget::Password), None);
        assert_eq!(copy_field_index(&note, CopyTarget::Username), None);
    }
}
