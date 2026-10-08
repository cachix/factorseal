use gpui::{
    AnyElement, App, Context, Div, Entity, EventEmitter, SharedString, Subscription, Window, div,
    prelude::*, rems,
};
use gpui_component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, IndexPath, StyledExt as _,
    button::Button,
    button::ButtonVariants as _,
    h_flex,
    select::{Select, SelectEvent, SelectItem, SelectState},
    switch::Switch,
    v_flex,
};

use crate::{
    appearance::{self, Choice},
    branding::Glyph,
    settings::DesktopSettings,
};

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Theme(Choice),
    Scale(u16),
    Text(Option<u16>),
    Font(Option<String>),
    Idle(u64),
    Maximum(u64),
}

impl Value {
    fn label(&self) -> SharedString {
        match self {
            Self::Theme(choice) => choice.label().into(),
            Self::Scale(value) => format!("{value}%").into(),
            Self::Text(Some(value)) => format!("{value} px").into(),
            Self::Font(Some(value)) => value.clone().into(),
            Self::Text(None) | Self::Font(None) => "System default".into(),
            Self::Idle(seconds) | Self::Maximum(seconds) => {
                if seconds.is_multiple_of(3600) {
                    let hours = seconds / 3600;
                    format!("{hours} {}", if hours == 1 { "hour" } else { "hours" }).into()
                } else if seconds.is_multiple_of(60) {
                    let minutes = seconds / 60;
                    format!(
                        "{minutes} {}",
                        if minutes == 1 { "minute" } else { "minutes" }
                    )
                    .into()
                } else {
                    format!(
                        "{} minutes",
                        std::time::Duration::from_secs(*seconds).as_secs_f64() / 60.
                    )
                    .into()
                }
            }
        }
    }

    fn apply(&self, settings: &mut DesktopSettings) {
        match self {
            Self::Theme(value) => settings.theme = *value,
            Self::Scale(value) => settings.ui_scale = *value,
            Self::Text(value) => settings.text_size = *value,
            Self::Font(value) => settings.font.clone_from(value),
            Self::Idle(value) => settings.idle_seconds = *value,
            Self::Maximum(value) => settings.maximum_seconds = *value,
        }
    }
}

#[derive(Clone)]
struct Item(Value);

impl SelectItem for Item {
    type Value = Value;

    fn title(&self) -> SharedString {
        self.0.label()
    }

    fn value(&self) -> &Value {
        &self.0
    }
}

type Control = Entity<SelectState<Vec<Item>>>;

pub(crate) struct BrowserRow {
    pub(crate) name: &'static str,
    pub(crate) state: SharedString,
    pub(crate) install: Option<AnyElement>,
}

pub(crate) struct Browsers {
    pub(crate) rows: Vec<BrowserRow>,
    pub(crate) notes: Vec<&'static str>,
    pub(crate) error: Option<&'static str>,
    pub(crate) paired: Vec<AnyElement>,
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Appearance,
    Security,
    Browsers,
    Diagnostics,
}

impl Section {
    fn icon(self) -> Icon {
        match self {
            Self::Appearance => IconName::Palette.into(),
            Self::Security => Glyph::Lock.into(),
            Self::Browsers => IconName::Globe.into(),
            Self::Diagnostics => Glyph::Bug.into(),
        }
    }
}

pub(crate) struct ReportIssue;

impl EventEmitter<ReportIssue> for SettingsView {}

pub(crate) struct SettingsView {
    section: Section,
    controls: Vec<Control>,
    error: Option<&'static str>,
    export_busy: bool,
    export_complete: bool,
    _subscriptions: Vec<Subscription>,
}

fn values(settings: &DesktopSettings) -> [Value; 6] {
    [
        Value::Theme(settings.theme),
        Value::Scale(settings.ui_scale),
        Value::Text(settings.text_size),
        Value::Font(settings.font.clone()),
        Value::Idle(settings.idle_seconds),
        Value::Maximum(settings.maximum_seconds),
    ]
}

fn options(cx: &App) -> [Vec<Value>; 6] {
    let mut fonts = cx.text_system().all_font_names();
    fonts.sort_unstable();
    fonts.dedup();
    [
        Choice::all().map(Value::Theme).collect(),
        [80, 90, 100, 110, 125, 150, 175, 200]
            .into_iter()
            .map(Value::Scale)
            .collect(),
        std::iter::once(Value::Text(None))
            .chain(
                [12, 14, 16, 18, 20, 24]
                    .into_iter()
                    .map(|size| Value::Text(Some(size))),
            )
            .collect(),
        std::iter::once(Value::Font(None))
            .chain(fonts.into_iter().map(|font| Value::Font(Some(font))))
            .collect(),
        [60, 300, 900, 1800, 3600]
            .into_iter()
            .map(Value::Idle)
            .collect(),
        [900, 3600, 14_400, 28_800, 86_400]
            .into_iter()
            .map(Value::Maximum)
            .collect(),
    ]
}

impl SettingsView {
    pub(crate) fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let current = values(appearance::current(cx));
        let controls: Vec<_> = options(cx)
            .into_iter()
            .zip(current)
            .map(|(mut options, selected)| {
                if !options.contains(&selected) {
                    options.push(selected.clone());
                }
                let index = options
                    .iter()
                    .position(|value| value == &selected)
                    .map(|index| IndexPath::default().row(index));
                cx.new(|cx| {
                    SelectState::new(
                        options.into_iter().map(Item).collect::<Vec<_>>(),
                        index,
                        window,
                        cx,
                    )
                    .searchable(true)
                })
            })
            .collect();
        let subscriptions = controls
            .iter()
            .map(|control| {
                cx.subscribe_in(
                    control,
                    window,
                    |view, _, event: &SelectEvent<Vec<Item>>, window, cx| {
                        if let SelectEvent::Confirm(Some(value)) = event {
                            let mut settings = appearance::current(cx).clone();
                            value.apply(&mut settings);
                            view.save(settings, window, cx);
                        }
                    },
                )
            })
            .collect();
        Self {
            section: Section::Appearance,
            controls,
            error: None,
            export_busy: false,
            export_complete: false,
            _subscriptions: subscriptions,
        }
    }

    pub(crate) fn show_browsers(&mut self, cx: &mut Context<Self>) {
        self.section = Section::Browsers;
        self.error = None;
        cx.notify();
    }

    fn save(&mut self, settings: DesktopSettings, window: &mut Window, cx: &mut Context<Self>) {
        self.error = if settings.idle_seconds > settings.maximum_seconds {
            Some("Idle lock timeout must not exceed maximum unlock duration.")
        } else if let Err(error) = appearance::update(settings, cx) {
            factorseal::diagnostics::event("desktop", "save_settings", "error");
            eprintln!("could not save desktop settings: {error:#}");
            Some("Could not save settings.")
        } else {
            None
        };
        if self.error.is_some() {
            self.sync_controls(window, cx);
        }
        cx.notify();
    }

    fn sync_controls(&self, window: &mut Window, cx: &mut Context<Self>) {
        for (control, value) in self.controls.iter().zip(values(appearance::current(cx))) {
            control.update(cx, |control, cx| {
                control.set_selected_value(&value, window, cx);
            });
        }
    }

    fn default_appearance(settings: &DesktopSettings) -> DesktopSettings {
        let defaults = DesktopSettings::default();
        DesktopSettings {
            theme: defaults.theme,
            ui_scale: defaults.ui_scale,
            text_size: defaults.text_size,
            font: defaults.font,
            reduced_motion: defaults.reduced_motion,
            ..settings.clone()
        }
    }

    fn reset_button(cx: &mut Context<Self>) -> Button {
        let current = appearance::current(cx);
        Button::new("reset-appearance")
            .icon(IconName::Undo2)
            .label("Reset to defaults")
            .disabled(*current == Self::default_appearance(current))
            .on_click(cx.listener(|view, _, window, cx| {
                let settings = Self::default_appearance(appearance::current(cx));
                view.save(settings, window, cx);
                view.sync_controls(window, cx);
            }))
    }

    fn select(&self, label: &'static str, index: usize) -> Div {
        div().w(rems(18.)).max_w_full().flex_none().child(
            Select::new(&self.controls[index])
                .accessibility_label(label)
                .search_placeholder(label)
                .w_full(),
        )
    }

    fn switch(
        id: &'static str,
        label: &'static str,
        checked: bool,
        apply: fn(&mut DesktopSettings, bool),
        cx: &mut Context<Self>,
    ) -> Switch {
        Switch::new(id)
            .accessibility_label(label)
            .checked(checked)
            .on_click(cx.listener(move |view, checked: &bool, window, cx| {
                let mut settings = appearance::current(cx).clone();
                apply(&mut settings, *checked);
                view.save(settings, window, cx);
            }))
    }

    fn setting(label: impl IntoElement, control: impl IntoElement) -> Div {
        h_flex()
            .w_full()
            .min_h(rems(3.5))
            .items_center()
            .justify_between()
            .gap_4()
            .py_2()
            .child(div().font_medium().child(label))
            .child(control)
    }

    fn list(rows: impl IntoIterator<Item = Div>, cx: &App) -> Div {
        let border = cx.theme().border;
        v_flex()
            .w_full()
            .children(rows.into_iter().enumerate().map(move |(index, row)| {
                row.when(index > 0, |row| row.border_t_1().border_color(border))
            }))
    }

    fn note(text: impl IntoElement, cx: &App) -> Div {
        div()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(text)
    }

    fn appearance_rows(&self, cx: &mut Context<Self>) -> Vec<Div> {
        let reduced_motion = appearance::current(cx).reduced_motion;
        vec![
            Self::setting("Theme", self.select("Theme", 0)),
            Self::setting("UI scale", self.select("UI scale", 1)),
            Self::setting("Text size", self.select("Text size", 2)),
            Self::setting("Font", self.select("Font", 3)),
            Self::setting(
                "Reduced motion",
                Self::switch(
                    "reduced-motion",
                    "Reduced motion",
                    reduced_motion,
                    |settings, value| settings.reduced_motion = value,
                    cx,
                ),
            ),
        ]
    }

    fn security_rows(&self) -> Vec<Div> {
        vec![
            Self::setting("Idle lock timeout", self.select("Idle lock timeout", 4)),
            Self::setting(
                "Maximum unlock duration",
                self.select("Maximum unlock duration", 5),
            ),
        ]
    }

    fn crash_reports_row(cx: &mut Context<Self>) -> Div {
        let checked = appearance::current(cx).automatic_crash_reports;
        Self::setting(
            "Automatically send crash reports",
            Self::switch(
                "automatic-crash-reports",
                "Automatically send crash reports",
                checked,
                |settings, value| settings.automatic_crash_reports = value,
                cx,
            ),
        )
    }

    fn diagnostics_text() -> [&'static str; 3] {
        [
            "Crash reports include recent operations, timings, and backtraces. Secret values and panic messages are excluded. Local reports remain available for export.",
            if crate::crash_reporting::configured() {
                "Sentry is configured. Automatic submission sends Desktop and vault-worker crash reports in the background, including pending reports after a restart."
            } else {
                "Automatic submission is unavailable in this session. Reports stay local."
            },
            "The bug button in the footer opens a form for describing an issue. Send report submits your description and recent diagnostic logs, even when automatic crash reporting is off.",
        ]
    }

    fn export_button(&self, cx: &mut Context<Self>) -> Button {
        Button::new("export-diagnostics")
            .icon(Glyph::Download)
            .loading(self.export_busy)
            .label(if self.export_busy {
                "Exporting…"
            } else {
                "Export diagnostics…"
            })
            .disabled(self.export_busy)
            .on_click(cx.listener(|view, _, _, cx| view.export_diagnostics(cx)))
    }

    fn report_button(cx: &mut Context<Self>) -> Button {
        Button::new("report-issue-from-settings")
            .icon(Glyph::Bug)
            .label("Report an issue")
            .on_click(cx.listener(|_, _, _, cx| cx.emit(ReportIssue)))
    }

    fn export_status(&self, cx: &App) -> Option<Div> {
        self.export_complete.then(|| {
            Self::note(
                "Diagnostics exported. Review the file before sharing it.",
                cx,
            )
        })
    }

    fn browser_rows(rows: Vec<BrowserRow>, cx: &App) -> Vec<Div> {
        rows.into_iter()
            .map(|row| {
                h_flex()
                    .w_full()
                    .min_h(rems(3.5))
                    .items_center()
                    .gap_4()
                    .py_2()
                    .child(div().w(rems(7.)).flex_none().font_medium().child(row.name))
                    .child(Self::note(row.state, cx).flex_1())
                    .children(row.install)
            })
            .collect()
    }

    fn browser_notes(notes: Vec<&'static str>, error: Option<&'static str>, cx: &App) -> Div {
        v_flex()
            .gap_2()
            .children(notes.into_iter().map(|note| Self::note(note, cx)))
            .children(error.map(|error| div().text_sm().text_color(cx.theme().danger).child(error)))
    }

    fn paired_rows(paired: Vec<AnyElement>) -> Vec<Div> {
        paired
            .into_iter()
            .map(|button| h_flex().w_full().py_2().child(button))
            .collect()
    }

    fn diagnostics(&self, cx: &mut Context<Self>) -> Div {
        let crash_reports = Self::crash_reports_row(cx);
        let export = self.export_button(cx);
        v_flex()
            .gap_3()
            .py_4()
            .child(div().font_semibold().child("Crash reports and logs"))
            .children(Self::diagnostics_text().map(|text| Self::note(text, cx)))
            .child(
                Self::list([crash_reports], cx)
                    .border_t_1()
                    .border_b_1()
                    .border_color(cx.theme().border),
            )
            .child(
                h_flex()
                    .gap_3()
                    .items_center()
                    .child(export)
                    .child(Self::report_button(cx))
                    .children(self.export_status(cx)),
            )
    }

    fn browsers(browsers: Browsers, cx: &App) -> Div {
        v_flex()
            .pb_4()
            .gap_3()
            .child(Self::list(Self::browser_rows(browsers.rows, cx), cx))
            .child(Self::browser_notes(browsers.notes, browsers.error, cx))
            .when(!browsers.paired.is_empty(), |panel| {
                panel
                    .child(
                        div()
                            .pt_3()
                            .font_semibold()
                            .child("Paired browser profiles"),
                    )
                    .child(Self::list(Self::paired_rows(browsers.paired), cx))
            })
    }

    pub(crate) fn page(&mut self, browsers: Option<Browsers>, cx: &mut Context<Self>) -> Div {
        let sections: Vec<(Section, &'static str)> = [
            (Section::Appearance, "Appearance"),
            (Section::Security, "Security"),
        ]
        .into_iter()
        .chain(
            browsers
                .is_some()
                .then_some((Section::Browsers, "Browser extensions")),
        )
        .chain([(Section::Diagnostics, "Diagnostics")])
        .collect();
        let selected = sections
            .iter()
            .position(|(section, _)| *section == self.section)
            .unwrap_or_default();
        let content = match sections[selected].0 {
            Section::Appearance => v_flex()
                .pb_4()
                .gap_2()
                .child(Self::list(self.appearance_rows(cx), cx))
                .child(h_flex().child(Self::reset_button(cx))),
            Section::Security => v_flex()
                .pb_4()
                .gap_2()
                .child(Self::list(self.security_rows(), cx))
                .child(Self::note(
                    "Applies the next time you unlock the vault.",
                    cx,
                )),
            Section::Browsers => browsers.map_or_else(div, |browsers| Self::browsers(browsers, cx)),
            Section::Diagnostics => self.diagnostics(cx),
        };
        let theme = cx.theme().clone();
        let tabs = h_flex()
            .id("settings-tabs")
            .self_start()
            .p_1()
            .gap_1()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.background)
            .children(
                sections
                    .iter()
                    .enumerate()
                    .map(|(index, (section, label))| {
                        let section = *section;
                        Button::new(*label)
                            .ghost()
                            .icon(section.icon())
                            .label(*label)
                            .when(index == selected, |tab| {
                                tab.bg(theme.secondary_active).text_color(theme.foreground)
                            })
                            .when(index != selected, |tab| {
                                tab.text_color(theme.muted_foreground)
                            })
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.section = section;
                                view.error = None;
                                cx.notify();
                            }))
                    }),
            );
        let theme = cx.theme();
        h_flex().w_full().justify_center().child(
            v_flex()
                .w_full()
                .max_w(rems(760. / 16.))
                .gap_5()
                .child(tabs)
                .child(
                    v_flex()
                        .w_full()
                        .rounded_xl()
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.popover)
                        .px_6()
                        .py_2()
                        .child(content),
                )
                .when_some(self.error, |page, error| {
                    page.child(div().text_color(theme.danger).child(error))
                }),
        )
    }

    fn export_diagnostics(&mut self, cx: &mut Context<Self>) {
        self.export_busy = true;
        self.export_complete = false;
        self.error = None;
        cx.notify();
        cx.spawn(async move |view, cx| {
            let chosen = rfd::AsyncFileDialog::new()
                .add_filter("Diagnostic report", &["json"])
                .set_file_name("factorseal-diagnostics.json")
                .save_file()
                .await;
            let result = if let Some(chosen) = chosen {
                let path = chosen.path().to_owned();
                Some(smol::unblock(move || factorseal::diagnostics::export(&path)).await)
            } else {
                None
            };
            let _ = view.update(cx, |view, cx| {
                view.export_busy = false;
                match result {
                    Some(Ok(())) => view.export_complete = true,
                    Some(Err(_)) => view.error = Some("Could not export diagnostics. Choose a writable location and try again."),
                    None => {}
                }
                cx.notify();
            });
        }).detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resetting_appearance_keeps_other_settings() {
        let settings = DesktopSettings {
            device_name: Some("laptop".into()),
            theme: Choice::all()
                .find(|choice| *choice != Choice::default())
                .unwrap(),
            ui_scale: 150,
            text_size: Some(18),
            font: Some("Inter".into()),
            reduced_motion: true,
            automatic_crash_reports: false,
            idle_seconds: 60,
            maximum_seconds: 900,
        };
        assert_eq!(
            SettingsView::default_appearance(&settings),
            DesktopSettings {
                device_name: Some("laptop".into()),
                automatic_crash_reports: false,
                idle_seconds: 60,
                maximum_seconds: 900,
                ..DesktopSettings::default()
            }
        );
    }
}
