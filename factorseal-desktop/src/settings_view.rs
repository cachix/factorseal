use gpui::{
    App, Context, Div, Entity, Render, SharedString, Subscription, Window, div, prelude::*, px,
    rems,
};
use gpui_component::{
    ActiveTheme as _, IndexPath, Selectable as _, StyledExt as _,
    button::Button,
    h_flex,
    select::{Select, SelectEvent, SelectItem, SelectState},
    switch::Switch,
    v_flex,
};

use crate::{
    appearance::{self, Choice},
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

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Appearance,
    Security,
}

pub(crate) struct SettingsView {
    section: Section,
    controls: Vec<Control>,
    error: Option<&'static str>,
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
            _subscriptions: subscriptions,
        }
    }

    fn save(&mut self, settings: DesktopSettings, window: &mut Window, cx: &mut Context<Self>) {
        self.error = if settings.idle_seconds > settings.maximum_seconds {
            Some("Idle lock timeout must not exceed maximum unlock duration.")
        } else if let Err(error) = appearance::update(settings, cx) {
            eprintln!("could not save desktop settings: {error:#}");
            Some("Could not save settings.")
        } else {
            None
        };
        if self.error.is_some() {
            for (control, value) in self.controls.iter().zip(values(appearance::current(cx))) {
                control.update(cx, |control, cx| {
                    control.set_selected_value(&value, window, cx);
                });
            }
        }
        cx.notify();
    }

    fn row(&self, label: &'static str, index: usize, cx: &App) -> Div {
        h_flex()
            .w_full()
            .items_center()
            .justify_between()
            .flex_wrap()
            .gap_3()
            .py_4()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(div().font_medium().child(label))
            .child(
                div().w(rems(18.)).max_w_full().flex_none().p_1().child(
                    Select::new(&self.controls[index])
                        .accessibility_label(label)
                        .search_placeholder(label)
                        .w_full(),
                ),
            )
    }

    fn appearance(&self, cx: &mut Context<Self>) -> Div {
        v_flex()
            .w_full()
            .child(self.row("Theme", 0, cx))
            .child(self.row("UI scale", 1, cx))
            .child(self.row("Text size", 2, cx))
            .child(self.row("Font", 3, cx))
            .child(
                h_flex()
                    .w_full()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .py_4()
                    .child("Reduced motion")
                    .child(
                        Switch::new("reduced-motion")
                            .accessibility_label("Reduced motion")
                            .checked(appearance::current(cx).reduced_motion)
                            .on_click(cx.listener(|view, checked: &bool, window, cx| {
                                let mut settings = appearance::current(cx).clone();
                                settings.reduced_motion = *checked;
                                view.save(settings, window, cx);
                            })),
                    ),
            )
    }

    fn security(&self, cx: &App) -> Div {
        v_flex()
            .w_full()
            .gap_2()
            .child(self.row("Idle lock timeout", 4, cx))
            .child(self.row("Maximum unlock duration", 5, cx))
            .child(
                div()
                    .pt_3()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child("Applies the next time you unlock the vault."),
            )
    }
}

impl Render for SettingsView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let compact = window.viewport_size().width < px(900.) * appearance::scale(cx);
        let section = self.section;
        let content = if section == Section::Appearance {
            self.appearance(cx)
        } else {
            self.security(cx)
        };
        let theme = cx.theme();
        h_flex()
            .w_full()
            .min_w_0()
            .gap_6()
            .items_start()
            .when(compact, gpui::Styled::flex_col)
            .child(
                v_flex()
                    .w(rems(12.))
                    .flex_none()
                    .gap_2()
                    .p_4()
                    .rounded_lg()
                    .bg(theme.sidebar)
                    .when(compact, gpui::Styled::w_full)
                    .child(
                        h_flex()
                            .gap_2()
                            .items_center()
                            .mb_3()
                            .child(
                                gpui_component::Icon::new(gpui_component::IconName::Settings)
                                    .text_color(theme.foreground),
                            )
                            .child(div().text_lg().font_semibold().child("Settings")),
                    )
                    .children(
                        [
                            (
                                Section::Appearance,
                                "Appearance",
                                gpui_component::Icon::new(gpui_component::IconName::Palette),
                            ),
                            (
                                Section::Security,
                                "Security",
                                gpui_component::Icon::default()
                                    .path(crate::branding::MICRO_MARK_ASSET),
                            ),
                        ]
                        .into_iter()
                        .map(|(section, label, icon)| {
                            Button::new(label)
                                .icon(icon.text_color(theme.foreground))
                                .justify_start()
                                .label(label)
                                .w_full()
                                .selected(self.section == section)
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.section = section;
                                    view.error = None;
                                    cx.notify();
                                }))
                        }),
                    ),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .w_full()
                    .gap_4()
                    .py_4()
                    .child(div().text_2xl().font_semibold().child(
                        if section == Section::Appearance {
                            "Appearance"
                        } else {
                            "Security"
                        },
                    ))
                    .child(content)
                    .when_some(self.error, |view, error| {
                        view.child(div().text_color(theme.danger).child(error))
                    }),
            )
    }
}
