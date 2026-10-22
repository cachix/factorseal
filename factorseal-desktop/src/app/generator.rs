use gpui::{AnyElement, EventEmitter, Pixels, Subscription, anchored, canvas, deferred, point};
use gpui_component::{
    ThemeStyled as _,
    slider::{Slider, SliderEvent, SliderState},
    switch::Switch,
};

use super::*;
use crate::password_generator::{
    LENGTHS, Options, Strength, Style, WORD_COUNTS, WORD_STEP, generate,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum GeneratorTarget {
    Field(usize),
}

#[derive(Default)]
pub(super) struct GeneratorAnchor {
    row: Rc<Cell<Option<Bounds<Pixels>>>>,
    button: Rc<Cell<Option<Bounds<Pixels>>>>,
}

fn measure(bounds: &Rc<Cell<Option<Bounds<Pixels>>>>) -> impl IntoElement {
    let bounds = Rc::clone(bounds);
    canvas(
        move |measured, window, _| {
            if bounds.replace(Some(measured)) != Some(measured) {
                window.refresh();
            }
        },
        |_, (), _, _| {},
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full()
}

pub(super) struct UsePassword(pub(super) Zeroizing<String>);

pub(super) struct PasswordGenerator {
    options: Options,
    length: gpui::Entity<SliderState>,
    words: gpui::Entity<SliderState>,
    preview: Option<(Zeroizing<String>, Strength)>,
    shown: gpui::Entity<SecretInputState>,
    revealed: bool,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<UsePassword> for PasswordGenerator {}

fn closest(range: std::ops::RangeInclusive<u8>, step: u8, value: f32) -> u8 {
    range
        .step_by(usize::from(step))
        .min_by(|a, b| {
            (f32::from(*a) - value)
                .abs()
                .total_cmp(&(f32::from(*b) - value).abs())
        })
        .unwrap_or_default()
}

pub(super) fn strength_meter(strength: Strength, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    let color = match strength {
        Strength::Weak => theme.danger,
        Strength::Good => theme.warning,
        Strength::Strong => theme.success,
    };
    h_flex()
        .gap_2()
        .items_center()
        .child(h_flex().flex_1().gap_1().children((0..3).map(|level| {
            div()
                .id(("strength-level", level))
                .transitions(|transitions| transitions.bg(crate::motion::change()))
                .flex_1()
                .h_1()
                .rounded_full()
                .bg(if level < strength.level() {
                    color
                } else {
                    theme.muted
                })
        })))
        .child(
            div()
                .w(rems(3.5))
                .text_body()
                .text_color(theme.muted_foreground)
                .child(strength.label()),
        )
}

impl PasswordGenerator {
    pub(super) fn new(cx: &mut Context<Self>) -> Self {
        let options = crate::appearance::current(cx).generator;
        let length = cx.new(|_| {
            SliderState::new()
                .min(f32::from(*LENGTHS.start()))
                .max(f32::from(*LENGTHS.end()))
                .step(1.)
                .default_value(f32::from(options.length))
        });
        let words = cx.new(|_| {
            SliderState::new()
                .min(f32::from(*WORD_COUNTS.start()))
                .max(f32::from(*WORD_COUNTS.end()))
                .step(f32::from(WORD_STEP))
                .default_value(f32::from(options.words))
        });
        let subscriptions = vec![
            cx.subscribe(&length, |view, _, event: &SliderEvent, cx| {
                if let SliderEvent::Change(value) = event {
                    let length = closest(LENGTHS, 1, value.start());
                    if view.options.length != length {
                        view.options.length = length;
                        view.refresh(cx);
                    }
                }
            }),
            cx.subscribe(&words, |view, _, event: &SliderEvent, cx| {
                if let SliderEvent::Change(value) = event {
                    let words = closest(WORD_COUNTS, WORD_STEP, value.start());
                    if view.options.words != words {
                        view.options.words = words;
                        view.refresh(cx);
                    }
                }
            }),
        ];
        let mut view = Self {
            options,
            length,
            words,
            preview: None,
            shown: cx.new(SecretInputState::read_only),
            revealed: false,
            _subscriptions: subscriptions,
        };
        view.refresh(cx);
        view
    }

    pub(super) fn refresh(&mut self, cx: &mut Context<Self>) {
        let strength = self.options.strength();
        self.preview = generate(self.options)
            .ok()
            .map(|password| (password, strength));
        let password = self
            .preview
            .as_ref()
            .map_or("", |(password, _)| password.as_str());
        self.shown
            .update(cx, |shown, cx| shown.replace(password, cx));
        cx.notify();
    }

    fn forget(&mut self, cx: &mut Context<Self>) {
        self.preview = None;
        self.shown.update(cx, SecretInputState::clear);
        self.reveal(false, cx);
    }

    fn reveal(&mut self, revealed: bool, cx: &mut Context<Self>) {
        self.revealed = revealed;
        self.shown
            .update(cx, |shown, cx| shown.set_masked(!revealed, cx));
        cx.notify();
    }

    fn update_options(&mut self, update: impl FnOnce(&mut Options), cx: &mut Context<Self>) {
        update(&mut self.options);
        self.refresh(cx);
    }

    fn use_password(&mut self, cx: &mut Context<Self>) {
        let Some((password, _)) = &self.preview else {
            return;
        };
        let options = self.options;
        crate::appearance::remember(|settings| settings.generator = options, cx);
        cx.emit(UsePassword(password.clone()));
    }

    fn switch_row(
        id: &'static str,
        label: &'static str,
        checked: bool,
        cx: &mut Context<Self>,
        update: fn(&mut Options, bool),
    ) -> impl IntoElement {
        h_flex()
            .justify_between()
            .items_center()
            .child(label)
            .child(crate::controls::toggle_frame(
                format!("{id}-frame"),
                Switch::new(id)
                    .accessibility_label(label)
                    .checked(checked)
                    .on_click(cx.listener(move |view, checked: &bool, _, cx| {
                        let checked = *checked;
                        view.update_options(|options| update(options, checked), cx);
                    })),
            ))
    }

    fn size_row(&self, cx: &App) -> impl IntoElement {
        let random = self.options.style == Style::Random;
        v_flex()
            .gap_1()
            .child(
                h_flex()
                    .justify_between()
                    .child(if random { "Length" } else { "Words" })
                    .child(
                        div().text_color(cx.theme().muted_foreground).child(
                            if random {
                                self.options.length
                            } else {
                                self.options.words
                            }
                            .to_string(),
                        ),
                    ),
            )
            .child(
                div()
                    .px_2()
                    .child(Slider::new(if random { &self.length } else { &self.words })),
            )
    }
}

impl Render for PasswordGenerator {
    #[allow(clippy::too_many_lines)]
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let random = self.options.style == Style::Random;
        let mut styles = h_flex().gap_1();
        for (style, id, label) in [
            (Style::Random, "generator-random", "Random"),
            (Style::Words, "generator-words", "Words"),
        ] {
            styles = styles.child(
                button(id)
                    .label(label)
                    .selected(self.options.style == style)
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.update_options(|options| options.style = style, cx);
                    })),
            );
        }
        v_flex()
            .w(rems(22.))
            .gap_3()
            .child(styles)
            .child(
                h_flex()
                    .items_start()
                    .gap_2()
                    .child(
                        div()
                            .id("generated-password")
                            .flex_1()
                            .min_w_0()
                            .h(rems(5.75))
                            .overflow_y_scroll()
                            .rounded_md()
                            .bg(theme.muted)
                            .font_family(theme.mono_font_family.clone())
                            .text_body()
                            .map(|preview| {
                                if self.preview.is_some() {
                                    preview.child(self.shown.clone())
                                } else {
                                    preview
                                        .px_3()
                                        .py_2()
                                        .child("Could not generate a password. Please try again.")
                                }
                            }),
                    )
                    .child(
                        button("reveal-generated-password")
                            .ghost()
                            .icon(if self.revealed {
                                IconName::EyeOff
                            } else {
                                IconName::Eye
                            })
                            .tooltip(if self.revealed {
                                "Hide password"
                            } else {
                                "Show password"
                            })
                            .accessibility_label(if self.revealed {
                                "Hide password"
                            } else {
                                "Show password"
                            })
                            .on_click(cx.listener(|view, _, _, cx| {
                                view.reveal(!view.revealed, cx);
                            })),
                    )
                    .child(
                        button("regenerate-password")
                            .ghost()
                            .icon(IconName::Redo)
                            .tooltip("Generate another")
                            .accessibility_label("Generate another")
                            .on_click(cx.listener(|view, _, _, cx| view.refresh(cx))),
                    ),
            )
            .when_some(self.preview.as_ref(), |panel, (_, strength)| {
                panel.child(strength_meter(*strength, cx))
            })
            .child(
                v_flex()
                    .gap_3()
                    .child(self.size_row(cx))
                    .when(random, |options| {
                        options
                            .child(Self::switch_row(
                                "generator-digits",
                                "Digits",
                                self.options.digits,
                                cx,
                                |options, checked| options.digits = checked,
                            ))
                            .child(Self::switch_row(
                                "generator-symbols",
                                "Symbols",
                                self.options.symbols,
                                cx,
                                |options, checked| options.symbols = checked,
                            ))
                    }),
            )
            .child(
                h_flex().justify_end().child(
                    button("use-generated-password")
                        .primary()
                        .label("Use password")
                        .disabled(self.preview.is_none())
                        .on_click(cx.listener(|view, _, _, cx| view.use_password(cx))),
                ),
            )
    }
}

impl DesktopView {
    pub(super) fn render_generator(
        &self,
        target: GeneratorTarget,
        icon_only: bool,
        style: impl FnOnce(Button) -> Button,
        cx: &Context<Self>,
    ) -> Vec<AnyElement> {
        let GeneratorTarget::Field(key) = target;
        let (id, tooltip) = (("generate-field-password", key), "Generate a password");
        let open = self.generator_target == Some(target);
        let panel = open
            .then(|| self.generator_anchor.row.get())
            .flatten()
            .map(|row| {
                deferred(
                    anchored()
                        .anchor(gpui::Anchor::TopRight)
                        .position(row.top_right())
                        .offset(point(px(0.), row.size.height))
                        .child(self.render_generator_panel(cx)),
                )
                .priority(1)
            });
        let trigger = div()
            .flex_none()
            .when(open, |trigger| {
                trigger
                    .track_focus(&self.generator_focus)
                    .on_key_down(cx.listener(|view, event: &gpui::KeyDownEvent, _, cx| {
                        if event.keystroke.key == "escape" {
                            cx.stop_propagation();
                            view.close_generator(cx);
                        }
                    }))
            })
            .child(style(
                button(id)
                    .icon(Glyph::Generate)
                    .when(!icon_only, |button| button.label("Generate"))
                    .tooltip(tooltip)
                    .accessibility_label(tooltip)
                    .on_click(cx.listener(move |view, _, window, cx| {
                        view.toggle_generator(target, window, cx);
                    })),
            ))
            .when(open, |trigger| {
                trigger.child(measure(&self.generator_anchor.button))
            })
            .children(panel);
        let mut elements = vec![trigger.into_any_element()];
        if open {
            elements.push(measure(&self.generator_anchor.row).into_any_element());
        }
        elements
    }

    fn render_generator_panel(&self, cx: &Context<Self>) -> impl IntoElement {
        crate::motion::enter("password-generator-panel", div().relative().py_1()).child(
            div()
                .id("password-generator")
                .occlude()
                .popover_style(cx)
                .p_3()
                .on_mouse_down_out(cx.listener(|view, event: &gpui::MouseDownEvent, _, cx| {
                    if !view
                        .generator_anchor
                        .button
                        .get()
                        .is_some_and(|button| button.contains(&event.position))
                    {
                        view.close_generator(cx);
                    }
                }))
                .child(self.generator.clone()),
        )
    }

    fn toggle_generator(
        &mut self,
        target: GeneratorTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.generator_target == Some(target) {
            self.close_generator(cx);
            return;
        }
        self.generator_target = Some(target);
        self.generator_anchor.row.set(None);
        self.generator_anchor.button.set(None);
        self.generator.update(cx, PasswordGenerator::refresh);
        window.focus(&self.generator_focus, cx);
        cx.notify();
    }

    pub(super) fn close_generator(&mut self, cx: &mut Context<Self>) {
        self.generator_target = None;
        self.generator.update(cx, PasswordGenerator::forget);
        cx.notify();
    }

    pub(super) fn use_generated_password(
        &mut self,
        password: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let target = self.generator_target;
        self.close_generator(cx);
        if let Some(GeneratorTarget::Field(key)) = target {
            self.use_generated_editor_value(key, password, window, cx);
        }
        cx.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slider_values_snap_to_supported_steps() {
        assert_eq!(closest(LENGTHS, 1, 7.2), 8);
        assert_eq!(closest(LENGTHS, 1, 20.4), 20);
        assert_eq!(closest(LENGTHS, 1, 99.), 64);
        assert_eq!(closest(WORD_COUNTS, WORD_STEP, 16.), 15);
        assert_eq!(closest(WORD_COUNTS, WORD_STEP, 17.), 18);
        assert_eq!(closest(WORD_COUNTS, WORD_STEP, 30.), 24);
    }
}
