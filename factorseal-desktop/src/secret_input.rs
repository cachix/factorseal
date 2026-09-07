//! Protected input without editor ropes or undo history.
//! Masked by default. Ordinary personal fields can opt into visible text;
//! secret fields never send plaintext to the renderer or text-query callbacks.

use factorseal::security::LockedBytes;
use gpui::{
    App, Bounds, Context, ElementInputHandler, EntityInputHandler, EventEmitter, FocusHandle,
    Focusable, KeyDownEvent, MouseButton, Pixels, Point, SharedString, TextRun, UTF16Selection,
    Window, canvas, div, prelude::*, px,
};
use gpui_component::{ActiveTheme as _, input::InputEvent};
use std::ops::{Deref, Range};
use zeroize::Zeroizing;

fn rendered_text(value: &str, masked: bool) -> String {
    if masked {
        "•".repeat(value.chars().count())
    } else {
        value.to_owned()
    }
}

fn queried_text(value: &str, masked: bool) -> String {
    if masked {
        "*".repeat(value.encode_utf16().count())
    } else {
        value.to_owned()
    }
}

fn rendered_index(value: &str, index: usize, masked: bool) -> usize {
    if masked {
        value[..index].chars().count() * "•".len()
    } else {
        index
    }
}

const MAX_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct LockedText(LockedBytes);
impl Deref for LockedText {
    type Target = str;
    fn deref(&self) -> &str {
        std::str::from_utf8(&self.0).expect("secret edits preserve valid UTF-8")
    }
}
#[derive(Default)]
struct SecretBuffer {
    text: LockedText,
    allocation_failed: bool,
    multiline: bool,
}
impl SecretBuffer {
    fn replace(&mut self, range: Range<usize>, text: &str) -> bool {
        self.replace_with(range, text, LockedBytes::zeroed)
    }
    fn replace_with(
        &mut self,
        range: Range<usize>,
        text: &str,
        allocate: impl FnOnce(usize) -> factorseal::VaultResult<LockedBytes>,
    ) -> bool {
        if range.start > range.end
            || range.end > self.text.len()
            || !self.text.is_char_boundary(range.start)
            || !self.text.is_char_boundary(range.end)
            || self.text.len() - range.len() + text.len() > MAX_BYTES
            || (!self.multiline && text.contains(['\n', '\r']))
        {
            return false;
        }
        // Allocate and lock before copying; the superseded mapping wipes on drop.
        let Ok(mut next) = allocate(self.text.len() - range.len() + text.len()) else {
            self.allocation_failed = true;
            return false;
        };
        next[..range.start].copy_from_slice(self.text[..range.start].as_bytes());
        next[range.start..range.start + text.len()].copy_from_slice(text.as_bytes());
        next[range.start + text.len()..].copy_from_slice(self.text[range.end..].as_bytes());
        self.text = LockedText(next);
        self.allocation_failed = false;
        true
    }
    fn byte_offset(&self, offset: usize) -> usize {
        let mut count = 0;
        for (index, ch) in self.text.char_indices() {
            if count >= offset {
                return index;
            }
            count += ch.len_utf16();
        }
        self.text.len()
    }
    fn utf16_offset(&self, offset: usize) -> usize {
        self.text[..offset].encode_utf16().count()
    }
}

pub(crate) struct SecretInputState {
    secret: SecretBuffer,
    masked: bool,
    focus: FocusHandle,
    placeholder: SharedString,
    selection: Range<usize>,
    marked: Option<Range<usize>>,
    reversed: bool,
    last_layout: Option<(gpui::ShapedLine, Point<Pixels>)>,
}
impl EventEmitter<InputEvent> for SecretInputState {}
impl Focusable for SecretInputState {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}
impl SecretInputState {
    pub(crate) fn masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }
    pub(crate) fn set_masked(&mut self, masked: bool, cx: &mut Context<Self>) {
        self.masked = masked;
        self.last_layout = None;
        self.marked = None;
        cx.notify();
    }
    /// Allow multiline values in the same bounded, locked storage.
    pub(crate) fn multiline(mut self) -> Self {
        self.secret.multiline = true;
        self
    }
    pub(crate) fn new(_window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::empty(cx)
    }
    fn empty(cx: &mut Context<Self>) -> Self {
        Self {
            secret: SecretBuffer::default(),
            masked: true,
            focus: cx.focus_handle(),
            placeholder: "".into(),
            selection: 0..0,
            marked: None,
            reversed: false,
            last_layout: None,
        }
    }
    pub(crate) fn from_value(value: &str, masked: bool, cx: &mut Context<Self>) -> Self {
        let mut input = Self::empty(cx).multiline().masked(masked);
        if !input.secret.replace(0..0, value) {
            input.secret.allocation_failed = true;
        }
        input.selection = input.secret.text.len()..input.secret.text.len();
        input
    }
    pub(crate) fn placeholder(mut self, value: &'static str) -> Self {
        self.placeholder = value.into();
        self
    }
    pub(crate) fn value(&self) -> Zeroizing<String> {
        Zeroizing::new(if self.secret.allocation_failed {
            String::new()
        } else {
            self.secret.text.to_string()
        })
    }
    pub(crate) fn allocation_failed(&self) -> bool {
        self.secret.allocation_failed
    }
    pub(crate) fn clear(&mut self, cx: &mut Context<Self>) {
        self.secret = SecretBuffer {
            multiline: self.secret.multiline,
            ..SecretBuffer::default()
        };
        self.selection = 0..0;
        self.reversed = false;
        self.last_layout = None;
        self.marked = None;
        cx.notify();
    }
    pub(crate) fn set_value(&mut self, value: &str, _: &mut Window, cx: &mut Context<Self>) {
        self.clear(cx);
        self.secret.replace(0..0, value);
        let end = self.secret.text.len();
        self.selection = end..end;
        self.reversed = false;
    }
    pub(crate) fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus, cx);
    }
    fn range_byte_offset(&self, range: Range<usize>) -> Range<usize> {
        self.secret.byte_offset(range.start)..self.secret.byte_offset(range.end)
    }
    fn byte_index_for_point(&self, point: Point<Pixels>) -> usize {
        let Some((line, origin)) = &self.last_layout else {
            return self.secret.text.len();
        };
        let index = line.closest_index_for_x(point.x - origin.x);
        if !self.masked {
            return index.min(self.secret.text.len());
        }
        let index = index / "•".len();
        self.secret
            .text
            .char_indices()
            .nth(index)
            .map_or(self.secret.text.len(), |(i, _)| i)
    }
    fn key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        let modifiers = event.keystroke.modifiers;
        let command = if cfg!(target_os = "macos") {
            modifiers.platform
        } else {
            modifiers.control
        };
        match key {
            "escape" => self.clear(cx),
            "enter" if self.secret.multiline => {
                let range = self.selection.clone();
                if self.secret.replace(range.clone(), "\n") {
                    self.selection = range.start + 1..range.start + 1;
                    cx.notify();
                }
            }
            "enter" => cx.emit(InputEvent::PressEnter {
                secondary: false,
                shift: modifiers.shift,
            }),
            "a" if command => {
                self.selection = 0..self.secret.text.len();
                self.reversed = false;
                cx.notify();
            }
            "v" if command => {
                if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
                    let text = Zeroizing::new(text);
                    self.replace_text_in_range(None, &text, window, cx);
                }
            }
            // Secret inputs deliberately have no copy/cut or undo/redo export path.
            "c" | "x" | "z" | "y" if command => {}
            "backspace" | "delete" => {
                if self.selection.is_empty() {
                    if key == "backspace" {
                        self.selection.start = self.secret.text[..self.selection.start]
                            .char_indices()
                            .next_back()
                            .map_or(0, |(i, _)| i);
                    } else if let Some(ch) = self.secret.text[self.selection.end..].chars().next() {
                        self.selection.end += ch.len_utf8();
                    }
                }
                self.replace_text_in_range(None, "", window, cx);
            }
            "left" | "right" | "home" | "end" => {
                let end = if self.reversed {
                    self.selection.start
                } else {
                    self.selection.end
                };
                let anchor = if self.reversed {
                    self.selection.end
                } else {
                    self.selection.start
                };
                let next = match key {
                    "home" => 0,
                    "end" => self.secret.text.len(),
                    "left" if !modifiers.shift && !self.selection.is_empty() => {
                        self.selection.start
                    }
                    "right" if !modifiers.shift && !self.selection.is_empty() => self.selection.end,
                    "left" => self.secret.text[..end]
                        .char_indices()
                        .next_back()
                        .map_or(0, |(i, _)| i),
                    _ => {
                        end + self.secret.text[end..]
                            .chars()
                            .next()
                            .map_or(0, char::len_utf8)
                    }
                };
                self.selection = if modifiers.shift {
                    anchor.min(next)..anchor.max(next)
                } else {
                    next..next
                };
                self.reversed = modifiers.shift && next < anchor;
                self.marked = None;
                cx.notify();
            }
            _ => return,
        }
        cx.stop_propagation();
    }
}

impl EntityInputHandler for SecretInputState {
    fn text_for_range(
        &mut self,
        range: Range<usize>,
        actual: &mut Option<Range<usize>>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<String> {
        let range = self.range_byte_offset(range);
        *actual = Some(self.secret.utf16_offset(range.start)..self.secret.utf16_offset(range.end));
        Some(queried_text(&self.secret.text[range], self.masked))
    }
    fn selected_text_range(
        &mut self,
        _: bool,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.secret.utf16_offset(self.selection.start)
                ..self.secret.utf16_offset(self.selection.end),
            reversed: self.reversed,
        })
    }
    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked
            .as_ref()
            .map(|r| self.secret.utf16_offset(r.start)..self.secret.utf16_offset(r.end))
    }
    fn unmark_text(&mut self, _: &mut Window, _: &mut Context<Self>) {
        self.marked = None;
    }
    fn replace_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range
            .map(|r| self.range_byte_offset(r))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        let end = range.start + text.len();
        if self.secret.replace(range, text) {
            self.selection = end..end;
            self.reversed = false;
            self.marked = None;
            cx.emit(InputEvent::Change);
        }
        cx.notify();
    }
    fn replace_and_mark_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        selected: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range
            .map(|r| self.range_byte_offset(r))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        let start = range.start;
        let utf16_start = self.secret.utf16_offset(start);
        if !self.secret.replace(range, text) {
            cx.notify();
            return;
        }
        self.selection = start + text.len()..start + text.len();
        self.reversed = false;
        self.marked = (!text.is_empty()).then_some(start..start + text.len());
        if let Some(selected) = selected {
            self.selection =
                self.range_byte_offset(utf16_start + selected.start..utf16_start + selected.end);
        }
        cx.emit(InputEvent::Change);
        cx.notify();
    }
    fn bounds_for_range(
        &mut self,
        _: Range<usize>,
        bounds: Bounds<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        Some(bounds)
    }
    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<usize> {
        Some(self.secret.utf16_offset(self.byte_index_for_point(point)))
    }
}

impl Render for SecretInputState {
    #[allow(clippy::too_many_lines)]
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let entity = cx.entity();
        let text: SharedString = if self.secret.text.is_empty() {
            self.placeholder.clone()
        } else {
            rendered_text(&self.secret.text, self.masked).into()
        };
        let color = if self.secret.text.is_empty() {
            cx.theme().muted_foreground
        } else {
            cx.theme().foreground
        };
        let input = div()
            .w_full()
            .h(px(40.))
            .px_3()
            .py_2()
            .overflow_hidden()
            .rounded_md()
            .border_1()
            .border_color(cx.theme().border)
            .bg(crate::theming::input_background(cx))
            .track_focus(&self.focus)
            .key_context("FactorsealSecret")
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, event: &gpui::MouseDownEvent, window, cx| {
                    this.focus(window, cx);
                    let end = this.byte_index_for_point(event.position);
                    this.selection = end..end;
                    this.reversed = false;
                    cx.notify();
                }),
            )
            .child(
                canvas(
                    move |_, window, _| {
                        let style = window.text_style();
                        let run = TextRun {
                            len: text.len(),
                            font: style.font(),
                            color,
                            background_color: None,
                            underline: None,
                            strikethrough: None,
                        };
                        window.text_system().shape_line(text, px(14.), &[run], None)
                    },
                    move |bounds, line, window, cx| {
                        let input = entity.read(cx);
                        let focus = input.focus.clone();
                        let display_index =
                            |index| rendered_index(&input.secret.text, index, input.masked);
                        let selection = display_index(input.selection.start)
                            ..display_index(input.selection.end);
                        let caret = line.x_for_index(if input.reversed {
                            selection.start
                        } else {
                            selection.end
                        });
                        let offset = (caret - bounds.size.width + px(2.)).max(px(0.));
                        let origin = bounds.origin - gpui::point(offset, px(0.));
                        if focus.is_focused(window) {
                            if selection.is_empty() {
                                window.paint_quad(gpui::fill(
                                    Bounds::new(
                                        origin + gpui::point(caret, px(0.)),
                                        gpui::size(px(1.), bounds.size.height),
                                    ),
                                    cx.theme().foreground,
                                ));
                            } else {
                                window.paint_quad(gpui::fill(
                                    Bounds::from_corners(
                                        origin
                                            + gpui::point(
                                                line.x_for_index(selection.start),
                                                px(0.),
                                            ),
                                        origin
                                            + gpui::point(
                                                line.x_for_index(selection.end),
                                                bounds.size.height,
                                            ),
                                    ),
                                    cx.theme().selection,
                                ));
                            }
                        }
                        window.handle_input(
                            &focus,
                            ElementInputHandler::new(bounds, entity.clone()),
                            cx,
                        );
                        let _ = line.paint(
                            origin,
                            bounds.size.height,
                            gpui::TextAlign::Left,
                            None,
                            window,
                            cx,
                        );
                        entity.update(cx, |input, _| input.last_layout = Some((line, origin)));
                    },
                )
                .w_full()
                .h_full(),
            );
        div()
            .w_full()
            .child(input)
            .when(self.secret.allocation_failed, |this| {
                this.child(div().text_xs().child("Unable to secure input memory"))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_and_masked_fields_preserve_unicode_positions_without_leaking_secrets() {
        let value = "aé🔑";
        assert_eq!(rendered_text(value, false), value);
        assert_eq!(queried_text(value, false), value);
        assert_eq!(rendered_index(value, 3, false), 3);
        assert_eq!(rendered_text(value, true), "•••");
        assert_eq!(queried_text(value, true), "****");
        assert_eq!(rendered_index(value, 3, true), 6);
    }

    #[test]
    fn multiline_personal_values_use_the_bounded_secret_buffer() {
        let mut secret = SecretBuffer {
            multiline: true,
            ..SecretBuffer::default()
        };
        assert!(secret.replace(0..0, "-----BEGIN KEY-----\nsecret\n-----END KEY-----\n"));
        assert!(secret.text.ends_with("-----END KEY-----\n"));
        assert!(!secret.replace(0..0, &"x".repeat(MAX_BYTES)));
        assert!(secret.replace(0..secret.text.len(), ""));
        assert!(secret.text.is_empty());
    }
    #[test]
    fn failed_lock_keeps_previous_edit_and_reports_failure_until_recovery() {
        let mut secret = SecretBuffer::default();
        assert!(secret.replace(0..0, "original"));
        assert!(!secret.replace_with(0..8, "replacement", |_| Err(
            factorseal::VaultError::Protection("test lock failure".into())
        )));
        assert_eq!(&*secret.text, "original");
        assert!(secret.allocation_failed);
        assert!(secret.replace(0..8, "recovered"));
        assert!(!secret.allocation_failed);
        assert_eq!(&*secret.text, "recovered");
    }
    #[test]
    fn large_password_edits_and_clear_preserve_utf8() {
        let mut secret = SecretBuffer::default();
        let text = "🔐".repeat(MAX_BYTES / 4);
        assert!(secret.replace(0..0, &text));
        assert_eq!(&*secret.text, text);
        assert!(!secret.replace(0..0, "x"));
        assert_eq!(&*secret.text, text);
        assert!(secret.replace(0..MAX_BYTES, ""));
        assert!(secret.text.is_empty());
    }
    #[test]
    fn bounded_utf8_edits_preserve_only_current_text() {
        let mut secret = SecretBuffer::default();
        assert!(secret.replace(0..0, "a🔐b"));
        assert_eq!(secret.byte_offset(3), 5);
        assert_eq!(secret.utf16_offset(5), 3);
        assert!(!secret.replace(2..3, "x"));
        assert!(secret.replace(1..5, "X"));
        assert_eq!(&*secret.text, "aXb");
        assert!(!secret.replace(0..0, &"x".repeat(MAX_BYTES)));
        assert!(!secret.replace(0..0, "\n"));
        assert!(secret.replace(0..3, ""));
        assert!(secret.text.is_empty());
    }
}
