use gpui::{
    AnyElement, App, ElementId, Hsla, InteractiveElement, IntoElement, ParentElement, RenderOnce,
    StatefulInteractiveElement, Styled, Window, div, prelude::FluentBuilder, px,
};
use gpui_component::{ActiveTheme as _, ThemeStyled as _};

pub(crate) fn text_field<T>(element: T, focused: bool, window: &Window, cx: &App) -> T
where
    T: Styled + InteractiveElement + ParentElement + FluentBuilder,
{
    let hover = field_border(true, cx);
    element
        .border_1()
        .border_color(field_border(false, cx))
        .cursor_text()
        .when(focused, |this| this.focus_ring_style(window, cx))
        .when(!focused, |this| {
            this.hover(|style| style.border_color(hover))
        })
}

pub(crate) trait ClickStyle:
    StatefulInteractiveElement + Styled + FluentBuilder + Sized
{
    fn fill_control(self, selected: bool, cx: &App) -> Self {
        let theme = cx.theme();
        let (hover, active) = (theme.secondary_hover, theme.secondary_active);
        let (ring, inner) = (theme.ring, theme.primary_foreground);
        self.cursor_pointer()
            .tab_index(0)
            .focus_visible(move |style| {
                if selected {
                    style
                        .ring(FOCUS_RING)
                        .ring_color(ring)
                        .inset_ring(FOCUS_RING)
                        .inset_ring_color(inner)
                } else {
                    style.inset_ring(FOCUS_RING).inset_ring_color(ring)
                }
            })
            .when(!selected, |this| {
                this.hover(|style| style.bg(hover))
                    .active(|style| style.bg(active))
            })
    }

    fn keyboard_cursor(self, selected: bool, cx: &App) -> Self {
        let theme = cx.theme();
        let (hover, ring, inner) = (theme.secondary_hover, theme.ring, theme.primary_foreground);
        if selected {
            self.ring(FOCUS_RING)
                .ring_color(ring)
                .inset_ring(FOCUS_RING)
                .inset_ring_color(inner)
        } else {
            self.bg(hover).inset_ring(FOCUS_RING).inset_ring_color(ring)
        }
    }

    fn text_focus(self, cx: &App) -> Self {
        focus_states(self, cx).px_1().mx(px(-4.))
    }

    fn text_control(self, cx: &App) -> Self {
        let hover = cx.theme().muted_foreground;
        self.text_focus(cx)
            .hover(|style| style.text_color(hover))
            .active(|style| style.opacity(0.7))
    }

    fn quiet_text_control(self, cx: &App) -> Self {
        let hover = cx.theme().foreground;
        focus_states(self, cx)
            .hover(|style| style.text_color(hover))
            .active(|style| style.opacity(0.7))
    }
}

impl<T: StatefulInteractiveElement + Styled + FluentBuilder + Sized> ClickStyle for T {}

fn focus_states<T: ClickStyle>(element: T, cx: &App) -> T {
    let ring = cx.theme().ring;
    element
        .cursor_pointer()
        .tab_index(0)
        .rounded_sm()
        .focus_visible(|style| style.inset_ring(FOCUS_RING).inset_ring_color(ring))
}

const FOCUS_RING: gpui::Pixels = px(2.);

fn field_border(hovered: bool, cx: &App) -> Hsla {
    if hovered {
        cx.theme().muted_foreground
    } else {
        cx.theme().input
    }
}

#[derive(IntoElement)]
pub(crate) struct HoverField {
    id: ElementId,
    build: Box<dyn FnOnce(Hsla) -> AnyElement>,
}

pub(crate) fn hover_field(
    id: impl Into<ElementId>,
    field: impl Styled + IntoElement + 'static,
) -> HoverField {
    HoverField {
        id: id.into(),
        build: Box::new(move |border| field.border_color(border).into_any_element()),
    }
}

impl RenderOnce for HoverField {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let hovered = window.use_keyed_state(self.id.clone(), cx, |_, _| false);
        let border = field_border(*hovered.read(cx), cx);
        div()
            .id(self.id)
            .w_full()
            .on_hover(move |is_hovered, _, cx| {
                hovered.update(cx, |hovered, cx| {
                    if *hovered != *is_hovered {
                        *hovered = *is_hovered;
                        cx.notify();
                    }
                });
            })
            .child((self.build)(border))
    }
}

#[derive(IntoElement)]
pub(crate) struct ToggleFrame {
    id: ElementId,
    child: AnyElement,
    disabled: bool,
    focus_ring: bool,
}

pub(crate) fn toggle_frame(id: impl Into<ElementId>, child: impl IntoElement) -> ToggleFrame {
    ToggleFrame {
        id: id.into(),
        child: child.into_any_element(),
        disabled: false,
        focus_ring: true,
    }
}

impl ToggleFrame {
    pub(crate) fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    pub(crate) fn without_focus_ring(mut self) -> Self {
        self.focus_ring = false;
        self
    }
}

impl RenderOnce for ToggleFrame {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        let focus = window
            .use_keyed_state(self.id.clone(), cx, |_, cx| cx.focus_handle())
            .read(cx)
            .clone();
        let focus_visible = self.focus_ring
            && window.last_input_was_keyboard()
            && focus.contains_focused(window, cx);
        let theme = cx.theme();
        let (hover, ring) = (theme.secondary_hover, theme.ring);
        div()
            .id(self.id)
            .track_focus(&focus)
            .p_1()
            .m(px(-4.))
            .rounded(theme.radius)
            .when(!self.disabled, |this| this.hover(|style| style.bg(hover)))
            .when(focus_visible, |this| {
                this.inset_ring(FOCUS_RING).inset_ring_color(ring)
            })
            .child(self.child)
    }
}
