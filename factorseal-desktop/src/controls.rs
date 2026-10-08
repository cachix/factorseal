use gpui::{
    AnyElement, App, ColorExt as _, ElementId, Hsla, InteractiveElement, IntoElement, MouseButton,
    ParentElement, RenderOnce, SharedString, Stateful, StatefulInteractiveElement, Styled, Window,
    div, prelude::FluentBuilder, px,
};
use gpui_component::{ActiveTheme as _, ThemeStyled as _};

pub(crate) trait ControlStyle:
    Styled + InteractiveElement + ParentElement + FluentBuilder + Sized
{
    fn text_field(self, focused: bool, window: &Window, cx: &App) -> Self {
        let hover = field_border(true, cx);
        self.border_1()
            .border_color(field_border(false, cx))
            .cursor_text()
            .when(focused, |this| this.focus_ring_style(window, cx))
            .when(!focused, |this| {
                this.hover(|style| style.border_color(hover))
            })
    }
}

impl<T: Styled + InteractiveElement + ParentElement + FluentBuilder + Sized> ControlStyle for T {}

pub(crate) trait ClickStyle:
    StatefulInteractiveElement + Styled + FluentBuilder + Sized
{
    fn fill_control(self, selected: bool, cx: &App) -> Self {
        let theme = cx.theme();
        let (hover, active) = (theme.secondary_hover, theme.secondary_active);
        let ring = if selected {
            theme.primary_foreground
        } else {
            theme.ring
        };
        self.cursor_pointer()
            .tab_index(0)
            .focus_visible(|style| style.inset_ring(FOCUS_RING).inset_ring_color(ring))
            .when(!selected, |this| {
                this.hover(|style| style.bg(hover))
                    .active(|style| style.bg(active))
            })
    }

    fn text_control(self, cx: &App) -> Self {
        text_states(self, cx.theme().muted_foreground, cx)
            .px_1()
            .mx(px(-4.))
    }

    fn quiet_text_control(self, cx: &App) -> Self {
        text_states(self, cx.theme().foreground, cx)
    }
}

fn text_states<T: ClickStyle>(element: T, hover: Hsla, cx: &App) -> T {
    let ring = cx.theme().ring;
    element
        .cursor_pointer()
        .tab_index(0)
        .rounded_sm()
        .hover(|style| style.text_color(hover))
        .active(|style| style.opacity(0.7))
        .focus_visible(|style| style.inset_ring(FOCUS_RING).inset_ring_color(ring))
}

impl<T: StatefulInteractiveElement + Styled + FluentBuilder + Sized> ClickStyle for T {}

const FOCUS_RING: gpui::Pixels = px(2.);

pub(crate) fn link(
    id: impl Into<ElementId>,
    href: impl Into<SharedString>,
    cx: &App,
) -> Stateful<gpui::Div> {
    let href = href.into();
    let color = cx.theme().link;
    div()
        .id(id)
        .text_color(color)
        .text_decoration_1()
        .text_decoration_color(color.opacity(0.5))
        .text_control(cx)
        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
        .on_click(move |_, _, cx| cx.open_url(&href))
}

pub(crate) fn field_border(hovered: bool, cx: &App) -> Hsla {
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

pub(crate) fn hover_field<E: IntoElement>(
    id: impl Into<ElementId>,
    build: impl FnOnce(Hsla) -> E + 'static,
) -> HoverField {
    HoverField {
        id: id.into(),
        build: Box::new(move |border| build(border).into_any_element()),
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

    pub(crate) fn own_focus_ring(mut self) -> Self {
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
