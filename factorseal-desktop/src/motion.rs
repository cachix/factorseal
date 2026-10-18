use std::time::Duration;

use gpui::{
    Animation, AnimationElement, AnimationExt as _, ElementId, IntoElement, Motion, Styled, px,
};
use gpui_component::animation::ease_out_cubic;

const ENTER_DURATION: Duration = Duration::from_millis(160);
const NAVIGATE_DURATION: Duration = Duration::from_millis(200);
const NAVIGATE_TRAVEL: f32 = 20.;
const PATIENCE: Duration = Duration::from_millis(400);
pub(crate) const SETTLE: Duration = Duration::from_millis(400);
const HOVER_DURATION: Duration = Duration::from_millis(120);
pub(crate) const LEAVE_DURATION: Duration = Duration::from_millis(140);
const ENTER_TRAVEL: f32 = 6.;

pub(crate) fn enter<E: IntoElement + Styled + 'static>(
    id: impl Into<ElementId>,
    element: E,
) -> AnimationElement<E> {
    element.with_animation(
        id,
        Animation::new(ENTER_DURATION).with_easing(ease_out_cubic),
        |element, delta| element.top(px(ENTER_TRAVEL * (1. - delta))).opacity(delta),
    )
}

pub(crate) fn navigate<E: IntoElement + Styled + 'static>(
    id: impl Into<ElementId>,
    direction: i8,
    element: E,
) -> AnimationElement<E> {
    element.with_animation(
        id,
        Animation::new(NAVIGATE_DURATION).with_easing(ease_out_cubic),
        move |element, delta| {
            let rest = 1. - delta;
            if direction == 0 {
                element.top(px(ENTER_TRAVEL * rest)).opacity(delta)
            } else {
                element
                    .left(px(NAVIGATE_TRAVEL * f32::from(direction) * rest))
                    .opacity(delta)
            }
        },
    )
}

pub(crate) fn fade<E: IntoElement + Styled + 'static>(
    id: impl Into<ElementId>,
    element: E,
) -> AnimationElement<E> {
    element.with_animation(
        id,
        Animation::new(ENTER_DURATION).with_easing(ease_out_cubic),
        Styled::opacity,
    )
}

pub(crate) fn after_a_moment<E: IntoElement + Styled + 'static>(
    id: impl Into<ElementId>,
    element: E,
) -> AnimationElement<E> {
    element.with_animation(
        id,
        Animation::new(PATIENCE).with_easing(|delta| ((delta - 0.6) / 0.4).clamp(0., 1.)),
        Styled::opacity,
    )
}

pub(crate) fn leave<E: IntoElement + Styled + 'static>(
    id: impl Into<ElementId>,
    element: E,
) -> AnimationElement<E> {
    element.with_animation(
        id,
        Animation::new(LEAVE_DURATION).with_easing(ease_out_cubic),
        |element, delta| element.top(px(ENTER_TRAVEL * delta)).opacity(1. - delta),
    )
}

pub(crate) fn change() -> Motion {
    Motion::new(ENTER_DURATION).with_easing(ease_out_cubic)
}

pub(crate) fn hover() -> Motion {
    Motion::new(HOVER_DURATION).with_easing(ease_out_cubic)
}
