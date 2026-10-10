use std::time::Duration;

use gpui::{Animation, AnimationElement, AnimationExt as _, ElementId, IntoElement, Styled, px};
use gpui_component::animation::ease_out_cubic;

const ENTER_DURATION: Duration = Duration::from_millis(160);
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
