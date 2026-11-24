use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{JsCast as _, JsValue, closure::Closure};
use web_sys::MessageEvent;
use zeroize::Zeroizing;

use crate::site::Demo;

const SYNC: &str = "factorseal:sync";
const ADD: &str = "factorseal:add";

pub(super) type Change = (String, Option<Zeroizing<Vec<u8>>>);

pub(super) enum Message {
    Changes(Vec<Change>),
    Add,
}

pub(super) fn connect(receive: impl Fn(Message) + 'static) {
    let Some(window) = web_sys::window().filter(|_| syncing()) else {
        return;
    };
    let origin = window.location().origin().ok();
    let listener = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        if origin.as_deref() == Some(event.origin().as_str())
            && let Some(message) = read(&event.data())
        {
            receive(message);
        }
    });
    let _ = window.add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
    listener.forget();
}

pub(super) fn send(changes: &[Change]) {
    let Some(window) = web_sys::window().filter(|_| syncing()) else {
        return;
    };
    let (Ok(Some(parent)), Ok(origin)) = (window.parent(), window.location().origin()) else {
        return;
    };
    let message = Object::new();
    let _ = Reflect::set(&message, &"type".into(), &SYNC.into());
    let _ = Reflect::set(&message, &"changes".into(), &encode(changes));
    let _ = parent.post_message(&message, &origin);
}

pub(super) fn syncing() -> bool {
    matches!(crate::site::demo(), Demo::Computer | Demo::Phone)
}

fn read(data: &JsValue) -> Option<Message> {
    let field = |name: &str| Reflect::get(data, &name.into()).ok();
    match field("type")?.as_string()?.as_str() {
        SYNC => Some(Message::Changes(decode(&field("changes")?)?)),
        ADD => Some(Message::Add),
        _ => None,
    }
}

fn encode(changes: &[Change]) -> Array {
    changes
        .iter()
        .map(|(id, value)| {
            let value = value.as_ref().map_or(JsValue::NULL, |value| {
                Uint8Array::from(value.as_slice()).into()
            });
            Array::of2(&id.into(), &value)
        })
        .collect()
}

fn decode(data: &JsValue) -> Option<Vec<Change>> {
    data.dyn_ref::<Array>()?
        .iter()
        .map(|change| {
            let change = change.dyn_into::<Array>().ok()?;
            let id = change.get(0).as_string()?;
            let value = change.get(1);
            let value = if value.is_null() {
                None
            } else {
                Some(Zeroizing::new(
                    value.dyn_into::<Uint8Array>().ok()?.to_vec(),
                ))
            };
            Some((id, value))
        })
        .collect()
}
