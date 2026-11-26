use gpui::{App, Hsla};
use gpui_component::theme::Theme;
use wasm_bindgen::{JsCast as _, JsValue, closure::Closure};
use web_sys::MessageEvent;

use crate::appearance::Choice;
use crate::settings::{DesktopSettings, Page};

enum Message {
    Dark(bool),
    Theme(Choice),
    Fill(String),
    Cancel,
}

pub(crate) fn connect(cx: &mut App) {
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Some(dark) = window
        .document()
        .and_then(|document| document.document_element())
        .and_then(|root| root.get_attribute("data-theme"))
        .and_then(|mode| is_dark(&mode))
    {
        crate::appearance::follow_site(dark, cx);
    }
    let (sender, receiver) = async_channel::unbounded();
    let origin = window.location().origin().ok();
    let listener = Closure::<dyn Fn(MessageEvent)>::new(move |event: MessageEvent| {
        if origin.as_deref() == Some(event.origin().as_str())
            && let Some(message) = read(&event.data())
        {
            let _ = sender.try_send(message);
        }
    });
    let _ = window.add_event_listener_with_callback("message", listener.as_ref().unchecked_ref());
    listener.forget();
    if let Ok(launched) = web_sys::Event::new("factorseal:launched") {
        let _ = window.dispatch_event(&launched);
    }
    cx.spawn(async move |cx| {
        while let Ok(message) = receiver.recv().await {
            cx.update(|cx| match message {
                Message::Dark(dark) => crate::appearance::follow_site(dark, cx),
                Message::Theme(choice) => crate::appearance::choose(choice, cx),
                Message::Fill(site) => crate::app::request_browser(site, cx),
                Message::Cancel => crate::app::cancel_browser(cx),
            });
        }
    })
    .detach();
}

pub(crate) fn publish(choice: Choice, theme: &Theme) {
    post(&serde_json::json!({
        "type": "factorseal:theme",
        "theme": choice,
        "dark": theme.is_dark(),
        "colors": {
            "canvas": css(theme.background),
            "surface": css(theme.popover),
            "raised": css(theme.sidebar),
            "ink": css(theme.foreground),
            "quiet": css(theme.muted_foreground),
            "border": css(theme.border),
            "secondary": css(theme.secondary),
            "secondary-hover": css(theme.secondary_hover),
            "selection": css(theme.selection),
            "success": css(theme.success),
            "danger": css(theme.danger),
            "primary-hover": css(theme.primary_hover),
            "primary-active": css(theme.primary_active),
        },
    }));
}

pub(crate) fn report_access(granted: bool) {
    post(&serde_json::json!({ "type": "factorseal:access", "granted": granted }));
}

pub(crate) fn report_browser(approved: bool, username: Option<&str>) {
    post(&serde_json::json!({
        "type": "factorseal:browser",
        "approved": approved,
        "username": username,
    }));
}

fn post(message: &serde_json::Value) {
    let Some(window) = web_sys::window() else {
        return;
    };
    let (Ok(Some(parent)), Ok(origin)) = (window.parent(), window.location().origin()) else {
        return;
    };
    if let Ok(message) = js_sys::JSON::parse(&message.to_string()) {
        let _ = parent.post_message(&message, &origin);
    }
}

fn read(data: &JsValue) -> Option<Message> {
    let field = |name: &str| js_sys::Reflect::get(data, &name.into()).ok()?.as_string();
    match field("type")?.as_str() {
        "factorseal:mode" => is_dark(&field("mode")?).map(Message::Dark),
        "factorseal:theme" => serde_json::from_value(field("theme")?.into())
            .ok()
            .map(Message::Theme),
        "factorseal:fill" => field("site").map(Message::Fill),
        "factorseal:cancel" => Some(Message::Cancel),
        _ => None,
    }
}

fn is_dark(mode: &str) -> Option<bool> {
    match mode {
        "dark" => Some(true),
        "light" => Some(false),
        _ => None,
    }
}

fn css(color: Hsla) -> String {
    let color = gpui::hsla_to_rgba(color);
    format!(
        "rgb({:.0} {:.0} {:.0} / {:.3})",
        color.red * 255.,
        color.green * 255.,
        color.blue * 255.,
        color.alpha
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Demo {
    Desktop,
    Computer,
    Phone,
    Access,
    Browser,
}

pub(crate) fn demo() -> Demo {
    match parameter("demo").as_deref() {
        Some("computer") => Demo::Computer,
        Some("phone") => Demo::Phone,
        Some("access") => Demo::Access,
        Some("browser") => Demo::Browser,
        _ => Demo::Desktop,
    }
}

pub(crate) fn parameter(name: &str) -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    web_sys::UrlSearchParams::new_with_str(&search)
        .ok()?
        .get(name)
}

pub(crate) fn settings(settings: DesktopSettings) -> DesktopSettings {
    DesktopSettings {
        page: Some(Page::PersonalSecrets),
        ..settings
    }
}
