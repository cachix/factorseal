#![allow(
    clippy::unused_self,
    clippy::unused_async,
    clippy::unused_async_trait_impl
)]

use std::path::Path;

use wasm_bindgen::{JsCast as _, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, File, HtmlAnchorElement, HtmlInputElement, Url};
use zeroize::Zeroizing;

const DOWNLOAD_URL_LIFETIME_MS: i32 = 60_000;

pub(crate) enum ChosenFile {
    Picked(File),
    Download(String),
}

impl ChosenFile {
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Picked(file) => file.name(),
            Self::Download(name) => name.clone(),
        }
    }

    pub(crate) const fn path(&self) -> Option<&Path> {
        None
    }

    pub(crate) async fn read(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let Self::Picked(file) = self else {
            return Err("This file cannot be read.".to_owned());
        };
        let buffer = JsFuture::from(file.array_buffer())
            .await
            .map_err(|_| "The file could not be read.".to_owned())?;
        Ok(Zeroizing::new(js_sys::Uint8Array::new(&buffer).to_vec()))
    }

    pub(crate) async fn write(&self, bytes: Zeroizing<Vec<u8>>) -> Result<(), String> {
        let Self::Download(name) = self else {
            return Err("This file cannot be written.".to_owned());
        };
        download(name, &bytes).map_err(|_| "The download could not start.".to_owned())
    }
}

pub(crate) async fn open(_title: &str, _label: &str, extension: &str) -> Option<ChosenFile> {
    let document = web_sys::window()?.document()?;
    let input: HtmlInputElement = document.create_element("input").ok()?.dyn_into().ok()?;
    input.set_type("file");
    input.set_accept(&format!(".{extension}"));
    let chosen = js_sys::Promise::new(&mut |resolve, _| {
        let _ = input.add_event_listener_with_callback("change", &resolve);
        let _ = input.add_event_listener_with_callback("cancel", &resolve);
    });
    input.click();
    JsFuture::from(chosen).await.ok()?;
    input.files()?.get(0).map(ChosenFile::Picked)
}

pub(crate) async fn save(
    _title: &str,
    _label: &str,
    _extension: &str,
    name: &str,
) -> Option<ChosenFile> {
    Some(ChosenFile::Download(name.to_owned()))
}

fn download(name: &str, bytes: &[u8]) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or(JsValue::NULL)?;
    let document = window.document().ok_or(JsValue::NULL)?;
    let parts = js_sys::Array::of1(&js_sys::Uint8Array::from(bytes));
    let url = Url::create_object_url_with_blob(&Blob::new_with_u8_array_sequence(&parts)?)?;
    let anchor: HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
    anchor.set_href(&url);
    anchor.set_download(name);
    anchor.click();
    let revoke = Closure::once_into_js(move || Url::revoke_object_url(&url));
    window.set_timeout_with_callback_and_timeout_and_arguments_0(
        revoke.unchecked_ref(),
        DOWNLOAD_URL_LIFETIME_MS,
    )?;
    Ok(())
}
