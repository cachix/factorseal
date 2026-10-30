#[cfg(target_os = "android")]
mod android;
mod api;
mod autofill;
mod core;
mod ffi;
mod items;
mod protection;
mod qr;
mod sync;
#[cfg(test)]
mod tests;
mod transfer;

use crate::api::{ErrorCode, Request, Response};
use crate::core::{Core, Failure, Outcome};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

static CORE: Mutex<Option<Arc<Core>>> = Mutex::new(None);

#[must_use]
pub fn call(request: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = match serde_json::from_slice::<Request>(request) {
        Ok(request) => dispatch(request),
        Err(_) => Err(Failure::new(ErrorCode::Invalid, "the request is malformed")),
    };
    encode(&response.unwrap_or_else(|failure| Response::Error {
        code: failure.code,
        message: failure.message,
    }))
}

#[must_use]
pub fn scan(pixels: &[u8], width: usize, height: usize, stride: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(&qr::scan(pixels, width, height, stride)).unwrap_or_default())
}

pub fn seal() {
    if let Some(core) = CORE.lock().unwrap_or_else(PoisonError::into_inner).clone() {
        core.seal();
    }
}

fn dispatch(request: Request) -> Outcome<Response> {
    if let Request::Start {
        directory,
        platform,
    } = &request
    {
        let directory = Path::new(directory);
        let mut slot = CORE.lock().unwrap_or_else(PoisonError::into_inner);
        match slot.as_ref() {
            Some(core) if core.root() == directory.join("vault") => {}
            Some(_) => {
                return Err(Failure::new(
                    ErrorCode::Invalid,
                    "FactorSeal already started in another directory",
                ));
            }
            None => {
                *slot = Some(Arc::new(Core::new(
                    directory,
                    *platform,
                    Box::new(protection::DeviceProtection),
                )?));
            }
        }
    }
    let core = CORE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .ok_or_else(|| Failure::new(ErrorCode::NotStarted, "FactorSeal has not started"))?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| core.handle(request))).unwrap_or_else(
        |_| {
            Err(Failure::new(
                ErrorCode::Failed,
                "FactorSeal stopped this operation after an internal error",
            ))
        },
    )
}

fn encode(response: &Response) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"type":"error","code":"failed","message":"the response could not be encoded"}"#
            .to_vec()
    }))
}
