//! Timing for one Desktop unlock request from UI submission to UI update.

use std::sync::Mutex;
use std::time::Instant;

static UNLOCK_STARTED: Mutex<Option<Instant>> = Mutex::new(None);

fn enabled() -> bool {
    std::env::var_os("FACTORSEAL_TIMINGS").is_some_and(|value| value != "0")
}

pub(crate) fn begin_unlock() {
    if !enabled() {
        return;
    }
    if let Ok(mut started) = UNLOCK_STARTED.lock() {
        *started = Some(Instant::now());
    }
    eprintln!(
        "factorseal timing scope=desktop_unlock phase=request_accepted elapsed_ms=0.000 outcome=ok"
    );
}

pub(crate) fn mark_unlock(phase: &str, outcome: &str) {
    if !enabled() {
        return;
    }
    let Some(elapsed) = UNLOCK_STARTED
        .lock()
        .ok()
        .and_then(|started| *started)
        .map(|started| started.elapsed().as_secs_f64() * 1_000.0)
    else {
        return;
    };
    eprintln!(
        "factorseal timing scope=desktop_unlock phase={phase} elapsed_ms={elapsed:.3} outcome={outcome}"
    );
}

pub(crate) fn record(scope: &str, phase: &str, started: Instant, outcome: &str) {
    if enabled() {
        eprintln!(
            "factorseal timing scope={scope} phase={phase} elapsed_ms={:.3} outcome={outcome}",
            started.elapsed().as_secs_f64() * 1_000.0
        );
    }
}

pub(crate) fn result<T, E>(
    scope: &str,
    phase: &str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let started = Instant::now();
    let result = operation();
    record(
        scope,
        phase,
        started,
        if result.is_ok() { "ok" } else { "error" },
    );
    result
}

pub(crate) fn finish_unlock(phase: &str, outcome: &str) {
    mark_unlock(phase, outcome);
    if let Ok(mut started) = UNLOCK_STARTED.lock() {
        *started = None;
    }
}
