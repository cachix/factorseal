//! Opt-in internal performance timings shared by hardware backends.

use std::time::Instant;

pub(crate) fn enabled() -> bool {
    std::env::var_os("FACTORSEAL_TIMINGS").is_some_and(|value| value != "0")
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
