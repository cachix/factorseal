//! Opt-in internal performance timings.

use std::time::Instant;

pub(crate) fn enabled() -> bool {
    std::env::var_os("FACTORSEAL_TIMINGS").is_some_and(|value| value != "0")
}

pub(crate) fn record(
    scope: &'static str,
    phase: &'static str,
    started: Instant,
    outcome: &'static str,
) {
    #[cfg(feature = "diagnostics")]
    crate::diagnostics::timing(scope, phase, outcome, started.elapsed());
    if enabled() {
        eprintln!(
            "factorseal timing scope={scope} phase={phase} elapsed_ms={:.3} outcome={outcome}",
            started.elapsed().as_secs_f64() * 1_000.0
        );
    }
}

pub(crate) fn result<T, E>(
    scope: &'static str,
    phase: &'static str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let started = Instant::now();
    let result = operation();
    record_result(scope, phase, started, &result);
    result
}

pub(crate) fn record_result<T, E>(
    scope: &'static str,
    phase: &'static str,
    started: Instant,
    result: &Result<T, E>,
) {
    record(
        scope,
        phase,
        started,
        if result.is_ok() { "ok" } else { "error" },
    );
}
