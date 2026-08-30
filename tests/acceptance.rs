//! Static contract checks for the opt-in physical acceptance runners.
//!
//! CI cannot answer a native user-verification prompt or manufacture a real
//! TPM/Secure Enclave. It can still prevent one platform's runner from losing
//! the physical-host gate or emitting an incompatible evidence record.

use std::path::PathBuf;

fn runner(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("acceptance")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is missing or unreadable: {error}", path.display()))
}

#[test]
fn every_physical_runner_emits_the_same_core_evidence_contract() {
    for name in ["linux.sh", "macos.sh", "windows.ps1"] {
        let source = runner(name);
        for marker in [
            "factorseal-physical-acceptance-v1",
            "factorseal_filename",
            "factorseal_sha256",
            "factorseal_version",
            "os_summary",
            "expected_backend",
            "observed_backend",
            "physical_host_check",
            "hardware_summary",
            "native_prompt_observed",
            "lifecycle_event",
            "test.create",
            "test.initial_unseal",
            "test.ipc_round_trip",
            "test.lifecycle_seal",
            "test.sealed_read_denied",
            "test.reunseal_recovery",
            "test.delete",
            "completed_at_utc",
        ] {
            assert!(source.contains(marker), "{name} does not emit `{marker}`");
        }
    }
}

#[test]
fn physical_runners_reject_virtual_hosts_and_require_native_hardware() {
    let linux = runner("linux.sh");
    assert!(linux.contains("systemd-detect-virt --quiet"));
    assert!(linux.contains("/dev/tpmrm0"));

    let macos = runner("macos.sh");
    assert!(macos.contains("system_profiler SPHardwareDataType"));
    assert!(macos.contains("physical acceptance refuses virtualized hardware"));

    let windows = runner("windows.ps1");
    assert!(windows.contains("Win32_ComputerSystem"));
    assert!(windows.contains("Get-Tpm"));
    assert!(windows.contains("Physical acceptance refuses virtualized hardware"));
}
