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
            "test.hardware_self_test",
            "test.initial_unseal",
            "test.ipc_round_trip",
            "test.lifecycle_seal",
            "test.sealed_read_denied",
            "test.reunseal_recovery",
            "test.delete",
            "test.destroy",
            "completed_at_utc",
        ] {
            assert!(source.contains(marker), "{name} does not emit `{marker}`");
        }
    }
}

/// The self-test only means something on real hardware, so CI can check that
/// the runners still invoke it but never that it passes. The biometric half is
/// required exactly where a gated credential exists to remove.
#[test]
fn physical_runners_invoke_the_hardware_self_test() {
    for name in ["linux.sh", "macos.sh", "windows.ps1"] {
        assert!(
            runner(name).contains("hardware-self-test"),
            "{name} does not run the hardware self-test"
        );
    }
    for name in ["macos.sh", "windows.ps1"] {
        assert!(
            runner(name).contains("hardware-self-test --biometric"),
            "{name} does not exercise the biometric policy it accepts"
        );
    }
    assert!(
        !runner("linux.sh").contains("--biometric"),
        "linux.sh must not request a policy the TPM backend refuses"
    );
}

#[test]
fn physical_runners_reject_virtual_hosts_and_require_native_hardware() {
    let linux = runner("linux.sh");
    assert!(linux.contains("systemd-detect-virt --quiet"));
    assert!(linux.contains("/dev/tpmrm0"));

    let macos = runner("macos.sh");
    assert!(macos.contains("system_profiler SPHardwareDataType"));
    assert!(macos.contains("physical acceptance refuses virtualized hardware"));
    assert!(macos.contains("codesign --verify --strict"));
    assert!(macos.contains("com.apple.application-identifier"));
    assert!(macos.contains("embedded.provisionprofile"));

    let windows = runner("windows.ps1");
    assert!(windows.contains("Win32_ComputerSystem"));
    assert!(windows.contains("Get-Tpm"));
    assert!(windows.contains("Physical acceptance refuses virtualized hardware"));
    for cloud_identity in ["amazon ec2", "google compute engine"] {
        assert!(
            windows.to_ascii_lowercase().contains(cloud_identity),
            "windows.ps1 does not reject the cloud VM identity `{cloud_identity}`"
        );
    }
}

#[test]
fn guided_runs_choose_isolated_defaults_and_clean_up_after_success() {
    for name in ["linux.sh", "macos.sh"] {
        let source = runner(name);
        assert!(source.contains("acceptance-$run_id"));
        assert!(source.contains("factorseal-acceptance-password.XXXXXX"));
        assert!(source.contains("destroy_after=true"));
        assert!(source.contains("send this evidence file"));
    }

    let windows = runner("windows.ps1");
    assert!(windows.contains("Factorseal-acceptance-$runId"));
    assert!(windows.contains("RandomNumberGenerator"));
    assert!(windows.contains("$destroyAfterRun = $true"));
    assert!(windows.contains("send this evidence file"));
}

#[test]
fn windows_release_acceptance_requires_a_signed_artifact() {
    let windows = runner("windows.ps1");
    assert!(windows.contains("Get-AuthenticodeSignature"));
    assert!(windows.contains("SignatureStatus]::Valid"));
    assert!(windows.contains("artifact_signature"));
    assert!(windows.contains("AllowUnsignedDevelopmentArtifact"));
    assert!(windows.contains("DEVELOPMENT PASS"));
}

#[test]
fn windows_store_acceptance_requires_the_installed_store_signature() {
    let windows = runner("windows.ps1");
    assert!(windows.contains("StorePackageName"));
    assert!(windows.contains("Get-AppxPackage"));
    assert!(windows.contains("SignatureKind -ne 'Store'"));
    assert!(windows.contains("store_package_full_name"));
    assert!(windows.contains("microsoft-store"));
}

#[test]
fn windows_background_agents_preserve_arguments_containing_spaces() {
    let windows = runner("windows.ps1");
    assert!(windows.contains("function ConvertTo-NativeArgument"));
    assert!(windows.contains("function Start-FactorsealAgent"));
    assert!(windows.contains("-ArgumentList ($quotedArguments -join ' ')"));
    assert!(
        !windows.contains("-ArgumentList @("),
        "Start-Process must not flatten unquoted path arguments"
    );
}
