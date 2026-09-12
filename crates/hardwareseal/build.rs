use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/apple_pq.swift");
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
        || env::var_os("CARGO_FEATURE_APPLE").is_none()
    {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        other => panic!("unsupported macOS architecture: {other:?}"),
    };
    let deployment = env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "14.0".into());
    let target = format!("{arch}-apple-macosx{deployment}");
    let sdk = Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
        .expect("macOS CryptoKit support requires Xcode 26 or later");
    assert!(sdk.status.success(), "cannot locate the macOS SDK");
    let sdk = String::from_utf8(sdk.stdout).expect("UTF-8 SDK path");
    // Older deployment targets need the selected Swift toolchain's static
    // compatibility libraries. They are not in the SDK or OS runtime folders.
    // Query the same target used below instead of assuming an Xcode layout.
    let info = Command::new("xcrun")
        .args(["--sdk", "macosx", "swiftc", "-print-target-info", "-target"])
        .arg(&target)
        .args(["-sdk", sdk.trim()])
        .output()
        .expect("cannot query Swift runtime library paths");
    assert!(
        info.status.success(),
        "cannot query Swift target information"
    );
    let info: serde_json::Value =
        serde_json::from_slice(&info.stdout).expect("invalid Swift target information");
    let paths = info["paths"]["runtimeLibraryPaths"]
        .as_array()
        .filter(|paths| !paths.is_empty())
        .expect("Swift target has no runtime library paths");
    for path in paths {
        let path = path.as_str().expect("invalid Swift runtime library path");
        assert!(
            PathBuf::from(path).is_absolute(),
            "relative Swift library path"
        );
        println!("cargo:rustc-link-search=native={path}");
    }
    let status = Command::new("xcrun")
        .args([
            "--sdk",
            "macosx",
            "swiftc",
            "-parse-as-library",
            "-emit-library",
            "-static",
            "-O",
            "-swift-version",
            "6",
            "-module-name",
            "FactorsealApplePQ",
            "-target",
        ])
        .arg(&target)
        .arg("-sdk")
        .arg(sdk.trim())
        .arg("src/apple_pq.swift")
        .arg("-o")
        .arg(out.join("libfactorseal_apple_pq.a"))
        .status()
        .expect("cannot execute the Swift compiler");
    assert!(
        status.success(),
        "failed to build the CryptoKit bridge (Xcode 26+ required)"
    );
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}/usr/lib/swift",
        sdk.trim()
    );
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    println!("cargo:rustc-link-lib=static=factorseal_apple_pq");
    println!("cargo:rustc-link-lib=dylib=swiftCore");
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for framework in ["Foundation", "Security", "CryptoKit", "LocalAuthentication"] {
        println!("cargo:rustc-link-lib=framework={framework}");
    }
}
