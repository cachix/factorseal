use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=FACTORSEAL_APPLE_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=DEVELOPER_DIR");
    println!("cargo:rerun-if-changed=../platform/apple/Package.swift");
    println!("cargo:rerun-if-changed=../platform/apple/Sources");
    if env::var_os("CARGO_FEATURE_APPLE_CREDENTIAL_EXCHANGE").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let scratch = out.join("apple");
    let status = Command::new("xcrun")
        .args([
            "swift",
            "build",
            "--package-path",
            "../platform/apple",
            "--scratch-path",
        ])
        .arg(&scratch)
        .args(["-c", "release", "--product", "FactorSealAppleBridge"])
        .status()
        .expect("Apple credential exchange requires full Xcode 26+");
    assert!(
        status.success(),
        "building the Apple credential exchange bridge failed"
    );
    let output = Command::new("xcrun")
        .args([
            "swift",
            "build",
            "--package-path",
            "../platform/apple",
            "--scratch-path",
        ])
        .arg(&scratch)
        .args(["-c", "release", "--show-bin-path"])
        .output()
        .expect("locate Swift build output");
    assert!(output.status.success(), "locating the Swift bridge failed");
    let bin = String::from_utf8(output.stdout).expect("Swift build path is UTF-8");
    let bin = bin.trim();
    if let Some(destination) = env::var_os("FACTORSEAL_APPLE_BRIDGE_DIR") {
        let destination = PathBuf::from(destination);
        std::fs::create_dir_all(&destination).expect("create bridge staging directory");
        std::fs::copy(
            PathBuf::from(bin).join("libFactorSealAppleBridge.dylib"),
            destination.join("libFactorSealAppleBridge.dylib"),
        )
        .expect("stage Apple bridge");
    }
    println!("cargo:rustc-link-search=native={bin}");
    println!("cargo:rustc-link-lib=dylib=FactorSealAppleBridge");
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
    // Cargo tests run outside an app bundle. Release packages use only the
    // relative Frameworks rpath, never a build-machine path.
    if env::var("PROFILE").as_deref() == Ok("debug")
        && env::var_os("FACTORSEAL_APPLE_BRIDGE_DIR").is_none()
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{bin}");
    }
}
