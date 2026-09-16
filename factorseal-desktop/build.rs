use std::{env, path::PathBuf, process::Command};

fn main() {
    git_revision();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
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
        .args([
            "-c",
            "release",
            "--product",
            "FactorSealAppleBridge",
            "-Xswiftc",
            "-warnings-as-errors",
        ])
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

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn git_revision() {
    // Watch Git's actual paths, including linked worktrees and packed refs, so
    // committing or switching branches refreshes the embedded revision.
    let mut refs = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    if let Some(branch) = git_output(&["symbolic-ref", "-q", "HEAD"]) {
        refs.push(branch);
    }
    for reference in refs {
        if let Some(path) = git_output(&["rev-parse", "--git-path", &reference]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let revision = git_output(&["rev-parse", "--short=8", "HEAD"])
        .filter(|revision| revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_default();
    println!("cargo:rustc-env=FACTORSEAL_GIT_REVISION={revision}");
}
