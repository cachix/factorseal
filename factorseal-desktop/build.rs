use std::{env, path::PathBuf, process::Command};

fn main() -> std::io::Result<()> {
    git_revision();
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
        println!("cargo:rerun-if-env-changed=FACTORSEAL_BUILD_NUMBER");
        let build_number = env::var("FACTORSEAL_BUILD_NUMBER").unwrap_or_else(|_| "1".into());
        println!("cargo:rustc-env=FACTORSEAL_BUILD_NUMBER={build_number}");
    }
    println!("cargo:rerun-if-env-changed=FACTORSEAL_APPLE_BRIDGE_DIR");
    println!("cargo:rerun-if-env-changed=SDKROOT");
    println!("cargo:rerun-if-changed=../platform/macos/credential-exchange/Package.swift");
    println!("cargo:rerun-if-changed=../platform/macos/credential-exchange/Sources");
    if env::var_os("CARGO_FEATURE_APPLE_CREDENTIAL_EXCHANGE").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return Ok(());
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let scratch = out.join("apple");
    let status = Command::new("swift")
        .args([
            "build",
            // Allow SwiftPM to build inside the Nix sandbox.
            "--disable-sandbox",
            "--package-path",
            "../platform/macos/credential-exchange",
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
        .status()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    let bin = scratch.join("release");
    if let Some(destination) = env::var_os("FACTORSEAL_APPLE_BRIDGE_DIR") {
        let destination = PathBuf::from(destination);
        std::fs::create_dir_all(&destination)?;
        std::fs::copy(
            bin.join("libFactorSealAppleBridge.dylib"),
            destination.join("libFactorSealAppleBridge.dylib"),
        )?;
    }
    println!("cargo:rustc-link-search=native={}", bin.display());
    println!("cargo:rustc-link-lib=dylib=FactorSealAppleBridge");
    println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../Frameworks");
    // Cargo tests run outside an app bundle. Release packages use only the
    // relative Frameworks rpath, never a build-machine path.
    if env::var("PROFILE").as_deref() == Ok("debug")
        && env::var_os("FACTORSEAL_APPLE_BRIDGE_DIR").is_none()
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", bin.display());
    }
    Ok(())
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
