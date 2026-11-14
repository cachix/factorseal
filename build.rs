fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        // Headless helpers start with Win32k disabled. Eager COM/shell/UI
        // imports can initialize user32 before main, even when unused by the
        // helper. Keep those imports lazy, as Chromium's Windows build does.
        // The same applies to the library test executable used by deny probes.
        println!("cargo:rustc-link-lib=delayimp");
        for library in ["user32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll"] {
            println!("cargo:rustc-link-arg=/DELAYLOAD:{library}");
        }
    }
    app_icon();
    // CryptoKit's Swift runtime lives in the OS shared cache. This must be on
    // the final executable, not just on hardwareseal's library/test targets.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}

/// Gives the `factorseal` executable the application icon on Windows. Only a
/// build on Windows embeds it: the WSL broker is cross-compiled from Linux,
/// with no resource compiler, and needs no icon.
fn app_icon() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || !std::env::var("HOST").is_ok_and(|host| host.contains("windows"))
    {
        return;
    }
    println!("cargo:rerun-if-changed=assets/logo/factorseal-app-icon.ico");
    embed_resource::compile_for(
        "assets/logo/factorseal-app-icon.rc",
        ["factorseal"],
        embed_resource::ParamsIncludeDirs(["assets/logo"]),
    )
    .manifest_required()
    .expect("embedding the application icon");
}
