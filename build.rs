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
    // CryptoKit's Swift runtime lives in the OS shared cache. This must be on
    // the final executable, not just on hardwareseal's library/test targets.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
