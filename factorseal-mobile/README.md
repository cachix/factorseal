# FactorSeal for Android and iOS

[Back to the project overview](../README.md).

The mobile app keeps personal secrets on the phone and syncs them with Desktop.
The vault, sync, password generator and one-time codes run in Rust. The screens
are built once with Compose Multiplatform and match Desktop. Desktop keeps its
own GPUI app. Backups and transfer files use the same formats as Desktop, so a
backup made on one can be restored on the other.

## Layout

- `core/`: the Rust bridge crate `factorseal-mobile`. The app sends one JSON
  request per call, through JNI on Android and the C functions in
  `core/include/factorseal.h` on iOS.
- `protocol/messages.json`: every request the app sends and every kind of
  response the core returns. Rust and Kotlin tests both check it, so the two
  sides cannot drift apart.
- `shared/`: the Kotlin Multiplatform app. `app/` holds the state and editor
  logic, `ui/` the screens and design system, and `androidMain` and `iosMain`
  the platform hosts for clipboard, camera, files and lifecycle.
- `androidApp/`: the Android entry point. Gradle builds the Rust library with
  cargo-ndk.
- `iosApp/`: the iOS entry point, described by an XcodeGen `project.yml`.
- `scripts/icons.py`: regenerates the icon drawables from the Desktop icons.
- `fastlane/metadata/`: the Google Play and App Store listing text and images,
  in the folders fastlane reads.

## Android

Everything runs inside the devenv shell in this directory:

```console
$ devenv shell
$ ./gradlew :androidApp:installDebug -Pfactorseal.abis=arm64-v8a
$ ./gradlew :shared:testAndroidHostTest
$ ./gradlew spotlessApply lint
$ cargo test -p factorseal-mobile
```

`-Pfactorseal.abis` limits the Rust build to the devices you test on. Without
it Gradle builds `arm64-v8a`, `armeabi-v7a` and `x86_64`.

Gradle checks every dependency against `gradle/verification-metadata.xml`.
After changing a dependency, rerun the build with
`--write-verification-metadata sha256` and review the new checksums.

Creating a vault needs a phone with a hardware-backed Keystore. The emulator
has none, so FactorSeal shows that the device is not supported. Run
`android-emulator` to start one for layout work, and use a phone for
everything else.

Release builds block screenshots and screen recording. Debug builds allow them.

FactorSeal fills and saves logins in other apps and in browsers through Android
autofill. Turn it on under Settings, Security, Autofill. Chrome also needs
Autofill using another service under its Autofill services setting. On a
website FactorSeal only offers logins saved for that exact address, like
Desktop. In an app you pick a login once and FactorSeal remembers it for that
app.

```console
$ ./gradlew :androidApp:bundleRelease
```

This produces a bundle with R8 and a link-time optimized Rust library. To sign
it with the Google Play upload key, set `FACTORSEAL_UPLOAD_KEYSTORE`,
`FACTORSEAL_UPLOAD_KEYSTORE_PASSWORD`, `FACTORSEAL_UPLOAD_KEY_ALIAS` and
`FACTORSEAL_UPLOAD_KEY_PASSWORD`. Without them the bundle is unsigned.

The version name and code come from the version in the root `Cargo.toml`.
Pushing a matching `v` tag builds a signed bundle in CI and attaches it to a
draft GitHub release. CI reads the keystore from the
`FACTORSEAL_UPLOAD_KEYSTORE_BASE64` secret and the other three values from
secrets with the same names, all in the `android-release` environment.

## iOS

Building for iOS needs a Mac with Xcode, Rust with the `aarch64-apple-ios` and
`aarch64-apple-ios-sim` targets, JDK 21 and XcodeGen:

```console
$ xcodegen --spec iosApp/project.yml
$ open iosApp/FactorSeal.xcodeproj
```

Xcode builds the Rust core with `scripts/build-ios-core.sh` and the shared app
with Gradle before compiling the Swift entry point. Set your team under Signing
& Capabilities to run on a device. The shared iOS code also compiles on Linux:

```console
$ ./gradlew :shared:compileKotlinIosArm64
```

`scripts/ios-smoke.sh` runs the shared tests in a simulator, builds the app,
launches it and saves a screenshot to `build/ios-smoke/launch.png`. CI runs it
on pushes to `main` and on pull requests.

## Security

The vault lives in app storage that is left out of system backups, and its keys
stay in the Android Keystore or the Secure Enclave. Biometric unlock asks the
platform to approve the vault key every time. Adding a fingerprint or face
turns it off, so keep a password method or a backup. FactorSeal seals the vault
when the screen locks, after the idle timeout and at the maximum unlock
duration. Copied secrets are marked sensitive and cleared after 30 seconds. On
iOS they also stay off your other devices. The app switcher shows a blank
screen instead of the vault. Autofill trusts the website address only from
known browsers with a matching signing certificate and matches every other app
by its package name.

The [privacy policy](PRIVACY.md) lists what leaves the phone and who can see
it. Its address goes into both store listings.
