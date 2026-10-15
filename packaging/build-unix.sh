#!/usr/bin/env bash
set -eu

platform=${1:-}
output_dir=${2:-dist}
case "$platform" in
    linux|macos) ;;
    *) echo "usage: $0 <linux|macos> [output-directory]" >&2; exit 2 ;;
esac

case "$(uname -s)" in
    Linux) host=linux ;;
    Darwin) host=macos ;;
    *) echo "unsupported Unix host" >&2; exit 2 ;;
esac
if [ "$host" != "$platform" ]; then
    echo "native $platform packaging must run on a $platform host" >&2
    exit 2
fi

exchange=${FACTORSEAL_APPLE_EXCHANGE:-0}
case $exchange in 0|1) ;; *) echo "FACTORSEAL_APPLE_EXCHANGE must be 0 or 1" >&2; exit 2 ;; esac
[ "$exchange" = 0 ] || [ "$platform" = macos ] || { echo "Apple exchange requires macOS" >&2; exit 2; }
build_profile=${FACTORSEAL_BUILD_PROFILE:-release}
case $build_profile in
    release) profile_dir=release; configuration=Release ;;
    dev) profile_dir=debug; configuration=Debug ;;
    *) echo "FACTORSEAL_BUILD_PROFILE must be release or dev" >&2; exit 2 ;;
esac
# Xcode signs macOS builds. A development team enables automatic provisioning;
# without one, the package is only for build tests.
development_team=${FACTORSEAL_MACOS_DEVELOPMENT_TEAM:-}
FACTORSEAL_BUILD_NUMBER=${FACTORSEAL_BUILD_NUMBER:-1}

# Where README.md tells a Linux user to install the Factorseal binary. The systemd
# unit's ExecStart is generated from this, so the two cannot drift apart.
linux_install_dir=/usr/local/bin

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
archive="factorseal-${version}-${platform}-$(uname -m)"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

if [ "$platform" = linux ]; then
    cargo build --locked --profile "$build_profile" \
        --bin factorseal --bin factorseal-parser --bin factorseal-network --bin factorseal-browser
    target_dir=$(cargo metadata --locked --no-deps --format-version 1 |
        sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
    [ -n "$target_dir" ] || { echo "could not determine Cargo target directory" >&2; exit 1; }
fi

mkdir -p "$output_dir" "$stage/$archive"
cp LICENSE README.md "$stage/$archive/"
cp assets/fonts/ibm-plex-sans/license.txt "$stage/$archive/LICENSE.IBM-Plex-Sans"
cp "acceptance/$platform.sh" "$stage/$archive/run-acceptance.sh"
chmod 0755 "$stage/$archive/run-acceptance.sh"

if [ "$platform" = linux ]; then
    mkdir -p "$stage/$archive/bin" "$stage/$archive/share/systemd/user"
    cp "$target_dir/$profile_dir/factorseal" "$stage/$archive/bin/"
    cp "$target_dir/$profile_dir/factorseal-parser" "$target_dir/$profile_dir/factorseal-network" "$target_dir/$profile_dir/factorseal-browser" "$stage/$archive/bin/"
    cp packaging/linux/factorseal-start "$stage/$archive/bin/"
    # systemd needs an absolute ExecStart, so the unit is written for the
    # documented install prefix. Unpacking the tarball somewhere else means
    # substituting the template again, which is why it ships beside the unit.
    sed "s|@INSTALL_DIR@|$linux_install_dir|g" \
        packaging/linux/factorseal.service.in \
        > "$stage/$archive/share/systemd/user/factorseal.service"
    cp packaging/linux/factorseal.service.in "$stage/$archive/share/systemd/user/"
    chmod 0755 \
        "$stage/$archive/bin/factorseal" \
        "$stage/$archive/bin/factorseal-start"
else
    app="$stage/$archive/Factorseal.app"
    scheme=Factorseal
    if [ "$exchange" = 1 ]; then
        scheme='Factorseal Credential Exchange'
        configuration="${configuration}CredentialExchange"
    fi
    set -- /usr/bin/xcodebuild -project packaging/macos/Factorseal.xcodeproj -scheme "$scheme" \
        -configuration "$configuration" -derivedDataPath "$stage/DerivedData" \
        MARKETING_VERSION="$version" CURRENT_PROJECT_VERSION="$FACTORSEAL_BUILD_NUMBER"
    if [ -n "$development_team" ]; then
        set -- "$@" DEVELOPMENT_TEAM="$development_team" -allowProvisioningUpdates
    else
        # Build tests omit team entitlements and retain the runtime policy.
        set -- "$@" CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM= \
            CODE_SIGN_ENTITLEMENTS="$PWD/packaging/macos/FactorsealBuildTest.entitlements"
    fi
    "$@" build
    /usr/bin/ditto "$stage/DerivedData/Build/Products/$configuration/Factorseal.app" "$app"
    mkdir -p "$stage/$archive/Library/LaunchAgents"
    cp packaging/macos/dev.factorseal.plist "$stage/$archive/Library/LaunchAgents/"
    if [ -z "$development_team" ]; then
        echo "Created $app for build tests only."
        echo "This app cannot use Factorseal's protected macOS Keychain storage or pass physical acceptance."
    fi
fi

tar -C "$stage" -czf "$output_dir/$archive.tar.gz" "$archive"
echo "$output_dir/$archive.tar.gz"

cp "acceptance/$platform.sh" "$output_dir/$archive-acceptance.sh"
chmod 0755 "$output_dir/$archive-acceptance.sh"
echo "$output_dir/$archive-acceptance.sh"

if [ "$platform" = macos ]; then
    package_root="$stage/package-root"
    mkdir -p "$package_root/Applications" "$package_root/Library/LaunchAgents"
    /usr/bin/ditto \
        "$stage/$archive/Factorseal.app" \
        "$package_root/Applications/Factorseal.app"
    cp packaging/macos/dev.factorseal.plist "$package_root/Library/LaunchAgents/"
    pkgbuild \
        --root "$package_root" \
        --identifier dev.factorseal \
        --version "$version" \
        --install-location / \
        "$output_dir/$archive.pkg"
    echo "$output_dir/$archive.pkg"
fi
