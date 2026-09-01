#!/bin/sh
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

signing_identity=
provisioning_profile=
if [ "$platform" = macos ]; then
    signing_identity=${FACTORSEAL_MACOS_SIGNING_IDENTITY:-}
    provisioning_profile=${FACTORSEAL_MACOS_PROVISIONING_PROFILE:-}
    if [ -n "$signing_identity" ] && [ -z "$provisioning_profile" ]; then
        echo "FACTORSEAL_MACOS_PROVISIONING_PROFILE is required when FACTORSEAL_MACOS_SIGNING_IDENTITY is set" >&2
        exit 2
    fi
    if [ -n "$provisioning_profile" ] && [ -z "$signing_identity" ]; then
        echo "FACTORSEAL_MACOS_SIGNING_IDENTITY is required when FACTORSEAL_MACOS_PROVISIONING_PROFILE is set" >&2
        exit 2
    fi
    if [ -n "$provisioning_profile" ]; then
        [ -f "$provisioning_profile" ] || {
            echo "macOS provisioning profile does not exist: $provisioning_profile" >&2
            exit 2
        }
    else
        signing_identity=-
    fi
fi

# Where README.md tells a Linux user to install the Factorseal binary. The systemd
# unit's ExecStart is generated from this, so the two cannot drift apart.
linux_install_dir=/usr/local/bin

version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
archive="factorseal-${version}-${platform}-$(uname -m)"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

if [ "$platform" = macos ]; then
    # The SDK controls available declarations; the deployment target separately
    # controls the oldest runnable macOS. Build cleanly so stale metadata cannot
    # survive a target change.
    macos_deployment_target=11.0
    MACOSX_DEPLOYMENT_TARGET=$macos_deployment_target
    CARGO_TARGET_DIR="$stage/cargo-target"
    export MACOSX_DEPLOYMENT_TARGET CARGO_TARGET_DIR
fi

cargo build --locked --release --no-default-features \
    --features vault,cli,hardware \
    --bin factorseal
target_dir=$(cargo metadata --locked --no-deps --format-version 1 |
    sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
if [ -z "$target_dir" ]; then
    echo "could not determine Cargo target directory" >&2
    exit 1
fi

mkdir -p "$output_dir" "$stage/$archive"
cp LICENSE README.md "$stage/$archive/"
cp "acceptance/$platform.sh" "$stage/$archive/run-acceptance.sh"
chmod 0755 "$stage/$archive/run-acceptance.sh"

if [ "$platform" = linux ]; then
    mkdir -p \
        "$stage/$archive/bin" \
        "$stage/$archive/share/dbus-1/services" \
        "$stage/$archive/share/systemd/user" \
        "$stage/$archive/share/xdg-desktop-portal/portals"
    cp "$target_dir/release/factorseal" "$stage/$archive/bin/"
    cp packaging/linux/factorseal-start "$stage/$archive/bin/"
    # systemd needs an absolute ExecStart, so the unit is written for the
    # documented install prefix. Unpacking the tarball somewhere else means
    # substituting the template again, which is why it ships beside the unit.
    sed "s|@INSTALL_DIR@|$linux_install_dir|g" \
        packaging/linux/factorseal.service.in \
        > "$stage/$archive/share/systemd/user/factorseal.service"
    cp packaging/linux/factorseal.service.in "$stage/$archive/share/systemd/user/"
    sed "s|@INSTALL_DIR@|$linux_install_dir|g" \
        packaging/linux/factorseal-portal.service.in \
        > "$stage/$archive/share/systemd/user/factorseal-portal.service"
    sed "s|@INSTALL_DIR@|$linux_install_dir|g" \
        packaging/linux/org.freedesktop.impl.portal.desktop.factorseal.service.in \
        > "$stage/$archive/share/dbus-1/services/org.freedesktop.impl.portal.desktop.factorseal.service"
    cp packaging/linux/factorseal.portal \
        "$stage/$archive/share/xdg-desktop-portal/portals/"
    chmod 0755 \
        "$stage/$archive/bin/factorseal" \
        "$stage/$archive/bin/factorseal-start"
else
    app="$stage/$archive/Factorseal.app/Contents"
    mkdir -p "$app/MacOS" "$app/Resources" "$stage/$archive/Library/LaunchAgents"
    cp "$target_dir/release/factorseal" "$app/MacOS/"
    cp packaging/macos/factorseal-askpass "$app/Resources/"
    sed "s/@VERSION@/$version/g" packaging/macos/Info.plist > "$app/Info.plist"
    cp packaging/macos/dev.factorseal.plist "$stage/$archive/Library/LaunchAgents/"
    chmod 0755 "$app/MacOS/factorseal" "$app/Resources/factorseal-askpass"

    sh packaging/macos/prepare-app.sh \
        "${app%/Contents}" \
        "$macos_deployment_target"
    if [ -n "$provisioning_profile" ]; then
        sh packaging/macos/sign-app.sh \
            "${app%/Contents}" \
            "$signing_identity" \
            "$provisioning_profile"
    else
        sh packaging/macos/sign-app.sh "${app%/Contents}" -
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
