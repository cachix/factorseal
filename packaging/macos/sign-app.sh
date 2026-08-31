#!/bin/sh
set -eu
umask 077

usage() {
    echo "usage: $0 APP_BUNDLE SIGNING_IDENTITY [PROVISIONING_PROFILE]" >&2
    exit 2
}

case $# in 2|3) ;; *) usage ;; esac
app=$1
signing_identity=$2
profile=${3:-}

[ "$(uname -s)" = Darwin ] || {
    echo "macOS app signing must run on macOS" >&2
    exit 2
}
[ -d "$app/Contents" ] || { echo "app bundle not found: $app" >&2; exit 2; }
[ -f "$app/Contents/Info.plist" ] || { echo "Info.plist not found in $app" >&2; exit 2; }
[ -n "$signing_identity" ] || { echo "signing identity must not be empty" >&2; exit 2; }
[ -n "$profile" ] || [ "$signing_identity" = - ] || {
    echo "a signing identity requires a provisioning profile" >&2
    exit 2
}
[ -z "$profile" ] || [ "$signing_identity" != - ] || {
    echo "a provisioning profile requires an Apple signing identity" >&2
    exit 2
}
[ -z "$profile" ] || [ -f "$profile" ] || {
    echo "provisioning profile not found: $profile" >&2
    exit 2
}

script_dir=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/factorseal-signing.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
case $bundle_id in
    ''|*[!A-Za-z0-9.-]*) echo "invalid bundle identifier: $bundle_id" >&2; exit 2 ;;
esac

if [ -n "$profile" ]; then
    profile_plist="$scratch/profile.plist"
    /usr/bin/security cms -D -i "$profile" >"$profile_plist"
    team_id=$(/usr/libexec/PlistBuddy -c 'Print :TeamIdentifier:0' "$profile_plist")
    app_id_prefix=$(/usr/libexec/PlistBuddy -c 'Print :ApplicationIdentifierPrefix:0' "$profile_plist")
    profile_app_id=$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist")
    application_id="$app_id_prefix.$bundle_id"

    case $team_id in
        ''|*[!A-Za-z0-9]*) echo "invalid team identifier in provisioning profile" >&2; exit 2 ;;
    esac
    case $app_id_prefix in
        ''|*[!A-Za-z0-9]*) echo "invalid app identifier prefix in provisioning profile" >&2; exit 2 ;;
    esac
    if [ "$profile_app_id" != "$application_id" ] && [ "$profile_app_id" != "$app_id_prefix.*" ]; then
        echo "provisioning profile authorizes $profile_app_id, not $application_id" >&2
        exit 2
    fi

    profile_authorizes_group=false
    group_index=0
    while profile_group=$(/usr/bin/plutil -extract \
        "Entitlements.keychain-access-groups.$group_index" \
        raw -o - "$profile_plist" 2>/dev/null); do
        if [ "$profile_group" = "$application_id" ] || \
            [ "$profile_group" = "$app_id_prefix.*" ]; then
            profile_authorizes_group=true
        fi
        group_index=$((group_index + 1))
    done
    [ "$profile_authorizes_group" = true ] || {
        echo "provisioning profile does not authorize keychain access group $application_id" >&2
        exit 2
    }

    identities=$(/usr/bin/security find-identity -v -p codesigning)
    identity_matches=$(printf '%s\n' "$identities" | /usr/bin/awk \
        -v requested="$signing_identity" '
        /^[[:space:]]*[0-9]+\)[[:space:]]+[0-9A-Fa-f]{40}[[:space:]]+"/ {
            hash = toupper($2)
            name = $0
            sub(/^[^"]*"/, "", name)
            sub(/"[^"]*$/, "", name)
            if (toupper(requested) == hash || requested == name)
                print hash "\t" name
        }')
    match_count=$(printf '%s\n' "$identity_matches" | /usr/bin/awk 'NF { count++ } END { print count + 0 }')
    case $match_count in
        0)
            echo "signing identity not found: $signing_identity" >&2
            exit 2
            ;;
        1) ;;
        *)
            echo "more than one signing identity has that name; use its SHA-1 hash" >&2
            exit 2
            ;;
    esac
    identity_hash=$(printf '%s\n' "$identity_matches" | /usr/bin/awk -F '\t' 'NF { print $1 }')
    identity_name=$(printf '%s\n' "$identity_matches" | /usr/bin/awk -F '\t' 'NF { print $2 }')

    profile_authorizes_identity=false
    certificate_index=0
    while encoded_certificate=$(/usr/bin/plutil -extract \
        "DeveloperCertificates.$certificate_index" \
        raw -o - "$profile_plist" 2>/dev/null); do
        certificate="$scratch/profile-certificate-$certificate_index.der"
        printf '%s' "$encoded_certificate" | /usr/bin/base64 -D >"$certificate"
        certificate_hash=$(/usr/bin/openssl x509 \
            -inform DER -in "$certificate" -noout -fingerprint -sha1 |
            /usr/bin/sed 's/^[^=]*=//; s/://g')
        if [ "$certificate_hash" = "$identity_hash" ]; then
            profile_authorizes_identity=true
        fi
        certificate_index=$((certificate_index + 1))
    done
    [ "$profile_authorizes_identity" = true ] || {
        echo "provisioning profile does not authorize signing identity $identity_name ($identity_hash)" >&2
        exit 2
    }

    entitlements="$scratch/Factorseal.entitlements"
    /usr/bin/sed \
        -e "s/@APPLICATION_ID@/$application_id/g" \
        -e "s/@TEAM_ID@/$team_id/g" \
        "$script_dir/Factorseal.entitlements.in" >"$entitlements"
    cp "$profile" "$app/Contents/embedded.provisionprofile"
else
    # Do not carry a profile from an earlier Team-signed copy into a local build.
    rm -f "$app/Contents/embedded.provisionprofile"
fi

case ${identity_name:-} in
    'Developer ID Application:'*) timestamp=--timestamp ;;
    *) timestamp=--timestamp=none ;;
esac

sign_nested() {
    nested_code=$1
    /usr/bin/codesign \
        --force \
        --sign "$signing_identity" \
        --options runtime \
        "$timestamp" \
        "$nested_code"
}

main_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")
main="$app/Contents/MacOS/$main_name"

# Sign individual nested Mach-O files first. The main executable is signed as
# part of the outer app so it receives the app's Keychain entitlements.
/usr/bin/find "$app/Contents" -type f -print | while IFS= read -r nested_code; do
    [ "$nested_code" != "$main" ] || continue
    /usr/bin/file -b "$nested_code" | /usr/bin/grep -q 'Mach-O' || continue
    sign_nested "$nested_code"
done

# Then sign nested bundle containers from the inside out. Do not use
# `codesign --deep` for signing; it cannot preserve intentional bundle policy.
/usr/bin/find "$app/Contents" -depth -type d \
    \( -name '*.framework' -o -name '*.app' -o -name '*.xpc' \
    -o -name '*.appex' -o -name '*.plugin' \) -print |
    while IFS= read -r nested_bundle; do
        sign_nested "$nested_bundle"
    done

if [ -n "$profile" ]; then
    /usr/bin/codesign \
        --force \
        --sign "$signing_identity" \
        --identifier "$bundle_id" \
        --entitlements "$entitlements" \
        --options runtime \
        "$timestamp" \
        "$app"
else
    /usr/bin/codesign \
        --force \
        --sign "$signing_identity" \
        --identifier "$bundle_id" \
        --options runtime \
        "$timestamp" \
        "$app"
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app"
if [ -n "$profile" ]; then
    signed_entitlements="$scratch/signed-entitlements.plist"
    /usr/bin/codesign -d --entitlements - --xml "$app" >"$signed_entitlements"
    [ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.application-identifier' "$signed_entitlements")" = "$application_id" ]
    [ "$(/usr/libexec/PlistBuddy -c 'Print :com.apple.developer.team-identifier' "$signed_entitlements")" = "$team_id" ]
    [ "$(/usr/libexec/PlistBuddy -c 'Print :keychain-access-groups:0' "$signed_entitlements")" = "$application_id" ]
    signature_details=$(/usr/bin/codesign -dvvv "$app" 2>&1)
    signed_team_id=$(printf '%s\n' "$signature_details" | /usr/bin/sed -n 's/^TeamIdentifier=//p')
    [ "$signed_team_id" = "$team_id" ] || {
        echo "signature Team ID $signed_team_id does not match profile Team ID $team_id" >&2
        exit 1
    }
    case $identity_name in
        'Developer ID Application:'*)
            printf '%s\n' "$signature_details" | /usr/bin/grep -q '^Timestamp=' || {
                echo "Developer ID signature has no secure timestamp" >&2
                exit 1
            }
            ;;
    esac
    echo "Signed $app as $application_id with team $team_id"
else
    echo "Locally signed $app for packaging checks only."
    echo "This app cannot use Factorseal's protected macOS Keychain storage or pass physical acceptance."
fi
