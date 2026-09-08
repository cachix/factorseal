"""Validate decoded app/extension profiles before signing credential exchange."""

import hashlib
import plistlib
import sys
from pathlib import Path


CAPABILITY = "com.apple.developer.authentication-services.autofill-credential-provider"


def extension_entitlements(app, extension, bundle_id, identity_hash):
    team = app["TeamIdentifier"][0]
    prefix = app["ApplicationIdentifierPrefix"][0]
    application_id = f"{prefix}.{bundle_id}.credentials"
    if extension.get("TeamIdentifier") != [team]:
        raise ValueError("extension profile must belong to the app's Apple team")
    if extension.get("ApplicationIdentifierPrefix") != [prefix]:
        raise ValueError("extension profile must use the app's identifier prefix")
    for profile in (app, extension):
        if profile.get("Entitlements", {}).get(CAPABILITY) is not True:
            raise ValueError("both profiles must authorize the AutoFill credential-provider entitlement")
    if extension["Entitlements"].get("com.apple.application-identifier") != application_id:
        raise ValueError("extension profile does not authorize the credential extension bundle identifier")
    certificates = extension.get("DeveloperCertificates", [])
    if not any(hashlib.sha1(cert).hexdigest().upper() == identity_hash.upper() for cert in certificates):
        raise ValueError("extension profile does not authorize the selected signing certificate")
    return {
        "com.apple.application-identifier": application_id,
        "com.apple.developer.team-identifier": team,
        "com.apple.security.app-sandbox": True,
        CAPABILITY: True,
    }


def main():
    if len(sys.argv) != 7:
        raise ValueError("expected APP_PROFILE EXTENSION_PROFILE BUNDLE_ID CERT_HASH APP_ENTITLEMENTS EXTENSION_ENTITLEMENTS")
    app_path, extension_path, bundle_id, identity_hash, main_path, output = sys.argv[1:]
    app = plistlib.loads(Path(app_path).read_bytes())
    extension = plistlib.loads(Path(extension_path).read_bytes())
    entitlements = extension_entitlements(app, extension, bundle_id, identity_hash)
    main_entitlements = plistlib.loads(Path(main_path).read_bytes())
    main_entitlements[CAPABILITY] = True
    Path(main_path).write_bytes(plistlib.dumps(main_entitlements))
    Path(output).write_bytes(plistlib.dumps(entitlements))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, IndexError, TypeError, OSError) as error:
        sys.exit(f"credential exchange signing: {error}")
