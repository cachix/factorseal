# FactorSeal for Android and iOS privacy policy

Last updated 23 October 2026.

FactorSeal has no accounts and no servers of its own. It collects no analytics,
no crash reports and no advertising data, and it has no ads or trackers.

## Your vault

Your vault, its keys and your settings stay on your phone. The vault is
encrypted with keys held by the Android Keystore or the Secure Enclave.
FactorSeal leaves the vault and your settings out of system backups and device
transfers. A copy leaves your phone only when you export a backup or a transfer
file yourself. Uninstalling FactorSeal deletes the vault from your phone.

Face ID, Touch ID and fingerprint unlock are handled by your phone. FactorSeal
never receives your face or fingerprint data.

## Sync

FactorSeal goes online only after you start pairing a device, and only while
the app is open. Your devices send each other encrypted changes that nobody
else can read.

To find and reach your devices, FactorSeal uses public servers run by n0, the
company that makes the iroh networking library. Relay servers pass encrypted
traffic between your devices when they cannot connect directly. A discovery
server stores which relay your device uses so your other devices can find it.

These servers see your IP address, a random ID for each device, which devices
talk to each other, and when and how much data they send. They never see your
secrets or your device names. Paired devices see each other's names, and they
see each other's IP addresses when they connect directly. If your network's DNS
does not answer, FactorSeal looks up these servers through Cloudflare, Google
or Quad9 public DNS.

## Camera

FactorSeal uses the camera only to scan QR codes for one-time passwords and
pairing. It reads each image on your phone and never saves or sends it.

## Autofill on Android

When an app or website asks for a login, Android tells FactorSeal its name or
address. FactorSeal matches it against your vault on your phone and sends
nothing over the network.

## Changes and questions

Changes to this policy appear in this file with a new date. Ask questions in
the [FactorSeal issues](https://github.com/cachix/factorseal/issues).
