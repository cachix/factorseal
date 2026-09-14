# Wi-Fi credentials on Linux

FactorSeal Desktop registers a NetworkManager secret agent while it is running.
Saved credentials appear under **System integrations → Wi-Fi passwords** and
are encrypted in the vault. Connections are identified by UUID, so two networks
with the same display name do not share a password.

Supported connections include WPA-PSK, WPA3-SAE, and enterprise Wi-Fi using
802.1X passwords, private key passwords, and certificate/token PINs. NetworkManager
continues to manage the connection, certificates, and server verification.
WEP, VPN authentication, and wired 802.1X are not handled by this adapter.

## Move an existing connection

1. Start FactorSeal Desktop and unlock the vault. Unlock the previous keyring
   too if it holds your Wi-Fi passwords.
2. Open **System integrations → Wi-Fi passwords** and select **Move existing
   Wi-Fi passwords**. Use this with FactorSeal as your only Wi-Fi secret agent.
3. Review the result for each connection. NetworkManager may require system
   authorization to read credentials or update profiles. Resolve reported
   permission, locked-keyring, or conflicting-value errors and retry.
4. When convenient, reconnect with FactorSeal unlocked to verify authentication
   against your access point. Migration itself does not disconnect devices.

Migration reads the Wi-Fi profiles visible to your user and obtains existing
secrets through NetworkManager and the current Secret Service keyring. Keyring
lookup is limited to NetworkManager's `connection-uuid`, `setting-name`, and
`setting-key` attributes. Other formats, including KWallet-native entries not
exposed through Secret Service, need to be imported or entered separately.

For each profile, FactorSeal copies eligible secrets into the vault and reads
them back to verify the values. It then updates the profile's per-secret flags
to `agent-owned` and persists the profile through NetworkManager. NetworkManager's
settings plugin omits agent-owned secrets from its persistent profile. After
verifying the flags and vault values again, FactorSeal removes matching old
keyring entries. It rechecks each entry's identity and value before deletion.
If the previous keyring is unavailable, the result explicitly reports that its
copies were not checked. Locked collections and deletion prompts are reported
for the user to resolve; they are not silently approved.

This requires NetworkManager 1.44 or newer: migration uses `Update2` with a
nonzero `VersionId` to reject concurrent profile edits. Unsaved profiles are
left alone. Updates use `to-disk | no-reapply`, preserving EAP, certificate,
network, and other non-secret settings. One-time, not-required, and unknown
secret flags remain unchanged. A different existing vault value is a conflict,
not an instruction to overwrite it.

A rejected or timed-out profile update keeps the verified vault copy. A cleanup
failure keeps the old keyring copy too. Retrying verifies these copies again
before completing migration; there is no rollback that deletes the recovery
copy. Sealing the vault stops subsequent migration work. This verifies storage
and routing flags, not a live connection or removal from historical backups.

Other desktop components may register their own Wi-Fi agents. NetworkManager's
agent-owned flag chooses agent storage, not a named provider. If another agent
answers instead, configure that desktop component's Wi-Fi agent where supported;
confirm FactorSeal receives the request before removing existing credentials.
FactorSeal does not disable other agents. Network profiles change only when you
select the migration action or edit them in your connection editor.

## Unlocking and temporary credentials

Interactive connection requests can ask you to unlock FactorSeal and enter a
missing password. Background requests fail while the vault is sealed. A request
for a new password bypasses the stored value. Canceling a connection request
expires its pending FactorSeal dialog.

Choose **Ask for this password every time** for one-time passwords and PINs that
should not persist. NetworkManager calls this `not-saved`; FactorSeal returns the
entered value for that request and removes an older saved value when the request
succeeds. It also removes values omitted or marked nonpersistent in a
`SaveSecrets` update. Binary enterprise passwords can be stored and retrieved
through the agent API; the entry dialog accepts text only.

## Protocol and testing

The adapter exports the [NetworkManager SecretAgent interface](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.SecretAgent.html)
on the system bus and authenticates every call against NetworkManager's current
unique bus owner. Registration retries after daemon or bus restarts. The vault
worker enforces a separate credential namespace and an executable-bound grant.
[Secret flags](https://networkmanager.dev/docs/api/latest/secrets-flags.html)
control ownership and persistence separately for every property.

Local tests use a mock NetworkManager on a private D-Bus session to exercise
registration, owner replacement, cancellation, storage, and enterprise wire
types. Migration tests cover copy-before-update ordering, rejected updates,
retries, concurrent edits, conflicts, temporary credentials, and keyring cleanup.
They do not change the host's network profiles or establish real EAP
authentication. A real access-point check should cover personal Wi-Fi and the
enterprise EAP methods used by the deployment.
