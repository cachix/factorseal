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

Migration is currently manual, one connection at a time. There is no automatic
scan or deletion of passwords in system profiles or another keyring.

1. Make sure you can recover or re-enter the existing password before changing
   its storage settings. Keep your current connection active during setup.
2. Start FactorSeal Desktop and unlock the vault.
3. In your network connection editor, choose **Store the password only for this
   user** (the wording depends on the editor), then save the connection. This
   sets the secret's NetworkManager flags to `agent-owned`. For personal Wi-Fi
   the property is `802-11-wireless-security.psk-flags=1`; for an enterprise
   password it is `802-1x.password-flags=1`. Certificate passwords and PINs each
   have independent flags. Preserve the existing EAP and certificate settings.
4. Reconnect when a brief network interruption is acceptable. If FactorSeal
   requests the password, enter it there. Confirm that the credential appears
   under **System integrations → Wi-Fi passwords**.
5. Reconnect again with FactorSeal unlocked to verify that the saved credential
   works. Only then remove any leftover copy from the previous keyring using
   that keyring's UI. Changing flags alone does not prove an old copy was erased.

Other desktop components may register their own Wi-Fi agents. NetworkManager's
agent-owned flag chooses agent storage, not a named provider. If another agent
answers instead, configure that desktop component's Wi-Fi agent where supported;
confirm FactorSeal receives the request before removing existing credentials.
FactorSeal does not disable other agents or change network profiles itself.

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
types. They do not change the host's network profiles or establish real EAP
authentication. A real access-point check should cover personal Wi-Fi and the
enterprise EAP methods used by the deployment.
