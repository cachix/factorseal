---
title: 'Introducing FactorSeal: give apps a secret, not your vault'
description: A hardware-backed local vault that authorizes the exact operation an app asks for and returns only the requested value.
date: 2026-09-03
authors: domen
---

:::note
This post is from September 2026. Since then, FactorSeal has added experimental sync between devices and an Android and iOS app. There are no signed releases yet.
:::

Password managers made it practical for people to keep unique passwords. But most were designed around a human opening a vault: unlock it, and the trusted session can reach everything inside. That is a poor default when software, not a person, needs one credential to do one job.

FactorSeal is our answer. It is an open-source secrets vault written in Rust, kept on your device, and protected at rest by the TPM or Secure Enclave. Instead of treating an unlocked vault as a blanket capability, FactorSeal checks every request against the identity of the calling application and the scope you granted it.

> The unit of access should be the requested secret, not the unlocked vault.

## Unlocking is not the same as authorizing

In the common password-manager model, the vault is the security boundary. Once it is unlocked, a trusted client often operates with access to the collection as a whole. That makes sense for a person browsing and editing their passwords. It makes less sense for a build tool that needs `REGISTRY_TOKEN`, or an app that needs one database password.

The difference is blast radius. If a client only needs one value, giving it a path to unrelated logins, recovery codes, and API keys creates authority it never needed. A confirmation dialog does not fix that if the permission behind it is still broad.

Scope is checked again for every operation, even while the vault has an active unseal lease.

## A permission has coordinates

A FactorSeal grant binds who is asking, what kind of document they may reach, the exact partition or address, and which operations are allowed. Reading, writing, listing, and deleting are separate permissions. Grants may also expire.

For example, you can grant an app access to only one specific SecretSpec project, such as `storefront`. The app can read that project's secrets through FactorSeal while secrets belonging to your other projects remain outside the grant. You can limit the allowed operations to reads, so access to the project does not also allow the app to change or delete its secrets.

1. **Authenticate the caller.** The native transport supplies the application identity. The request cannot claim its own.
2. **Match the exact grant.** Application, document scope, address, operation, and expiry must all agree.
3. **Open the requested document.** Only that document's independent encryption key is unwrapped for the operation.
4. **Return one result.** Only the requested value is sent back to the authenticated client.

This does not mean interrupting you with a prompt for every read. Approval can be durable or time-limited. It means every read is still authorized as its own scoped operation. An earlier unlock never silently turns into permission for the rest of the vault.

## The cloud is optional

FactorSeal's current device vault is local and does not synchronize. Encrypted state stays on the machine, and applications talk to a per-user service over authenticated native IPC. The installation root is hardware-bound and retained only during a bounded unseal lease. Document keys and plaintext are short-lived.

FactorSeal can serve as a durable keyring for local credentials or as a disposable cache for [SecretSpec](https://secretspec.dev/concepts/providers/caching/). A remote provider can be resolved once, then subsequent reads stay fast and local without granting the requesting tool access to a general-purpose password vault.

- **Hardware bound:** TPM or Secure Enclave protects the installation root at rest.
- **App scoped:** grants bind the authenticated executable, not a client-supplied name.
- **Document isolated:** each document has an independent encryption key.

## Built in the open, early

FactorSeal is available today as a developer preview for Windows, macOS, and Linux. The preview is unaudited and is not ready for production secrets. We are sharing it now because the access model should be inspectable, and because better boundaries get stronger when people challenge them.

If "give the app exactly what it asked for" sounds like the right primitive, try the preview, [read the security model](/security/), and tell us where it falls short.

[Explore the source](https://github.com/cachix/factorseal).
