# Native acceptance record

Copy this file for each physical-host run and attach the completed, redacted
record to the release approval. Do not include a nested factor, secret value,
vault ID, device key ID, full username, or raw logs containing those values.

| Field | Value |
| --- | --- |
| Release candidate version and SHA-256 | |
| Date, operator, and independent reviewer | |
| OS edition/version/build and architecture | |
| Device model, firmware, and TPM/Secure Enclave details | |
| Installed artifact signature/notarization verification | |
| Factorseal recorded platform and hardware backend | |
| Native verification prompt observed (where policy requires it) | |
| Initial hardware-backed create and unseal | pass / fail |
| Native IPC set/get/delete | pass / fail |
| Lock/session switch seals the vault | pass / fail |
| Sleep seals the vault before suspend | pass / fail |
| Logout/disconnect seals the vault | pass / fail |
| Shutdown preparation seals the vault | pass / fail |
| Re-unseal recovers the value | pass / fail |
| Installed login launcher and askpass flow | pass / fail |
| Redacted runner output attached | yes / no |
| Exceptions or failures | |

A result is acceptable only when every applicable line passes. A missing native
prompt, software fallback, lifecycle timeout, failed re-unseal, or unsigned
artifact blocks the release until investigated and rerun.
