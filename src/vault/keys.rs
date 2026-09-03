//! Installation-root-protected operational and per-document keys.

#[cfg(feature = "key-protection")]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
#[cfg(feature = "key-protection")]
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::EncryptionAlgorithm;

#[cfg(feature = "vault-store")]
use super::{DocumentId, DocumentKind};
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
use super::{InstallationId, VaultId};
use super::{VaultError, VaultResult};

const KEY_BYTES: usize = 32;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
const INSTALLATION_KEY_DOMAIN: &[u8] = b"factorseal/installation-key/v1\0";
#[cfg(feature = "key-protection")]
const INDEX_KEY_DOMAIN: &[u8] = b"factorseal/index-key/v1\0";
#[cfg(feature = "vault-store")]
const DOCUMENT_KEY_DOMAIN: &[u8] = b"factorseal/document-key/v1\0";

/// Root and index capabilities retained only for one unseal lease.
///
/// Document keys and the exportable signing seed are deliberately absent.
/// They are unwrapped into a `Zeroizing` allocation for the operation that
/// needs them. The index key is derived from the root rather than stored, so
/// the metadata file holds one root-wrapped secret: the signing seed.
#[allow(dead_code)]
pub(crate) struct InstallationSecrets {
    root_key: Zeroizing<[u8; KEY_BYTES]>,
    index_key: Zeroizing<[u8; KEY_BYTES]>,
    wrapped_signing_seed: WrappedKey,
}

impl std::fmt::Debug for InstallationSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallationSecrets")
            .field("root_key", &"[REDACTED]")
            .field("index_key", &"[REDACTED]")
            .field("wrapped_signing_seed", &"[ENCRYPTED]")
            .finish()
    }
}

/// Root-wrapped operational secrets persisted in `factorseal.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrappedInstallationSecrets {
    signing_seed: WrappedKey,
}

/// One authenticated root-wrapped key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrappedKey {
    encryption_algorithm: EncryptionAlgorithm,
    nonce: [u8; crate::algorithm::AES_GCM_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl InstallationSecrets {
    #[cfg(feature = "key-protection")]
    pub(crate) fn generate(
        installation_id: InstallationId,
        device_vault_id: VaultId,
        root_key: Zeroizing<[u8; KEY_BYTES]>,
        signing_seed: &[u8; KEY_BYTES],
    ) -> VaultResult<(Self, WrappedInstallationSecrets)> {
        let wrapped = WrappedInstallationSecrets {
            signing_seed: wrap_key(
                &root_key,
                &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
                signing_seed,
            )?,
        };
        Ok((
            Self {
                index_key: derive_index_key(&root_key, installation_id, device_vault_id),
                root_key,
                wrapped_signing_seed: wrapped.signing_seed.clone(),
            },
            wrapped,
        ))
    }

    /// Reopen the operational secrets. The wrapped signing seed is
    /// authenticated here so tampered metadata fails before the store opens.
    #[cfg(feature = "key-protection")]
    pub(crate) fn open(
        installation_id: InstallationId,
        device_vault_id: VaultId,
        root_key: Zeroizing<[u8; KEY_BYTES]>,
        wrapped: &WrappedInstallationSecrets,
    ) -> VaultResult<Self> {
        wrapped.validate()?;
        drop(unwrap_key(
            &root_key,
            &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
            &wrapped.signing_seed,
            "operational signing seed",
        )?);
        Ok(Self {
            index_key: derive_index_key(&root_key, installation_id, device_vault_id),
            root_key,
            wrapped_signing_seed: wrapped.signing_seed.clone(),
        })
    }

    #[cfg(feature = "vault-store")]
    pub(crate) fn index_key(&self) -> &[u8; KEY_BYTES] {
        &self.index_key
    }

    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    pub(crate) fn signing_seed(
        &self,
        installation_id: InstallationId,
        device_vault_id: VaultId,
    ) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
        unwrap_key(
            &self.root_key,
            &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
            &self.wrapped_signing_seed,
            "operational signing seed",
        )
    }

    #[cfg(feature = "vault-store")]
    pub(crate) fn generate_document_key(
        &self,
        installation_id: InstallationId,
        vault_id: VaultId,
        document_id: DocumentId,
        kind: DocumentKind,
        epoch: u64,
    ) -> VaultResult<(Zeroizing<[u8; KEY_BYTES]>, WrappedKey)> {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(&mut *key)?;
        let wrapped = wrap_key(
            &self.root_key,
            &document_key_aad(installation_id, vault_id, document_id, kind, epoch),
            &key,
        )?;
        Ok((key, wrapped))
    }

    #[cfg(feature = "vault-store")]
    pub(crate) fn unwrap_document_key(
        &self,
        installation_id: InstallationId,
        vault_id: VaultId,
        document_id: DocumentId,
        kind: DocumentKind,
        epoch: u64,
        wrapped: &WrappedKey,
    ) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
        unwrap_key(
            &self.root_key,
            &document_key_aad(installation_id, vault_id, document_id, kind, epoch),
            wrapped,
            "document data-encryption key",
        )
    }
}

impl WrappedInstallationSecrets {
    pub(crate) fn validate(&self) -> VaultResult<()> {
        self.signing_seed.validate()
    }
}

impl WrappedKey {
    pub(crate) fn validate(&self) -> VaultResult<()> {
        if self.encryption_algorithm != EncryptionAlgorithm::Aes256Gcm
            || self.ciphertext.len() != KEY_BYTES + 16
        {
            return Err(VaultError::Protection(
                "wrapped key structure is invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The document-index key is a keyed digest of the installation identity
/// under the root. It is only ever used to derive opaque document IDs, so
/// deriving it costs nothing and removes one wrapped blob from the metadata.
#[cfg(feature = "key-protection")]
fn derive_index_key(
    root_key: &[u8; KEY_BYTES],
    installation_id: InstallationId,
    device_vault_id: VaultId,
) -> Zeroizing<[u8; KEY_BYTES]> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(root_key).expect("HMAC accepts a 256-bit root key");
    mac.update(INDEX_KEY_DOMAIN);
    mac.update(installation_id.as_bytes());
    mac.update(device_vault_id.as_bytes());
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(&mac.finalize().into_bytes());
    key
}

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
fn wrap_key(
    root_key: &[u8; KEY_BYTES],
    aad: &[u8],
    plaintext: &[u8; KEY_BYTES],
) -> VaultResult<WrappedKey> {
    let encrypted =
        crate::crypto::encrypt(root_key, aad, plaintext).map_err(|_| VaultError::Crypto)?;
    Ok(WrappedKey {
        encryption_algorithm: encrypted.algorithm,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
fn unwrap_key(
    root_key: &[u8; KEY_BYTES],
    aad: &[u8],
    wrapped: &WrappedKey,
    label: &str,
) -> VaultResult<Zeroizing<[u8; KEY_BYTES]>> {
    wrapped.validate()?;
    let plaintext = crate::crypto::decrypt(
        wrapped.encryption_algorithm,
        root_key,
        &wrapped.nonce,
        aad,
        &wrapped.ciphertext,
    )
    .map_err(|_| VaultError::Protection(format!("cannot authenticate {label}")))?;
    if plaintext.len() != KEY_BYTES {
        return Err(VaultError::Protection(format!("invalid {label} length")));
    }
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
fn installation_key_aad(
    installation_id: InstallationId,
    device_vault_id: VaultId,
    purpose: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(INSTALLATION_KEY_DOMAIN.len() + 32 + 8 + purpose.len());
    aad.extend_from_slice(INSTALLATION_KEY_DOMAIN);
    aad.extend_from_slice(installation_id.as_bytes());
    aad.extend_from_slice(device_vault_id.as_bytes());
    append_bytes(&mut aad, purpose);
    aad
}

#[cfg(feature = "vault-store")]
fn document_key_aad(
    installation_id: InstallationId,
    vault_id: VaultId,
    document_id: DocumentId,
    kind: DocumentKind,
    epoch: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOCUMENT_KEY_DOMAIN.len() + 16 + 16 + 32 + 64);
    aad.extend_from_slice(DOCUMENT_KEY_DOMAIN);
    aad.extend_from_slice(installation_id.as_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(document_id.as_bytes());
    append_bytes(&mut aad, kind.as_str().as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(all(test, feature = "key-protection", feature = "vault-store"))]
mod tests {
    use super::*;

    #[test]
    fn operational_keys_are_identity_bound() {
        let installation_id = InstallationId::from_bytes([7; 16]);
        let vault_id = VaultId::from_bytes([8; 16]);
        let root = Zeroizing::new([10; KEY_BYTES]);
        let signing = [11; KEY_BYTES];
        let (secrets, wrapped) =
            InstallationSecrets::generate(installation_id, vault_id, root, &signing).unwrap();
        let reopened = InstallationSecrets::open(
            installation_id,
            vault_id,
            Zeroizing::new([10; KEY_BYTES]),
            &wrapped,
        )
        .unwrap();
        assert_eq!(reopened.index_key(), secrets.index_key());
        assert_ne!(reopened.index_key(), &[10; KEY_BYTES]);
        assert_eq!(
            *reopened.signing_seed(installation_id, vault_id).unwrap(),
            signing
        );
        assert!(
            reopened
                .signing_seed(InstallationId::from_bytes([6; 16]), vault_id)
                .is_err()
        );
        assert!(
            reopened
                .signing_seed(installation_id, VaultId::from_bytes([6; 16]))
                .is_err()
        );
        // A different installation derives a different index key from the
        // same root, and cannot open the other installation's seed at all.
        assert!(
            InstallationSecrets::open(
                InstallationId::from_bytes([6; 16]),
                vault_id,
                Zeroizing::new([10; KEY_BYTES]),
                &wrapped,
            )
            .is_err()
        );
        assert!(
            InstallationSecrets::open(
                installation_id,
                vault_id,
                Zeroizing::new([12; KEY_BYTES]),
                &wrapped,
            )
            .is_err()
        );
    }

    #[test]
    fn document_keys_are_independent_and_context_bound() {
        let installation_id = InstallationId::from_bytes([7; 16]);
        let vault_id = VaultId::from_bytes([8; 16]);
        let document_id = DocumentId::from_bytes([9; 32]);
        let signing = [11; KEY_BYTES];
        let (_, wrapped_installation) = InstallationSecrets::generate(
            installation_id,
            vault_id,
            Zeroizing::new([10; KEY_BYTES]),
            &signing,
        )
        .unwrap();
        let reopened = InstallationSecrets::open(
            installation_id,
            vault_id,
            Zeroizing::new([10; KEY_BYTES]),
            &wrapped_installation,
        )
        .unwrap();
        let (key, wrapped_key) = reopened
            .generate_document_key(
                installation_id,
                vault_id,
                document_id,
                DocumentKind::SecretSpecProviderCache,
                0,
            )
            .unwrap();
        let unwrapped = reopened
            .unwrap_document_key(
                installation_id,
                vault_id,
                document_id,
                DocumentKind::SecretSpecProviderCache,
                0,
                &wrapped_key,
            )
            .unwrap();
        assert_eq!(*unwrapped, *key);
        let (other_key, other_wrapped) = reopened
            .generate_document_key(
                installation_id,
                vault_id,
                DocumentId::from_bytes([13; 32]),
                DocumentKind::SecretSpecProviderCache,
                0,
            )
            .unwrap();
        assert_ne!(*other_key, *key);
        assert_ne!(other_wrapped, wrapped_key);
        assert!(
            reopened
                .unwrap_document_key(
                    installation_id,
                    VaultId::from_bytes([12; 16]),
                    document_id,
                    DocumentKind::SecretSpecProviderCache,
                    0,
                    &wrapped_key,
                )
                .is_err()
        );
        for (changed_installation, changed_document, changed_kind, changed_epoch) in [
            (
                InstallationId::from_bytes([6; 16]),
                document_id,
                DocumentKind::SecretSpecProviderCache,
                0,
            ),
            (
                installation_id,
                DocumentId::from_bytes([6; 32]),
                DocumentKind::SecretSpecProviderCache,
                0,
            ),
            (installation_id, document_id, DocumentKind::LocalKeyring, 0),
            (
                installation_id,
                document_id,
                DocumentKind::SecretSpecProviderCache,
                1,
            ),
        ] {
            assert!(
                reopened
                    .unwrap_document_key(
                        changed_installation,
                        vault_id,
                        changed_document,
                        changed_kind,
                        changed_epoch,
                        &wrapped_key,
                    )
                    .is_err()
            );
        }
    }
}
