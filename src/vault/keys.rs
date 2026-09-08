//! Installation-root-protected operational and per-document keys.

#[cfg(feature = "key-protection")]
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
#[cfg(feature = "key-protection")]
use sha2::Sha256;

use crate::EncryptionAlgorithm;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
use crate::security::memory::LockedKey;

#[cfg(feature = "vault-store")]
use super::{DocumentId, DocumentKind};
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
use super::{InstallationId, VaultId};
use super::{VaultError, VaultResult};

const KEY_BYTES: usize = 32;

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
struct InstallationSigner<'a> {
    secrets: &'a InstallationSecrets,
    installation: InstallationId,
    vault: VaultId,
}

#[cfg(any(feature = "key-protection", feature = "vault-store"))]
impl super::signature::SigningProvider for InstallationSigner<'_> {
    fn public_key(&self) -> VaultResult<Vec<u8>> {
        if self.secrets.wrapped_enclave_key.is_some() {
            return self
                .secrets
                .enclave_signer(self.installation, self.vault)?
                .public_key();
        }
        let seed = self.secrets.signing_seed(self.installation, self.vault)?;
        super::signature::SoftwareSigner(&seed).public_key()
    }

    #[cfg(feature = "vault-store")]
    fn sign(&self, payload: &[u8]) -> VaultResult<Vec<u8>> {
        if self.secrets.wrapped_enclave_key.is_some() {
            return self
                .secrets
                .enclave_signer(self.installation, self.vault)?
                .sign(payload);
        }
        let seed = self.secrets.signing_seed(self.installation, self.vault)?;
        super::signature::SoftwareSigner(&seed).sign(payload)
    }
}
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
const INSTALLATION_KEY_DOMAIN: &[u8] = b"factorseal/installation-key/v1\0";
#[cfg(feature = "key-protection")]
const INDEX_KEY_DOMAIN: &[u8] = b"factorseal/index-key/v1\0";
#[cfg(feature = "vault-store")]
const DOCUMENT_KEY_DOMAIN: &[u8] = b"factorseal/document-key/v1\0";

/// Root and index capabilities retained only for one unseal lease.
///
/// Document keys and signing capabilities are unwrapped only for an operation.
/// Software signing seeds use guarded, locked allocations; enclave references
/// never contain exportable private material. The root and its derived index
/// share one locked page; temporary bootstrap sources still zeroize.
#[allow(dead_code)]
pub(crate) struct InstallationSecrets {
    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    retained_keys: LockedKey<64>,
    wrapped_signing_seed: Option<WrappedKey>,
    wrapped_enclave_key: Option<WrappedSigningReference>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_seed: Option<WrappedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enclave_mldsa65: Option<WrappedSigningReference>,
}

/// A root-encrypted CryptoKit capability. Keeping this separate from WrappedKey
/// preserves the strict 32-byte plaintext contract of document and reader keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedSigningReference {
    encryption_algorithm: EncryptionAlgorithm,
    nonce: [u8; crate::algorithm::AES_GCM_NONCE_BYTES],
    ciphertext: Vec<u8>,
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
    pub(crate) fn generate_new(
        installation: InstallationId,
        vault: VaultId,
        root: LockedKey<KEY_BYTES>,
        platform: super::VaultPlatform,
        native_signing: bool,
    ) -> VaultResult<(Self, WrappedInstallationSecrets)> {
        #[cfg(all(feature = "hardware", target_os = "macos"))]
        if native_signing
            && platform == super::VaultPlatform::Macos
            && hardwareseal::apple_pq::is_available()
        {
            let key =
                hardwareseal::apple_pq::MlDsa65Key::generate(hardwareseal::AccessPolicy::None)
                    .map_err(|error| VaultError::Protection(error.to_string()))?;
            let encrypted = crate::crypto::encrypt(
                &root,
                &installation_key_aad(installation, vault, b"secure-enclave-mldsa65-reference-v1"),
                key.reference(),
            )
            .map_err(|_| VaultError::Crypto)?;
            let reference = WrappedSigningReference {
                encryption_algorithm: encrypted.algorithm,
                nonce: encrypted.nonce,
                ciphertext: encrypted.ciphertext,
            };
            let secrets = Self {
                retained_keys: retain_keys(&root, installation, vault)?,
                wrapped_signing_seed: None,
                wrapped_enclave_key: Some(reference.clone()),
            };
            return Ok((
                secrets,
                WrappedInstallationSecrets {
                    signing_seed: None,
                    enclave_mldsa65: Some(reference),
                },
            ));
        }
        let _ = (platform, native_signing);
        let mut seed = LockedKey::<KEY_BYTES>::zeroed()?;
        getrandom::fill(&mut *seed)?;
        Self::generate(installation, vault, root, &seed)
    }

    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    fn enclave_signer(
        &self,
        installation: InstallationId,
        vault: VaultId,
    ) -> VaultResult<Box<dyn super::signature::SigningProvider>> {
        #[cfg(all(feature = "hardware", target_os = "macos"))]
        {
            let wrapped = self.wrapped_enclave_key.as_ref().ok_or_else(|| {
                VaultError::Protection("missing enclave signing reference".into())
            })?;
            let reference = crate::crypto::decrypt(
                wrapped.encryption_algorithm,
                self.root_key(),
                &wrapped.nonce,
                &installation_key_aad(installation, vault, b"secure-enclave-mldsa65-reference-v1"),
                &wrapped.ciphertext,
            )
            .map_err(|_| {
                VaultError::Protection("cannot authenticate enclave signing reference".into())
            })?;
            let key = hardwareseal::apple_pq::MlDsa65Key::from_reference(&reference)
                .map_err(|error| VaultError::Protection(error.to_string()))?;
            Ok(Box::new(super::signature::EnclaveSigner(key)))
        }
        #[cfg(not(all(feature = "hardware", target_os = "macos")))]
        {
            let _ = (self, installation, vault);
            Err(VaultError::Protection(
                "this vault requires macOS 26+ Secure Enclave signing support".into(),
            ))
        }
    }

    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    pub(crate) fn signer(
        &self,
        installation: InstallationId,
        vault: VaultId,
    ) -> impl super::signature::SigningProvider + '_ {
        InstallationSigner {
            secrets: self,
            installation,
            vault,
        }
    }

    #[cfg(feature = "key-protection")]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consume and wipe the bootstrap root after moving it into locked memory"
    )]
    pub(crate) fn generate(
        installation_id: InstallationId,
        device_vault_id: VaultId,
        root_key: LockedKey<KEY_BYTES>,
        signing_seed: &[u8; KEY_BYTES],
    ) -> VaultResult<(Self, WrappedInstallationSecrets)> {
        let wrapped = WrappedInstallationSecrets {
            signing_seed: Some(wrap_key(
                &root_key,
                &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
                signing_seed,
            )?),
            enclave_mldsa65: None,
        };
        Ok((
            Self {
                retained_keys: retain_keys(&root_key, installation_id, device_vault_id)?,
                wrapped_signing_seed: wrapped.signing_seed.clone(),
                wrapped_enclave_key: None,
            },
            wrapped,
        ))
    }

    /// Authenticate the selected signing capability before the store opens.
    #[cfg(feature = "key-protection")]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "consume and wipe the bootstrap root after moving it into locked memory"
    )]
    pub(crate) fn open(
        installation_id: InstallationId,
        device_vault_id: VaultId,
        root_key: LockedKey<KEY_BYTES>,
        wrapped: &WrappedInstallationSecrets,
    ) -> VaultResult<Self> {
        wrapped.validate()?;
        if let Some(seed) = &wrapped.signing_seed {
            drop(unwrap_key(
                &root_key,
                &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
                seed,
                "operational signing seed",
            )?);
        }
        let secrets = Self {
            retained_keys: retain_keys(&root_key, installation_id, device_vault_id)?,
            wrapped_signing_seed: wrapped.signing_seed.clone(),
            wrapped_enclave_key: wrapped.enclave_mldsa65.clone(),
        };
        if secrets.wrapped_enclave_key.is_some() {
            // Authentication of the reference and native reconstruction happen
            // before a caller may open the database. No software fallback.
            secrets
                .enclave_signer(installation_id, device_vault_id)?
                .public_key()?;
        }
        Ok(secrets)
    }

    #[cfg(feature = "vault-store")]
    pub(crate) fn index_key(&self) -> &[u8; KEY_BYTES] {
        self.retained_keys[KEY_BYTES..]
            .try_into()
            .expect("index key length")
    }

    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    fn root_key(&self) -> &[u8; KEY_BYTES] {
        self.retained_keys[..KEY_BYTES]
            .try_into()
            .expect("root key length")
    }

    #[cfg(any(feature = "key-protection", feature = "vault-store"))]
    pub(crate) fn signing_seed(
        &self,
        installation_id: InstallationId,
        device_vault_id: VaultId,
    ) -> VaultResult<LockedKey<KEY_BYTES>> {
        unwrap_key(
            self.root_key(),
            &installation_key_aad(installation_id, device_vault_id, b"signing-seed"),
            self.wrapped_signing_seed.as_ref().ok_or_else(|| {
                VaultError::Protection("Secure Enclave signing keys have no exportable seed".into())
            })?,
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
    ) -> VaultResult<(LockedKey<KEY_BYTES>, WrappedKey)> {
        let mut key = LockedKey::zeroed()?;
        getrandom::fill(&mut *key)?;
        let wrapped = wrap_key(
            self.root_key(),
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
    ) -> VaultResult<LockedKey<KEY_BYTES>> {
        unwrap_key(
            self.root_key(),
            &document_key_aad(installation_id, vault_id, document_id, kind, epoch),
            wrapped,
            "document data-encryption key",
        )
    }
}

#[cfg(feature = "key-protection")]
fn retain_keys(
    root: &[u8; KEY_BYTES],
    installation: InstallationId,
    vault: VaultId,
) -> VaultResult<LockedKey<64>> {
    let mut keys = LockedKey::zeroed()?;
    keys[..KEY_BYTES].copy_from_slice(root);
    keys[KEY_BYTES..].copy_from_slice(&*derive_index_key(root, installation, vault)?);
    Ok(keys)
}

impl WrappedInstallationSecrets {
    pub(crate) fn validate(&self) -> VaultResult<()> {
        match (&self.signing_seed, &self.enclave_mldsa65) {
            (Some(seed), None) => seed.validate(),
            (None, Some(reference))
                if reference.encryption_algorithm == EncryptionAlgorithm::Aes256Gcm
                    && (17..=32768 + 16).contains(&reference.ciphertext.len()) =>
            {
                Ok(())
            }
            _ => Err(VaultError::Protection(
                "installation must contain exactly one valid signing provider".into(),
            )),
        }
    }

    pub(crate) const fn uses_enclave_signer(&self) -> bool {
        self.enclave_mldsa65.is_some()
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
) -> VaultResult<LockedKey<KEY_BYTES>> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(root_key).expect("HMAC accepts a 256-bit root key");
    mac.update(INDEX_KEY_DOMAIN);
    mac.update(installation_id.as_bytes());
    mac.update(device_vault_id.as_bytes());
    let mut key = LockedKey::zeroed()?;
    key.copy_from_slice(&mac.finalize().into_bytes());
    Ok(key)
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
) -> VaultResult<LockedKey<KEY_BYTES>> {
    wrapped.validate()?;
    let plaintext = crate::crypto::decrypt_key(
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
    Ok(plaintext)
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
    fn signing_metadata_rejects_missing_ambiguous_and_unsupported_providers() {
        let installation = InstallationId::from_bytes([7; 16]);
        let vault = VaultId::from_bytes([8; 16]);
        let (_, mut wrapped) = InstallationSecrets::generate(
            installation,
            vault,
            LockedKey::from_slice(&[10; 32]).unwrap(),
            &[11; 32],
        )
        .unwrap();
        let reference = WrappedSigningReference {
            encryption_algorithm: EncryptionAlgorithm::Aes256Gcm,
            nonce: [0; 12],
            ciphertext: vec![0; 32],
        };
        wrapped.enclave_mldsa65 = Some(reference);
        assert!(
            wrapped.validate().is_err(),
            "two providers must not select one implicitly"
        );
        wrapped.signing_seed = None;
        assert!(wrapped.validate().is_ok());
        #[cfg(not(all(feature = "hardware", target_os = "macos")))]
        assert!(
            InstallationSecrets::open(
                installation,
                vault,
                LockedKey::from_slice(&[10; 32]).unwrap(),
                &wrapped
            )
            .is_err()
        );
        wrapped.enclave_mldsa65 = None;
        assert!(wrapped.validate().is_err());
    }

    #[test]
    fn software_provider_preserves_identity_and_authenticates_before_signing() {
        use crate::vault::signature::{self, SigningProvider as _};
        let installation = InstallationId::from_bytes([7; 16]);
        let vault = VaultId::from_bytes([8; 16]);
        let (keys, wrapped) = InstallationSecrets::generate(
            installation,
            vault,
            LockedKey::from_slice(&[10; 32]).unwrap(),
            &[11; 32],
        )
        .unwrap();
        let legacy = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(legacy.as_object().unwrap().len(), 1);
        assert!(legacy.get("signing_seed").is_some());
        let signer = keys.signer(installation, vault);
        let public = signer.public_key().unwrap();
        assert_eq!(public, signature::public_key_for_seed(&[11; 32]));
        let proof = signer.sign(b"provider transcript").unwrap();
        signature::verify(&public, b"provider transcript", &proof).unwrap();
        assert!(
            keys.signer(InstallationId::from_bytes([1; 16]), vault)
                .sign(b"provider transcript")
                .is_err()
        );
    }

    #[test]
    fn operational_keys_are_identity_bound() {
        let installation_id = InstallationId::from_bytes([7; 16]);
        let vault_id = VaultId::from_bytes([8; 16]);
        let root = LockedKey::from_slice(&[10; KEY_BYTES]).unwrap();
        let signing = [11; KEY_BYTES];
        let (secrets, wrapped) =
            InstallationSecrets::generate(installation_id, vault_id, root, &signing).unwrap();
        let reopened = InstallationSecrets::open(
            installation_id,
            vault_id,
            LockedKey::from_slice(&[10; KEY_BYTES]).unwrap(),
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
                LockedKey::from_slice(&[10; KEY_BYTES]).unwrap(),
                &wrapped,
            )
            .is_err()
        );
        assert!(
            InstallationSecrets::open(
                installation_id,
                vault_id,
                LockedKey::from_slice(&[12; KEY_BYTES]).unwrap(),
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
            LockedKey::from_slice(&[10; KEY_BYTES]).unwrap(),
            &signing,
        )
        .unwrap();
        let reopened = InstallationSecrets::open(
            installation_id,
            vault_id,
            LockedKey::from_slice(&[10; KEY_BYTES]).unwrap(),
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

/// Reader seeds are root-wrapped separately from personal content. Copying or
/// exporting items does not enroll a restored installation as this reader.
#[cfg(feature = "personal-sync")]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WrappedReaderIdentity {
    kem_left: WrappedKey,
    kem_right: WrappedKey,
    signing: WrappedKey,
}

#[cfg(feature = "personal-sync")]
impl InstallationSecrets {
    pub(crate) fn protect_reader(
        &self,
        installation: InstallationId,
        vault: VaultId,
        reader: &crate::personal::sync::ReaderIdentity,
    ) -> VaultResult<WrappedReaderIdentity> {
        Ok(WrappedReaderIdentity {
            kem_left: wrap_key(
                self.root_key(),
                &installation_key_aad(installation, vault, b"personal-sync-kem-left-v1"),
                reader.encryption_seed[..32].try_into().expect("seed half"),
            )?,
            kem_right: wrap_key(
                self.root_key(),
                &installation_key_aad(installation, vault, b"personal-sync-kem-right-v1"),
                reader.encryption_seed[32..].try_into().expect("seed half"),
            )?,
            signing: wrap_key(
                self.root_key(),
                &installation_key_aad(installation, vault, b"personal-sync-signing-v1"),
                &reader.signing_seed,
            )?,
        })
    }
    pub(crate) fn open_reader(
        &self,
        installation: InstallationId,
        vault: VaultId,
        wrapped: &WrappedReaderIdentity,
    ) -> VaultResult<crate::personal::sync::ReaderIdentity> {
        let left = unwrap_key(
            self.root_key(),
            &installation_key_aad(installation, vault, b"personal-sync-kem-left-v1"),
            &wrapped.kem_left,
            "reader seed",
        )?;
        let right = unwrap_key(
            self.root_key(),
            &installation_key_aad(installation, vault, b"personal-sync-kem-right-v1"),
            &wrapped.kem_right,
            "reader seed",
        )?;
        let signing = unwrap_key(
            self.root_key(),
            &installation_key_aad(installation, vault, b"personal-sync-signing-v1"),
            &wrapped.signing,
            "reader seed",
        )?;
        let mut kem = LockedKey::<64>::zeroed()?;
        kem[..32].copy_from_slice(&left[..]);
        kem[32..].copy_from_slice(&right[..]);
        crate::personal::sync::ReaderIdentity::from_seeds(kem, signing)
    }
}

#[cfg(all(test, feature = "personal-sync"))]
mod reader_tests {
    use super::*;
    use crate::personal::sync::ReaderIdentity;
    #[test]
    fn personal_reader_seeds_are_root_and_purpose_bound() {
        let installation = InstallationId::from_bytes([7; 16]);
        let vault = VaultId::from_bytes([8; 16]);
        let (keys, _) = InstallationSecrets::generate(
            installation,
            vault,
            LockedKey::from_slice(&[10; 32]).unwrap(),
            &[11; 32],
        )
        .unwrap();
        let reader = ReaderIdentity::generate().unwrap();
        let wrapped = keys.protect_reader(installation, vault, &reader).unwrap();
        assert_eq!(
            keys.open_reader(installation, vault, &wrapped)
                .unwrap()
                .public_keys(),
            reader.public_keys()
        );
        assert!(
            keys.open_reader(InstallationId::from_bytes([9; 16]), vault, &wrapped)
                .is_err()
        );
        assert!(
            keys.open_reader(installation, VaultId::from_bytes([9; 16]), &wrapped)
                .is_err()
        );
        let mut swapped = wrapped.clone();
        std::mem::swap(&mut swapped.kem_left, &mut swapped.kem_right);
        assert!(keys.open_reader(installation, vault, &swapped).is_err());
        let (other_root, _) = InstallationSecrets::generate(
            installation,
            vault,
            LockedKey::from_slice(&[12; 32]).unwrap(),
            &[11; 32],
        )
        .unwrap();
        assert!(
            other_root
                .open_reader(installation, vault, &wrapped)
                .is_err()
        );
    }
}
