//! Portable, passphrase-encrypted FactorSeal vault archives.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{VaultEntryMetadata, VaultError, VaultResult, WireSecret};

const FORMAT: &str = "factorseal-vault-archive";
const VERSION: u16 = 1;
const SALT_BYTES: usize = 16;
const MAX_ARCHIVE_FILE_BYTES: usize = 256 * 1024 * 1024;
// Base64 and the JSON envelope add roughly one third. Keeping the decrypted
// payload below this bound guarantees that archives we create fit the file
// bound accepted by the reader.
const MAX_ARCHIVE_PAYLOAD_BYTES: usize = 192 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
#[cfg(not(test))]
const ARGON2_MEMORY_KIB: u32 = 128 * 1024;
#[cfg(test)]
const ARGON2_MEMORY_KIB: u32 = 8 * 1024;
#[cfg(not(test))]
const ARGON2_ITERATIONS: u32 = 3;
#[cfg(test)]
const ARGON2_ITERATIONS: u32 = 1;
const ARGON2_PARALLELISM: u32 = 1;
const MAX_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ARGON2_ITERATIONS: u32 = 10;
const MAX_ARGON2_PARALLELISM: u32 = 16;

/// One durable vault entry inside a portable archive.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultArchiveEntry {
    pub metadata: VaultEntryMetadata,
    pub value: WireSecret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict_at: Option<u64>,
}

/// Decrypted contents of a portable FactorSeal archive.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultArchive {
    format: String,
    version: u16,
    pub created_at: u64,
    pub entries: Vec<VaultArchiveEntry>,
}

impl VaultArchive {
    #[must_use]
    pub fn new(created_at: u64, entries: Vec<VaultArchiveEntry>) -> Self {
        Self {
            format: FORMAT.to_owned(),
            version: VERSION,
            created_at,
            entries,
        }
    }

    fn validate(&self) -> VaultResult<()> {
        if self.format != FORMAT || self.version != VERSION {
            return Err(VaultError::InvalidData(
                "unsupported FactorSeal archive format or version".to_owned(),
            ));
        }
        if self.entries.len() > MAX_ARCHIVE_ENTRIES {
            return Err(VaultError::InvalidData(
                "FactorSeal archive contains too many entries".to_owned(),
            ));
        }
        for entry in &self.entries {
            entry.metadata.validate_transfer()?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveHeader {
    format: String,
    version: u16,
    kdf: ArchiveKdf,
    cipher: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveKdf {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedArchive {
    header: ArchiveHeader,
    nonce: String,
    ciphertext: String,
}

/// Encrypt an archive with a separate portable-backup passphrase.
pub fn encrypt_vault_archive(
    archive: &VaultArchive,
    passphrase: &[u8],
) -> VaultResult<Zeroizing<Vec<u8>>> {
    archive.validate()?;
    crate::security::validate_new_password(passphrase).map_err(VaultError::Protection)?;
    encrypt_archive(archive, passphrase)
}

fn encrypt_archive(archive: &VaultArchive, passphrase: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
    let mut salt = [0_u8; SALT_BYTES];
    getrandom::fill(&mut salt)?;
    let header = ArchiveHeader {
        format: FORMAT.to_owned(),
        version: VERSION,
        kdf: ArchiveKdf {
            algorithm: "argon2id".to_owned(),
            version: 19,
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
            salt: STANDARD.encode(salt),
        },
        cipher: "aes-256-gcm".to_owned(),
    };
    let aad =
        serde_json::to_vec(&header).map_err(|error| VaultError::InvalidData(error.to_string()))?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(archive).map_err(|error| VaultError::InvalidData(error.to_string()))?,
    );
    if plaintext.len() > MAX_ARCHIVE_PAYLOAD_BYTES {
        return Err(VaultError::InvalidData(
            "FactorSeal archive is too large".to_owned(),
        ));
    }
    let key = derive_key(passphrase, &header.kdf)?;
    let encrypted =
        crate::crypto::encrypt(&key, &aad, &plaintext).map_err(|_| VaultError::Crypto)?;
    let envelope = EncryptedArchive {
        header,
        nonce: STANDARD.encode(encrypted.nonce),
        ciphertext: STANDARD.encode(encrypted.ciphertext),
    };
    serde_json::to_vec_pretty(&envelope)
        .map(Zeroizing::new)
        .map_err(|error| VaultError::InvalidData(error.to_string()))
}

/// Authenticate and decrypt a portable FactorSeal archive.
pub fn decrypt_vault_archive(bytes: &[u8], passphrase: &[u8]) -> VaultResult<VaultArchive> {
    if bytes.len() > MAX_ARCHIVE_FILE_BYTES {
        return Err(VaultError::InvalidData(
            "FactorSeal archive is too large".to_owned(),
        ));
    }
    validate_passphrase(passphrase)?;
    let envelope: EncryptedArchive = serde_json::from_slice(bytes)
        .map_err(|error| VaultError::InvalidData(format!("invalid archive: {error}")))?;
    validate_header(&envelope.header)?;
    let nonce = decode_array::<{ crate::algorithm::AES_GCM_NONCE_BYTES }>(
        "archive nonce",
        &envelope.nonce,
    )?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| VaultError::InvalidData("invalid archive ciphertext".to_owned()))?;
    if ciphertext.len() > MAX_ARCHIVE_PAYLOAD_BYTES + 16 {
        return Err(VaultError::InvalidData(
            "FactorSeal archive is too large".to_owned(),
        ));
    }
    let aad = serde_json::to_vec(&envelope.header)
        .map_err(|error| VaultError::InvalidData(error.to_string()))?;
    let key = derive_key(passphrase, &envelope.header.kdf)?;
    let plaintext = crate::crypto::decrypt(
        crate::EncryptionAlgorithm::Aes256Gcm,
        &key,
        &nonce,
        &aad,
        &ciphertext,
    )
    .map_err(|_| VaultError::Protection("incorrect passphrase or damaged archive".to_owned()))?;
    let archive: VaultArchive = serde_json::from_slice(&plaintext)
        .map_err(|error| VaultError::InvalidData(format!("invalid archive contents: {error}")))?;
    archive.validate()?;
    Ok(archive)
}

fn validate_passphrase(passphrase: &[u8]) -> VaultResult<()> {
    if passphrase.is_empty() {
        return Err(VaultError::Protection(
            "archive passphrase must not be empty".to_owned(),
        ));
    }
    Ok(())
}

fn validate_header(header: &ArchiveHeader) -> VaultResult<()> {
    if header.format != FORMAT || header.version != VERSION {
        return Err(VaultError::InvalidData(
            "unsupported FactorSeal archive format or version".to_owned(),
        ));
    }
    if header.kdf.algorithm != "argon2id"
        || header.kdf.version != 19
        || header.kdf.memory_kib == 0
        || header.kdf.memory_kib > MAX_ARGON2_MEMORY_KIB
        || header.kdf.iterations == 0
        || header.kdf.iterations > MAX_ARGON2_ITERATIONS
        || header.kdf.parallelism == 0
        || header.kdf.parallelism > MAX_ARGON2_PARALLELISM
        || header.cipher != "aes-256-gcm"
    {
        return Err(VaultError::InvalidData(
            "unsupported or unsafe archive encryption parameters".to_owned(),
        ));
    }
    Ok(())
}

fn derive_key(passphrase: &[u8], kdf: &ArchiveKdf) -> VaultResult<Zeroizing<[u8; 32]>> {
    validate_header(&ArchiveHeader {
        format: FORMAT.to_owned(),
        version: VERSION,
        kdf: ArchiveKdf {
            algorithm: kdf.algorithm.clone(),
            version: kdf.version,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            salt: kdf.salt.clone(),
        },
        cipher: "aes-256-gcm".to_owned(),
    })?;
    let salt = decode_array::<SALT_BYTES>("archive salt", &kdf.salt)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|error| VaultError::Protection(format!("invalid archive KDF: {error}")))?;
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); params.block_count()]);
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(passphrase, &salt, &mut *key, &mut memory)
        .map_err(|error| VaultError::Protection(format!("archive KDF failed: {error}")))?;
    Ok(key)
}

fn decode_array<const N: usize>(label: &str, encoded: &str) -> VaultResult<[u8; N]> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidData(format!("invalid {label}")))?;
    decoded
        .try_into()
        .map_err(|_| VaultError::InvalidData(format!("invalid {label} length")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DocumentKind, SecretAddress};

    fn example() -> VaultArchive {
        VaultArchive::new(
            42,
            vec![VaultArchiveEntry {
                metadata: VaultEntryMetadata {
                    document_kind: DocumentKind::LocalKeyring,
                    partition: b"factorseal/personal-secrets/v1".to_vec(),
                    address: SecretAddress::new("example", None).unwrap(),
                },
                value: WireSecret::new(b"needle-secret".to_vec()),
                evict_at: None,
            }],
        )
    }

    #[test]
    fn archive_round_trips_without_exposing_plaintext() {
        let encrypted = encrypt_vault_archive(&example(), b"correct horse battery staple").unwrap();
        assert!(!encrypted.windows(13).any(|bytes| bytes == b"needle-secret"));
        let decrypted = decrypt_vault_archive(&encrypted, b"correct horse battery staple").unwrap();
        assert_eq!(decrypted.created_at, 42);
        assert_eq!(decrypted.entries[0].value.expose(), b"needle-secret");
        assert!(!format!("{decrypted:?}").contains("needle-secret"));
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_rejected() {
        let mut encrypted =
            encrypt_vault_archive(&example(), b"opal nebula lantern saffron velocity").unwrap();
        assert!(decrypt_vault_archive(&encrypted, b"wrong").is_err());
        let index = encrypted.len() - 4;
        encrypted[index] ^= 1;
        assert!(
            decrypt_vault_archive(&encrypted, b"opal nebula lantern saffron velocity").is_err()
        );
    }

    #[test]
    fn unknown_versions_are_rejected_before_key_derivation() {
        let encrypted =
            encrypt_vault_archive(&example(), b"opal nebula lantern saffron velocity").unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&encrypted).unwrap();
        envelope["header"]["version"] = 2.into();
        let changed = serde_json::to_vec(&envelope).unwrap();
        assert!(decrypt_vault_archive(&changed, b"right").is_err());
    }

    #[test]
    fn existing_weak_passphrase_archive_stays_readable() {
        assert!(encrypt_vault_archive(&example(), b"weak").is_err());
        // Model an archive produced before the creation policy was introduced.
        let old = encrypt_archive(&example(), b"weak").unwrap();
        let restored = decrypt_vault_archive(&old, b"weak").unwrap();
        assert_eq!(restored.entries[0].value.expose(), b"needle-secret");
    }
}
