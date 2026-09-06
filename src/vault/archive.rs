//! Portable, passphrase-encrypted FactorSeal vault archives.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{VaultEntryMetadata, VaultError, VaultResult, WireSecret};

const FORMAT: &str = "factorseal-vault-archive";
const VERSION: u16 = 2;
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
            if entry.metadata.document_kind == super::DocumentKind::LinuxSecretService {
                if entry.metadata.partition != super::secret_service_data::NAMESPACE
                    || entry.evict_at.is_some()
                {
                    return Err(VaultError::InvalidData(
                        "unsupported portable keyring partition or expiry".to_owned(),
                    ));
                }
                super::secret_service_data::PortableItem::decode(
                    entry.value.expose(),
                    &entry.metadata.address,
                )?;
            }
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

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_archive(bytes: &[u8]) {
    if let Ok(archive) = serde_json::from_slice::<VaultArchive>(bytes) {
        let _ = archive.validate();
    }
    if let Ok(archive) = serde_json::from_slice::<EncryptedArchive>(bytes) {
        let _ = validate_header(&archive.header);
        let _ = STANDARD.decode(&archive.header.kdf.salt);
        let _ = STANDARD.decode(&archive.nonce);
        let _ = STANDARD.decode(&archive.ciphertext);
    }
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
        version: archive.version,
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
    let mut archive: VaultArchive = serde_json::from_slice(&plaintext)
        .map_err(|error| VaultError::InvalidData(format!("invalid archive contents: {error}")))?;
    if archive.version == 1 {
        archive.upgrade_legacy_keyring()?;
    }
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
    if header.format != FORMAT || ![1, VERSION].contains(&header.version) {
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

/// Export a freshly enumerated, consistent set of portable entries. Never
/// return a partial backup after an inventory error or concurrent mutation.
pub fn read_vault_export(
    client: &(impl super::VaultClient + ?Sized),
    include: impl Fn(&VaultEntryMetadata) -> bool,
) -> VaultResult<Vec<VaultArchiveEntry>> {
    use super::{DocumentKind, MAX_LIST_PAGE_SIZE, VaultAction, VaultRequest, VaultResponseBody};
    let request = |action| {
        client
            .request(&VaultRequest::new(action)?)?
            .result
            .map_err(|error| VaultError::Protocol(error.message))
    };
    let revision = || match request(VaultAction::ExportRevision)? {
        VaultResponseBody::ExportRevision { revision } => Ok(revision),
        _ => Err(VaultError::Protocol(
            "unexpected export revision response".to_owned(),
        )),
    };
    let expected = revision()?;
    let mut cursor = None;
    let mut archived = Vec::new();
    loop {
        let VaultResponseBody::VaultEntries {
            entries,
            next_cursor,
        } = request(VaultAction::ListVaultEntries {
            cursor: cursor.clone(),
            limit: MAX_LIST_PAGE_SIZE,
        })?
        else {
            return Err(VaultError::Protocol(
                "unexpected export inventory response".to_owned(),
            ));
        };
        for entry in entries.into_iter().filter(|entry| {
            !matches!(
                entry.document_kind,
                DocumentKind::Authorization | DocumentKind::SecretSpecProviderCache
            ) && include(entry)
        }) {
            let VaultResponseBody::VaultEntrySecret { value, evict_at } =
                request(VaultAction::ExportVaultEntry {
                    entry: entry.clone(),
                })?
            else {
                return Err(VaultError::Protocol(
                    "unexpected export entry response".to_owned(),
                ));
            };
            archived.push(VaultArchiveEntry {
                metadata: entry,
                value,
                evict_at,
            });
        }
        let Some(next) = next_cursor else { break };
        if cursor.as_ref().is_some_and(|old| old >= &next) {
            return Err(VaultError::Protocol(
                "export inventory cursor did not advance".to_owned(),
            ));
        }
        cursor = Some(next);
    }
    if revision()? != expected {
        return Err(VaultError::Protocol(
            "vault changed during export; retry the export".to_owned(),
        ));
    }
    Ok(archived)
}

impl VaultArchive {
    // Version 1 stored the adapter's singleton index as an independent entry.
    // Join it to its values before issuing any import requests.
    fn upgrade_legacy_keyring(&mut self) -> VaultResult<()> {
        use super::{
            DocumentKind,
            secret_service_data::{INDEX_ITEM, Index, NAMESPACE, PortableItem},
        };
        let mut index = None;
        let mut ordinary = Vec::new();
        let mut keyring = Vec::new();
        for entry in std::mem::take(&mut self.entries) {
            if entry.metadata.document_kind != DocumentKind::LinuxSecretService {
                ordinary.push(entry);
                continue;
            }
            if entry.metadata.partition != NAMESPACE || entry.evict_at.is_some() {
                return Err(VaultError::InvalidData(
                    "invalid legacy keyring entry".to_owned(),
                ));
            }
            if entry.metadata.address.as_local() == Some((INDEX_ITEM, None)) {
                if index.is_some() {
                    return Err(VaultError::InvalidData(
                        "duplicate legacy keyring index".to_owned(),
                    ));
                }
                index = Some(Index::decode(Some(entry.value.expose()))?);
            } else {
                keyring.push(entry);
            }
        }
        let mut items = index
            .unwrap_or_default()
            .items
            .into_iter()
            .map(|item| Ok((item.address()?, item)))
            .collect::<VaultResult<std::collections::HashMap<_, _>>>()?;
        for mut entry in keyring {
            let item = items.remove(&entry.metadata.address).ok_or_else(|| {
                VaultError::InvalidData("legacy keyring value has no unique index entry".to_owned())
            })?;
            entry.value = PortableItem::new(item, entry.value).encode()?;
            ordinary.push(entry);
        }
        if !items.is_empty() {
            return Err(VaultError::InvalidData(
                "legacy keyring index has missing values".to_owned(),
            ));
        }
        self.entries = ordinary;
        self.version = VERSION;
        Ok(())
    }
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
        envelope["header"]["version"] = (VERSION + 1).into();
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
    #[test]
    fn legacy_archives_join_keyring_metadata_and_values() {
        use crate::vault::secret_service_data::{
            INDEX_ITEM, Index, IndexItem, NAMESPACE, PortableItem,
        };
        let item = IndexItem {
            id: "0123456789abcdef0123456789abcdef".into(),
            label: "Legacy login".into(),
            attributes: [("service".into(), "example".into())].into(),
            content_type: "text/plain".into(),
            created: 1,
            modified: 2,
        };
        let mut index = Index::default();
        index.items.push(item.clone());
        let metadata = |address| VaultEntryMetadata {
            document_kind: DocumentKind::LinuxSecretService,
            partition: NAMESPACE.to_vec(),
            address,
        };
        let mut legacy = VaultArchive::new(
            42,
            vec![
                VaultArchiveEntry {
                    metadata: metadata(SecretAddress::new(INDEX_ITEM, None).unwrap()),
                    value: WireSecret::new(serde_json::to_vec(&index).unwrap()),
                    evict_at: None,
                },
                VaultArchiveEntry {
                    metadata: metadata(item.address().unwrap()),
                    value: WireSecret::new(b"legacy secret".to_vec()),
                    evict_at: None,
                },
            ],
        );
        legacy.version = 1;
        let encrypted = encrypt_archive(&legacy, b"legacy").unwrap();
        let restored = decrypt_vault_archive(&encrypted, b"legacy").unwrap();
        assert_eq!(restored.version, VERSION);
        assert_eq!(restored.entries.len(), 1);
        let entry = &restored.entries[0];
        let portable = PortableItem::decode(entry.value.expose(), &entry.metadata.address).unwrap();
        assert_eq!(portable.item, item);
        assert_eq!(portable.value.expose(), b"legacy secret");
        let encrypted = encrypt_archive(&restored, b"legacy").unwrap();
        assert_eq!(
            decrypt_vault_archive(&encrypted, b"legacy")
                .unwrap()
                .entries
                .len(),
            1
        );
        // Incomplete old archives must fail before any restore writes occur.
        legacy.entries.pop();
        let encrypted = encrypt_archive(&legacy, b"legacy").unwrap();
        assert!(decrypt_vault_archive(&encrypted, b"legacy").is_err());
    }

    struct ExportClient {
        responses:
            std::sync::Mutex<std::collections::VecDeque<VaultResult<crate::VaultResponseBody>>>,
        actions: std::sync::Mutex<Vec<crate::VaultAction>>,
    }

    impl crate::VaultClient for ExportClient {
        fn request(&self, request: &crate::VaultRequest) -> VaultResult<crate::VaultResponse> {
            self.actions
                .lock()
                .unwrap()
                .push(crate::VaultRequest::decode(&request.encode()?)?.action);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request")
                .map(|body| crate::VaultResponse::success(request.request_id(), body))
        }
    }

    fn export_client(changed: bool, fail_inventory: bool) -> ExportClient {
        use crate::VaultResponseBody as Body;
        let entry = example().entries.remove(0);
        let mut responses = std::collections::VecDeque::from([
            Ok(Body::ExportRevision {
                revision: Some([1; 32]),
            }),
            Ok(Body::VaultEntries {
                entries: vec![entry.metadata],
                next_cursor: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()),
            }),
            Ok(Body::VaultEntrySecret {
                value: entry.value,
                evict_at: None,
            }),
        ]);
        responses.push_back(if fail_inventory {
            Err(VaultError::Protocol("inventory unavailable".into()))
        } else {
            Ok(Body::VaultEntries {
                entries: Vec::new(),
                next_cursor: None,
            })
        });
        if !fail_inventory {
            responses.push_back(Ok(Body::ExportRevision {
                revision: Some([if changed { 2 } else { 1 }; 32]),
            }));
        }
        ExportClient {
            responses: std::sync::Mutex::new(responses),
            actions: std::sync::Mutex::new(Vec::new()),
        }
    }

    #[test]
    fn export_reads_live_inventory_and_all_pages() {
        let client = export_client(false, false);
        let entries = read_vault_export(&client, |_| true).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value.expose(), b"needle-secret");
        assert!(client.responses.lock().unwrap().is_empty());
        assert!(
            matches!(&client.actions.lock().unwrap()[3], crate::VaultAction::ListVaultEntries { cursor: Some(cursor), .. } if cursor == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    #[test]
    fn export_rejects_partial_inventory_and_changed_snapshots() {
        for (changed, failed) in [(true, false), (false, true)] {
            assert!(read_vault_export(&export_client(changed, failed), |_| true).is_err());
        }
    }
}
