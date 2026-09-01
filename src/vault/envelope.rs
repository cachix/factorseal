use automerge::{Change, ChangeHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::EncryptionAlgorithm;
use crate::crypto::{self, NONCE_BYTES};

use super::signature;
use super::{DeviceKeyId, DocumentId, DocumentKind, VaultError, VaultResult};

const ENVELOPE_VERSION: u8 = 3;
const DIGEST_BYTES: usize = 32;
const SNAPSHOT_DOMAIN: &[u8] = b"factorseal/encrypted-snapshot/v2\0";
const CHANGE_DOMAIN: &[u8] = b"factorseal/signed-change/v2\0";
const CURRENT_SIGNATURE_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::MlDsa65;

/// Algorithm that authenticates an envelope's device signature.
///
/// The identifier is written into every signed payload and into the AEAD
/// additional data, so it cannot be swapped without breaking both signature
/// verification and decryption. It is a closed enum, so an unrecognized name
/// fails to deserialize instead of selecting a weaker algorithm, and there is
/// no "none" variant to downgrade to.
///
/// ML-DSA-65 is the only variant today. The identifier is still explicit so a
/// later algorithm migration cannot silently weaken verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    MlDsa65,
}

impl SignatureAlgorithm {
    /// Stable byte written into signed payloads. Never reuse a code.
    const fn code(self) -> u8 {
        match self {
            Self::MlDsa65 => 2,
        }
    }
}

/// Encrypted and device-signed Automerge snapshot persisted by the vault.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSnapshot {
    version: u8,
    encryption_algorithm: EncryptionAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    document_id: DocumentId,
    scope: DocumentKind,
    device_key_id: DeviceKeyId,
    generation: u64,
    key_epoch: u64,
    heads: Vec<[u8; DIGEST_BYTES]>,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    ciphertext_digest: [u8; DIGEST_BYTES],
    signature: Vec<u8>,
}

impl EncryptedSnapshot {
    #[must_use]
    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    #[must_use]
    pub const fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    #[must_use]
    pub const fn document_id(&self) -> DocumentId {
        self.document_id
    }

    #[must_use]
    pub const fn scope(&self) -> DocumentKind {
        self.scope
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// One encrypted Automerge change authenticated by the vault device.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedChangeEnvelope {
    version: u8,
    encryption_algorithm: EncryptionAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    document_id: DocumentId,
    scope: DocumentKind,
    device_key_id: DeviceKeyId,
    actor_id: Vec<u8>,
    generation: u64,
    key_epoch: u64,
    dependencies: Vec<[u8; DIGEST_BYTES]>,
    change_hash: [u8; DIGEST_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
    ciphertext_digest: [u8; DIGEST_BYTES],
    signature: Vec<u8>,
}

impl SignedChangeEnvelope {
    #[must_use]
    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    #[must_use]
    pub const fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }

    #[must_use]
    pub const fn document_id(&self) -> DocumentId {
        self.document_id
    }

    #[must_use]
    pub const fn scope(&self) -> DocumentKind {
        self.scope
    }

    #[must_use]
    pub const fn device_key_id(&self) -> DeviceKeyId {
        self.device_key_id
    }

    #[must_use]
    pub fn actor_id(&self) -> &[u8] {
        &self.actor_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    #[must_use]
    pub const fn change_hash(&self) -> &[u8; DIGEST_BYTES] {
        &self.change_hash
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

pub(crate) struct EnvelopeContext<'a> {
    pub(crate) document_id: DocumentId,
    pub(crate) scope: DocumentKind,
    pub(crate) device_key_id: DeviceKeyId,
    pub(crate) actor_id: &'a [u8],
    pub(crate) generation: u64,
    pub(crate) key_epoch: u64,
}

pub(crate) fn encrypt_snapshot(
    context: &EnvelopeContext<'_>,
    heads: &[ChangeHash],
    plaintext: &[u8],
    data_key: &[u8; 32],
    signing_seed: &[u8; 32],
) -> VaultResult<EncryptedSnapshot> {
    let heads: Vec<[u8; DIGEST_BYTES]> = heads.iter().map(|head| head.0).collect();
    let encryption_algorithm = crypto::CURRENT_ENCRYPTION_ALGORITHM;
    let aad = snapshot_header(
        context,
        encryption_algorithm,
        CURRENT_SIGNATURE_ALGORITHM,
        &heads,
    );
    let encrypted = crypto::encrypt(data_key, &aad, plaintext).map_err(|_| VaultError::Crypto)?;
    let ciphertext_digest = digest(&encrypted.ciphertext);
    let signature = signature::sign(
        signing_seed,
        &signed_payload(SNAPSHOT_DOMAIN, &aad, &encrypted.nonce, &ciphertext_digest),
    )?;
    Ok(EncryptedSnapshot {
        version: ENVELOPE_VERSION,
        encryption_algorithm,
        signature_algorithm: CURRENT_SIGNATURE_ALGORITHM,
        document_id: context.document_id,
        scope: context.scope,
        device_key_id: context.device_key_id,
        generation: context.generation,
        key_epoch: context.key_epoch,
        heads,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
        ciphertext_digest,
        signature,
    })
}

pub(crate) fn encrypt_changes(
    context: &EnvelopeContext<'_>,
    changes: &[Change],
    data_key: &[u8; 32],
    signing_seed: &[u8; 32],
) -> VaultResult<Vec<SignedChangeEnvelope>> {
    changes
        .iter()
        .map(|change| encrypt_change(context, change, data_key, signing_seed))
        .collect()
}

fn encrypt_change(
    context: &EnvelopeContext<'_>,
    change: &Change,
    data_key: &[u8; 32],
    signing_seed: &[u8; 32],
) -> VaultResult<SignedChangeEnvelope> {
    if change.actor_id().to_bytes() != context.actor_id {
        return Err(VaultError::InvalidData(
            "Automerge change actor does not match the device actor".to_owned(),
        ));
    }
    let dependencies: Vec<[u8; DIGEST_BYTES]> = change
        .deps()
        .iter()
        .map(|dependency| dependency.0)
        .collect();
    let change_hash = change.hash().0;
    let encryption_algorithm = crypto::CURRENT_ENCRYPTION_ALGORITHM;
    let aad = change_header(
        context,
        encryption_algorithm,
        CURRENT_SIGNATURE_ALGORITHM,
        &dependencies,
        &change_hash,
    );
    let encrypted =
        crypto::encrypt(data_key, &aad, change.raw_bytes()).map_err(|_| VaultError::Crypto)?;
    let ciphertext_digest = digest(&encrypted.ciphertext);
    let signature = signature::sign(
        signing_seed,
        &signed_payload(CHANGE_DOMAIN, &aad, &encrypted.nonce, &ciphertext_digest),
    )?;
    Ok(SignedChangeEnvelope {
        version: ENVELOPE_VERSION,
        encryption_algorithm,
        signature_algorithm: CURRENT_SIGNATURE_ALGORITHM,
        document_id: context.document_id,
        scope: context.scope,
        device_key_id: context.device_key_id,
        actor_id: context.actor_id.to_vec(),
        generation: context.generation,
        key_epoch: context.key_epoch,
        dependencies,
        change_hash,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
        ciphertext_digest,
        signature,
    })
}

/// Verify an encrypted snapshot's device signature and decrypt it.
pub fn verify_and_decrypt_snapshot(
    envelope: &EncryptedSnapshot,
    expected_device_key_id: DeviceKeyId,
    public_key: &[u8],
    data_key: &[u8; 32],
) -> VaultResult<Vec<u8>> {
    if envelope.version != ENVELOPE_VERSION || envelope.device_key_id != expected_device_key_id {
        return Err(VaultError::Signature);
    }
    verify_ciphertext_digest(&envelope.ciphertext, &envelope.ciphertext_digest)?;
    let context = EnvelopeContext {
        document_id: envelope.document_id,
        scope: envelope.scope,
        device_key_id: envelope.device_key_id,
        actor_id: &[],
        generation: envelope.generation,
        key_epoch: envelope.key_epoch,
    };
    let aad = snapshot_header(
        &context,
        envelope.encryption_algorithm,
        envelope.signature_algorithm,
        &envelope.heads,
    );
    verify_signature(
        envelope.signature_algorithm,
        public_key,
        &signed_payload(
            SNAPSHOT_DOMAIN,
            &aad,
            &envelope.nonce,
            &envelope.ciphertext_digest,
        ),
        &envelope.signature,
    )?;
    crypto::decrypt(
        envelope.encryption_algorithm,
        data_key,
        &envelope.nonce,
        &aad,
        &envelope.ciphertext,
    )
    .map(|plaintext| plaintext.to_vec())
    .map_err(|_| VaultError::Crypto)
}

/// Verify and decrypt one change, including its Automerge hash, dependencies,
/// and stable actor binding.
pub fn verify_and_decrypt_change(
    envelope: &SignedChangeEnvelope,
    expected_device_key_id: DeviceKeyId,
    public_key: &[u8],
    data_key: &[u8; 32],
) -> VaultResult<Change> {
    if envelope.version != ENVELOPE_VERSION || envelope.device_key_id != expected_device_key_id {
        return Err(VaultError::Signature);
    }
    verify_ciphertext_digest(&envelope.ciphertext, &envelope.ciphertext_digest)?;
    let context = EnvelopeContext {
        document_id: envelope.document_id,
        scope: envelope.scope,
        device_key_id: envelope.device_key_id,
        actor_id: &envelope.actor_id,
        generation: envelope.generation,
        key_epoch: envelope.key_epoch,
    };
    let aad = change_header(
        &context,
        envelope.encryption_algorithm,
        envelope.signature_algorithm,
        &envelope.dependencies,
        &envelope.change_hash,
    );
    verify_signature(
        envelope.signature_algorithm,
        public_key,
        &signed_payload(
            CHANGE_DOMAIN,
            &aad,
            &envelope.nonce,
            &envelope.ciphertext_digest,
        ),
        &envelope.signature,
    )?;
    let plaintext = crypto::decrypt(
        envelope.encryption_algorithm,
        data_key,
        &envelope.nonce,
        &aad,
        &envelope.ciphertext,
    )
    .map_err(|_| VaultError::Crypto)?;
    let change = Change::from_bytes(plaintext.to_vec()).map_err(|error| {
        VaultError::InvalidData(format!("invalid encrypted Automerge change: {error}"))
    })?;
    let dependencies: Vec<[u8; DIGEST_BYTES]> = change
        .deps()
        .iter()
        .map(|dependency| dependency.0)
        .collect();
    if change.actor_id().to_bytes() != envelope.actor_id
        || change.hash().0 != envelope.change_hash
        || dependencies != envelope.dependencies
    {
        return Err(VaultError::Signature);
    }
    Ok(change)
}

fn verify_ciphertext_digest(ciphertext: &[u8], expected: &[u8; DIGEST_BYTES]) -> VaultResult<()> {
    if digest(ciphertext) == *expected {
        Ok(())
    } else {
        Err(VaultError::Signature)
    }
}

fn verify_signature(
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    payload: &[u8],
    bytes: &[u8],
) -> VaultResult<()> {
    match algorithm {
        SignatureAlgorithm::MlDsa65 => signature::verify(public_key, payload, bytes),
    }
}

fn snapshot_header(
    context: &EnvelopeContext<'_>,
    encryption_algorithm: EncryptionAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    heads: &[[u8; DIGEST_BYTES]],
) -> Vec<u8> {
    let mut bytes = common_header(
        SNAPSHOT_DOMAIN,
        encryption_algorithm,
        signature_algorithm,
        context,
    );
    append_array_list(&mut bytes, heads);
    bytes
}

fn change_header(
    context: &EnvelopeContext<'_>,
    encryption_algorithm: EncryptionAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    dependencies: &[[u8; DIGEST_BYTES]],
    change_hash: &[u8; DIGEST_BYTES],
) -> Vec<u8> {
    let mut bytes = common_header(
        CHANGE_DOMAIN,
        encryption_algorithm,
        signature_algorithm,
        context,
    );
    append_bytes(&mut bytes, context.actor_id);
    append_array_list(&mut bytes, dependencies);
    bytes.extend_from_slice(change_hash);
    bytes
}

fn common_header(
    domain: &[u8],
    encryption_algorithm: EncryptionAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    context: &EnvelopeContext<'_>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(domain);
    bytes.push(ENVELOPE_VERSION);
    bytes.push(encryption_algorithm.code());
    bytes.push(signature_algorithm.code());
    bytes.extend_from_slice(context.document_id.as_bytes());
    append_bytes(&mut bytes, context.scope.as_str().as_bytes());
    bytes.extend_from_slice(context.device_key_id.as_bytes());
    bytes.extend_from_slice(&context.generation.to_be_bytes());
    bytes.extend_from_slice(&context.key_epoch.to_be_bytes());
    bytes
}

fn signed_payload(
    domain: &[u8],
    header: &[u8],
    nonce: &[u8; NONCE_BYTES],
    ciphertext_digest: &[u8; DIGEST_BYTES],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len() + header.len() + NONCE_BYTES + DIGEST_BYTES);
    bytes.extend_from_slice(domain);
    append_bytes(&mut bytes, header);
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(ciphertext_digest);
    bytes
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn append_array_list(target: &mut Vec<u8>, values: &[[u8; DIGEST_BYTES]]) {
    target.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        target.extend_from_slice(value);
    }
}

fn digest(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use automerge::transaction::Transactable;

    #[test]
    fn envelopes_declare_their_algorithms() {
        let signing = [7; 32];
        let verifying = signature::public_key_for_seed(&signing).unwrap();
        let data_key = [9; 32];
        let context = context(b"device-a", &verifying);
        let envelope = encrypt_snapshot(
            &context,
            &[ChangeHash([1; 32])],
            b"payload",
            &data_key,
            &signing,
        )
        .unwrap();

        assert_eq!(
            envelope.encryption_algorithm(),
            EncryptionAlgorithm::Aes256Gcm
        );
        assert_eq!(envelope.signature_algorithm(), SignatureAlgorithm::MlDsa65);
    }

    /// An unrecognized algorithm must fail to load rather than be ignored or
    /// silently downgraded, which is the failure mode this identifier exists
    /// to prevent when a second algorithm is added.
    #[test]
    fn an_unknown_signature_algorithm_is_refused() {
        let signing = [8; 32];
        let verifying = signature::public_key_for_seed(&signing).unwrap();
        let data_key = [10; 32];
        let context = context(b"device-a", &verifying);
        let envelope = encrypt_snapshot(
            &context,
            &[ChangeHash([1; 32])],
            b"payload",
            &data_key,
            &signing,
        )
        .unwrap();

        let mut json = serde_json::to_value(&envelope).unwrap();
        json["signature_algorithm"] = serde_json::Value::String("unknown-signature".to_owned());
        assert!(serde_json::from_value::<EncryptedSnapshot>(json).is_err());

        let mut absent = serde_json::to_value(&envelope).unwrap();
        absent
            .as_object_mut()
            .unwrap()
            .remove("signature_algorithm");
        assert!(serde_json::from_value::<EncryptedSnapshot>(absent).is_err());
    }

    #[test]
    fn an_unknown_or_missing_encryption_algorithm_is_refused() {
        let signing = [8; 32];
        let verifying = signature::public_key_for_seed(&signing).unwrap();
        let data_key = [10; 32];
        let context = context(b"device-a", &verifying);
        let envelope = encrypt_snapshot(
            &context,
            &[ChangeHash([1; 32])],
            b"payload",
            &data_key,
            &signing,
        )
        .unwrap();

        let mut json = serde_json::to_value(&envelope).unwrap();
        json["encryption_algorithm"] = serde_json::Value::String("unknown-encryption".to_owned());
        assert!(serde_json::from_value::<EncryptedSnapshot>(json).is_err());

        let mut absent = serde_json::to_value(&envelope).unwrap();
        absent
            .as_object_mut()
            .unwrap()
            .remove("encryption_algorithm");
        assert!(serde_json::from_value::<EncryptedSnapshot>(absent).is_err());
    }

    use automerge::{ActorId, AutoCommit, ROOT};

    use super::*;
    use crate::vault::{DocumentKind, VaultId};

    fn context<'a>(actor_id: &'a [u8], public_key: &[u8]) -> EnvelopeContext<'a> {
        EnvelopeContext {
            document_id: DocumentId::derive_for_test(
                VaultId::from_bytes([7; 16]),
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
            ),
            scope: DocumentKind::SecretSpecProviderCache,
            device_key_id: DeviceKeyId::for_public_key(public_key),
            actor_id,
            generation: 3,
            key_epoch: 0,
        }
    }

    #[test]
    fn snapshot_is_encrypted_signed_and_bound_to_metadata() {
        let signing = [9; 32];
        let verifying = signature::public_key_for_seed(&signing).unwrap();
        let data_key = [4; 32];
        let context = context(b"device-a", &verifying);
        let envelope = encrypt_snapshot(
            &context,
            &[ChangeHash([1; 32])],
            b"highly classified",
            &data_key,
            &signing,
        )
        .unwrap();

        assert!(
            !envelope
                .ciphertext()
                .windows(b"classified".len())
                .any(|window| window == b"classified")
        );
        assert_eq!(
            verify_and_decrypt_snapshot(&envelope, context.device_key_id, &verifying, &data_key,)
                .unwrap(),
            b"highly classified"
        );

        let mut changed_scope = envelope.clone();
        changed_scope.scope = DocumentKind::LocalKeyring;
        assert!(matches!(
            verify_and_decrypt_snapshot(
                &changed_scope,
                context.device_key_id,
                &verifying,
                &data_key,
            ),
            Err(VaultError::Signature)
        ));
    }

    #[test]
    fn change_verification_checks_actor_hash_and_dependencies() {
        let signing = [8; 32];
        let verifying = signature::public_key_for_seed(&signing).unwrap();
        let data_key = [5; 32];
        let actor = ActorId::from(b"device-a".as_slice());
        let mut document = AutoCommit::new().with_actor(actor);
        document.put(ROOT, "secret", b"value".to_vec()).unwrap();
        let changes = document.get_changes(&[]);
        let context = context(b"device-a", &verifying);
        let envelope = encrypt_changes(&context, &changes, &data_key, &signing)
            .unwrap()
            .remove(0);

        assert_eq!(
            verify_and_decrypt_change(&envelope, context.device_key_id, &verifying, &data_key,)
                .unwrap()
                .hash(),
            changes[0].hash()
        );

        let mut tampered = envelope;
        tampered.change_hash[0] ^= 1;
        assert!(matches!(
            verify_and_decrypt_change(&tampered, context.device_key_id, &verifying, &data_key,),
            Err(VaultError::Signature)
        ));
    }
}
