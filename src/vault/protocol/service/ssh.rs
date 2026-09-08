//! Signing capabilities for the in-process SSH transport. SSH clients receive
//! public keys and signatures only; decoded signing keys are dropped per operation.

use std::time::Instant;

use ssh_key::{Algorithm, HashAlg, PrivateKey};

use crate::personal::{
    PERSONAL_SECRET_NAMESPACE, PersonalFieldType, PersonalSecret, PersonalSecretKind,
};
use crate::vault::ssh_agent::{AgentReply, AgentRequest, SshIdentity};
use crate::vault::{SecretAddress, VaultStore};

use super::super::grant::require_grant_until;
use super::{
    ApprovalCandidate, CallerIdentity, DocumentKind, Duration, GrantPermission, GrantRequirement,
    RequestTime, VaultError, VaultResult, VaultService,
};

const MAX_INVENTORY_ENTRIES: usize = 4096;
const MAX_IDENTITIES: usize = 128;
const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

impl VaultService {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn ssh_request(
        &self,
        caller: &CallerIdentity,
        request: &AgentRequest<'_>,
        now: u64,
    ) -> VaultResult<AgentReply> {
        caller.validate()?;
        let clock = RequestTime::new(now, Instant::now());
        let mut state = self.state.lock_live(Instant::now())?;
        let now = clock.wall();
        let mut deadline = self.state.deadline()?;
        let bytes = match request {
            AgentRequest::Bind { .. } => {
                return Err(VaultError::Protocol(
                    "session binding belongs to its connection".into(),
                ));
            }
            AgentRequest::Identities => {
                let identities = identities(state.store(), now)?;
                // Public-key discovery is available to same-user clients so SSH
                // can choose a key before requesting its signing permission.
                // Discovery does not refresh the vault's idle lease.
                crate::vault::ssh_agent::encode_identities(&identities)?
            }
            AgentRequest::Sign {
                public_key,
                data,
                flags,
                destination,
            } => {
                let algorithm = ssh_key::PublicKey::from_bytes(public_key)
                    .map_err(ssh_error)?
                    .algorithm();
                if !matches!(
                    (algorithm, flags),
                    (Algorithm::Rsa { .. }, 2 | 4)
                        | (Algorithm::Ed25519 | Algorithm::Ecdsa { .. }, 0)
                ) {
                    return Err(VaultError::Protocol(
                        "unsupported SSH signature algorithm or flags".into(),
                    ));
                }
                let identity = identities(state.store(), now)?
                    .into_iter()
                    .find(|identity| identity.public_key == *public_key)
                    .ok_or(VaultError::AuthorizationRequired)?;
                let namespace = crate::vault::ssh_agent::grant_namespace(
                    &identity.fingerprint,
                    destination.as_ref(),
                )?;
                let expiry = match require_grant_until(
                    state.store(),
                    caller,
                    GrantRequirement {
                        scope: DocumentKind::Authorization,
                        namespace: Some(&namespace),
                        address: None,
                        project: None,
                        permission: GrantPermission::SshSign,
                    },
                    now,
                ) {
                    Ok(expiry) => expiry,
                    Err(VaultError::AuthorizationRequired) => {
                        let interaction = state.create_approval(
                            ApprovalCandidate::ssh(
                                caller,
                                identity.fingerprint,
                                identity.title,
                                destination.clone(),
                            )?,
                            clock.wall(),
                        )?;
                        return Ok(AgentReply::Pending(interaction.id));
                    }
                    Err(error) => return Err(error),
                };
                let key = load_key(state.store(), &identity.address, clock.wall(), true)?
                    .ok_or(VaultError::AuthorizationRequired)?;
                // Bind to key material even if an item changes or is replaced.
                if key.public_key().to_bytes().map_err(ssh_error)? != *public_key {
                    return Err(VaultError::AuthorizationRequired);
                }
                clock.check(expiry)?;
                let signature = crate::vault::ssh_agent::crypto::sign(&key, data, *flags)?;
                drop(key);
                clock.check(expiry)?;
                let (now, monotonic) = clock.sample();
                state.touch(now, monotonic)?;
                deadline = self
                    .state
                    .deadline()?
                    .into_iter()
                    .chain(expiry.map(|expiry| clock.deadline(expiry)))
                    .min();
                let signature = Vec::<u8>::try_from(signature).map_err(ssh_error)?;
                crate::vault::ssh_agent::encode_signature(&signature)?
            }
        };
        drop(state);
        self.state.check_live(Instant::now())?;
        Ok(AgentReply::Ready {
            bytes,
            deadline,
            cancelled: self.state.seal_signal(),
        })
    }

    pub(crate) fn ssh_wait_permission(
        &self,
        caller: &CallerIdentity,
        id: &str,
        now: u64,
    ) -> VaultResult<super::super::PermissionWaitStatus> {
        self.state.lock_live(Instant::now())?.wait_for_permission(
            caller,
            id,
            Duration::from_millis(250),
            RequestTime::new(now, Instant::now()),
        )
    }
}

fn identities(store: &VaultStore, now: u64) -> VaultResult<Vec<SshIdentity>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut result = Vec::new();
    let mut cursor = None;
    let mut scanned = 0;
    loop {
        if Instant::now() >= deadline {
            return Err(VaultError::Expired);
        }
        let page =
            store.list_vault_entries(cursor.as_deref(), super::super::MAX_LIST_PAGE_SIZE, now)?;
        scanned += page.items.len();
        if scanned > MAX_INVENTORY_ENTRIES {
            return Err(VaultError::Protocol("SSH inventory limit exceeded".into()));
        }
        for entry in page.items {
            if Instant::now() >= deadline {
                return Err(VaultError::Expired);
            }
            if entry.document_kind != DocumentKind::LocalKeyring
                || entry.partition != PERSONAL_SECRET_NAMESPACE
                || entry.display_type.as_deref() != Some(PersonalSecretKind::SshKey.label())
            {
                continue;
            }
            let key = match load_key(store, &entry.address, now, false) {
                Ok(Some(key)) => key,
                Ok(None) | Err(VaultError::Conflict) => continue,
                Err(error) => return Err(error),
            };
            let public_key = key.public_key().to_bytes().map_err(ssh_error)?;
            if result
                .iter()
                .any(|identity: &SshIdentity| identity.public_key == public_key)
            {
                continue;
            }
            if result.len() >= MAX_IDENTITIES {
                return Err(VaultError::Protocol("SSH identity limit exceeded".into()));
            }
            result.push(SshIdentity {
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                public_key,
                // Do not send a private-key comment or an unbounded item title.
                title: entry.display_name.unwrap_or_else(|| "SSH key".into()),
                address: entry.address,
            });
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(result);
        }
    }
}

fn load_key(
    store: &VaultStore,
    address: &SecretAddress,
    now: u64,
    decrypt: bool,
) -> VaultResult<Option<PrivateKey>> {
    let Some(value) = store.get_at(
        DocumentKind::LocalKeyring,
        PERSONAL_SECRET_NAMESPACE,
        address,
        now,
    )?
    else {
        return Ok(None);
    };
    let item = PersonalSecret::decode_current(&value)
        .map_err(|_| VaultError::InvalidData("invalid personal SSH item".into()))?;
    if item.kind != PersonalSecretKind::SshKey || item.archived {
        return Ok(None);
    }
    let mut fields = item
        .sections
        .iter()
        .flat_map(|section| &section.fields)
        .filter(|field| field.field_type == PersonalFieldType::SshKey);
    let Some(field) = fields.next() else {
        return Ok(None);
    };
    // Ambiguous items must be corrected in the vault instead of picking a key.
    if fields.next().is_some() {
        return Ok(None);
    }
    let Some(pem) = field.value.as_str() else {
        return Ok(None);
    };
    if pem.len() > MAX_PRIVATE_KEY_BYTES {
        return Ok(None);
    }
    let Ok(mut key) = PrivateKey::from_openssh(pem) else {
        return Ok(None);
    };
    if !matches!(
        key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Rsa { .. } | Algorithm::Ecdsa { .. }
    ) {
        return Ok(None);
    }
    if let Some(rsa) = key.public_key().key_data().rsa()
        && !(2048..=8192).contains(&rsa.key_size())
    {
        return Ok(None);
    }
    if decrypt && key.is_encrypted() {
        // Bound attacker-controlled KDF work before decrypting a saved key.
        if !matches!(key.kdf(), ssh_key::Kdf::Bcrypt { rounds: 1..=1024, salt } if salt.len() <= 64)
        {
            return Err(VaultError::Protocol(
                "SSH key KDF exceeds the supported work limit".into(),
            ));
        }
        let mut passphrases = item
            .sections
            .iter()
            .flat_map(|section| &section.fields)
            .filter(|field| {
                field.id == "passphrase" || field.label.eq_ignore_ascii_case("passphrase")
            });
        let passphrase = passphrases
            .next()
            .and_then(|field| field.value.as_str())
            .ok_or_else(|| {
                VaultError::Protocol("Save the SSH key passphrase in its Passphrase field".into())
            })?;
        if passphrases.next().is_some() {
            return Err(VaultError::Protocol(
                "SSH key has multiple passphrases".into(),
            ));
        }
        key = key.decrypt(passphrase).map_err(|_| {
            VaultError::Protocol("Could not decrypt the SSH key with its saved passphrase".into())
        })?;
    }
    Ok(Some(key))
}

fn ssh_error(_: impl std::fmt::Display) -> VaultError {
    VaultError::Protocol("invalid SSH key or signature".into())
}
