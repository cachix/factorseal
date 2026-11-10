use crate::api::{ErrorCode, Format, TransferKey};
use crate::core::{Failure, Outcome};
use data_encoding::BASE64;
use factorseal::personal::{PERSONAL_SECRET_NAMESPACE, totp};
use factorseal::transfer::cxf::{self, HybridIdentity, HybridRecipient};
use factorseal::transfer::import_plan::{
    ImportChoice, ImportSummary, PreparedImport, ReviewedImport,
};
use factorseal::transfer::{
    MAX_TRANSFER_FILE_BYTES, PersonalSecret, TransferFormat, export_manager,
};
use factorseal::{
    CallerIdentity, DocumentKind, VaultArchive, VaultClient, VaultEntryMetadata, VaultRequest,
    VaultResponse, VaultResult, VaultService, decrypt_vault_archive, encrypt_vault_archive,
    read_vault_export,
};
use zeroize::Zeroizing;

pub(crate) struct Client<'a> {
    pub(crate) service: &'a VaultService,
    pub(crate) caller: &'a CallerIdentity,
}

impl VaultClient for Client<'_> {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        Ok(self.service.handle(
            self.caller,
            VaultRequest::decode(&request.encode()?)?,
            totp::unix_now(),
        ))
    }
}

pub(crate) fn file_name(format: Format) -> String {
    let format = transfer_format(format);
    format!(
        "factorseal-{}.{}",
        if format.is_native() {
            "backup"
        } else {
            "credentials"
        },
        format.extension()
    )
}

pub(crate) fn export(
    client: &Client<'_>,
    format: Format,
    key: Option<&TransferKey>,
) -> Outcome<Zeroizing<String>> {
    let format = transfer_format(format);
    let output = if format.is_native() {
        let passphrase = new_passphrase(key)?;
        let archive = VaultArchive::new(totp::unix_now(), read_vault_export(client, |_| true)?);
        encrypt_vault_archive(&archive, passphrase.as_bytes())?
    } else {
        let payload = export_manager(format, &personal_secrets(client)?).map_err(failed)?;
        if format == TransferFormat::CxfAge {
            match key {
                Some(TransferKey::KeyFile(text)) => {
                    let recipient: HybridRecipient =
                        cxf::parse_key_file(text.0.as_bytes()).map_err(invalid)?;
                    cxf::encrypt_to_recipient(&payload, &recipient).map_err(failed)?
                }
                _ => cxf::encrypt(&payload, new_passphrase(key)?.as_bytes()).map_err(failed)?,
            }
        } else {
            payload
        }
    };
    Ok(Zeroizing::new(BASE64.encode(&output)))
}

pub(crate) fn prepare(
    format: Format,
    file: &str,
    key: Option<&TransferKey>,
) -> Outcome<PreparedImport> {
    let format = transfer_format(format);
    if BASE64.decode_len(file.len()).map_err(invalid)? as u64 > MAX_TRANSFER_FILE_BYTES {
        return Err(Failure::new(
            ErrorCode::Invalid,
            "input exceeds its size limit",
        ));
    }
    let bytes = Zeroizing::new(BASE64.decode(file.as_bytes()).map_err(invalid)?);
    if format.is_native() {
        let archive = decrypt_vault_archive(&bytes, passphrase(key)?.as_bytes())?;
        return PreparedImport::archive(archive, totp::unix_now()).map_err(failed);
    }
    let decrypted;
    let bytes = if format == TransferFormat::CxfAge {
        decrypted = match key {
            Some(TransferKey::KeyFile(text)) => {
                let identity: HybridIdentity =
                    cxf::parse_key_file(text.0.as_bytes()).map_err(invalid)?;
                cxf::decrypt_with_hybrid_identity(&bytes, &identity)
            }
            _ => cxf::decrypt(&bytes, passphrase(key)?.as_bytes()),
        }
        .map_err(failed)?;
        &decrypted
    } else {
        &bytes
    };
    PreparedImport::manager(format, bytes).map_err(failed)
}

pub(crate) fn commit(
    client: &Client<'_>,
    prepared: ReviewedImport,
    choices: &[ImportChoice],
) -> Outcome<ImportSummary> {
    prepared.commit(client, choices).map_err(|error| {
        if matches!(
            error.downcast_ref::<factorseal::VaultError>(),
            Some(factorseal::VaultError::Conflict)
        ) {
            Failure::from(factorseal::VaultError::Conflict)
        } else {
            failed(error)
        }
    })
}

pub(crate) fn review_items(review: &ReviewedImport) -> Vec<crate::api::ImportItem> {
    review
        .items()
        .iter()
        .map(|entry| {
            let metadata = &entry.item.metadata;
            crate::api::ImportItem {
                title: metadata
                    .display_name
                    .clone()
                    .or_else(|| metadata.address.as_local().map(|(item, _)| item.to_owned()))
                    .unwrap_or_else(|| {
                        metadata
                            .address
                            .as_secret_spec()
                            .map(|address| match address {
                                factorseal::SecretSpecAddress::Convention { key, .. } => {
                                    key.clone()
                                }
                                factorseal::SecretSpecAddress::Native { coordinates } => {
                                    coordinates.item.clone()
                                }
                            })
                            .unwrap_or_default()
                    }),
                username: metadata.display_username.clone(),
                website: metadata.display_website.clone(),
                kind: metadata.display_type.clone(),
                existing: entry.existing,
                changes: entry.changes.clone(),
                retained: entry.item.unusable.clone(),
            }
        })
        .collect()
}

pub(crate) fn comparisons(
    review: &ReviewedImport,
    item: usize,
    revealed: &[usize],
) -> Outcome<Vec<crate::api::ImportComparison>> {
    let value = |value: factorseal::transfer::import_plan::ImportValue| -> Outcome<crate::api::ImportValue> {
        Ok(crate::api::ImportValue {
            value: value.value.map(|secret| {
                std::str::from_utf8(secret.expose())
                    .map(|text| crate::api::Revealed(Zeroizing::new(text.to_owned())))
                    .map_err(failed)
            }).transpose()?,
            concealed: value.concealed,
            filled: value.filled,
            context: value.context,
        })
    };
    review
        .comparisons(item, revealed)
        .map_err(invalid)?
        .into_iter()
        .map(|row| {
            Ok(crate::api::ImportComparison {
                change: row.change,
                section: row.section,
                current: value(row.current)?,
                incoming: value(row.incoming)?,
            })
        })
        .collect()
}

fn personal_secrets(client: &Client<'_>) -> Outcome<Vec<PersonalSecret>> {
    read_vault_export(client, is_personal)?
        .into_iter()
        .map(|entry| {
            let (title, _) = entry.metadata.address.as_local().ok_or_else(|| {
                Failure::new(ErrorCode::Failed, "invalid personal-secret address")
            })?;
            PersonalSecret::decode(title, entry.value.expose()).map_err(failed)
        })
        .collect()
}

fn is_personal(entry: &VaultEntryMetadata) -> bool {
    entry.document_kind == DocumentKind::LocalKeyring
        && entry.partition == PERSONAL_SECRET_NAMESPACE
}

fn passphrase(key: Option<&TransferKey>) -> Outcome<&str> {
    match key {
        Some(TransferKey::Passphrase(passphrase)) if !passphrase.0.is_empty() => Ok(&passphrase.0),
        _ => Err(Failure::new(
            ErrorCode::PasswordRequired,
            "enter the passphrase for this file",
        )),
    }
}

fn new_passphrase(key: Option<&TransferKey>) -> Outcome<&str> {
    let passphrase = passphrase(key)?;
    factorseal::security::validate_new_password(passphrase.as_bytes())
        .map_err(|message| Failure::new(ErrorCode::WeakPassword, message))?;
    Ok(passphrase)
}

const fn transfer_format(format: Format) -> TransferFormat {
    match format {
        Format::FactorSeal => TransferFormat::FactorSeal,
        Format::CxfAge => TransferFormat::CxfAge,
        Format::BitwardenJson => TransferFormat::BitwardenJson,
        Format::OnePasswordCsv => TransferFormat::OnePasswordCsv,
        Format::OnePasswordPux => TransferFormat::OnePasswordPux,
        Format::KeePassCsv => TransferFormat::KeePassCsv,
    }
}

fn failed(error: impl std::fmt::Display) -> Failure {
    Failure::new(ErrorCode::Failed, error.to_string())
}

fn invalid(error: impl std::fmt::Display) -> Failure {
    Failure::new(ErrorCode::Invalid, error.to_string())
}
