//! Parser entry points for the opt-in fuzz workspace. Fixed keys and corpus
//! fixtures are synthetic; this module performs no vault or hardware access.
use super::*;

pub const MAX_INPUT: usize = 1024 * 1024;

pub fn personal_sync(bytes: &[u8]) {
    crate::personal::sync::fuzz(bytes);
}

pub fn metadata(bytes: &[u8]) {
    if bytes.len() <= MAX_INPUT {
        seal::fuzz_metadata(bytes);
    }
}

pub fn protocol(bytes: &[u8]) {
    if let Ok(value) = VaultRequest::decode(bytes)
        && let Ok(encoded) = value.encode()
    {
        VaultRequest::decode(&encoded).unwrap();
    }
    if let Ok(value) = VaultResponse::decode(bytes)
        && let Ok(encoded) = value.encode()
    {
        VaultResponse::decode(&encoded).unwrap();
    }
}

pub fn document(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT {
        return;
    }
    if let Ok(mut value) =
        document::SecretDocument::load(bytes, b"fuzz", DocumentKind::LocalKeyring, None)
    {
        let _ = value.addresses();
        let encoded = value.save();
        document::SecretDocument::load(&encoded, b"fuzz", DocumentKind::LocalKeyring, None)
            .unwrap();
    }
    let _ = document::SecretDocument::migrate_v2(bytes, b"fuzz", DocumentKind::LocalKeyring);
    let _ = crate::transfer::PersonalSecret::decode("synthetic", bytes);
}

pub fn history(bytes: &[u8]) {
    if bytes.len() <= MAX_INPUT {
        let _ = history::HistoryLog::load(bytes, DocumentKind::LocalKeyring, None);
    }
}

pub fn envelope(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT {
        return;
    }
    hardwareseal::fuzz_parsers(bytes);
    if let Ok(value) = serde_json::from_slice::<EncryptedSnapshot>(bytes) {
        let _ = decrypt_snapshot(&value, &[0; 32]);
        let _ = super::envelope::decrypt_history(&value, &[0; 32]);
    }
    if let Ok(value) = serde_json::from_slice::<keys::WrappedInstallationSecrets>(bytes) {
        let _ = keys::InstallationSecrets::open(
            InstallationId::from_bytes([0; 16]),
            VaultId::from_bytes([0; 16]),
            crate::security::memory::LockedKey::zeroed().unwrap(),
            &value,
        );
    }
}

pub fn commit_chain(bytes: &[u8]) {
    if bytes.len() <= MAX_INPUT {
        store::fuzz_commit(bytes);
    }
}
pub fn archive(bytes: &[u8]) {
    if bytes.len() <= MAX_INPUT {
        super::archive::fuzz_archive(bytes);
    }
}

pub fn transfer(bytes: &[u8]) {
    if bytes.len() > MAX_INPUT {
        return;
    }
    for format in crate::transfer::TransferFormat::ALL {
        let _ = crate::transfer::import_manager(format, bytes);
    }
}

pub fn bootstrap(bytes: &[u8]) {
    let _ = crate::desktop_worker::receive::<crate::desktop_worker::Bootstrap>(&mut &*bytes);
    let _ =
        crate::desktop_worker::sync::receive::<crate::desktop_worker::sync::Command>(&mut &*bytes);
}

pub fn secret_service(bytes: &[u8]) {
    use secret_service_protocol::{ALGORITHM_DH, ALGORITHM_PLAIN, Session};
    if bytes.len() > MAX_INPUT {
        return;
    }
    let _ = Session::open(ALGORITHM_DH, bytes);
    let (session, _) = Session::open(ALGORITHM_PLAIN, &[]).unwrap();
    let split = bytes.len().min(16);
    let _ = session.decrypt(&bytes[..split], &bytes[split..]);
    // A fixed valid DH public value reaches CBC/PKCS#7 parsing even when
    // arbitrary negotiation inputs are rejected.
    let (session, _) = Session::open(ALGORITHM_DH, &[2]).unwrap();
    let _ = session.decrypt(&bytes[..split], &bytes[split..]);
}

/// Valid structured seeds make mutation reach beyond format/version checks.
#[must_use]
pub fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut document =
        document::SecretDocument::new(b"fuzz", DocumentKind::LocalKeyring, b"fuzz").unwrap();
    let history = serde_json::to_vec(&history::HistoryLog::new(
        DocumentKind::LocalKeyring,
        b"fuzz",
    ))
    .unwrap();
    let records = document.save();
    let context = super::envelope::EnvelopeContext {
        vault_id: VaultId::from_bytes([0; 16]),
        document_id: DocumentId::from_bytes([0; 32]),
        scope: DocumentKind::LocalKeyring,
        device_key_id: DeviceKeyId::from_bytes([0; 32]),
        generation: 0,
        key_epoch: 0,
    };
    let envelope =
        super::envelope::encrypt_snapshot(&context, &records, &history, &[0; 32]).unwrap();
    let bootstrap = crate::desktop_worker::Bootstrap {
        desktop_executable: std::path::PathBuf::from("/synthetic/desktop"),
        operation: crate::desktop_worker::Operation::Unlock {
            group: UnlockGroup::new([UnlockFactorKind::Password]).unwrap(),
            idle_seconds: 60,
            maximum_seconds: 600,
        },
        password: WireSecret::new(b"synthetic".to_vec()).unwrap(),
        hosts_secret_service: false,
        sync_control: true,
    };
    let mut frame = Vec::new();
    crate::desktop_worker::send(&mut frame, &bootstrap).unwrap();
    let mut control = Vec::new();
    crate::desktop_worker::sync::send(&mut control, &crate::desktop_worker::sync::Command::State)
        .unwrap();
    let mut seeds = vec![
        ("bootstrap", control),
        ("metadata", seal::fuzz_metadata_seed()),
        ("bootstrap", frame),
        ("document", records),
        ("history", history),
        ("envelope", serde_json::to_vec(&envelope).unwrap()),
        ("commit_chain", store::fuzz_commit_seed()),
        (
            "protocol",
            VaultRequest::new(VaultAction::Seal {
                namespace: b"fuzz".to_vec(),
            })
            .unwrap()
            .encode()
            .unwrap()
            .to_vec(),
        ),
        (
            "archive",
            serde_json::to_vec(&VaultArchive::new(0, vec![])).unwrap(),
        ),
        ("secret_service", vec![2]),
        ("transfer", b"{\"items\":[]}".to_vec()),
    ];
    seeds.extend(
        hardwareseal::fuzz_seeds()
            .into_iter()
            .map(|bytes| ("envelope", bytes)),
    );
    seeds.extend(
        crate::personal::sync::fuzz_seeds()
            .into_iter()
            .map(|bytes| ("personal_sync", bytes)),
    );
    seeds
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_bundle_returns_errors_without_panicking() {
        let bytes = include_bytes!("../../fuzz/regressions/document/truncated-counter-bundle.bin");
        assert!(
            document::SecretDocument::load(bytes, b"fuzz", DocumentKind::LocalKeyring, None)
                .is_err()
        );
        assert!(
            document::SecretDocument::migrate_v2(bytes, b"fuzz", DocumentKind::LocalKeyring)
                .is_err()
        );
    }

    #[test]
    fn unread_change_column_bytes_are_rejected_without_panicking() {
        // Automerge change whose value metadata says null with a nonzero
        // length, leaving bytes in the raw column that no op reads. Older
        // Automerge accepted it and later rebuilt it under a different hash.
        let bytes =
            include_bytes!("../../fuzz/regressions/personal_sync/null-value-with-payload.bin");
        personal_sync(bytes);
        let update: crate::personal::replica::PersonalUpdate =
            serde_json::from_slice(bytes).unwrap();
        assert!(update.validate().is_err());
    }

    #[test]
    fn synthetic_corpus_exercises_production_parsers() {
        for (name, bytes) in seeds() {
            match name {
                "document" => document(&bytes),
                "history" => history(&bytes),
                "envelope" => envelope(&bytes),
                "commit_chain" => commit_chain(&bytes),
                "protocol" => protocol(&bytes),
                "archive" => archive(&bytes),
                "secret_service" => secret_service(&bytes),
                "transfer" => transfer(&bytes),
                "metadata" => metadata(&bytes),
                "bootstrap" => bootstrap(&bytes),
                "personal_sync" => personal_sync(&bytes),
                _ => unreachable!(),
            }
        }
    }
}
