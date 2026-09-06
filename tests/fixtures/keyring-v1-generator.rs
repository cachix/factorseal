use factorseal::{DocumentKind, SecretAddress, VaultArchive, VaultArchiveEntry, VaultEntryMetadata, WireSecret, encrypt_vault_archive};
fn main() {
    let entries = [
        ("secret-service-index", br#"{"version":1,"items":[{"id":"0123456789abcdef0123456789abcdef","label":"Legacy fixture","attributes":{"service":"factorseal-release-drill"},"content_type":"text/plain","created":1,"modified":2}]}"#.as_slice()),
        ("item/0123456789abcdef0123456789abcdef", b"synthetic legacy secret".as_slice()),
    ].into_iter().map(|(name, value)| VaultArchiveEntry {
        metadata: VaultEntryMetadata { document_kind: DocumentKind::LinuxSecretService, partition: b"factorseal/secret-service/v1".to_vec(), address: SecretAddress::new(name, None).unwrap() },
        value: WireSecret::new(value.to_vec()), evict_at: None,
    }).collect();
    let bytes = encrypt_vault_archive(&VaultArchive::new(1, entries), b"synthetic archive orchard violet lantern 2026").unwrap();
    std::fs::write(std::env::args().nth(1).unwrap(), bytes).unwrap();
}
