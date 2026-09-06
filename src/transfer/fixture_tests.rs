use super::*;

fn round_trip(format: TransferFormat, secrets: &[PersonalSecret]) -> Zeroizing<Vec<u8>> {
    let exported = export_manager(format, secrets).unwrap();
    assert_eq!(import_manager(format, &exported).unwrap(), secrets);
    exported
}

#[test]
fn bitwarden_upstream_fixture() {
    let bytes = include_bytes!("../../tests/fixtures/transfer/keepassxc/bitwarden_export.json");
    let secrets = import_manager(TransferFormat::BitwardenJson, bytes).unwrap();
    assert_eq!(secrets.len(), 4);
    assert_eq!(secrets[0].kind, PersonalSecretKind::SecureNote);
    assert_eq!(secrets[0].folder.as_deref(), Some("My Folder"));
    assert_eq!(secrets[0].custom_fields[1].value, "hidden-field-value");
    assert_eq!(secrets[1].kind, PersonalSecretKind::Card);
    assert_eq!(secrets[2].kind, PersonalSecretKind::Identity);
    assert_eq!(secrets[3].kind, PersonalSecretKind::Login);
    assert!(secrets[3].favorite);
    assert_eq!(secrets[3].urls.len(), 3);
    assert_eq!(secrets[3].password.as_deref(), Some("mypassword"));
    let exported = round_trip(TransferFormat::BitwardenJson, &secrets);
    let json: serde_json::Value = serde_json::from_slice(&exported).unwrap();
    assert_eq!(json["items"][1]["card"]["cardholderName"], "Jane Doe");
    assert_eq!(
        json["items"][2]["identity"]["address1"],
        " 1 North Calle Cesar Chavez "
    );
    for format in [TransferFormat::OnePasswordCsv, TransferFormat::KeePassCsv] {
        assert!(export_manager(format, &secrets).is_err());
    }
}

#[test]
fn onepassword8_documented_columns_fixture() {
    let bytes = include_bytes!("../../tests/fixtures/transfer/onepassword8.csv");
    let secrets = import_manager(TransferFormat::OnePasswordCsv, bytes).unwrap();
    assert_eq!(secrets.len(), 3);
    assert_eq!(secrets[0].title, "Example, personal");
    assert_eq!(secrets[0].username.as_deref(), Some("zoë@example.com"));
    assert_eq!(
        secrets[0].password.as_deref(),
        Some("fake-\"quoted\",password\\tail")
    );
    assert_eq!(
        secrets[0].notes.as_deref(),
        Some("First line\nSecond line with \"quotes\" and café.")
    );
    assert_eq!(secrets[0].tags, ["personal", "work"]);
    assert!(secrets[0].favorite);
    assert!(secrets[1].archived);
    assert!(secrets[2].username.is_none());
    round_trip(TransferFormat::OnePasswordCsv, &secrets);
}

#[test]
fn keepass_official_sample_fixture() {
    let bytes = include_bytes!("../../tests/fixtures/transfer/keepass-official.csv");
    let secrets = import_manager(TransferFormat::KeePassCsv, bytes).unwrap();
    assert_eq!(secrets.len(), 4);
    assert_eq!(secrets[0].title, "Sample Entry Title");
    assert_eq!(secrets[0].username.as_deref(), Some("Greg"));
    assert_eq!(
        secrets[2].username.as_deref(),
        Some("!\"§$%&/()=?´`_#²³{[]}\\")
    );
    assert_eq!(secrets[2].password.as_deref(), Some("öäüÖÄÜß€@<>µ©®"));
    assert_eq!(secrets[3].notes.as_ref().unwrap().lines().count(), 7);
    let exported = round_trip(TransferFormat::KeePassCsv, &secrets);
    // Check the target dialect independently of FactorSeal's importer.
    let text = std::str::from_utf8(&exported).unwrap();
    assert!(
        text.starts_with("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n")
    );
    assert!(text.contains("\"!\\\"§$%&/()=?´`_#²³{[]}\\\\\""));
}

#[test]
fn older_factorseal_keepass_csv_preserves_literal_backslashes() {
    let bytes = b"Account,Login Name,Password,Web Site,Comments\nExample,user,\"a\\b,c\",,\"quoted \"\"note\"\"\"\n";
    let secrets = import_manager(TransferFormat::KeePassCsv, bytes).unwrap();
    assert_eq!(secrets[0].password.as_deref(), Some("a\\b,c"));
    assert_eq!(secrets[0].notes.as_deref(), Some("quoted \"note\""));
    round_trip(TransferFormat::KeePassCsv, &secrets);
}
