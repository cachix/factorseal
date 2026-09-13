use super::*;

const APPLE_FIXTURE: &[u8] = include_bytes!(
    "../../../platform/apple/Tests/FactorSealCredentialExchangeTests/Fixtures/login-totp.json"
);

fn assert_json_preserved(source: &Value, result: &Value, allow_extra_array_items: bool) {
    match source {
        Value::Object(members) => {
            for (key, value) in members {
                assert_json_preserved(value, &result[key], allow_extra_array_items);
            }
        }
        Value::Array(values) => {
            let actual = result.as_array().expect("expected an array");
            if allow_extra_array_items {
                assert!(actual.len() >= values.len());
            } else {
                assert_eq!(actual.len(), values.len());
            }
            for (expected, actual) in values.iter().zip(actual) {
                assert_json_preserved(expected, actual, allow_extra_array_items);
            }
        }
        _ => assert_eq!(source, result),
    }
}

fn check_apple_roundtrip(bytes: &[u8]) {
    let reference: Value = serde_json::from_slice(APPLE_FIXTURE).unwrap();
    let output: Value = serde_json::from_slice(bytes).unwrap();
    assert_json_preserved(&reference, &output, false);
    let _: credential_exchange_format::Header = serde_json::from_slice(bytes).unwrap();
    let items = import_json(bytes).unwrap();
    assert_eq!(items.len(), 1);
    let exported: Value = serde_json::from_slice(&export_json(&items).unwrap()).unwrap();
    // FactorSeal appends typed custom fields for scope-only URLs.
    assert_json_preserved(&reference["accounts"], &exported["accounts"], true);
}

#[test]
fn apple_fixture_is_compatible_with_rust_readers_and_reexport() {
    check_apple_roundtrip(APPLE_FIXTURE);
}

#[test]
#[ignore = "requires output from scripts/test-apple-exchange.sh on macOS 26+"]
fn apple_sdk_roundtrip() {
    let path = std::env::var_os("FACTORSEAL_TEST_APPLE_CXF_OUTPUT")
        .expect("set FACTORSEAL_TEST_APPLE_CXF_OUTPUT to the Swift test output");
    let bytes = super::super::read_transfer_file(std::path::Path::new(&path)).unwrap();
    check_apple_roundtrip(&bytes);
}

#[test]
#[ignore = "requires the native export output from scripts/test-apple-exchange.sh"]
fn apple_native_sdk_roundtrip() {
    let path = std::env::var_os("FACTORSEAL_TEST_APPLE_NATIVE_OUTPUT")
        .expect("set FACTORSEAL_TEST_APPLE_NATIVE_OUTPUT to the Swift native export output");
    let bytes = super::super::read_transfer_file(std::path::Path::new(&path)).unwrap();
    let _: credential_exchange_format::Header = serde_json::from_slice(&bytes).unwrap();
    let imported = import_json(&bytes).unwrap();
    assert_eq!(imported.len(), 1);
    let login = &imported[0];
    assert_eq!(login.kind, PersonalSecretKind::Login);
    assert_eq!(login.notes.as_deref(), Some("a note"));
    assert!(login.favorite);
    assert_eq!(login.tags, ["team"]);
    let values: Vec<_> = login
        .sections
        .iter()
        .flat_map(|section| &section.fields)
        .filter_map(PersonalField::text)
        .collect();
    for expected in ["alice", "synthetic password", "https://example.org", "true"] {
        assert!(
            values.contains(&expected),
            "synthetic native field was lost"
        );
    }
}

const HYBRID_KEY: &str = include_str!("../../../tests/fixtures/transfer/cxf/hybrid-key.txt");
const HYBRID_RECIPIENT: &str =
    include_str!("../../../tests/fixtures/transfer/cxf/hybrid-recipient.txt");

fn hybrid_identity() -> HybridIdentity {
    HYBRID_KEY
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn hybrid_authenticates_all_chunks_and_rejects_wrong_keys() {
    use age_core::primitives::bech32_encode;
    use hpke::{Kem as _, Serializable as _};
    let identity = hybrid_identity();
    let recipient: HybridRecipient = HYBRID_RECIPIENT.trim().parse().unwrap();
    let payload = vec![b'x'; 150_000];
    let encrypted = encrypt_to_recipient(&payload, &recipient).unwrap();
    assert_eq!(
        *decrypt_with_hybrid_identity(&encrypted, &identity).unwrap(),
        payload
    );
    assert_ne!(
        *encrypt_to_recipient(&payload, &recipient).unwrap(),
        *encrypted
    );
    let (wrong, _) = hpke::kem::XWing::gen_keypair();
    let wrong = age_core::primitives::bech32_decode(
        HYBRID_KEY
            .lines()
            .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
            .unwrap(),
        |_| (),
        |_| Ok(()),
        |hrp, _| Ok(bech32_encode(hrp, &wrong.to_bytes())),
    )
    .unwrap();
    assert!(decrypt_with_hybrid_identity(&encrypted, &wrong.parse().unwrap()).is_err());
    assert!(decrypt(&encrypted, b"synthetic passphrase").is_err());
    for length in [0, 20, encrypted.len() - 1, encrypted.len() - 32] {
        assert!(decrypt_with_hybrid_identity(&encrypted[..length], &identity).is_err());
    }
    for position in [
        encrypted.len() - 1,
        encrypted.len() - 40_000,
        encrypted.len() - 100_000,
    ] {
        let mut damaged = encrypted.clone();
        damaged[position] ^= 1;
        assert!(decrypt_with_hybrid_identity(&damaged, &identity).is_err());
    }
    assert!(
        decrypt_with_hybrid_identity(&encrypt(b"{}", b"synthetic passphrase").unwrap(), &identity)
            .is_err()
    );
}

#[test]
fn hybrid_rejects_classical_keys_and_mixed_encryption() {
    use age::secrecy::ExposeSecret as _;
    let classical = age::x25519::Identity::generate();
    let recipient = classical.to_public();
    assert!(recipient.to_string().parse::<HybridRecipient>().is_err());
    assert!(
        classical
            .to_string()
            .expose_secret()
            .parse::<HybridIdentity>()
            .is_err()
    );
    let hybrid: HybridRecipient = HYBRID_RECIPIENT.trim().parse().unwrap();
    assert!(
        age::Encryptor::with_recipients([&hybrid as &dyn age::Recipient, &recipient].into_iter())
            .is_err()
    );
    let mut broken = HYBRID_RECIPIENT.trim().as_bytes().to_vec();
    let last = broken.last_mut().unwrap();
    *last = if *last == b'q' { b'p' } else { b'q' };
    assert!(
        std::str::from_utf8(&broken)
            .unwrap()
            .parse::<HybridRecipient>()
            .is_err()
    );
}

#[test]
fn hybrid_rejects_malformed_stanzas_before_unwrapping() {
    use age::Identity as _;
    use age_core::format::Stanza;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    let identity = hybrid_identity();
    let mut stanza = Stanza {
        tag: "mlkem768x25519".into(),
        args: vec![STANDARD_NO_PAD.encode([0; 1120])],
        body: vec![0; 32],
    };
    // Correct shape, but authentication fails: this is not our stanza.
    assert!(identity.unwrap_stanza(&stanza).is_none());
    stanza.body.push(0);
    assert!(matches!(
        identity.unwrap_stanza(&stanza),
        Some(Err(age::DecryptError::InvalidHeader))
    ));
    stanza.body.pop();
    // 1120 bytes leave four unused base64 bits. Reject non-canonical encodings.
    stanza.args[0].pop();
    stanza.args[0].push('B');
    assert!(matches!(
        identity.unwrap_stanza(&stanza),
        Some(Err(age::DecryptError::InvalidHeader))
    ));
    stanza.args.clear();
    assert!(matches!(
        identity.unwrap_stanza(&stanza),
        Some(Err(age::DecryptError::InvalidHeader))
    ));
}

#[test]
fn hybrid_key_files_are_bounded_and_require_exactly_one_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.txt");
    for invalid in [
        String::new(),
        "# no key\n".into(),
        format!("{HYBRID_RECIPIENT}{HYBRID_RECIPIENT}"),
        "x".repeat(65537),
    ] {
        crate::security::write_private_file(&path, invalid.as_bytes()).unwrap();
        assert!(read_recipient_file(&path).is_err());
    }
    crate::security::write_private_file(
        &path,
        format!("# public key\r\n\r\n{}\r\n", HYBRID_RECIPIENT.trim()).as_bytes(),
    )
    .unwrap();
    assert!(read_recipient_file(&path).is_ok());
    assert!(read_identity_file(&path).is_err());
    crate::security::write_private_file(&path, HYBRID_KEY.as_bytes()).unwrap();
    assert!(read_identity_file(&path).is_ok());
    assert!(read_recipient_file(&path).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_identity_file(&path).is_err());
    }
}

#[test]
#[ignore = "requires the independent Go age 1.3+ CLI; set FACTORSEAL_TEST_AGE_BIN"]
fn hybrid_go_cli_interoperability() {
    let executable = std::env::var_os("FACTORSEAL_TEST_AGE_BIN").unwrap_or_else(|| "age".into());
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("identity.txt");
    let encrypted = dir.path().join("export.age");
    let decrypted = dir.path().join("decrypted.json");
    crate::security::write_private_file(&key, HYBRID_KEY.as_bytes()).unwrap();
    let payload = include_bytes!("../../../tests/fixtures/transfer/cxf/external.json");
    let recipient = HYBRID_RECIPIENT.trim().parse().unwrap();
    crate::security::write_private_file(
        &encrypted,
        &encrypt_to_recipient(payload, &recipient).unwrap(),
    )
    .unwrap();
    let result = std::process::Command::new(executable)
        .arg("--decrypt")
        .arg("--identity")
        .arg(&key)
        .arg("--output")
        .arg(&decrypted)
        .arg(&encrypted)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "Go age decryption failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(decrypted).unwrap(), payload);
}

#[test]
fn hybrid_decrypts_independent_go_age_export() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/transfer/cxf");
    // Copy the public test identity into a private file: git doesn't preserve mode 0600.
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("key.txt");
    crate::security::write_private_file(
        &key,
        include_bytes!("../../../tests/fixtures/transfer/cxf/hybrid-key.txt"),
    )
    .unwrap();
    let identity = read_identity_file(&key).unwrap();
    let plaintext = decrypt_with_hybrid_identity(
        include_bytes!("../../../tests/fixtures/transfer/cxf/hybrid.age"),
        &identity,
    )
    .unwrap();
    assert_eq!(
        &*plaintext,
        include_bytes!("../../../tests/fixtures/transfer/cxf/external.json")
    );
    let recipient = read_recipient_file(&root.join("hybrid-recipient.txt")).unwrap();
    let encrypted = encrypt_to_recipient(&plaintext, &recipient).unwrap();
    assert_eq!(
        decrypt_with_hybrid_identity(&encrypted, &identity).unwrap(),
        plaintext
    );
}

#[allow(clippy::needless_pass_by_value)]
fn fixture(credentials: Value) -> Value {
    json!({"version":{"major":1,"minor":0},"exporterRpId":"example.org","exporterDisplayName":"Example","timestamp":0,
        "accounts":[{"id":"AQ","username":"","email":"","collections":[],"items":[{"id":"Ag","title":"Example","credentials":credentials}]}]})
}

fn import(value: &Value) -> anyhow::Result<Vec<PersonalSecret>> {
    import_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn native_fields_round_trip_through_independent_cxf_reader() {
    let mut login = PersonalSecret::template(PersonalSecretKind::Login, "Example".into());
    login.sections[0].fields[0].value = "alice".into();
    login.sections[0].fields[1].value = "synthetic password".into();
    login.sections[0].fields[2].value = "https://example.org".into();
    login.sections[0].fields.push(PersonalField::new(
        "enabled",
        "Enabled",
        PersonalFieldType::Boolean,
        true,
    ));
    login.sections.push(PersonalSection {
        id: "empty".into(),
        label: "Empty section".into(),
        fields: vec![],
    });
    login.notes = Some("a note".into());
    login.folder = Some("Work".into());
    login.archived = true;
    login.favorite = true;
    login.tags = vec!["team".into()];
    let encoded = export_json(std::slice::from_ref(&login)).unwrap();
    if let Some(path) = std::env::var_os("FACTORSEAL_TEST_APPLE_NATIVE_CXF") {
        // This test constructs only public synthetic credentials, never vault data.
        std::fs::write(path, &encoded).unwrap();
    }
    // Independent implementation maintained by Bitwarden. Synthetic data only:
    // these third-party types do not wipe secrets when dropped.
    let external: credential_exchange_format::Header = serde_json::from_slice(&encoded).unwrap();
    let external_json = serde_json::to_vec(&external).unwrap();
    let decoded = import_json(&external_json).unwrap();
    assert_eq!(decoded, vec![login]);
    let standard: Value = serde_json::from_slice(&encoded).unwrap();
    let credentials = standard["accounts"][0]["items"][0]["credentials"]
        .as_array()
        .unwrap();
    assert!(
        credentials
            .iter()
            .any(|c| c["type"] == "basic-auth" && c["password"]["value"] == "synthetic password")
    );
}

#[test]
fn personal_templates_are_accepted_by_independent_reader() {
    for kind in PersonalSecretKind::ALL {
        let item = PersonalSecret::template(kind, "Template".into());
        let json = export_json(std::slice::from_ref(&item)).unwrap();
        let external: credential_exchange_format::Header = serde_json::from_slice(&json).unwrap();
        let decoded = import_json(&serde_json::to_vec(&external).unwrap()).unwrap();
        assert_eq!(decoded, vec![item]);
    }
}

#[test]
fn multiple_fields_mapping_to_one_standard_slot_are_preserved() {
    let mut item = PersonalSecret::template(PersonalSecretKind::ApiCredential, "Two keys".into());
    item.sections[0].fields[1].value = "first synthetic key".into();
    item.sections[0].fields.push(PersonalField::new(
        "key",
        "Key",
        PersonalFieldType::Concealed,
        "second synthetic key",
    ));
    let encoded = export_json(std::slice::from_ref(&item)).unwrap();
    assert_eq!(import_json(&encoded).unwrap(), vec![item]);
}

#[test]
fn known_extension_future_data_is_retained() {
    let item = PersonalSecret::template(PersonalSecretKind::Login, "Example".into());
    let mut value: Value = serde_json::from_slice(&export_json(&[item]).unwrap()).unwrap();
    value["accounts"][0]["items"][0]["extensions"][0]["future"] = "preserve me".into();
    let imported = import(&value).unwrap();
    assert!(imported[0].source.is_some());
}

#[test]
fn third_party_logins_are_editable_and_exportable() {
    let source = fixture(
        json!([{"type":"basic-auth","username":{"fieldType":"string","value":"alice"},"password":{"fieldType":"concealed-string","value":"before"}}]),
    );
    let mut items = import(&source).unwrap();
    assert_eq!(items[0].kind, PersonalSecretKind::Login);
    assert!(items[0].source.is_some());
    assert_eq!(super::super::preserved_only_items(&items), 0);
    items[0].sections[0]
        .fields
        .iter_mut()
        .find(|f| f.id == "password")
        .unwrap()
        .value = "after".into();
    let exported = export_json(&items).unwrap();
    let external: credential_exchange_format::Header = serde_json::from_slice(&exported).unwrap();
    let value = serde_json::to_value(external).unwrap();
    assert_eq!(
        value["accounts"][0]["items"][0]["credentials"][0]["password"]["value"],
        "after"
    );
    assert_eq!(
        import(&source).unwrap()[0].id,
        import(&source).unwrap()[0].id
    );
}

#[test]
fn totp_parameters_survive_standard_exchange() {
    let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
    let mut item = PersonalSecret::template(PersonalSecretKind::Login, "OTP".into());
    item.sections[0].fields[3].value = uri.into();
    let json = export_json(&[item]).unwrap();
    let _: credential_exchange_format::Header = serde_json::from_slice(&json).unwrap();
    let restored = import_json(&json).unwrap();
    let value = restored[0].sections[0]
        .fields
        .iter()
        .find(|f| f.field_type == PersonalFieldType::Totp)
        .unwrap()
        .text()
        .unwrap();
    assert_eq!(totp::export(uri).unwrap(), totp::export(value).unwrap());
    let bad =
        fixture(json!([{"type":"totp","secret":"ABC","period":0,"digits":6,"algorithm":"sha1"}]));
    assert!(import(&bad).is_err());
}

#[test]
fn unknown_credentials_are_preserved_and_reported() {
    let original = fixture(json!([{"type":"future-credential","opaque":"synthetic secret"}]));
    let items = import(&original).unwrap();
    assert_eq!(super::super::preserved_only_items(&items), 1);
    assert_eq!(
        items[0].source.as_ref().unwrap()["item"],
        original["accounts"][0]["items"][0]
    );
    let exported: Value = serde_json::from_slice(&export_json(&items).unwrap()).unwrap();
    assert_eq!(
        exported["accounts"][0]["items"][0]["credentials"],
        original["accounts"][0]["items"][0]["credentials"]
    );
}

#[test]
fn type_only_future_credentials_survive_export() {
    let source = fixture(json!([{"type":"future-credential"}]));
    let exported: Value =
        serde_json::from_slice(&export_json(&import(&source).unwrap()).unwrap()).unwrap();
    assert_eq!(
        exported["accounts"][0]["items"][0]["credentials"],
        source["accounts"][0]["items"][0]["credentials"]
    );
}

#[test]
fn empty_account_metadata_is_rejected_before_import() {
    let mut source = fixture(json!([]));
    let mut empty_account = source["accounts"][0].clone();
    empty_account["id"] = "Aw".into();
    empty_account["username"] = "owner with no items".into();
    empty_account["items"] = json!([]);
    source["accounts"]
        .as_array_mut()
        .unwrap()
        .push(empty_account);
    assert!(
        import(&source)
            .unwrap_err()
            .to_string()
            .contains("empty account")
    );
}

#[test]
fn imported_local_metadata_survives_without_changing_foreign_identity() {
    let source = fixture(
        json!([{"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6,"algorithm":"sha1"}]),
    );
    let mut imported = import(&source).unwrap();
    imported[0].folder = Some("Work".into());
    imported[0].archived = true;
    imported[0].sections[0].label = "New section label".into();
    imported[0].sections[0].fields[0].label = "New code label".into();
    let encoded = export_json(&imported).unwrap();
    let mut exported: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(exported["accounts"][0]["items"][0]["id"], "Ag");
    let restored = import_json(&encoded).unwrap();
    assert_eq!(restored[0].id, imported[0].id);
    assert_eq!(restored[0].folder, imported[0].folder);
    assert_eq!(restored[0].archived, imported[0].archived);
    assert_eq!(restored[0].sections, imported[0].sections);
    exported["accounts"][0]["items"][0]["extensions"][0]["id"] = "forged-local-identity".into();
    assert!(import(&exported).is_err());
}

#[test]
fn account_and_header_metadata_are_not_silently_lost() {
    let mut source = fixture(json!([]));
    source["future"] = "header metadata".into();
    source["accounts"][0]["fullName"] = "Account owner".into();
    let items = import(&source).unwrap();
    let metadata = items[0].source.as_ref().unwrap();
    assert_eq!(metadata["header"]["future"], "header metadata");
    assert_eq!(metadata["account"]["fullName"], "Account owner");
    assert!(metadata["account"].get("items").is_none());
    let exported: Value = serde_json::from_slice(&export_json(&items).unwrap()).unwrap();
    assert_eq!(exported["future"], source["future"]);
    assert_eq!(exported["accounts"][0]["fullName"], "Account owner");
}

#[test]
fn source_roundtrip_applies_edits_and_deletions_without_reviving_old_secrets() {
    let mut source = fixture(json!([
        {"type":"basic-auth","username":{"fieldType":"string","value":"old-user","future":"retain field metadata"},"password":{"fieldType":"concealed-string","value":"deleted-password"}},
        {"type":"note","content":{"fieldType":"string","value":"deleted-note"}},
        {"type":"totp","secret":"JBSWY3DPEHPK3PXP","period":30,"digits":6,"algorithm":"sha1","future":"retain TOTP metadata"},
        {"type":"future-credential","opaque":"preserve opaque value"}
    ]));
    source["accounts"][0]["items"][0]["scope"] =
        json!({"urls":["https://old.example"],"androidApps":[{"bundleId":"example.app"}]});
    let mut items = import(&source).unwrap();
    items[0].title = "Edited login".into();
    items[0].notes = None;
    for section in &mut items[0].sections {
        section.fields.retain(|field| field.id != "password");
        for field in &mut section.fields {
            match field.field_type {
                PersonalFieldType::Totp => field.value = "otpauth://totp/New:bob?secret=KRUGS4ZANFZSAYJA&issuer=New&algorithm=SHA256&digits=8&period=60".into(),
                PersonalFieldType::Url => field.value = "https://new.example".into(),
                _ if field.id == "username" => field.value = "new-user".into(),
                _ => {}
            }
        }
    }
    let encoded = export_json(&items).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    for deleted in [
        "old-user",
        "deleted-password",
        "deleted-note",
        "JBSWY3DPEHPK3PXP",
        "https://old.example",
    ] {
        assert!(!text.contains(deleted), "revived deleted value: {deleted}");
    }
    let value: Value = serde_json::from_slice(&encoded).unwrap();
    let item = &value["accounts"][0]["items"][0];
    assert_eq!(item["id"], "Ag");
    assert_eq!(item["title"], "Edited login");
    assert_eq!(
        item["credentials"][0]["username"]["future"],
        "retain field metadata"
    );
    assert_eq!(item["credentials"][1]["secret"], "KRUGS4ZANFZSAYJA");
    assert_eq!(item["credentials"][1]["future"], "retain TOTP metadata");
    assert_eq!(
        item["credentials"][2],
        source["accounts"][0]["items"][0]["credentials"][3]
    );
    assert_eq!(
        item["scope"]["androidApps"],
        source["accounts"][0]["items"][0]["scope"]["androidApps"]
    );
    let reimported = import_json(&encoded).unwrap();
    let second: Value = serde_json::from_slice(&export_json(&reimported).unwrap()).unwrap();
    assert_eq!(second["accounts"], value["accounts"]);
}

#[test]
fn source_accounts_and_cross_account_collections_keep_their_identities() {
    let mut source = fixture(json!([]));
    source["accounts"][0]["username"] = "alice".into();
    source["accounts"][0]["collections"] = json!([{"id":"Aw","title":"Shared","items":[{"item":"Ag"},{"item":"Ag","account":"BA"}],"extensions":[{"name":"example.collection","data":"keep"}]}]);
    let mut other = source["accounts"][0].clone();
    other["id"] = "BA".into();
    other["username"] = "bob".into();
    other["collections"] = json!([]);
    source["accounts"].as_array_mut().unwrap().push(other);
    let imported = import(&source).unwrap();
    assert_ne!(imported[0].id, imported[1].id);
    let exported: Value = serde_json::from_slice(&export_json(&imported).unwrap()).unwrap();
    for index in 0..2 {
        assert_eq!(
            exported["accounts"][index]["id"],
            source["accounts"][index]["id"]
        );
        assert_eq!(
            exported["accounts"][index]["username"],
            source["accounts"][index]["username"]
        );
        assert_eq!(
            exported["accounts"][index]["collections"],
            source["accounts"][index]["collections"]
        );
    }
    let _: credential_exchange_format::Header =
        serde_json::from_slice(&serde_json::to_vec(&exported).unwrap()).unwrap();
}

#[test]
fn adding_a_verification_code_to_an_imported_login_exports_standard_totp() {
    let source =
        fixture(json!([{"type":"basic-auth","username":{"fieldType":"string","value":"alice"}}]));
    let mut imported = import(&source).unwrap();
    imported[0].sections[0].fields.push(PersonalField::new(
        "new-code",
        "Code",
        PersonalFieldType::Totp,
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
    ));
    let exported: Value = serde_json::from_slice(&export_json(&imported).unwrap()).unwrap();
    assert!(
        exported["accounts"][0]["items"][0]["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["type"] == "totp" && c["secret"] == "JBSWY3DPEHPK3PXP")
    );
    let _: credential_exchange_format::Header =
        serde_json::from_slice(&serde_json::to_vec(&exported).unwrap()).unwrap();
}

#[test]
fn tampered_stored_bindings_cannot_redirect_export_edits() {
    let source = fixture(
        json!([{"type":"basic-auth","username":{"fieldType":"string","value":"alice"},"password":{"fieldType":"concealed-string","value":"password"}}]),
    );
    let mut imported = import(&source).unwrap();
    imported[0].source.as_mut().unwrap()["bindings"] = json!([{"path":"/credentials/0/password","section":"cxf-0","field":"username","kind":"Field"}]);
    imported[0].sections[0]
        .fields
        .iter_mut()
        .find(|f| f.id == "username")
        .unwrap()
        .value = "bob".into();
    let exported: Value = serde_json::from_slice(&export_json(&imported).unwrap()).unwrap();
    assert_eq!(
        exported["accounts"][0]["items"][0]["credentials"][0]["password"]["value"],
        "password"
    );
    assert_eq!(
        exported["accounts"][0]["items"][0]["credentials"][0]["username"]["value"],
        "bob"
    );
}

#[test]
fn invalid_identity_version_and_missing_files_fail_preparation() {
    for mutation in ["version", "duplicate", "id", "file"] {
        let mut source = fixture(json!([]));
        match mutation {
            "version" => source["version"]["major"] = 2.into(),
            "duplicate" => {
                let item = source["accounts"][0]["items"][0].clone();
                source["accounts"][0]["items"]
                    .as_array_mut()
                    .unwrap()
                    .push(item);
            }
            "id" => source["accounts"][0]["id"] = "not base64!".into(),
            "file" => {
                source["accounts"][0]["items"][0]["credentials"] = json!([{"type":"file","id":"Aw","name":"missing.txt","decryptedSize":42,"integrityHash":"AA"}]);
            }
            _ => unreachable!(),
        }
        assert!(import(&source).is_err(), "{mutation}");
    }
}

#[test]
fn oversized_items_fail_before_writes_and_secrets_stay_out_of_errors() {
    let source = fixture(
        json!([{"type":"note","content":{"fieldType":"string","value":"S".repeat(600*1024)}}]),
    );
    let error = import(&source).unwrap_err().to_string();
    assert!(!error.contains("SSSS"));
}

#[test]
fn age_authenticates_complete_payload_and_rejects_wrong_password() {
    let plain = export_json(&[]).unwrap();
    let encrypted = encrypt(&plain, b"synthetic test passphrase").unwrap();
    assert!(encrypted.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !encrypted
            .windows(plain.len())
            .any(|w| w == plain.as_slice())
    );
    assert_eq!(
        *decrypt(&encrypted, b"synthetic test passphrase").unwrap(),
        *plain
    );
    assert!(decrypt(&encrypted, b"wrong").is_err());
    assert!(
        decrypt(
            &encrypted[..encrypted.len() - 1],
            b"synthetic test passphrase"
        )
        .is_err()
    );
    let mut corrupted = encrypted.to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(decrypt(&corrupted, b"synthetic test passphrase").is_err());
    assert!(decrypt(&plain, b"synthetic test passphrase").is_err());
    assert!(encrypt(&plain, b"").is_err());
}

#[test]
fn decrypts_go_age_reference_fixture() {
    let bytes = include_bytes!("../../../tests/fixtures/transfer/cxf/external.age");
    let plain = decrypt(bytes, b"synthetic interop fixture passphrase").unwrap();
    assert_eq!(
        plain.as_slice(),
        include_bytes!("../../../tests/fixtures/transfer/cxf/external.json")
    );
    let items = import_json(&plain).unwrap();
    assert_eq!(items[0].title, "Example login");
}
