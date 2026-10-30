use crate::api::{Platform, Request};
use crate::core::Core;
use factorseal::{HardwareBackend, KeyProtector, KeyProtectorFactory, VaultResult};
use serde_json::{Value, json};
use std::path::Path;
use zeroize::Zeroizing;

struct TestProtector(u8);

impl KeyProtector for TestProtector {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::AndroidTrustedEnvironment
    }

    fn wrap(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        Ok(plaintext.iter().map(|byte| byte ^ self.0).collect())
    }

    fn unwrap(&self, ciphertext: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(
            ciphertext.iter().map(|byte| byte ^ self.0).collect(),
        ))
    }

    fn delete(&self) -> VaultResult<()> {
        Ok(())
    }
}

struct TestProtection;

impl KeyProtectorFactory for TestProtection {
    fn create(
        &self,
        root: &Path,
        label: &str,
        biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        self.open(root, label, biometric)
    }

    fn open(
        &self,
        _root: &Path,
        label: &str,
        _biometric: bool,
    ) -> VaultResult<Box<dyn KeyProtector>> {
        let key = label.bytes().fold(0x5a, |key, byte| key ^ byte);
        Ok(Box::new(TestProtector(key)))
    }
}

const PASSWORD: &str = "orbit lantern velvet harbor quiet";

fn core(directory: &Path) -> Core {
    Core::new(directory, Platform::Android, Box::new(TestProtection)).unwrap()
}

fn send(core: &Core, request: &Value) -> Value {
    let request: Request = serde_json::from_value(request.clone()).unwrap();
    let response = match core.handle(request) {
        Ok(response) => response,
        Err(failure) => crate::api::Response::Error {
            code: failure.code,
            message: failure.message,
        },
    };
    serde_json::to_value(&response).unwrap()
}

fn lease() -> Value {
    json!({"idle-seconds": 300, "maximum-seconds": 28800})
}

fn create(core: &Core) {
    let status = send(
        core,
        &json!({"type": "create", "groups": [["password"]], "password": PASSWORD, "lease": lease()}),
    );
    assert_eq!(status["type"], "status", "{status}");
    assert_eq!(status["vault"], "unsealed");
}

fn field<'a>(item: &'a Value, section: &str, field: &str) -> &'a Value {
    item["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == section)
        .unwrap()["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == field)
        .unwrap()
}

fn set(item: &mut Value, section: &str, field: &str, value: &str) {
    for candidate in item["sections"].as_array_mut().unwrap() {
        if candidate["id"] == section {
            for entry in candidate["fields"].as_array_mut().unwrap() {
                if entry["id"] == field {
                    entry["value"] = json!(value);
                }
            }
        }
    }
}

fn draft(item: &Value) -> Value {
    json!({
        "id": item["id"],
        "kind": item["kind"],
        "title": item["title"],
        "favorite": item["favorite"],
        "notes": item["notes"],
        "sections": item["sections"],
    })
}

#[test]
fn a_new_vault_starts_empty_then_seals_and_unlocks_with_its_password() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    let status = send(&core, &json!({"type": "status"}));
    assert_eq!(
        status,
        json!({
            "type": "status",
            "vault": "absent",
            "groups": [],
            "backend": null,
            "paired": false,
            "idle-deadline": null,
            "absolute-deadline": null,
        })
    );

    create(&core);
    assert_eq!(
        send(&core, &json!({"type": "items"})),
        json!({"type": "items", "items": []})
    );

    let sealed = send(&core, &json!({"type": "seal"}));
    assert_eq!(sealed["vault"], "sealed");
    assert_eq!(sealed["groups"], json!([["password"]]));
    assert_eq!(sealed["backend"], "android-trusted-environment");
    assert_eq!(send(&core, &json!({"type": "items"}))["code"], "sealed");

    let wrong = send(
        &core,
        &json!({"type": "unlock", "group": ["password"], "password": "not the password", "lease": lease()}),
    );
    assert_eq!(wrong["code"], "password-rejected");
    let missing = send(
        &core,
        &json!({"type": "unlock", "group": ["password"], "password": null, "lease": lease()}),
    );
    assert_eq!(missing["code"], "password-required");
    let unlocked = send(
        &core,
        &json!({"type": "unlock", "group": ["password"], "password": PASSWORD, "lease": lease()}),
    );
    assert_eq!(unlocked["vault"], "unsealed");
    let again = send(
        &core,
        &json!({"type": "create", "groups": [["password"]], "password": PASSWORD, "lease": lease()}),
    );
    assert_eq!(again["code"], "exists");
}

#[test]
fn weak_passwords_and_bad_timeouts_do_not_create_a_vault() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    let weak = send(
        &core,
        &json!({"type": "create", "groups": [["password"]], "password": "password", "lease": lease()}),
    );
    assert_eq!(weak["code"], "weak-password");
    let timeouts = send(
        &core,
        &json!({"type": "create", "groups": [["password"]], "password": PASSWORD, "lease": {"idle-seconds": 600, "maximum-seconds": 60}}),
    );
    assert_eq!(timeouts["code"], "invalid");
    assert_eq!(send(&core, &json!({"type": "status"}))["vault"], "absent");
}

#[test]
fn logins_are_created_shown_with_hidden_secrets_edited_and_listed() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);

    let template = send(&core, &json!({"type": "template", "kind": "login"}));
    assert_eq!(template["type"], "draft");
    let mut item = template["item"].clone();
    assert_eq!(item["version"], Value::Null);
    item["title"] = json!("GitHub");
    set(&mut item, "account", "username", "octocat");
    set(
        &mut item,
        "account",
        "password",
        "correct horse battery staple",
    );
    set(&mut item, "account", "url-0", "https://github.com/login");
    set(
        &mut item,
        "account",
        "totp",
        "gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
    );
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    assert_eq!(saved["type"], "saved", "{saved}");
    let id = saved["id"].as_str().unwrap().to_owned();

    let shown = send(&core, &json!({"type": "item", "id": id}))["item"].clone();
    assert_eq!(shown["title"], "GitHub");
    assert_eq!(shown["website"], "github.com");
    assert_eq!(shown["version"], saved["version"]);
    assert_eq!(field(&shown, "account", "username")["value"], "octocat");
    let password = field(&shown, "account", "password");
    assert_eq!(password["value"], Value::Null);
    assert_eq!(password["filled"], true);
    assert_eq!(password["concealed"], true);
    assert_eq!(field(&shown, "account", "totp")["value"], Value::Null);

    let revealed = send(
        &core,
        &json!({"type": "reveal", "id": id, "section": "account", "field": "password"}),
    );
    assert_eq!(
        revealed,
        json!({"type": "value", "value": "correct horse battery staple"})
    );

    let codes = send(&core, &json!({"type": "codes", "id": id}));
    let first = &codes["codes"][0];
    assert_eq!(first["field"], "totp");
    assert_eq!(first["period"], 30);
    assert_eq!(first["value"].as_str().unwrap().len(), 6);

    let editing = send(&core, &json!({"type": "edit", "id": id}))["item"].clone();
    assert_eq!(
        field(&editing, "account", "totp")["value"],
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );
    let mut edited = editing.clone();
    edited["title"] = json!("GitHub work");
    let saved_edit = send(
        &core,
        &json!({"type": "save", "item": draft(&edited), "version": editing["version"]}),
    );
    assert_eq!(saved_edit["type"], "saved");
    let stale = send(
        &core,
        &json!({"type": "save", "item": draft(&edited), "version": editing["version"]}),
    );
    assert_eq!(stale["code"], "changed");

    let favorite = send(
        &core,
        &json!({"type": "favorite", "id": id, "favorite": true}),
    );
    assert_eq!(favorite["type"], "saved");
    let items = send(&core, &json!({"type": "items"}));
    assert_eq!(
        items["items"],
        json!([{
            "id": id,
            "title": "GitHub work",
            "kind": "login",
            "username": "octocat",
            "website": "github.com",
            "updated-at": items["items"][0]["updated-at"],
            "favorite": true,
        }])
    );
}

#[test]
fn invalid_setup_keys_are_refused_when_saving() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let mut item = send(&core, &json!({"type": "template", "kind": "login"}))["item"].clone();
    set(&mut item, "account", "totp", "not base32!");
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    assert_eq!(saved["code"], "invalid");
}

#[test]
fn deleted_items_can_be_restored_until_the_vault_seals() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let mut item = send(&core, &json!({"type": "template", "kind": "secure-note"}))["item"].clone();
    item["title"] = json!("Door code");
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    let id = saved["id"].clone();

    let deleted = send(
        &core,
        &json!({"type": "delete", "id": id, "version": saved["version"]}),
    );
    assert_eq!(deleted, json!({"type": "deleted"}));
    assert_eq!(send(&core, &json!({"type": "items"}))["items"], json!([]));
    assert_eq!(send(&core, &json!({"type": "restore"}))["type"], "saved");
    assert_eq!(
        send(&core, &json!({"type": "items"}))["items"][0]["title"],
        "Door code"
    );
    assert_eq!(
        send(&core, &json!({"type": "restore"}))["code"],
        "nothing-to-restore"
    );

    let version = send(&core, &json!({"type": "item", "id": id}))["item"]["version"].clone();
    send(
        &core,
        &json!({"type": "delete", "id": id, "version": version}),
    );
    send(&core, &json!({"type": "seal"}));
    send(
        &core,
        &json!({"type": "unlock", "group": ["password"], "password": PASSWORD, "lease": lease()}),
    );
    assert_eq!(
        send(&core, &json!({"type": "restore"}))["code"],
        "nothing-to-restore"
    );
}

#[test]
fn every_template_saves_and_reads_back() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    for kind in [
        "login",
        "secure-note",
        "card",
        "identity",
        "ssh-key",
        "api-credential",
        "passport",
        "bank-account",
        "document",
        "generic",
    ] {
        let mut item = send(&core, &json!({"type": "template", "kind": kind}))["item"].clone();
        item["title"] = json!(kind);
        let saved = send(
            &core,
            &json!({"type": "save", "item": draft(&item), "version": null}),
        );
        assert_eq!(saved["type"], "saved", "{kind}: {saved}");
        let shown = send(&core, &json!({"type": "item", "id": saved["id"]}));
        assert_eq!(shown["item"]["kind"], kind);
    }
    assert_eq!(
        send(&core, &json!({"type": "items"}))["items"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn tools_generate_rate_and_normalize_without_a_vault() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    let words = send(
        &core,
        &json!({"type": "generate", "options": {"style": "words", "length": 20, "words": 12, "digits": true, "symbols": true}}),
    );
    assert_eq!(words["strength"], "strong");
    assert_eq!(words["password"].as_str().unwrap().split(' ').count(), 12);
    let random = send(
        &core,
        &json!({"type": "generate", "options": {"style": "random", "length": 8, "words": 12, "digits": false, "symbols": false}}),
    );
    assert_eq!(random["password"].as_str().unwrap().len(), 8);
    assert_eq!(random["strength"], "weak");
    let invalid = send(
        &core,
        &json!({"type": "generate", "options": {"style": "random", "length": 7, "words": 12, "digits": false, "symbols": false}}),
    );
    assert_eq!(invalid["code"], "invalid");

    let weak = send(
        &core,
        &json!({"type": "rate-password", "password": "password"}),
    );
    assert_eq!(weak["acceptable"], false);
    assert_eq!(weak["strength"], "weak");
    let strong = send(
        &core,
        &json!({"type": "rate-password", "password": PASSWORD}),
    );
    assert_eq!(strong["acceptable"], true);

    let key = send(
        &core,
        &json!({"type": "setup-key", "value": "otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example"}),
    );
    assert_eq!(
        key,
        json!({
            "type": "setup-key",
            "value": "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example",
            "issuer": "Example",
            "account": "alice",
            "same": false,
        })
    );
    let link = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example";
    for (other, same) in [
        ("gezd gnbv gy3t qojq", true),
        (
            "otpauth://totp/Other?secret=GEZDGNBVGY3TQOJQ&digits=8",
            false,
        ),
        ("JBSWY3DPEHPK3PXP", false),
        ("not base32!", false),
    ] {
        let key = send(
            &core,
            &json!({"type": "setup-key", "value": link, "same-as": other}),
        );
        assert_eq!(key["same"], same, "{other}");
    }
    let bad = send(&core, &json!({"type": "setup-key", "value": "not base32!"}));
    assert_eq!(bad["value"], Value::Null);
}

#[test]
fn sync_needs_a_vault_and_stays_stopped_until_asked() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    assert_eq!(
        send(&core, &json!({"type": "sync-start", "name": "Phone"}))["code"],
        "absent"
    );
    let view = send(&core, &json!({"type": "sync-view"}));
    assert_eq!(view["running"], false);
    assert_eq!(view["paired"], false);
    assert_eq!(
        send(&core, &json!({"type": "sync-refresh"}))["code"],
        "sync"
    );
}

#[test]
fn sync_stays_off_the_network_until_pairing_begins() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let sync = directory.path().join("vault/personal-sync");
    let view = send(&core, &json!({"type": "sync-start", "name": " Phone "}));
    assert_eq!(view["running"], false);
    assert_eq!(
        view["devices"],
        json!([{"name": "Phone", "local": true, "reader": true}])
    );
    assert!(!sync.join("transport.key").exists());
    assert_eq!(
        send(&core, &json!({"type": "sync-refresh"}))["code"],
        "sync"
    );

    let stopped = send(&core, &json!({"type": "sync-stop"}));
    assert_eq!(stopped["devices"], json!([]));
    assert_eq!(
        send(&core, &json!({"type": "sync-invite", "name": "Phone"}))["code"],
        "sync"
    );
    assert!(!sync.exists());
}

#[test]
fn malformed_requests_never_echo_their_contents() {
    let response: Value =
        serde_json::from_slice(&crate::call(br#"{"type":"rate-password","password":7}"#)).unwrap();
    assert_eq!(response["code"], "invalid");
    assert_eq!(response["message"], "the request is malformed");
    let unstarted: Value = serde_json::from_slice(&crate::call(br#"{"type":"items"}"#)).unwrap();
    assert!(matches!(
        unstarted["code"].as_str(),
        Some("not-started" | "sealed")
    ));
}

#[test]
fn the_status_reports_lease_deadlines_and_touching_keeps_the_vault_open() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let status = send(&core, &json!({"type": "status"}));
    let idle = status["idle-deadline"].as_u64().unwrap();
    let absolute = status["absolute-deadline"].as_u64().unwrap();
    assert!(idle <= absolute);
    assert!(absolute - idle >= 28_800 - 300 - 5, "{status}");

    let touched = send(&core, &json!({"type": "touch"}));
    assert_eq!(touched["vault"], "unsealed");
    assert!(touched["idle-deadline"].as_u64().unwrap() >= idle);

    let sealed = send(&core, &json!({"type": "seal"}));
    assert_eq!(sealed["idle-deadline"], Value::Null);
    assert_eq!(sealed["absolute-deadline"], Value::Null);
    assert_eq!(send(&core, &json!({"type": "touch"}))["code"], "sealed");
}

#[test]
fn one_time_passwords_follow_saves_without_keeping_the_vault_open() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let mut item = send(&core, &json!({"type": "template", "kind": "login"}))["item"].clone();
    item["title"] = json!("GitHub");
    set(
        &mut item,
        "account",
        "totp",
        "otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example",
    );
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    let id = saved["id"].clone();
    let issuer = || send(&core, &json!({"type": "codes", "id": id}))["codes"][0]["issuer"].clone();
    assert_eq!(issuer(), "Example");

    let idle = send(&core, &json!({"type": "status"}))["idle-deadline"].clone();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert_eq!(issuer(), "Example");
    assert_eq!(
        send(&core, &json!({"type": "status"}))["idle-deadline"],
        idle
    );

    let mut edited = send(&core, &json!({"type": "edit", "id": id}))["item"].clone();
    set(
        &mut edited,
        "account",
        "totp",
        "otpauth://totp/Other:alice?secret=gezdgnbvgy3tqojq&issuer=Other",
    );
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&edited), "version": edited["version"]}),
    );
    assert_eq!(saved["type"], "saved", "{saved}");
    assert_eq!(issuer(), "Other");
}

#[test]
fn text_from_a_native_scanner_or_the_clipboard_is_classified() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    let classify =
        |text: &str| send(&core, &json!({"type": "classify", "text": text}))["scan"].clone();

    let ticket = format!("factorseal-sync:1:{}", "A".repeat(40));
    assert_eq!(
        classify(&format!("  {ticket}\n")),
        json!({"type": "pairing", "ticket": ticket})
    );
    assert_eq!(
        classify("otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example"),
        json!({
            "type": "one-time-password",
            "value": "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQ&issuer=Example",
            "issuer": "Example",
            "account": "alice",
        })
    );
    assert_eq!(
        classify("https://example.com"),
        json!({"type": "unsupported"})
    );
    assert_eq!(classify("   "), json!({"type": "nothing"}));
}

const PASSPHRASE: &str = "copper meadow lantern orbit quiet harbor";
const HYBRID_KEY: &str = include_str!("../../../tests/fixtures/transfer/cxf/hybrid-key.txt");
const HYBRID_RECIPIENT: &str =
    include_str!("../../../tests/fixtures/transfer/cxf/hybrid-recipient.txt");

fn save_login(core: &Core, title: &str) {
    let mut item = send(core, &json!({"type": "template", "kind": "login"}))["item"].clone();
    item["title"] = json!(title);
    set(&mut item, "account", "username", "octocat");
    set(
        &mut item,
        "account",
        "password",
        "correct horse battery staple",
    );
    let saved = send(
        core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    assert_eq!(saved["type"], "saved", "{saved}");
}

fn titles(core: &Core) -> Vec<String> {
    let mut titles: Vec<String> = send(core, &json!({"type": "items"}))["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["title"].as_str().unwrap().to_owned())
        .collect();
    titles.sort();
    titles
}

fn add_login(core: &Core, title: &str, username: &str, website: &str) -> Value {
    let mut item = send(core, &json!({"type": "template", "kind": "login"}))["item"].clone();
    item["title"] = json!(title);
    set(&mut item, "account", "username", username);
    set(
        &mut item,
        "account",
        "password",
        &format!("{username} password"),
    );
    set(&mut item, "account", "url-0", website);
    let saved = send(
        core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    assert_eq!(saved["type"], "saved", "{saved}");
    saved["id"].clone()
}

fn web(address: &str) -> Value {
    json!({"web": address})
}

fn app(package: &str) -> Value {
    json!({"app": package})
}

fn login_titles(logins: &Value, group: &str) -> Vec<String> {
    logins[group]
        .as_array()
        .unwrap()
        .iter()
        .map(|login| login["title"].as_str().unwrap().to_owned())
        .collect()
}

fn websites(core: &Core, id: &Value) -> Vec<String> {
    send(core, &json!({"type": "item", "id": id}))["item"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|section| section["fields"].as_array().unwrap())
        .filter(|field| field["type"] == "url")
        .map(|field| field["value"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn autofill_offers_and_fills_only_logins_saved_for_the_exact_website() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let github = add_login(&core, "GitHub", "octocat", "https://github.com/login");
    add_login(&core, "Example", "alice", "https://example.com");
    let note = send(&core, &json!({"type": "template", "kind": "secure-note"}))["item"].clone();
    let note = send(
        &core,
        &json!({"type": "save", "item": draft(&note), "version": null}),
    )["id"]
        .clone();

    let logins = send(
        &core,
        &json!({"type": "logins", "site": web("https://GitHub.com/session")}),
    );
    assert_eq!(login_titles(&logins, "linked"), ["GitHub"]);
    assert_eq!(logins["linked"][0]["username"], "octocat");
    assert_eq!(login_titles(&logins, "others"), Vec::<String>::new());
    let logins = send(
        &core,
        &json!({"type": "logins", "site": web("https://gist.github.com")}),
    );
    assert_eq!(login_titles(&logins, "linked"), Vec::<String>::new());
    assert_eq!(login_titles(&logins, "others"), Vec::<String>::new());
    let refused = send(
        &core,
        &json!({"type": "logins", "site": web("http://github.com")}),
    );
    assert_eq!(refused["code"], "invalid", "{refused}");

    assert_eq!(
        send(
            &core,
            &json!({"type": "fill", "id": github, "site": web("https://github.com")})
        ),
        json!({"type": "credentials", "username": "octocat", "password": "octocat password"})
    );
    let refused = send(
        &core,
        &json!({"type": "fill", "id": github, "site": web("https://example.com")}),
    );
    assert_eq!(refused["code"], "denied", "{refused}");
    let refused = send(
        &core,
        &json!({"type": "fill", "id": note, "site": web("https://github.com")}),
    );
    assert_eq!(refused["code"], "invalid", "{refused}");
    assert_eq!(websites(&core, &github), ["https://github.com/login"]);

    send(&core, &json!({"type": "seal"}));
    let sealed = send(
        &core,
        &json!({"type": "logins", "site": web("https://github.com")}),
    );
    assert_eq!(sealed["code"], "sealed", "{sealed}");
}

#[test]
fn autofill_hides_a_concealed_username_but_still_fills_it() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let github = add_login(&core, "GitHub", "octocat", "https://github.com/login");
    let mut item = send(&core, &json!({"type": "edit", "id": github}))["item"].clone();
    for section in item["sections"].as_array_mut().unwrap() {
        for field in section["fields"].as_array_mut().unwrap() {
            if field["id"] == "username" {
                field["concealed"] = json!(true);
            }
        }
    }
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": item["version"]}),
    );
    assert_eq!(saved["type"], "saved", "{saved}");

    let logins = send(
        &core,
        &json!({"type": "logins", "site": web("https://github.com")}),
    );
    assert_eq!(login_titles(&logins, "linked"), ["GitHub"]);
    assert_eq!(logins["linked"][0]["username"], "");
    assert_eq!(
        send(
            &core,
            &json!({"type": "fill", "id": github, "site": web("https://github.com")})
        ),
        json!({"type": "credentials", "username": "octocat", "password": "octocat password"})
    );
}

#[test]
fn an_app_learns_the_login_picked_for_it() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let github = add_login(&core, "GitHub", "octocat", "https://github.com/login");
    add_login(&core, "Example", "alice", "https://example.com");

    let logins = send(
        &core,
        &json!({"type": "logins", "site": app("com.github.android")}),
    );
    assert_eq!(login_titles(&logins, "linked"), Vec::<String>::new());
    assert_eq!(login_titles(&logins, "others"), ["Example", "GitHub"]);

    for _ in 0..2 {
        assert_eq!(
            send(
                &core,
                &json!({"type": "fill", "id": github, "site": app("com.github.android")})
            ),
            json!({"type": "credentials", "username": "octocat", "password": "octocat password"})
        );
    }
    assert_eq!(
        websites(&core, &github),
        [
            "https://github.com/login",
            "androidapp://com.github.android"
        ]
    );
    let logins = send(
        &core,
        &json!({"type": "logins", "site": app("com.github.android")}),
    );
    assert_eq!(login_titles(&logins, "linked"), ["GitHub"]);
    assert_eq!(login_titles(&logins, "others"), ["Example"]);
    let logins = send(
        &core,
        &json!({"type": "logins", "site": web("https://github.com")}),
    );
    assert_eq!(login_titles(&logins, "linked"), ["GitHub"]);

    for package in [
        "",
        "github",
        "com..github",
        "com.1github",
        "com.git-hub",
        "com.github/x",
    ] {
        let refused = send(&core, &json!({"type": "logins", "site": app(package)}));
        assert_eq!(refused["code"], "invalid", "{package}");
    }
}

#[test]
fn saving_from_autofill_adds_updates_or_keeps_a_login() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let save = |site: Value, title: &str, username: &str, password: &str| {
        send(
            &core,
            &json!({"type": "save-login", "site": site, "title": title, "username": username, "password": password}),
        )
    };

    let added = save(
        web("https://example.com/sign-up"),
        "example.com",
        "alice",
        "first",
    );
    assert_eq!(added["change"], "added", "{added}");
    let id = added["id"].clone();
    assert_eq!(websites(&core, &id), ["https://example.com"]);
    assert_eq!(
        send(&core, &json!({"type": "item", "id": id}))["item"]["title"],
        "example.com"
    );
    let kept = save(web("https://example.com"), "example.com", "alice", "first");
    assert_eq!((&kept["change"], &kept["id"]), (&json!("unchanged"), &id));
    let updated = save(web("https://example.com"), "example.com", "alice", "second");
    assert_eq!(
        (&updated["change"], &updated["id"]),
        (&json!("updated"), &id)
    );
    assert_eq!(
        send(
            &core,
            &json!({"type": "fill", "id": id, "site": web("https://example.com")})
        )["password"],
        "second"
    );
    assert_eq!(
        save(web("https://example.com"), "example.com", "bob", "third")["change"],
        "added"
    );
    assert_eq!(
        save(
            web("https://login.example.com"),
            "login.example.com",
            "alice",
            "fourth"
        )["change"],
        "added"
    );

    let refused = save(web("https://example.com"), "example.com", "alice", "");
    assert_eq!(refused["code"], "invalid", "{refused}");
    let refused = save(web("http://example.com"), "example.com", "alice", "fifth");
    assert_eq!(refused["code"], "invalid", "{refused}");
    add_login(&core, "Example again", "alice", "https://example.com/other");
    let refused = save(web("https://example.com"), "example.com", "alice", "sixth");
    assert_eq!(refused["code"], "conflict", "{refused}");

    let added = save(app("com.example.mail"), "  ", "carol", "seventh");
    assert_eq!(added["change"], "added", "{added}");
    assert_eq!(
        websites(&core, &added["id"]),
        ["androidapp://com.example.mail"]
    );
    assert_eq!(
        send(&core, &json!({"type": "item", "id": added["id"]}))["item"]["title"],
        "androidapp://com.example.mail"
    );
    assert_eq!(
        titles(&core),
        [
            "Example again",
            "androidapp://com.example.mail",
            "example.com",
            "example.com",
            "login.example.com"
        ]
    );
}

#[test]
fn notes_are_stored_on_the_item_like_desktop_stores_them() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    let mut item = send(&core, &json!({"type": "template", "kind": "login"}))["item"].clone();
    item["title"] = json!("GitHub");
    set(&mut item, "account", "username", "octocat");
    set(
        &mut item,
        "notes",
        "notes",
        "recovery codes are in the safe",
    );
    let saved = send(
        &core,
        &json!({"type": "save", "item": draft(&item), "version": null}),
    );
    let shown = send(&core, &json!({"type": "item", "id": saved["id"]}))["item"].clone();
    assert_eq!(shown["notes"], Value::Null);
    assert_eq!(shown["notes-filled"], true);
    assert_eq!(
        send(
            &core,
            &json!({"type": "reveal", "id": saved["id"], "section": "notes", "field": "notes"})
        ),
        json!({"type": "value", "value": "recovery codes are in the safe"})
    );
    assert!(
        shown["sections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|section| section["id"] != "notes")
    );
    let file = send(
        &core,
        &json!({"type": "export", "format": "bitwarden-json", "key": null}),
    );
    assert_eq!(file["type"], "file", "{file}");

    let mut edited = send(&core, &json!({"type": "edit", "id": saved["id"]}))["item"].clone();
    assert_eq!(
        field(&edited, "notes", "notes")["value"],
        "recovery codes are in the safe"
    );
    set(&mut edited, "notes", "notes", "");
    send(
        &core,
        &json!({"type": "save", "item": draft(&edited), "version": edited["version"]}),
    );
    let shown = send(&core, &json!({"type": "item", "id": saved["id"]}))["item"].clone();
    assert_eq!(shown["notes"], Value::Null);
    assert_eq!(shown["notes-filled"], false);
}

#[test]
fn a_backup_restores_every_item_into_another_vault() {
    let (first, second) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let source = core(first.path());
    create(&source);
    save_login(&source, "GitHub");
    save_login(&source, "GitLab");
    let file = send(
        &source,
        &json!({"type": "export", "format": "factorseal", "key": {"passphrase": PASSPHRASE}}),
    );
    assert_eq!(file["type"], "file", "{file}");
    assert_eq!(file["name"], "factorseal-backup.factorseal");

    let target = core(second.path());
    create(&target);
    let wrong = send(
        &target,
        &json!({"type": "import", "format": "factorseal", "file": file["data"], "key": {"passphrase": "orbit lantern wrong harbor"}}),
    );
    assert_eq!(wrong["type"], "error", "{wrong}");
    let review = send(
        &target,
        &json!({"type": "import", "format": "factorseal", "file": file["data"], "key": {"passphrase": PASSPHRASE}}),
    );
    assert_eq!(
        review,
        json!({"type": "import-review", "items": 2, "preserved": 0})
    );
    let imported = send(&target, &json!({"type": "import-commit", "replace": false}));
    assert_eq!(
        imported,
        json!({"type": "imported", "added": 2, "replaced": 0, "kept": 0, "preserved": 0})
    );
    assert_eq!(titles(&target), ["GitHub", "GitLab"]);
    assert_eq!(
        send(&target, &json!({"type": "import-commit", "replace": false}))["code"],
        "not-found"
    );
}

#[test]
fn credentials_move_between_vaults_in_every_export_format() {
    let directory = tempfile::tempdir().unwrap();
    let source = core(directory.path());
    create(&source);
    save_login(&source, "GitHub");
    for (format, export, import) in [
        (
            "cxf-age",
            json!({"passphrase": PASSPHRASE}),
            json!({"passphrase": PASSPHRASE}),
        ),
        (
            "cxf-age",
            json!({"key-file": HYBRID_RECIPIENT}),
            json!({"key-file": HYBRID_KEY}),
        ),
        ("bitwarden-json", Value::Null, Value::Null),
        ("1password-csv", Value::Null, Value::Null),
        ("keepass-csv", Value::Null, Value::Null),
    ] {
        let file = send(
            &source,
            &json!({"type": "export", "format": format, "key": export}),
        );
        assert_eq!(file["type"], "file", "{format}: {file}");
        let directory = tempfile::tempdir().unwrap();
        let target = core(directory.path());
        create(&target);
        let review = send(
            &target,
            &json!({"type": "import", "format": format, "file": file["data"], "key": import}),
        );
        assert_eq!(review["items"], 1, "{format}: {review}");
        let imported = send(&target, &json!({"type": "import-commit", "replace": false}));
        assert_eq!(imported["added"], 1, "{format}: {imported}");
        assert_eq!(titles(&target), ["GitHub"], "{format}");
    }
}

#[test]
fn imports_keep_or_replace_existing_items_and_can_be_cancelled() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    save_login(&core, "GitHub");
    let file = send(
        &core,
        &json!({"type": "export", "format": "factorseal", "key": {"passphrase": PASSPHRASE}}),
    );
    let import = json!({"type": "import", "format": "factorseal", "file": file["data"], "key": {"passphrase": PASSPHRASE}});
    send(&core, &import);
    assert_eq!(
        send(&core, &json!({"type": "import-commit", "replace": false}))["kept"],
        1
    );
    send(&core, &import);
    assert_eq!(
        send(&core, &json!({"type": "import-commit", "replace": true}))["replaced"],
        1
    );
    send(&core, &import);
    assert_eq!(
        send(&core, &json!({"type": "import-cancel"}))["type"],
        "status"
    );
    assert_eq!(
        send(&core, &json!({"type": "import-commit", "replace": false}))["code"],
        "not-found"
    );
    send(&core, &import);
    send(&core, &json!({"type": "seal"}));
    assert_eq!(
        send(&core, &json!({"type": "import-commit", "replace": false}))["code"],
        "sealed"
    );
}

#[test]
fn encrypted_exports_need_a_strong_passphrase_and_an_open_vault() {
    let directory = tempfile::tempdir().unwrap();
    let core = core(directory.path());
    create(&core);
    for format in ["factorseal", "cxf-age"] {
        let weak = send(
            &core,
            &json!({"type": "export", "format": format, "key": {"passphrase": "hunter2"}}),
        );
        assert_eq!(weak["code"], "weak-password", "{format}: {weak}");
        let missing = send(
            &core,
            &json!({"type": "export", "format": format, "key": null}),
        );
        assert_eq!(missing["code"], "password-required", "{format}: {missing}");
    }
    send(&core, &json!({"type": "seal"}));
    let sealed = send(
        &core,
        &json!({"type": "export", "format": "bitwarden-json", "key": null}),
    );
    assert_eq!(sealed["code"], "sealed");
}

const MESSAGES: &str = include_str!("../../protocol/messages.json");

macro_rules! every {
    ($kind:ident: $($variant:ident),+ $(,)?) => {{
        let exhaustive = |value: &crate::api::$kind| match value {
            $(crate::api::$kind::$variant)|+ => {}
        };
        [$(crate::api::$kind::$variant),+]
            .iter()
            .inspect(|value| exhaustive(value))
            .map(|value| serde_json::to_value(value).unwrap())
            .collect::<Vec<_>>()
    }};
}

fn conforms(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => {
            actual.len() == expected.len()
                && actual.iter().all(|(key, value)| {
                    expected.get(key).is_some_and(|other| {
                        if key == "type" {
                            value == other
                        } else {
                            conforms(value, other)
                        }
                    })
                })
        }
        (Value::Array(actual), Value::Array(expected)) => {
            match (actual.first(), expected.first()) {
                (Some(actual), Some(expected)) => conforms(actual, expected),
                _ => true,
            }
        }
        (Value::Null, _)
        | (_, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => true,
        _ => false,
    }
}

fn messages() -> Value {
    serde_json::from_str(MESSAGES).unwrap()
}

#[test]
fn the_core_accepts_every_request_the_app_sends() {
    for request in messages()["requests"].as_array().unwrap() {
        if let Err(failure) = serde_json::from_value::<Request>(request.clone()) {
            panic!("the core rejects {request}: {failure}");
        }
    }
}

#[test]
fn the_shared_messages_list_every_value_the_core_can_send() {
    let messages = messages();
    let enums = &messages["enums"];
    let error_codes = every!(ErrorCode:
        NotStarted, Absent, Exists, Sealed, PasswordRequired, PasswordRejected, WeakPassword,
        Cancelled, Denied, UiUnavailable, SessionLocked, CredentialInvalidated,
        HardwareUnavailable, PolicyUnsupported, NotFound, Changed, Conflict, Invalid,
        NothingToRestore, Sync, Failed,
    );
    let field_types = every!(FieldType:
        Text, Concealed, Url, Email, Phone, Date, MonthYear, Totp, Multiline, Boolean,
        CardNumber, SshKey, Address, Reference, Unknown,
    );
    let kinds = every!(Kind:
        Login, SecureNote, Card, Identity, SshKey, ApiCredential, Passport, BankAccount,
        Document, Generic,
    );
    assert_eq!(enums["error-code"], json!(error_codes));
    assert_eq!(enums["field-type"], json!(field_types));
    assert_eq!(enums["kind"], json!(kinds));
    assert_eq!(
        enums["login-change"],
        json!(every!(LoginChange: Added, Updated, Unchanged))
    );
    assert_eq!(
        enums["strength"],
        json!(every!(Strength: Weak, Good, Strong))
    );
    assert_eq!(
        enums["vault-state"],
        json!(every!(VaultState: Absent, Sealed, Unsealed))
    );
}

fn conversation(core: &Core) -> Vec<Value> {
    let mut sent = Vec::new();
    let mut exchange = |request: Value| {
        let response = send(core, &request);
        sent.push(response.clone());
        response
    };
    exchange(json!({"type": "status"}));
    exchange(
        json!({"type": "create", "groups": [["password"]], "password": PASSWORD, "lease": lease()}),
    );
    exchange(json!({"type": "rate-password", "password": PASSWORD}));
    exchange(
        json!({"type": "generate", "options": {"style": "words", "length": 20, "words": 12, "digits": true, "symbols": true}}),
    );
    exchange(
        json!({"type": "setup-key", "value": "otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example"}),
    );
    let mut item = exchange(json!({"type": "template", "kind": "login"}))["item"].clone();
    item["title"] = json!("GitHub");
    set(&mut item, "account", "username", "octocat");
    set(
        &mut item,
        "account",
        "password",
        "correct horse battery staple",
    );
    set(&mut item, "account", "url-0", "https://github.com/login");
    set(&mut item, "account", "totp", "gezdgnbvgy3tqojq");
    let saved = exchange(json!({"type": "save", "item": draft(&item), "version": null}));
    let id = saved["id"].clone();
    exchange(json!({"type": "items"}));
    exchange(json!({"type": "item", "id": id}));
    exchange(json!({"type": "reveal", "id": id, "section": "account", "field": "password"}));
    exchange(json!({"type": "codes", "id": id}));
    exchange(json!({"type": "logins", "site": {"app": "com.github.android"}}));
    exchange(json!({"type": "fill", "id": id, "site": {"web": "https://github.com"}}));
    exchange(
        json!({"type": "save-login", "site": {"app": "com.github.android"}, "title": "GitHub", "username": "octocat", "password": "a new password"}),
    );
    exchange(json!({"type": "delete", "id": id, "version": saved["version"]}));
    exchange(json!({"type": "item", "id": id}));
    exchange(json!({"type": "sync-view"}));
    let file = exchange(json!({"type": "export", "format": "bitwarden-json", "key": null}));
    exchange(
        json!({"type": "import", "format": "bitwarden-json", "file": file["data"], "key": null}),
    );
    exchange(json!({"type": "import-commit", "replace": false}));
    for text in [
        "",
        &format!("factorseal-sync:1:{}", "A".repeat(40)),
        "otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example",
        "https://example.com",
    ] {
        exchange(json!({"type": "classify", "text": text}));
    }
    sent
}

fn pairing() -> Value {
    let device = |name: &str, local: bool| crate::api::Device {
        name: name.to_owned(),
        local,
        reader: false,
    };
    let view = crate::api::SyncView {
        running: true,
        paired: true,
        devices: vec![device("Pixel 9", true)],
        reachable: 1,
        last_exchange: Some(1_800_000_000),
        invitation: Some(crate::api::Invitation {
            ticket: crate::api::Revealed(Zeroizing::new("factorseal-sync:1:ticket".to_owned())),
            modules: vec![vec![true, false], vec![false, true]],
            expires: 1_800_000_300,
        }),
        review: Some(crate::api::Review {
            request: "request-1".to_owned(),
            code: "482 913".to_owned(),
            devices: vec![device("Laptop", false)],
            verified: true,
            waiting: false,
            approved_here: false,
        }),
        ..Default::default()
    };
    serde_json::to_value(crate::api::Response::Sync(view)).unwrap()
}

#[test]
fn the_shared_messages_show_every_response_the_core_sends() {
    let directory = tempfile::tempdir().unwrap();
    let mut sent = conversation(&core(directory.path()));
    sent.push(pairing());
    let messages = messages();
    let samples = messages["responses"].as_array().unwrap();
    for response in &sent {
        assert!(
            samples.iter().any(|sample| conforms(response, sample)),
            "protocol/messages.json has nothing shaped like {response}"
        );
    }
    for sample in samples {
        assert!(
            sent.iter().any(|response| conforms(response, sample)),
            "the core never sends anything shaped like {sample}"
        );
    }
}
