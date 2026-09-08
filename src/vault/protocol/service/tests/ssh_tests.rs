use super::*;
use crate::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret, PersonalSecretKind};
use crate::vault::ssh_agent::{AgentReply, AgentRequest};
use signature::Verifier;

pub(super) fn key(seed: u8) -> ssh_key::PrivateKey {
    ssh_key::private::Ed25519Keypair::from(ssh_key::private::Ed25519PrivateKey::from_bytes(
        &[seed; 32],
    ))
    .into()
}

pub(super) fn item(key: &ssh_key::PrivateKey) -> PersonalSecret {
    let mut item = PersonalSecret::template(PersonalSecretKind::SshKey, "Work SSH key".into());
    item.sections[0].fields[0].value = key
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string()
        .into();
    item
}

pub(super) fn save(service: &VaultService, item: &PersonalSecret, now: u64) {
    service
        .state
        .lock_live(Instant::now())
        .unwrap()
        .store()
        .put_at(
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
            &SecretAddress::new(item.id.clone(), None).unwrap(),
            &item.encode().unwrap(),
            None,
            &Provenance::caller(&caller(), None),
            now,
        )
        .unwrap();
}

fn pending(service: &VaultService, caller: &CallerIdentity, public_key: &[u8], now: u64) -> String {
    match service
        .ssh_request(
            caller,
            &AgentRequest::Sign {
                public_key,
                data: b"test challenge",
                flags: 0,
                destination: None,
            },
            now,
        )
        .unwrap()
    {
        AgentReply::Pending(id) => id,
        AgentReply::Ready { .. } => panic!("signature released without approval"),
    }
}

pub(super) fn approve(directory: &tempfile::TempDir, service: &VaultService, id: &str, now: u64) {
    let permissions = service
        .state
        .lock_live(Instant::now())
        .unwrap()
        .list_permissions(now)
        .unwrap()
        .1;
    let permission = permissions
        .iter()
        .find(|permission| permission.id == id)
        .unwrap();
    assert_eq!(permission.operation, PermissionOperation::SshSign);
    assert!(
        permission
            .key_fingerprint
            .as_deref()
            .unwrap()
            .starts_with("SHA256:")
    );
    let PermissionState::Pending { challenge, .. } = permission.state else {
        panic!("not pending")
    };
    let unsealed = Vault::unseal_for_test(&directory.path().join("factorseal")).unwrap();
    let signature = unsealed
        .sign_permission_challenge(id, &challenge, Some(60))
        .unwrap();
    service
        .state
        .lock_live(Instant::now())
        .unwrap()
        .approve(
            id,
            &signature,
            Some(60),
            now,
            &Provenance::caller(&caller(), None),
        )
        .unwrap();
}

#[test]
fn ssh_signatures_require_a_key_and_executable_grant_and_obey_revocation() {
    let (directory, service) = service(100, UnsealLeasePolicy::default());
    let key = key(1);
    let saved = item(&key);
    save(&service, &saved, 100);
    let public_key = key.public_key().to_bytes().unwrap();
    let caller = caller();
    // Ordinary read grants do not confer signing access.
    service
        .authorize_namespace(
            &caller,
            PERSONAL_SECRET_NAMESPACE,
            [GrantPermission::Get],
            None,
            100,
        )
        .unwrap();
    let id = pending(&service, &caller, &public_key, 100);
    assert_eq!(pending(&service, &caller, &public_key, 100), id);
    approve(&directory, &service, &id, 101);
    let request = AgentRequest::Sign {
        public_key: &public_key,
        data: b"test challenge",
        flags: 0,
        destination: None,
    };
    let AgentReply::Ready {
        bytes, deadline, ..
    } = service.ssh_request(&caller, &request, 102).unwrap()
    else {
        panic!("not signed")
    };
    assert_eq!(bytes[0], 14);
    assert_eq!(
        u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize,
        bytes.len() - 5
    );
    let signature = ssh_key::Signature::try_from(&bytes[5..]).unwrap();
    Verifier::verify(key.public_key(), b"test challenge", &signature).unwrap();
    assert!(Verifier::verify(key.public_key(), b"different challenge", &signature).is_err());
    assert!(deadline.unwrap() <= Instant::now() + Duration::from_secs(59));
    let other = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        caller.application_id(),
        [8; 32],
        None,
    )
    .unwrap();
    assert_ne!(pending(&service, &other, &public_key, 103), id);
    service
        .state
        .lock_live(Instant::now())
        .unwrap()
        .revoke_permission(&id, 104, &Provenance::caller(&caller, None))
        .unwrap();
    assert_ne!(pending(&service, &caller, &public_key, 105), id);
    service.seal().unwrap();
    assert!(matches!(
        service.ssh_request(&caller, &request, 106),
        Err(VaultError::Sealed)
    ));
}

#[test]
fn ssh_key_replacement_archival_denial_and_expiry_fail_closed() {
    let (directory, service) = service(100, UnsealLeasePolicy::default());
    let original = key(1);
    let replacement = key(2);
    let mut saved = item(&original);
    save(&service, &saved, 100);
    let public_key = original.public_key().to_bytes().unwrap();
    let caller = caller();
    let id = pending(&service, &caller, &public_key, 100);
    service
        .state
        .lock_live(Instant::now())
        .unwrap()
        .deny_approval(&id, 101)
        .unwrap();
    assert_eq!(
        service.ssh_wait_permission(&caller, &id, 101).unwrap(),
        PermissionWaitStatus::Denied
    );
    let id = pending(&service, &caller, &public_key, 102);
    approve(&directory, &service, &id, 102);
    let request = AgentRequest::Sign {
        public_key: &public_key,
        data: b"test challenge",
        flags: 0,
        destination: None,
    };
    assert!(matches!(
        service.ssh_request(&caller, &request, 162).unwrap(),
        AgentReply::Pending(_)
    ));
    saved.sections[0].fields[0].value = replacement
        .to_openssh(ssh_key::LineEnding::LF)
        .unwrap()
        .to_string()
        .into();
    save(&service, &saved, 163);
    assert!(service.ssh_request(&caller, &request, 163).is_err());
    let replacement_public = replacement.public_key().to_bytes().unwrap();
    pending(&service, &caller, &replacement_public, 163);
    saved.archived = true;
    save(&service, &saved, 164);
    let AgentReply::Ready { bytes, .. } = service
        .ssh_request(&caller, &AgentRequest::Identities, 164)
        .unwrap()
    else {
        panic!("not listed")
    };
    assert_eq!(bytes, [12, 0, 0, 0, 0]);
    assert!(
        service
            .ssh_request(
                &caller,
                &AgentRequest::Sign {
                    public_key: &replacement_public,
                    data: b"test",
                    flags: 0,
                    destination: None,
                },
                164
            )
            .is_err()
    );
}

#[test]
fn ssh_sign_grant_does_not_export_the_private_key() {
    let (directory, service) = service(100, UnsealLeasePolicy::default());
    let key = key(1);
    let saved = item(&key);
    save(&service, &saved, 100);
    let public_key = key.public_key().to_bytes().unwrap();
    let caller = caller();
    let id = pending(&service, &caller, &public_key, 100);
    approve(&directory, &service, &id, 101);
    let response = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Get {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: WireSecretAddress::new(saved.id.clone(), None),
        })
        .unwrap(),
        102,
    );
    assert!(matches!(
        response.result,
        Err(VaultResponseError {
            code: VaultResponseErrorCode::AuthorizationRequired,
            ..
        })
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ssh_openssh_lists_and_verifies_a_signature_after_interactive_approval() {
    openssh_round_trip(&key(3));
    for pem in [
        include_str!("../../../../../tests/fixtures/ssh/rsa"),
        include_str!("../../../../../tests/fixtures/ssh/p256"),
        include_str!("../../../../../tests/fixtures/ssh/p384"),
        include_str!("../../../../../tests/fixtures/ssh/p521"),
    ] {
        openssh_round_trip(
            &ssh_key::PrivateKey::from_openssh(pem)
                .unwrap()
                .decrypt("fixture-passphrase")
                .unwrap(),
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn openssh_round_trip(key: &ssh_key::PrivateKey) {
    use crate::vault::{CallerIdentityCache, ssh_agent, transport};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    if Command::new("ssh-add").arg("-?").output().is_err() {
        eprintln!("OpenSSH interoperability check skipped: ssh-add is unavailable");
        return;
    }
    let now = transport::unix_time().unwrap();
    let (directory, service) = service(now, UnsealLeasePolicy::default());
    save(&service, &item(key), now);
    let socket = directory.path().join("factorseal/interop.sock");
    let public_file = directory.path().join("test.pub");
    std::fs::write(&public_file, key.public_key().to_openssh().unwrap()).unwrap();
    let (listener, _guard) = transport::unix_socket::bind_listener(&socket).unwrap();
    let stopping = AtomicBool::new(false);
    let cache = CallerIdentityCache::default();
    std::thread::scope(|scope| {
        let _stop = Stop(&stopping);
        let server = scope.spawn(|| {
            ssh_agent::serve(&service, &listener, &stopping, &|stream| {
                #[cfg(target_os = "linux")]
                {
                    crate::vault::linux::caller_identity(stream, &cache)
                }
                #[cfg(target_os = "macos")]
                {
                    crate::vault::macos::caller_identity(stream, &cache)
                }
            })
        });
        let listed = Command::new("ssh-add")
            .arg("-L")
            .env("SSH_AUTH_SOCK", &socket)
            .output()
            .unwrap();
        assert!(
            listed.status.success(),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        assert!(String::from_utf8_lossy(&listed.stdout).starts_with(key.algorithm().as_str()));
        let mut client = Command::new("ssh-add")
            .arg("-T")
            .arg(&public_file)
            .env("SSH_AUTH_SOCK", &socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let timeout = Instant::now() + Duration::from_secs(10);
        let permission = loop {
            let permissions = service
                .state
                .lock_live(Instant::now())
                .unwrap()
                .list_permissions(transport::unix_time().unwrap())
                .unwrap()
                .1;
            if let Some(permission) = permissions.into_iter().next() {
                break permission;
            }
            if Instant::now() >= timeout {
                let _ = client.kill();
                let _ = client.wait();
                panic!("ssh-add did not request approval");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(permission.principal.application_id.ends_with("ssh-add"));
        approve(
            &directory,
            &service,
            &permission.id,
            transport::unix_time().unwrap(),
        );
        // OpenSSH checks the returned signature against the public key itself.
        let timeout = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = client.try_wait().unwrap() {
                assert!(status.success(), "OpenSSH signature verification failed");
                break;
            }
            if Instant::now() >= timeout {
                let _ = client.kill();
                let _ = client.wait();
                panic!("ssh-add did not finish after approval");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        stopping.store(true, Ordering::Release);
        server.join().unwrap().unwrap();
    });
}

#[test]
fn ssh_encrypted_openssh_keys_support_rsa_sha2_and_all_nist_curves() {
    for (pem, flags) in [
        (include_str!("../../../../../tests/fixtures/ssh/rsa"), 2),
        (include_str!("../../../../../tests/fixtures/ssh/rsa"), 4),
        (include_str!("../../../../../tests/fixtures/ssh/p256"), 0),
        (include_str!("../../../../../tests/fixtures/ssh/p384"), 0),
        (include_str!("../../../../../tests/fixtures/ssh/p521"), 0),
        (include_str!("../../../../../tests/fixtures/ssh/ed25519"), 0),
    ] {
        let (directory, service) = service(100, UnsealLeasePolicy::default());
        let key = ssh_key::PrivateKey::from_openssh(pem).unwrap();
        let mut saved = item(&key);
        save(&service, &saved, 100);
        let public_key = key.public_key().to_bytes().unwrap();
        let request = AgentRequest::Sign {
            public_key: &public_key,
            data: b"encrypted fixture challenge",
            flags,
            destination: None,
        };
        // Discovery and approval do not require a passphrase or perform the KDF.
        let AgentReply::Pending(id) = service.ssh_request(&caller(), &request, 100).unwrap() else {
            panic!("not pending");
        };
        approve(&directory, &service, &id, 100);
        assert!(service.ssh_request(&caller(), &request, 101).is_err());
        saved.sections[0]
            .fields
            .iter_mut()
            .find(|field| field.id == "passphrase")
            .unwrap()
            .value = "wrong passphrase".into();
        save(&service, &saved, 101);
        assert!(service.ssh_request(&caller(), &request, 101).is_err());
        saved.sections[0]
            .fields
            .iter_mut()
            .find(|field| field.id == "passphrase")
            .unwrap()
            .value = "fixture-passphrase".into();
        save(&service, &saved, 101);
        let AgentReply::Ready { bytes, .. } =
            service.ssh_request(&caller(), &request, 102).unwrap()
        else {
            panic!("not signed");
        };
        let signature = ssh_key::Signature::try_from(&bytes[5..]).unwrap();
        crate::vault::ssh_agent::crypto::verify(
            key.public_key().key_data(),
            b"encrypted fixture challenge",
            &signature,
        )
        .unwrap();
        let invalid_flags = if flags == 0 { 2 } else { 0 };
        assert!(
            service
                .ssh_request(
                    &caller(),
                    &AgentRequest::Sign {
                        public_key: &public_key,
                        data: b"test",
                        flags: invalid_flags,
                        destination: None,
                    },
                    102
                )
                .is_err()
        );
    }
}

#[test]
fn ssh_destination_grants_are_scoped_to_user_host_and_forwarding_path() {
    let (directory, service) = service(100, UnsealLeasePolicy::default());
    let key = key(9);
    save(&service, &item(&key), 100);
    let public_key = key.public_key().to_bytes().unwrap();
    let destination = crate::SshDestination {
        user: "alice".into(),
        host_keys: vec!["SHA256:jump".into(), "SHA256:target".into()],
    };
    let request = AgentRequest::Sign {
        public_key: &public_key,
        data: b"test",
        flags: 0,
        destination: Some(destination.clone()),
    };
    let AgentReply::Pending(id) = service.ssh_request(&caller(), &request, 100).unwrap() else {
        panic!("not pending");
    };
    approve(&directory, &service, &id, 100);
    assert!(matches!(
        service.ssh_request(&caller(), &request, 100).unwrap(),
        AgentReply::Ready { .. }
    ));
    for changed in [
        None,
        Some(crate::SshDestination {
            user: "bob".into(),
            ..destination.clone()
        }),
        Some(crate::SshDestination {
            host_keys: vec!["SHA256:target".into()],
            ..destination.clone()
        }),
        Some(crate::SshDestination {
            host_keys: vec!["SHA256:jump".into(), "SHA256:other".into()],
            ..destination.clone()
        }),
    ] {
        assert!(matches!(
            service
                .ssh_request(
                    &caller(),
                    &AgentRequest::Sign {
                        public_key: &public_key,
                        data: b"test",
                        flags: 0,
                        destination: changed,
                    },
                    100
                )
                .unwrap(),
            AgentReply::Pending(_)
        ));
    }
}
