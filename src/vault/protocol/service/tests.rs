use std::time::Duration;

use super::*;
use crate::Vault;

fn service(now: u64, policy: UnsealLeasePolicy) -> (tempfile::TempDir, VaultService) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let unsealed = Vault::create_for_test(&root).unwrap();
    let store = VaultStore::open(root, unsealed).unwrap();
    (directory, VaultService::new(store, now, policy).unwrap())
}

fn caller() -> CallerIdentity {
    CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.secretspec.cli",
        [7; 32],
        None,
    )
    .unwrap()
}

fn address() -> WireSecretAddress {
    WireSecretAddress::new("secretspec/demo/default/API_KEY", None)
}

#[test]
fn cache_actions_normalize_to_cache_scoped_base_actions() {
    let actions = [
        VaultAction::GetCache {
            namespace: vec![],
            address: address(),
        },
        VaultAction::PutCache {
            namespace: vec![],
            address: address(),
            value: WireSecret::new(vec![]),
            evict_at: None,
        },
        VaultAction::DeleteCache {
            namespace: vec![],
            address: address(),
        },
        VaultAction::ClearCache { namespace: vec![] },
        VaultAction::SealCache { namespace: vec![] },
    ];

    for action in actions {
        let ScopedAction { action, scope } = scope_action(action);
        assert_eq!(scope, DocumentScope::DeviceCache);
        assert!(!matches!(
            action,
            VaultAction::GetCache { .. }
                | VaultAction::PutCache { .. }
                | VaultAction::DeleteCache { .. }
                | VaultAction::ClearCache { .. }
                | VaultAction::SealCache { .. }
        ));
    }
    assert_eq!(
        scope_action(VaultAction::Status).scope,
        DocumentScope::DeviceLocal
    );
}

#[test]
fn eviction_deadline_may_be_immediate_but_not_in_the_past() {
    assert!(validate_evict_at(None, 100).is_ok());
    assert!(validate_evict_at(Some(100), 100).is_ok());
    assert!(matches!(
        validate_evict_at(Some(99), 100),
        Err(VaultError::Expired)
    ));
}

#[test]
fn request_round_trip_is_versioned_and_bounded() {
    let application = VaultApplicationContext::new(
        Some("demo".to_owned()),
        Some("production".to_owned()),
        Some(
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        ),
        Some("deploy".to_owned()),
    )
    .unwrap();
    let request = VaultRequest::new_with_application(
        VaultAction::Mutate {
            namespace: b"secretspec".to_vec(),
            mutations: vec![VaultMutation::Put {
                address: address(),
                value: WireSecret::new(b"secret".to_vec()),
                evict_at: None,
            }],
        },
        application.clone(),
    )
    .unwrap();
    let bytes = request.encode().unwrap();
    let decoded = VaultRequest::decode(&bytes).unwrap();
    assert_eq!(decoded.request_id(), request.request_id());
    assert_eq!(decoded.application(), Some(&application));
    assert!(matches!(decoded.action, VaultAction::Mutate { .. }));
    assert!(VaultRequest::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
}

#[test]
fn application_context_is_bounded_and_requires_an_absolute_base_directory() {
    assert!(
        VaultApplicationContext::new(Some(String::new()), Some("default".to_owned()), None, None,)
            .is_err()
    );
    assert!(
        VaultApplicationContext::new(
            Some("demo".to_owned()),
            Some("default".to_owned()),
            Some("relative/path".to_owned()),
            None,
        )
        .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn approval_is_project_scoped_and_requires_a_vault_signature() {
    let (directory, service) = service(100, UnsealLeasePolicy::default());
    let provider = caller();
    let application = |project: &str| {
        VaultApplicationContext::new(
            Some(project.to_owned()),
            Some("production".to_owned()),
            None,
            Some("deploy".to_owned()),
        )
        .unwrap()
    };
    let get_scoped = |project: &str, address_project: &str| {
        VaultRequest::new_with_application(
            VaultAction::GetCache {
                namespace: b"secretspec-cache/v1".to_vec(),
                address: address().scope_to_project(address_project).unwrap(),
            },
            application(project),
        )
        .unwrap()
    };
    let get = |project: &str| get_scoped(project, project);

    let denied = service.handle(&provider, get("demo"), 101);
    let interaction = denied.result.unwrap_err().interaction.unwrap();
    assert!(interaction.id.starts_with("prm_"));
    assert_eq!(interaction.expires_at, 101 + 7 * 24 * 60 * 60);

    let repeated = service.handle(&provider, get("demo"), 201);
    let refreshed = repeated.result.unwrap_err().interaction.unwrap();
    assert_eq!(refreshed.id, interaction.id);
    assert_eq!(refreshed.expires_at, 201 + 7 * 24 * 60 * 60);

    let manager = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.cli",
        [9; 32],
        None,
    )
    .unwrap();
    service.authorize_permission_manager(&manager, 101).unwrap();
    let listed = service.handle(
        &manager,
        VaultRequest::new(VaultAction::ListPermissions).unwrap(),
        202,
    );
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = listed.result else {
        panic!("expected pending approvals");
    };
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].application.reason.as_deref(), Some("deploy"));
    assert_eq!(
        permissions[0].principal.application_id,
        provider.application_id()
    );
    assert_eq!(
        permissions[0].principal.executable_digest,
        *provider.executable_digest()
    );

    let root = directory.path().join("factorseal");
    let unsealed = Vault::unseal_for_test(&root).unwrap();
    let PermissionState::Pending { challenge, .. } = &permissions[0].state else {
        panic!("expected pending permission");
    };
    let signature = unsealed
        .sign_permission_challenge(&permissions[0].id, challenge, Some(60 * 60))
        .unwrap();
    let duration_tampered = service.handle(
        &manager,
        VaultRequest::new(VaultAction::ApprovePermission {
            id: permissions[0].id.clone(),
            signature: signature.clone(),
            duration_seconds: None,
        })
        .unwrap(),
        203,
    );
    assert!(duration_tampered.result.is_err());
    let approved = service.handle(
        &manager,
        VaultRequest::new(VaultAction::ApprovePermission {
            id: permissions[0].id.clone(),
            signature,
            duration_seconds: Some(60 * 60),
        })
        .unwrap(),
        204,
    );
    assert!(matches!(
        approved.result,
        Ok(VaultResponseBody::PermissionChanged {
            status: PermissionChange::Granted
        })
    ));
    assert!(matches!(
        service.handle(&provider, get("demo"), 205).result,
        Ok(VaultResponseBody::Secret { value: None })
    ));
    let permissions = service.handle(
        &manager,
        VaultRequest::new(VaultAction::ListPermissions).unwrap(),
        206,
    );
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = permissions.result else {
        panic!("expected granted permission");
    };
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].id, interaction.id);
    assert!(matches!(
        permissions[0].state,
        PermissionState::Granted {
            granted_at: 204,
            expires_at: Some(deadline)
        } if deadline == 204 + 60 * 60
    ));
    assert!(
        service
            .handle(&provider, get("other-project"), 207)
            .result
            .unwrap_err()
            .interaction
            .is_some()
    );
    let mismatched = service
        .handle(&provider, get_scoped("demo", "other-project"), 208)
        .result
        .unwrap_err();
    assert_eq!(
        mismatched.code,
        VaultResponseErrorCode::AuthorizationRequired
    );
    assert!(
        mismatched.interaction.is_none(),
        "a mismatched project address must not even create an approvable request"
    );
    let revoked = service.handle(
        &manager,
        VaultRequest::new(VaultAction::RevokePermission {
            id: interaction.id.clone(),
        })
        .unwrap(),
        209,
    );
    assert!(matches!(
        revoked.result,
        Ok(VaultResponseBody::PermissionChanged {
            status: PermissionChange::Revoked
        })
    ));
    let remaining = service.handle(
        &manager,
        VaultRequest::new(VaultAction::ListPermissions).unwrap(),
        210,
    );
    let Ok(VaultResponseBody::Permissions { permissions, .. }) = remaining.result else {
        panic!("expected permission list");
    };
    assert!(
        permissions
            .iter()
            .all(|permission| permission.id != interaction.id)
    );
    assert!(
        service
            .handle(&provider, get("demo"), 211)
            .result
            .unwrap_err()
            .interaction
            .is_some(),
        "revocation must remove the underlying project authority"
    );
}

#[test]
fn approval_wait_wakes_on_revision_change_and_times_out_unchanged() {
    for timeout_ms in [0, super::super::MAX_PERMISSION_WAIT_MS + 1] {
        assert!(
            VaultRequest::new(VaultAction::WaitPermissions {
                after_revision: 0,
                timeout_ms,
            })
            .unwrap()
            .validate()
            .is_err()
        );
    }
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let service = std::sync::Arc::new(service);
    let manager = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.cli",
        [9; 32],
        None,
    )
    .unwrap();
    service.authorize_permission_manager(&manager, 100).unwrap();

    let timed_out = service.handle(
        &manager,
        VaultRequest::new(VaultAction::WaitPermissions {
            after_revision: 0,
            timeout_ms: 10,
        })
        .unwrap(),
        101,
    );
    assert!(matches!(
        timed_out.result,
        Ok(VaultResponseBody::Permissions {
            revision: 0,
            permissions
        }) if permissions.is_empty()
    ));

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let waiter_service = std::sync::Arc::clone(&service);
    let waiter_manager = manager.clone();
    let waiter_barrier = std::sync::Arc::clone(&barrier);
    let waiter = std::thread::spawn(move || {
        waiter_barrier.wait();
        waiter_service.handle(
            &waiter_manager,
            VaultRequest::new(VaultAction::WaitPermissions {
                after_revision: 0,
                timeout_ms: 1_000,
            })
            .unwrap(),
            102,
        )
    });
    barrier.wait();

    let provider = caller();
    let request = VaultRequest::new_with_application(
        VaultAction::GetCache {
            namespace: b"secretspec-cache/v1".to_vec(),
            address: address().scope_to_project("demo").unwrap(),
        },
        VaultApplicationContext::new(
            Some("demo".to_owned()),
            Some("default".to_owned()),
            None,
            Some("test notification".to_owned()),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(service.handle(&provider, request, 103).result.is_err());

    let changed = waiter.join().unwrap();
    assert!(matches!(
        changed.result,
        Ok(VaultResponseBody::Permissions {
            revision,
            permissions
        }) if revision > 0 && permissions.len() == 1
    ));
}

#[test]
fn direct_service_requests_obey_the_wire_size_bound() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let request = VaultRequest::new(VaultAction::Put {
        namespace: b"secretspec".to_vec(),
        address: address(),
        // JSON represents bytes as decimal array elements, so this is
        // unambiguously larger than the one-MiB protocol message limit.
        value: WireSecret::new(vec![0; MAX_MESSAGE_BYTES]),
        evict_at: None,
    })
    .unwrap();

    let response = service.handle(&caller(), request, 100);

    assert_eq!(
        response.result.unwrap_err().code,
        VaultResponseErrorCode::InvalidRequest
    );
}

#[test]
fn wire_errors_never_echo_internal_or_secret_details() {
    let marker = "visible-project/API_TOKEN=needle-secret-value";
    for error in [
        VaultError::InvalidData(marker.to_owned()),
        VaultError::Protocol(marker.to_owned()),
        VaultError::Database(marker.to_owned()),
        VaultError::Protection(marker.to_owned()),
    ] {
        let response = response_error(&error);
        assert!(!response.message.contains(marker));
        assert!(!response.message.contains("API_TOKEN"));
    }
}

#[test]
fn exact_grant_is_required_and_replay_is_rejected() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    let put_id = RequestId::from_bytes([1; REQUEST_ID_BYTES]);
    let put = || {
        VaultRequest::with_id(
            put_id,
            VaultAction::Put {
                namespace: b"secretspec".to_vec(),
                address: address(),
                value: WireSecret::new(b"secret".to_vec()),
                evict_at: None,
            },
        )
    };
    let denied = service.handle(&caller, put(), 101);
    assert_eq!(
        denied.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );

    service
        .authorize_entry(
            &caller,
            b"secretspec",
            &address(),
            [GrantPermission::Put],
            None,
            101,
        )
        .unwrap();
    let replayed = service.handle(&caller, put(), 102);
    assert_eq!(
        replayed.result.unwrap_err().code,
        VaultResponseErrorCode::Replay
    );

    let accepted = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Put {
            namespace: b"secretspec".to_vec(),
            address: address(),
            value: WireSecret::new(b"secret".to_vec()),
            evict_at: None,
        })
        .unwrap(),
        102,
    );
    assert!(matches!(accepted.result, Ok(VaultResponseBody::Stored)));
}

#[test]
fn caller_identity_is_part_of_grant_authority() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    service
        .authorize_entry(
            &caller,
            b"secretspec",
            &address(),
            [GrantPermission::Get],
            None,
            100,
        )
        .unwrap();
    let other = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.secretspec.cli",
        [8; 32],
        None,
    )
    .unwrap();
    let response = service.handle(
        &other,
        VaultRequest::new_with_application(
            VaultAction::Get {
                namespace: b"secretspec".to_vec(),
                address: address(),
            },
            VaultApplicationContext::new(
                Some("authorized-project".to_owned()),
                Some("default".to_owned()),
                None,
                Some("declared reason".to_owned()),
            )
            .unwrap(),
        )
        .unwrap(),
        101,
    );
    assert_eq!(
        response.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );
}

#[test]
fn local_keyring_operations_are_separate_from_disposable_cache_entries() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    service
        .authorize_namespace(
            &caller,
            b"factorseal/keyring/v1",
            [GrantPermission::Get, GrantPermission::Put],
            None,
            100,
        )
        .unwrap();

    let stored = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Put {
            namespace: b"factorseal/keyring/v1".to_vec(),
            address: address(),
            value: WireSecret::new(b"durable secret".to_vec()),
            evict_at: None,
        })
        .unwrap(),
        101,
    );
    assert!(matches!(stored.result, Ok(VaultResponseBody::Stored)));

    service
        .authorize_cache_namespace(
            &caller,
            b"factorseal/keyring/v1",
            [GrantPermission::Get],
            None,
            101,
        )
        .unwrap();
    let cache_read = service.handle(
        &caller,
        VaultRequest::new(VaultAction::GetCache {
            namespace: b"factorseal/keyring/v1".to_vec(),
            address: address(),
        })
        .unwrap(),
        102,
    );
    assert!(matches!(
        cache_read.result,
        Ok(VaultResponseBody::Secret { value: None })
    ));

    let local_read = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Get {
            namespace: b"factorseal/keyring/v1".to_vec(),
            address: address(),
        })
        .unwrap(),
        103,
    );
    let Ok(VaultResponseBody::Secret { value: Some(value) }) = local_read.result else {
        panic!("expected durable keyring secret");
    };
    assert_eq!(value.expose(), b"durable secret");
}

#[test]
fn cache_grants_cannot_authorize_durable_keyring_operations() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    service
        .authorize_cache_namespace(&caller, b"shared-name", [GrantPermission::Put], None, 100)
        .unwrap();

    let response = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Put {
            namespace: b"shared-name".to_vec(),
            address: address(),
            value: WireSecret::new(b"must not persist".to_vec()),
            evict_at: None,
        })
        .unwrap(),
        101,
    );
    assert_eq!(
        response.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );
}

#[test]
fn batch_mutations_are_pre_authorized_and_commit_together() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    let first = WireSecretAddress::new("secretspec/demo/first", None);
    let second = WireSecretAddress::new("secretspec/demo/second", None);
    service
        .authorize_entry(
            &caller,
            b"secretspec",
            &first,
            [GrantPermission::Get, GrantPermission::Put],
            None,
            100,
        )
        .unwrap();

    let denied = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Mutate {
            namespace: b"secretspec".to_vec(),
            mutations: vec![
                VaultMutation::Put {
                    address: first.clone(),
                    value: WireSecret::new(b"first".to_vec()),
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: second.clone(),
                    value: WireSecret::new(b"second".to_vec()),
                    evict_at: None,
                },
            ],
        })
        .unwrap(),
        101,
    );
    assert_eq!(
        denied.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );

    let absent = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Get {
            namespace: b"secretspec".to_vec(),
            address: first.clone(),
        })
        .unwrap(),
        102,
    );
    assert!(matches!(
        absent.result,
        Ok(VaultResponseBody::Secret { value: None })
    ));

    service
        .authorize_entry(
            &caller,
            b"secretspec",
            &second,
            [GrantPermission::Get, GrantPermission::Put],
            None,
            102,
        )
        .unwrap();
    let stored = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Mutate {
            namespace: b"secretspec".to_vec(),
            mutations: vec![
                VaultMutation::Put {
                    address: first.clone(),
                    value: WireSecret::new(b"first".to_vec()),
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: second.clone(),
                    value: WireSecret::new(b"second".to_vec()),
                    evict_at: None,
                },
            ],
        })
        .unwrap(),
        103,
    );
    assert!(matches!(stored.result, Ok(VaultResponseBody::Mutated)));

    for (address, expected) in [(first, b"first".as_slice()), (second, b"second")] {
        let response = service.handle(
            &caller,
            VaultRequest::new(VaultAction::Get {
                namespace: b"secretspec".to_vec(),
                address,
            })
            .unwrap(),
            104,
        );
        let Ok(VaultResponseBody::Secret { value: Some(value) }) = response.result else {
            panic!("expected a stored batch secret");
        };
        assert_eq!(value.expose(), expected);
    }
}

#[test]
fn idle_deadline_seals_without_a_request() {
    let policy = UnsealLeasePolicy {
        idle_timeout: Duration::from_secs(5),
        maximum_lifetime: Duration::from_secs(10),
    };
    let (_directory, service) = service(100, policy);
    let idle_expires_at = service.state.idle_expires_at();
    assert!(
        !service
            .expire_if_needed_at(
                104,
                idle_expires_at.checked_sub(Duration::from_secs(1)).unwrap(),
            )
            .unwrap()
    );
    assert!(service.expire_if_needed_at(105, idle_expires_at).unwrap());

    let response = service.handle(
        &caller(),
        VaultRequest::new(VaultAction::Status).unwrap(),
        105,
    );
    assert_eq!(
        response.result.unwrap_err().code,
        VaultResponseErrorCode::Sealed
    );
}

#[test]
fn status_requests_do_not_refresh_the_idle_deadline() {
    let policy = UnsealLeasePolicy {
        idle_timeout: Duration::from_secs(5),
        maximum_lifetime: Duration::from_secs(10),
    };
    let (_directory, service) = service(100, policy);
    let idle_expires_at = service.state.idle_expires_at();

    let response = service.handle_at(
        &caller(),
        VaultRequest::new(VaultAction::Status).unwrap(),
        104,
        idle_expires_at.checked_sub(Duration::from_secs(1)).unwrap(),
    );
    let VaultResponseBody::Status { idle_deadline, .. } = response.result.unwrap() else {
        panic!("expected status response");
    };
    assert_eq!(idle_deadline, 105);
    assert!(service.expire_if_needed_at(105, idle_expires_at).unwrap());
}

#[test]
fn wall_clock_rollback_does_not_extend_the_unseal_lease() {
    let policy = UnsealLeasePolicy {
        idle_timeout: Duration::from_secs(5),
        maximum_lifetime: Duration::from_secs(10),
    };
    let (_directory, service) = service(100, policy);
    let idle_expires_at = service.state.idle_expires_at();

    assert!(
        service.expire_if_needed_at(50, idle_expires_at).unwrap(),
        "the monotonic deadline must win even if Unix time moves backward"
    );
}

#[test]
fn storage_eviction_sweeps_at_most_once_a_second() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    for _ in 0..5 {
        assert!(!service.expire_if_needed(100).unwrap());
    }
    assert_eq!(
        service.purge_count(),
        0,
        "opening the store already swept this second"
    );

    for _ in 0..5 {
        assert!(!service.expire_if_needed(101).unwrap());
    }
    assert_eq!(service.purge_count(), 1);

    assert!(!service.expire_if_needed(102).unwrap());
    assert_eq!(service.purge_count(), 2);
}

#[test]
fn explicit_seal_invalidates_the_service() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    service
        .authorize_namespace(&caller, b"secretspec", [GrantPermission::Seal], None, 100)
        .unwrap();
    let response = service.handle(
        &caller,
        VaultRequest::new(VaultAction::Seal {
            namespace: b"secretspec".to_vec(),
        })
        .unwrap(),
        101,
    );
    assert!(matches!(response.result, Ok(VaultResponseBody::Sealed)));
    assert!(service.expire_if_needed(101).unwrap());
}

#[test]
fn lifecycle_seal_survives_a_poisoned_request_mutex() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        service.poison_state_for_test();
    }));
    assert!(poisoned.is_err());

    service.seal().unwrap();
    assert!(service.state.is_sealed());
}
