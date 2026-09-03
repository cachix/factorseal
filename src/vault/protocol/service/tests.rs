use std::time::{Duration, Instant};

use super::super::grant::{
    GrantTarget, list_granted_permissions, promote_permission, revoke_permission, store_grant,
};
use super::*;
use crate::vault::{
    DeviceKeyId, HistoryEntry, HistoryOperation, MAX_HISTORY_PAGE_SIZE, Permission,
    PermissionOperation, PermissionPrincipal, Provenance, SecretAddress, ServiceReason, VersionId,
};
use crate::{DocumentKind, MAX_LIST_PAGE_SIZE, SecretSpecAddress, SecretSpecCoordinates, Vault};

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

fn project_address(project: &str) -> SecretSpecAddress {
    SecretSpecAddress::convention(project, "default", "API_KEY").unwrap()
}

fn project_key(project: &str, key: &str) -> SecretSpecAddress {
    SecretSpecAddress::convention(project, "default", key).unwrap()
}

#[test]
fn typed_actions_select_semantic_document_kinds() {
    let actions = [
        VaultAction::GetCache {
            project: "demo".to_owned(),
            address: project_address("demo"),
        },
        VaultAction::PutCache {
            project: "demo".to_owned(),
            address: project_address("demo"),
            value: WireSecret::new(vec![]),
            evict_at: None,
        },
        VaultAction::DeleteCache {
            project: "demo".to_owned(),
            address: project_address("demo"),
        },
        VaultAction::ClearCache {
            project: "demo".to_owned(),
        },
        VaultAction::SealCache {
            project: "demo".to_owned(),
        },
    ];

    for action in actions {
        let ScopedAction { action, scope } = scope_action(action);
        assert_eq!(scope, DocumentKind::SecretSpecProviderCache);
        assert!(matches!(
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
        DocumentKind::LocalKeyring
    );
}

/// The vault's own helper processes are identified by their executable
/// digest. Restarting the same build must not write a generation, and an
/// upgraded build must take the namespace over from the build it replaces.
#[cfg(target_os = "linux")]
#[test]
fn helper_process_grants_are_exclusive_and_free_when_unchanged() {
    use super::super::grant::GRANT_DOCUMENT_NAMESPACE;

    const SECRET_SERVICE_NAMESPACE: &[u8] = b"factorseal/secret-service/v1";

    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let build = |digest: [u8; 32]| {
        CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "/usr/bin/factorseal",
            digest,
            None,
        )
        .unwrap()
    };
    let old_build = build([1; 32]);
    let new_build = build([2; 32]);
    let permissions = [GrantPermission::Get, GrantPermission::Put];
    let authorization_history = || {
        let state = service.state.lock_live(Instant::now()).unwrap();
        state
            .store()
            .list_history(
                DocumentKind::Authorization,
                GRANT_DOCUMENT_NAMESPACE,
                None,
                None,
                MAX_HISTORY_PAGE_SIZE,
            )
            .unwrap()
            .items
            .len()
    };
    let get = |caller: &CallerIdentity, now: u64| {
        service.handle(
            caller,
            VaultRequest::new(VaultAction::Get {
                namespace: SECRET_SERVICE_NAMESPACE.to_vec(),
                address: WireSecretAddress::new("application/dev.factorseal.Test", None),
            })
            .unwrap(),
            now,
        )
    };

    service
        .authorize_secret_service_namespace(&old_build, SECRET_SERVICE_NAMESPACE, permissions, 100)
        .unwrap();
    let after_first_start = authorization_history();
    assert!(after_first_start > 0);
    assert!(matches!(
        get(&old_build, 100).result,
        Ok(VaultResponseBody::Secret { value: None })
    ));

    service
        .authorize_secret_service_namespace(&old_build, SECRET_SERVICE_NAMESPACE, permissions, 101)
        .unwrap();
    assert_eq!(authorization_history(), after_first_start);

    service
        .authorize_secret_service_namespace(&new_build, SECRET_SERVICE_NAMESPACE, permissions, 102)
        .unwrap();
    assert!(matches!(
        get(&new_build, 102).result,
        Ok(VaultResponseBody::Secret { value: None })
    ));
    assert!(matches!(
        get(&old_build, 102).result,
        Err(VaultResponseError {
            code: VaultResponseErrorCode::AuthorizationRequired,
            ..
        })
    ));
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
fn durable_project_documents_are_partitioned_and_kind_authorized() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let caller = caller();
    service
        .authorize_document_kind(
            &caller,
            DocumentKind::SecretSpecProject,
            [GrantPermission::Get, GrantPermission::Put],
            None,
            100,
        )
        .unwrap();
    let stored = service.handle(
        &caller,
        VaultRequest::new(VaultAction::PutProject {
            project: "demo".to_owned(),
            address: project_address("demo"),
            value: WireSecret::new(b"secret".to_vec()),
        })
        .unwrap(),
        101,
    );
    assert!(matches!(stored.result, Ok(VaultResponseBody::Stored)));

    let other = service.handle(
        &caller,
        VaultRequest::new(VaultAction::GetProject {
            project: "other".to_owned(),
            address: project_address("other"),
        })
        .unwrap(),
        102,
    );
    assert!(matches!(
        other.result,
        Ok(VaultResponseBody::Secret { value: None })
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_metadata_listing_is_paginated_value_free_and_separately_authorized() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let writer = caller();
    service
        .authorize_document_kind(
            &writer,
            DocumentKind::SecretSpecProject,
            [GrantPermission::Put],
            None,
            100,
        )
        .unwrap();
    let native = SecretSpecAddress::native(SecretSpecCoordinates {
        item: "database".to_owned(),
        field: Some("password".to_owned()),
        vault: Some("production".to_owned()),
        section: Some("credentials".to_owned()),
        version: Some("2".to_owned()),
    })
    .unwrap();
    for (project, address, value) in [
        (
            "zeta",
            project_key("zeta", "TOKEN"),
            b"zeta-secret".as_slice(),
        ),
        ("alpha", project_key("alpha", "TOKEN"), b"alpha-secret"),
        ("alpha", native.clone(), b"native-secret"),
    ] {
        let response = service.handle(
            &writer,
            VaultRequest::new(VaultAction::PutProject {
                project: project.to_owned(),
                address,
                value: WireSecret::new(value.to_vec()),
            })
            .unwrap(),
            101,
        );
        assert!(matches!(response.result, Ok(VaultResponseBody::Stored)));
    }

    let browser = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.ui",
        [11; 32],
        None,
    )
    .unwrap();
    service
        .authorize_document_kind(
            &browser,
            DocumentKind::SecretSpecProject,
            [GrantPermission::List],
            None,
            101,
        )
        .unwrap();

    let first = service.handle(
        &browser,
        VaultRequest::new(VaultAction::ListProjects {
            cursor: None,
            limit: 1,
        })
        .unwrap(),
        102,
    );
    let Ok(VaultResponseBody::Projects {
        projects,
        next_cursor: Some(cursor),
    }) = first.result
    else {
        panic!("expected the first project page");
    };
    assert_eq!(projects, ["alpha"]);
    let second = service.handle(
        &browser,
        VaultRequest::new(VaultAction::ListProjects {
            cursor: Some(cursor),
            limit: 1,
        })
        .unwrap(),
        103,
    );
    assert!(matches!(
        second.result,
        Ok(VaultResponseBody::Projects {
            projects,
            next_cursor: None,
        }) if projects == ["zeta"]
    ));

    let mut addresses = Vec::new();
    let mut cursor = None;
    loop {
        let response = service.handle(
            &browser,
            VaultRequest::new(VaultAction::ListProjectAddresses {
                project: "alpha".to_owned(),
                cursor,
                limit: 1,
            })
            .unwrap(),
            104,
        );
        let encoded = response.encode().unwrap();
        assert!(
            !encoded
                .windows(b"alpha-secret".len())
                .any(|part| part == b"alpha-secret")
        );
        assert!(
            !encoded
                .windows(b"native-secret".len())
                .any(|part| part == b"native-secret")
        );
        let Ok(VaultResponseBody::ProjectAddresses {
            addresses: page,
            next_cursor,
        }) = response.result
        else {
            panic!("expected an address page");
        };
        addresses.extend(page);
        cursor = next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(addresses.len(), 2);
    assert!(addresses.contains(&project_key("alpha", "TOKEN")));
    assert!(addresses.contains(&native));

    let value_read = service.handle(
        &browser,
        VaultRequest::new(VaultAction::GetProject {
            project: "alpha".to_owned(),
            address: project_key("alpha", "TOKEN"),
        })
        .unwrap(),
        105,
    );
    assert_eq!(
        value_read.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );

    let cache_browser = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.cache-ui",
        [12; 32],
        None,
    )
    .unwrap();
    service
        .authorize_document_kind(
            &cache_browser,
            DocumentKind::SecretSpecProviderCache,
            [GrantPermission::List],
            None,
            105,
        )
        .unwrap();
    let isolated = service.handle(
        &cache_browser,
        VaultRequest::new(VaultAction::ListProjects {
            cursor: None,
            limit: 1,
        })
        .unwrap(),
        106,
    );
    assert_eq!(
        isolated.result.unwrap_err().code,
        VaultResponseErrorCode::AuthorizationRequired
    );
}

#[test]
fn list_requests_are_bounded_and_maximum_pages_fit_the_wire_limit() {
    for limit in [0, MAX_LIST_PAGE_SIZE + 1] {
        assert!(
            VaultRequest::new(VaultAction::ListProjects {
                cursor: None,
                limit,
            })
            .unwrap()
            .encode()
            .is_err()
        );
    }
    assert!(
        VaultRequest::new(VaultAction::ListProjectAddresses {
            project: "demo".to_owned(),
            cursor: Some("not-a-digest".to_owned()),
            limit: 1,
        })
        .unwrap()
        .encode()
        .is_err()
    );

    let component = "\u{1}".repeat(4 * 1024);
    let address = SecretSpecAddress::native(SecretSpecCoordinates {
        item: component.clone(),
        field: Some(component.clone()),
        vault: Some(component.clone()),
        section: Some(component.clone()),
        version: Some(component),
    })
    .unwrap();
    let response = VaultResponse::success(
        RequestId::from_bytes([31; REQUEST_ID_BYTES]),
        VaultResponseBody::ProjectAddresses {
            addresses: vec![address.clone(); usize::from(MAX_LIST_PAGE_SIZE)],
            next_cursor: Some("A".repeat(43)),
        },
    );
    let encoded = response.encode().unwrap();
    assert!(encoded.len() <= MAX_MESSAGE_BYTES);

    for limit in [0, MAX_HISTORY_PAGE_SIZE + 1] {
        assert!(
            VaultRequest::new(VaultAction::ListProjectHistory {
                project: "demo".to_owned(),
                address: None,
                cursor: None,
                limit,
            })
            .unwrap()
            .encode()
            .is_err()
        );
    }
    let identity = "\u{1}".repeat(4 * 1024);
    let declared = "\u{1}".repeat(512);
    let principal = CallerIdentity::new(
        CallerPlatform::Linux,
        identity.clone(),
        identity.clone(),
        [255; 32],
        Some(identity),
    )
    .unwrap();
    // The base directory must be absolute on every platform; only its bounded
    // length matters here.
    let base_dir = std::env::temp_dir().join(&declared).display().to_string();
    let context = VaultApplicationContext::new(
        Some(declared.clone()),
        Some(declared.clone()),
        Some(base_dir),
        Some(declared),
    )
    .unwrap();
    let worst = HistoryEntry {
        version: HistoryEntry::CURRENT_VERSION,
        seq: u64::MAX,
        at: u64::MAX,
        operation: HistoryOperation::Put { changed: true },
        address: SecretAddress::secret_spec(address).unwrap(),
        version_id: Some(VersionId::from_bytes([255; 16])),
        previous_version_id: Some(VersionId::from_bytes([255; 16])),
        evict_at: Some(u64::MAX),
        provenance: Provenance::caller(&principal, Some(&context)),
        device_key_id: DeviceKeyId::from_bytes([255; 32]),
    };
    let response = VaultResponse::success(
        RequestId::from_bytes([32; REQUEST_ID_BYTES]),
        VaultResponseBody::History {
            entries: vec![worst; usize::from(MAX_HISTORY_PAGE_SIZE)],
            next_cursor: Some(u64::MAX),
        },
    );
    let encoded = response.encode().unwrap();
    assert!(encoded.len() <= MAX_MESSAGE_BYTES);
}

/// The kind-wide check used to build a namespace target from a fixed
/// sentinel string, so a namespace grant on that literal would have satisfied
/// it. Only a grant on the whole kind may.
#[test]
fn kind_wide_listing_accepts_only_a_kind_wide_grant() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let browser = caller();
    {
        let state = service.state.lock_live(Instant::now()).unwrap();
        store_grant(
            state.store(),
            &browser,
            GrantTarget::Namespace {
                scope: DocumentKind::SecretSpecProject,
                namespace: b"factorseal/document-kind/v1",
            },
            [GrantPermission::List],
            None,
            100,
        )
        .unwrap();
    }
    let list = || {
        service.handle(
            &browser,
            VaultRequest::new(VaultAction::ListProjects {
                cursor: None,
                limit: 1,
            })
            .unwrap(),
            101,
        )
    };
    assert!(matches!(
        list().result,
        Err(VaultResponseError {
            code: VaultResponseErrorCode::AuthorizationRequired,
            ..
        })
    ));

    service
        .authorize_document_kind(
            &browser,
            DocumentKind::SecretSpecProject,
            [GrantPermission::List],
            None,
            101,
        )
        .unwrap();
    assert!(matches!(
        list().result,
        Ok(VaultResponseBody::Projects { .. })
    ));
}

/// An expired grant record may already have been swept when the user revokes
/// the permission. Revocation still removes the registry entry, and expired
/// entries are pruned whenever the registry is written.
#[test]
fn revoking_an_expired_permission_cleans_the_registry() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let principal = caller();
    let provenance = Provenance::service(ServiceReason::GrantStorage);
    let permission = |id: &str, expires_at: Option<u64>| Permission {
        id: id.to_owned(),
        operation: PermissionOperation::Get,
        principal: PermissionPrincipal::from(&principal),
        application: VaultApplicationContext::new(Some("demo".to_owned()), None, None, None)
            .unwrap(),
        state: PermissionState::Granted {
            granted_at: 100,
            expires_at,
        },
    };
    let state = service.state.lock_live(Instant::now()).unwrap();
    let store = state.store();
    for (id, expires_at) in [("prm_short", Some(150)), ("prm_long", None)] {
        promote_permission(
            store,
            &principal,
            GrantTarget::Project {
                scope: DocumentKind::SecretSpecProviderCache,
                namespace: b"demo",
                project: "demo",
            },
            GrantPermission::Get,
            permission(id, expires_at),
            100,
            &provenance,
        )
        .unwrap();
    }
    assert_eq!(list_granted_permissions(store, 100).unwrap().len(), 2);
    assert_eq!(list_granted_permissions(store, 150).unwrap().len(), 1);

    revoke_permission(store, "prm_short", 160, &provenance).unwrap();
    assert!(revoke_permission(store, "prm_short", 161, &provenance).is_err());
    revoke_permission(store, "prm_long", 162, &provenance).unwrap();
    assert!(list_granted_permissions(store, 162).unwrap().is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_history_is_paginated_value_free_and_separately_authorized() {
    let (_directory, service) = service(100, UnsealLeasePolicy::default());
    let writer = caller();
    service
        .authorize_document_kind(
            &writer,
            DocumentKind::SecretSpecProject,
            [GrantPermission::Put, GrantPermission::Delete],
            None,
            100,
        )
        .unwrap();
    let token = project_key("alpha", "TOKEN");
    let other = project_key("alpha", "OTHER");
    for (now, action) in [
        (
            101,
            VaultAction::PutProject {
                project: "alpha".to_owned(),
                address: token.clone(),
                value: WireSecret::new(b"first-secret-value".to_vec()),
            },
        ),
        (
            102,
            VaultAction::PutProject {
                project: "alpha".to_owned(),
                address: token.clone(),
                value: WireSecret::new(b"second-secret-value".to_vec()),
            },
        ),
        (
            103,
            VaultAction::DeleteProject {
                project: "alpha".to_owned(),
                address: token.clone(),
            },
        ),
    ] {
        let response = service.handle(&writer, VaultRequest::new(action).unwrap(), now);
        assert!(response.result.is_ok(), "{:?}", response.result);
    }

    let history = |caller: &CallerIdentity, address: Option<SecretSpecAddress>, cursor, limit| {
        service.handle(
            caller,
            VaultRequest::new(VaultAction::ListProjectHistory {
                project: "alpha".to_owned(),
                address,
                cursor,
                limit,
            })
            .unwrap(),
            104,
        )
    };

    // A put grant does not authorize listing history, and neither does an
    // unrelated caller.
    let browser = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.ui",
        [11; 32],
        None,
    )
    .unwrap();
    for caller in [&writer, &browser] {
        let response = history(caller, None, None, 2);
        assert!(matches!(
            response.result,
            Err(VaultResponseError {
                code: VaultResponseErrorCode::AuthorizationRequired,
                ..
            })
        ));
    }
    service
        .authorize_document_kind(
            &browser,
            DocumentKind::SecretSpecProject,
            [GrantPermission::List],
            None,
            104,
        )
        .unwrap();

    let first = history(&browser, None, None, 2);
    let encoded = first.encode().unwrap();
    for needle in [
        b"first-secret-value".as_slice(),
        b"second-secret-value",
        b"Zmlyc3Qtc2VjcmV0",
        b"c2Vjb25kLXNlY3JldA",
    ] {
        assert!(
            !encoded.windows(needle.len()).any(|window| window == needle),
            "history response carried a value"
        );
    }
    let Ok(VaultResponseBody::History {
        entries,
        next_cursor,
    }) = first.result
    else {
        panic!("expected a history page");
    };
    assert_eq!(next_cursor, Some(1));
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].seq, 2);
    assert_eq!(entries[0].at, 103);
    assert_eq!(entries[0].operation, HistoryOperation::Delete);
    assert_eq!(entries[1].seq, 1);
    assert_eq!(
        entries[1].operation,
        HistoryOperation::Put { changed: true }
    );
    assert_eq!(entries[0].previous_version_id, entries[1].version_id);
    // Another application's identity is withheld from a reader that only
    // holds a list grant.
    assert!(entries.iter().all(|entry| {
        entry.address == SecretAddress::secret_spec(token.clone()).unwrap()
            && entry.provenance == Provenance::Redacted
    }));

    let Ok(VaultResponseBody::History {
        entries,
        next_cursor,
    }) = history(&browser, None, Some(1), 2).result
    else {
        panic!("expected the last history page");
    };
    assert!(next_cursor.is_none());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, 0);
    assert_eq!(entries[0].at, 101);
    assert!(entries[0].previous_version_id.is_none());

    let Ok(VaultResponseBody::History { entries, .. }) =
        history(&browser, Some(other), None, 4).result
    else {
        panic!("expected an empty filtered page");
    };
    assert!(entries.is_empty());

    // The writer sees its own entries in full, and a permission manager sees
    // every principal, as it does through `ListPermissions`.
    let full = Provenance::Caller {
        principal: PermissionPrincipal::from(&writer),
        application: None,
    };
    service
        .authorize_document_kind(
            &writer,
            DocumentKind::SecretSpecProject,
            [GrantPermission::List],
            None,
            104,
        )
        .unwrap();
    let Ok(VaultResponseBody::History { entries, .. }) = history(&writer, None, None, 4).result
    else {
        panic!("expected the writer's history page");
    };
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|entry| entry.provenance == full));

    service.authorize_permission_manager(&browser, 104).unwrap();
    let Ok(VaultResponseBody::History { entries, .. }) = history(&browser, None, None, 4).result
    else {
        panic!("expected the manager's history page");
    };
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().all(|entry| entry.provenance == full));
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
                project: address_project.to_owned(),
                address: project_address(address_project),
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

    let pending = service.handle(
        &provider,
        VaultRequest::new(VaultAction::WaitPermission {
            id: interaction.id.clone(),
            timeout_ms: 1,
        })
        .unwrap(),
        201,
    );
    assert!(matches!(
        pending.result,
        Ok(VaultResponseBody::PermissionWait {
            status: PermissionWaitStatus::Pending
        })
    ));
    let stranger = CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "dev.factorseal.other-provider",
        [8; 32],
        None,
    )
    .unwrap();
    assert!(
        service
            .handle(
                &stranger,
                VaultRequest::new(VaultAction::WaitPermission {
                    id: interaction.id.clone(),
                    timeout_ms: 1,
                })
                .unwrap(),
                201,
            )
            .result
            .is_err(),
        "a caller must not observe another principal's permission"
    );

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
    let granted = service.handle(
        &provider,
        VaultRequest::new(VaultAction::WaitPermission {
            id: interaction.id.clone(),
            timeout_ms: 1,
        })
        .unwrap(),
        204,
    );
    assert!(matches!(
        granted.result,
        Ok(VaultResponseBody::PermissionWait {
            status: PermissionWaitStatus::Granted
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
    let new_interaction = service
        .handle(&provider, get("demo"), 211)
        .result
        .unwrap_err()
        .interaction
        .expect("revocation must remove the underlying project authority");
    let denied = service.handle(
        &manager,
        VaultRequest::new(VaultAction::DenyPermission {
            id: new_interaction.id.clone(),
        })
        .unwrap(),
        212,
    );
    assert!(matches!(
        denied.result,
        Ok(VaultResponseBody::PermissionChanged {
            status: PermissionChange::Denied
        })
    ));
    let observed = service.handle(
        &provider,
        VaultRequest::new(VaultAction::WaitPermission {
            id: new_interaction.id,
            timeout_ms: 1,
        })
        .unwrap(),
        212,
    );
    assert!(matches!(
        observed.result,
        Ok(VaultResponseBody::PermissionWait {
            status: PermissionWaitStatus::Denied
        })
    ));
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
            project: "demo".to_owned(),
            address: project_address("demo"),
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
            b"factorseal-keyring",
            [GrantPermission::Get],
            None,
            101,
        )
        .unwrap();
    let cache_read = service.handle(
        &caller,
        VaultRequest::new(VaultAction::GetCache {
            project: "factorseal-keyring".to_owned(),
            address: project_address("factorseal-keyring"),
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
