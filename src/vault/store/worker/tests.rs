use super::*;
use crate::vault::store::database::to_i64;
use crate::vault::{
    CallerIdentity, CallerPlatform, HistoryOperation, PermissionPrincipal, Vault,
    VaultApplicationContext,
};

const TEST_NOW: u64 = 10;

#[test]
fn watchdog_terminates_a_wedged_native_owner_without_aborting() {
    const CHILD: &str = "FACTORSEAL_TEST_WEDGED_OWNER";
    if std::env::var_os(CHILD).is_some() {
        let status = Arc::new(WorkerStatus::default());
        status.sealed.store(true, Ordering::Release);
        status.emergency_exit.store(true, Ordering::Release);
        watch_shutdown(&Arc::downgrade(&status));
        panic!("watchdog returned while teardown was incomplete");
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "vault::store::worker::tests::watchdog_terminates_a_wedged_native_owner_without_aborting"])
        .env(CHILD, "1").spawn().unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(
                status.code(),
                Some(1),
                "must exit normally, not abort/core dump"
            );
            break;
        }
        if start.elapsed() > Duration::from_secs(15) {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("watchdog did not terminate the wedged owner");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
#[test]
fn live_partial_rollback_is_rejected_without_compaction_blessing_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap()).await.unwrap();
        let scope = DocumentKind::LocalKeyring;
        let partition = b"audit";
        let address = SecretAddress::new("rollback-token", None).unwrap();
        let document_id = worker.document_id(scope, partition);
        let provenance = provenance();
        let context = worker.context(&provenance, TEST_NOW);
        worker.put(document_id, scope, partition, &address, b"old-value", None, &context).await.unwrap();
        let old_wrapped = super::super::database::query_optional_blob(&worker.connection,
            "SELECT wrapped_dek FROM documents", ()).await.unwrap().unwrap();
        let old_commit = super::super::database::query_optional_blob(&worker.connection,
            "SELECT current_commit_id FROM documents", ()).await.unwrap().unwrap();
        worker.put(document_id, scope, partition, &address, b"new-value", None, &context).await.unwrap();
        // Simulate a partial on-disk rollback with the original signed blobs.
        worker.connection.execute("UPDATE documents SET generation=1, key_epoch=1, wrapped_dek=?1, current_commit_id=?2",
            params![old_wrapped, old_commit]).await.unwrap();
        assert!(worker.verify_commit_chain().await.is_err());
        assert!(worker.get(document_id, scope, partition, &address, TEST_NOW).await.is_err());
        worker.verified.chain_length = MAX_RETAINED_COMMITS + 1;
        assert!(worker.compact_if_needed().await.is_err());
        assert!(worker.verify_commit_chain().await.is_err());
    });
    assert!(VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err());
}

#[test]
fn signed_eviction_metadata_cannot_be_changed_live_or_offline() {
    for mutation in [
        "UPDATE documents SET next_eviction = NULL",
        "UPDATE documents SET next_eviction = 4102444801",
        "UPDATE documents SET next_eviction = 1",
        "UPDATE documents SET next_eviction = 'invalid'",
    ] {
        let (_directory, root, store) = store();
        let address = SecretAddress::new("expiry", None).unwrap();
        store
            .put_at(
                DocumentKind::LocalKeyring,
                b"expiry",
                &address,
                b"value",
                Some(FAR_FUTURE),
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
        execute_database_mutation(&root, mutation);
        assert!(
            store.purge_expired_at(FAR_FUTURE + 2).is_err(),
            "{mutation}"
        );
        assert!(store.is_sealed());
        store.seal();
        assert!(
            VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn missing_live_document_is_corruption_not_an_empty_result() {
    let (_directory, root, store) = store();
    let address = put_two_generations(&store);
    execute_database_mutation(&root, "DELETE FROM documents");
    assert!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                TEST_NOW
            )
            .is_err()
    );
    assert!(store.is_sealed());
}

#[test]
fn empty_snapshots_expose_no_plaintext_content_hashes() {
    for scope in [
        DocumentKind::SecretSpecProject,
        DocumentKind::SecretSpecProviderCache,
        DocumentKind::LocalKeyring,
    ] {
        for cleanup in [0, 1, 2] {
            let (_directory, root, store) = store();
            let partition = b"confidential-acquisition";
            let address = if scope == DocumentKind::SecretSpecProject {
                SecretAddress::secret_spec(
                    SecretSpecAddress::convention("confidential-acquisition", "default", "TOKEN")
                        .unwrap(),
                )
                .unwrap()
            } else {
                SecretAddress::new("TOKEN", None).unwrap()
            };
            store
                .put_at(
                    scope,
                    partition,
                    &address,
                    b"secret",
                    Some(FAR_FUTURE),
                    &provenance(),
                    TEST_NOW,
                )
                .unwrap();
            match cleanup {
                0 => {
                    store
                        .delete(scope, partition, &address, &provenance(), TEST_NOW)
                        .unwrap();
                }
                1 => {
                    store
                        .clear(scope, partition, &provenance(), TEST_NOW)
                        .unwrap();
                }
                _ => {
                    store.purge_expired_at(FAR_FUTURE).unwrap();
                }
            }
            store.seal();
            for bytes in database_blobs(&root, "SELECT envelope FROM document_snapshots") {
                let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert!(envelope.get("heads").is_none());
                // Old public plaintext hashes are not merely ignored during decode.
                envelope["heads"] = serde_json::json!([]);
                assert!(serde_json::from_value::<EncryptedSnapshot>(envelope).is_err());
            }
            assert_eq!(
                fs::metadata(root.join("factorseal.db-wal")).map_or(0, |meta| meta.len()),
                0
            );
        }
    }
}

#[test]
fn shutdown_intent_does_not_wait_for_a_full_command_queue() {
    let (sender, receiver) = mpsc::sync_channel(1);
    sender.send(Command::Shutdown).unwrap();
    let control = WorkerControl {
        sender,
        join: Mutex::new(None),
        status: Arc::new(WorkerStatus::default()),
    };
    let started = Instant::now();
    control.request_shutdown();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(control.is_sealed());
    assert!(!control.is_shutdown_complete());
    drop(receiver);
}

#[test]
fn a_result_finishing_after_the_worker_deadline_is_discarded() {
    let status = WorkerStatus::default();
    *status.deadline.lock().unwrap() = Some(Instant::now());
    let (sender, receiver) = mpsc::channel();
    send_result(sender, Ok(Zeroizing::new(b"late-secret".to_vec())), &status);
    assert!(matches!(receiver.recv().unwrap(), Err(VaultError::Sealed)));
    assert!(status.is_sealed());
}
/// A deadline the eviction sweep that runs on every open cannot have reached.
const FAR_FUTURE: u64 = 4_102_444_800;

fn caller() -> CallerIdentity {
    CallerIdentity::new(
        CallerPlatform::Linux,
        "uid:1000",
        "/usr/bin/test-client",
        [3; 32],
        None,
    )
    .unwrap()
}

fn provenance() -> Provenance {
    Provenance::caller(&caller(), None)
}

fn store() -> (tempfile::TempDir, PathBuf, VaultStore) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("factorseal");
    let unsealed = Vault::create_for_test(&root).unwrap();
    let store = VaultStore::open(&root, unsealed).unwrap();
    (directory, root, store)
}

fn execute_database_mutation(root: &Path, statement: &str) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        connection.execute(statement, ()).await.unwrap();
    });
}

fn database_count(root: &Path, sql: &str) -> u64 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        query_count(&connection, sql, ()).await.unwrap()
    })
}

fn database_blobs(root: &Path, sql: &str) -> Vec<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        let mut rows = connection.query(sql, ()).await.unwrap();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await.unwrap() {
            values.push(row_blob(&row, 0).unwrap());
        }
        values
    })
}

fn insert_conflicting_snapshot(root: &Path, document_id: &[u8], generation: u64) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute(
                "INSERT INTO document_snapshots(document_id, generation, envelope)
                 VALUES (?1, ?2, X'00')",
                params![document_id.to_vec(), to_i64(generation).unwrap()],
            )
            .await
            .unwrap();
    });
}

fn put_two_generations(store: &VaultStore) -> SecretAddress {
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"first",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"second",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    address
}

#[test]
fn reopening_rejects_a_missing_database() {
    let (_directory, root, store) = store();
    drop(store);
    fs::remove_file(root.join(DATABASE_FILE)).unwrap();

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::Database(_))));
}

#[test]
fn reopening_rejects_a_recreated_empty_database() {
    let (_directory, root, store) = store();
    drop(store);
    fs::write(root.join(DATABASE_FILE), []).unwrap();

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::Database(_))));
}

#[test]
fn turso_round_trip_restart_and_idempotent_delete() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/API_TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"classified",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    assert_eq!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                10,
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"classified"
    );
    let expected_device = store.device().clone();
    drop(store);

    let reopened = Vault::unseal_for_test(&root).unwrap();
    let store = VaultStore::open(&root, reopened).unwrap();
    assert_eq!(store.device(), &expected_device);
    assert_eq!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                10,
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"classified"
    );
    assert!(
        store
            .delete(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                &provenance(),
                TEST_NOW
            )
            .unwrap()
    );
    assert!(
        !store
            .delete(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                &provenance(),
                TEST_NOW
            )
            .unwrap()
    );
}

/// Authorization checks read several grant addresses at once. That read must
/// not commit a generation, even when one of the records has expired.
#[test]
fn get_many_reads_one_document_without_writing() {
    let (_directory, root, store) = store();
    let durable = SecretAddress::new("grant/durable", None).unwrap();
    let expiring = SecretAddress::new("grant/expiring", None).unwrap();
    let missing = SecretAddress::new("grant/missing", None).unwrap();
    store
        .put_at(
            DocumentKind::Authorization,
            b"grants",
            &durable,
            b"durable",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    store
        .put_at(
            DocumentKind::Authorization,
            b"grants",
            &expiring,
            b"expiring",
            Some(50),
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    let commits_before = database_count(&root, "SELECT COUNT(*) FROM protected_commits");

    let values = store
        .get_many(
            DocumentKind::Authorization,
            b"grants",
            &[durable.clone(), expiring.clone(), missing.clone()],
            50,
        )
        .unwrap();
    assert_eq!(values.len(), 3);
    assert_eq!(
        values[0].as_deref().map(Vec::as_slice),
        Some(b"durable".as_slice())
    );
    assert!(values[1].is_none());
    assert!(values[2].is_none());
    assert_eq!(
        database_count(&root, "SELECT COUNT(*) FROM protected_commits"),
        commits_before
    );
    assert!(
        store
            .get_many(DocumentKind::Authorization, b"absent", &[missing], 50)
            .unwrap()
            .iter()
            .all(Option::is_none)
    );

    // A plain read of the same expired record still evicts it.
    assert!(
        store
            .get_at(DocumentKind::Authorization, b"grants", &expiring, 50)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        database_count(&root, "SELECT COUNT(*) FROM protected_commits"),
        commits_before + 1
    );
}

#[test]
fn history_survives_reopen_with_provenance_and_pages_newest_first() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    let other = SecretAddress::new("demo/default/OTHER", None).unwrap();
    // An absolute path on every platform, since the context validates it.
    let base_dir = std::env::temp_dir().display().to_string();
    let declared = VaultApplicationContext::new(
        Some("demo".to_owned()),
        Some("default".to_owned()),
        Some(base_dir.clone()),
        Some("build".to_owned()),
    )
    .unwrap();
    let declared_provenance = Provenance::caller(&caller(), Some(&declared));
    store
        .put_at(
            DocumentKind::LocalKeyring,
            b"keyring",
            &address,
            b"first",
            None,
            &declared_provenance,
            100,
        )
        .unwrap();
    store
        .put_at(
            DocumentKind::LocalKeyring,
            b"keyring",
            &other,
            b"other",
            Some(FAR_FUTURE),
            &provenance(),
            101,
        )
        .unwrap();
    assert!(
        store
            .delete(
                DocumentKind::LocalKeyring,
                b"keyring",
                &address,
                &provenance(),
                102
            )
            .unwrap()
    );
    drop(store);

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    let first_page = store
        .list_history(DocumentKind::LocalKeyring, b"keyring", None, None, 2)
        .unwrap();
    assert_eq!(first_page.items.len(), 2);
    assert_eq!(first_page.next_before_seq, Some(1));
    assert_eq!(first_page.items[0].seq, 2);
    assert_eq!(first_page.items[0].at, 102);
    assert_eq!(first_page.items[0].operation, HistoryOperation::Delete);
    assert_eq!(first_page.items[0].address, address);
    assert_eq!(first_page.items[1].seq, 1);
    assert_eq!(first_page.items[1].address, other);
    assert_eq!(first_page.items[1].evict_at, Some(FAR_FUTURE));

    let second_page = store
        .list_history(DocumentKind::LocalKeyring, b"keyring", None, Some(1), 2)
        .unwrap();
    assert_eq!(second_page.items.len(), 1);
    assert!(second_page.next_before_seq.is_none());
    let created = &second_page.items[0];
    assert_eq!(created.seq, 0);
    assert_eq!(created.at, 100);
    assert_eq!(created.operation, HistoryOperation::Put { changed: true });
    assert_eq!(created.device_key_id, store.device().device_key_id());
    assert_eq!(
        created.provenance,
        Provenance::Caller {
            principal: PermissionPrincipal::from(&caller()),
            application: Some(crate::vault::DeclaredApplication {
                project: Some("demo".to_owned()),
                profile: Some("default".to_owned()),
                base_dir: Some(base_dir),
                reason: Some("build".to_owned()),
            }),
        }
    );
    assert_eq!(first_page.items[0].previous_version_id, created.version_id);

    let filtered = store
        .list_history(
            DocumentKind::LocalKeyring,
            b"keyring",
            Some(&other),
            None,
            8,
        )
        .unwrap();
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(filtered.items[0].seq, 1);

    let absent = store
        .list_history(DocumentKind::LocalKeyring, b"missing", None, None, 8)
        .unwrap();
    assert!(absent.items.is_empty());
}

#[test]
fn documents_belong_to_one_device_vault_and_have_distinct_wrapped_keys() {
    let (_directory, root, store) = store();
    let device_vault_id = store.device().device_vault_id();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    for (kind, partition, value) in [
        (
            DocumentKind::SecretSpecProviderCache,
            b"cache".as_slice(),
            b"cache-value".as_slice(),
        ),
        (
            DocumentKind::LocalKeyring,
            b"keyring".as_slice(),
            b"keyring-value".as_slice(),
        ),
    ] {
        store
            .put_at(
                kind,
                partition,
                &address,
                value,
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
    }
    drop(store);

    assert_eq!(database_count(&root, "SELECT COUNT(*) FROM vaults"), 1);
    assert_eq!(
        database_blobs(&root, "SELECT vault_id FROM vaults"),
        [device_vault_id.as_bytes().to_vec()]
    );
    assert_eq!(
        database_count(
            &root,
            "SELECT COUNT(*) FROM documents
             WHERE vault_id = (SELECT vault_id FROM vaults WHERE vault_kind = 'device')",
        ),
        2
    );
    let wrapped = database_blobs(
        &root,
        "SELECT wrapped_dek FROM documents ORDER BY document_id",
    );
    assert_eq!(wrapped.len(), 2);
    assert_ne!(wrapped[0], wrapped[1]);
}

/// A superseded snapshot may linger in the database until compaction. Its key
/// must not: every generation wraps a fresh DEK and the row keeps only the
/// current one.
#[test]
fn every_generation_rotates_the_document_key() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    let mut wrapped_keys = Vec::new();
    for value in [b"first".as_slice(), b"second"] {
        store
            .put_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                value,
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
        wrapped_keys.extend(database_blobs(&root, "SELECT wrapped_dek FROM documents"));
    }
    assert!(
        store
            .delete(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                &provenance(),
                TEST_NOW
            )
            .unwrap()
    );
    wrapped_keys.extend(database_blobs(&root, "SELECT wrapped_dek FROM documents"));
    drop(store);

    assert_eq!(wrapped_keys.len(), 3);
    assert_ne!(wrapped_keys[0], wrapped_keys[1]);
    assert_ne!(wrapped_keys[1], wrapped_keys[2]);
    assert_ne!(wrapped_keys[0], wrapped_keys[2]);
    assert_eq!(database_count(&root, "SELECT key_epoch FROM documents"), 3);
    assert_eq!(database_count(&root, "SELECT generation FROM documents"), 3);

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    assert!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                10,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn protected_chain_authenticates_the_wrapped_document_key() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"cache",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    execute_database_mutation(&root, "UPDATE documents SET wrapped_dek = X'00'");
    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn wrapped_document_keys_cannot_be_swapped_between_documents() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    for partition in [b"first".as_slice(), b"second".as_slice()] {
        store
            .put_at(
                DocumentKind::SecretSpecProviderCache,
                partition,
                &address,
                partition,
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
    }
    drop(store);

    execute_database_mutation(
        &root,
        "UPDATE documents
         SET wrapped_dek = (
             SELECT wrapped_dek FROM documents AS source
             WHERE source.document_id != documents.document_id LIMIT 1
         )
         WHERE document_id = (SELECT document_id FROM documents ORDER BY document_id LIMIT 1)",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn encrypted_snapshots_cannot_be_swapped_between_documents() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    for partition in [b"first".as_slice(), b"second".as_slice()] {
        store
            .put_at(
                DocumentKind::SecretSpecProviderCache,
                partition,
                &address,
                partition,
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
    }
    drop(store);

    execute_database_mutation(
        &root,
        "UPDATE document_snapshots
         SET envelope = (
             SELECT envelope FROM document_snapshots AS source
             WHERE source.document_id != document_snapshots.document_id LIMIT 1
         )
         WHERE document_id = (
             SELECT document_id FROM document_snapshots ORDER BY document_id LIMIT 1
         )",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::Signature)));
}

#[test]
fn failed_persistence_rolls_back_the_entire_document_generation() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"committed",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    let document_id = database_blobs(&root, "SELECT document_id FROM documents")
        .pop()
        .unwrap();

    // Force the snapshot insert to fail after the transaction has updated
    // the document head. The update and every later insert must roll back.
    insert_conflicting_snapshot(&root, &document_id, 2);
    assert!(matches!(
        store.put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"must-not-commit",
            None,
            &provenance(),
            TEST_NOW,
        ),
        Err(VaultError::Database(_))
    ));
    assert!(store.is_sealed());
    assert!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                10
            )
            .is_err()
    );
    drop(store);
    execute_database_mutation(&root, "DELETE FROM document_snapshots WHERE generation = 2");

    assert_eq!(
        database_count(&root, "SELECT COUNT(*) FROM protected_commits"),
        1
    );
    assert_eq!(
        database_count(&root, "SELECT COUNT(*) FROM document_snapshots"),
        1
    );
    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    assert_eq!(
        reopened
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                10,
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"committed"
    );
}

#[test]
fn installation_rejects_an_unexpected_extra_vault() {
    let (_directory, root, store) = store();
    drop(store);
    execute_database_mutation(
        &root,
        "INSERT INTO vaults(vault_id, vault_kind, created_at)
         VALUES (X'01010101010101010101010101010101', 'personal', 1)",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn batch_mutation_commits_related_records_in_one_generation() {
    let (_directory, root, store) = store();
    let first = SecretAddress::new("secret-service/item/first", None).unwrap();
    let index = SecretAddress::new("secret-service/index", None).unwrap();
    store
        .mutate(
            DocumentKind::LinuxSecretService,
            b"secret-service",
            vec![
                DocumentOperation::Put {
                    address: first.clone(),
                    value: Zeroizing::new(b"secret".to_vec()),
                    evict_at: None,
                },
                DocumentOperation::Put {
                    address: index.clone(),
                    value: Zeroizing::new(b"index".to_vec()),
                    evict_at: None,
                },
            ],
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    for table in ["documents", "document_snapshots", "protected_commits"] {
        assert_eq!(
            database_count(&root, &format!("SELECT COUNT(*) FROM {table}")),
            1,
            "a batch mutation wrote more than one {table} row"
        );
    }

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    for (address, expected) in [(first, b"secret".as_slice()), (index, b"index")] {
        assert_eq!(
            store
                .get_at(
                    DocumentKind::LinuxSecretService,
                    b"secret-service",
                    &address,
                    10
                )
                .unwrap()
                .unwrap()
                .as_slice(),
            expected
        );
    }
}

#[test]
fn expiration_is_purged_without_read_and_stays_gone() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"short-lived",
            Some(50),
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    assert_eq!(store.purge_expired_at(49).unwrap(), 0);
    assert_eq!(store.purge_expired_at(50).unwrap(), 1);
    drop(store);

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    assert!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                50,
            )
            .unwrap()
            .is_none()
    );
}

/// Expired records in every document kind are removed by the sweep alone, so a
/// grant that is never read again does not stay in the authorization
/// document, and a sweep touches only documents with a deadline that is due.
#[test]
fn expired_records_are_swept_from_every_document_kind() {
    let (_directory, root, store) = store();
    let durable = SecretAddress::new("grant/durable", None).unwrap();
    let expiring = SecretAddress::new("grant/expiring", None).unwrap();
    let session = SecretAddress::new("session/token", None).unwrap();
    for (kind, namespace, address, value, evict_at) in [
        (
            DocumentKind::Authorization,
            b"grants".as_slice(),
            &durable,
            b"durable".as_slice(),
            None,
        ),
        (
            DocumentKind::Authorization,
            b"grants",
            &expiring,
            b"expiring",
            Some(50),
        ),
        (
            DocumentKind::LocalKeyring,
            b"keyring",
            &session,
            b"token",
            Some(60),
        ),
    ] {
        store
            .put_at(
                kind,
                namespace,
                address,
                value,
                evict_at,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
    }

    assert_eq!(store.purge_expired_at(49).unwrap(), 0);
    assert_eq!(store.purge_expired_at(50).unwrap(), 1);
    assert_eq!(store.purge_expired_at(59).unwrap(), 0);
    assert_eq!(store.purge_expired_at(60).unwrap(), 1);
    assert_eq!(store.purge_expired_at(61).unwrap(), 0);

    // The swept records are gone without a read evicting them, and the
    // durable one stays.
    let commits = database_count(&root, "SELECT COUNT(*) FROM protected_commits");
    let values = store
        .get_many(
            DocumentKind::Authorization,
            b"grants",
            &[durable.clone(), expiring.clone()],
            70,
        )
        .unwrap();
    assert_eq!(
        values[0].as_deref().map(Vec::as_slice),
        Some(b"durable".as_slice())
    );
    assert!(values[1].is_none());
    assert!(
        store
            .get_at(DocumentKind::LocalKeyring, b"keyring", &session, 70)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        database_count(&root, "SELECT COUNT(*) FROM protected_commits"),
        commits
    );
    let swept = store
        .list_history(
            DocumentKind::Authorization,
            b"grants",
            Some(&expiring),
            None,
            8,
        )
        .unwrap();
    assert_eq!(swept.items[0].operation, HistoryOperation::Expire);
    assert_eq!(swept.items[0].at, 50);
}

#[test]
fn project_listing_purges_expired_entries_and_hides_empty_projects() {
    let (_directory, _root, store) = store();
    let address = SecretAddress::secret_spec(
        SecretSpecAddress::convention("demo", "default", "TOKEN").unwrap(),
    )
    .unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProject,
            b"demo",
            &address,
            b"short-lived",
            Some(50),
            &provenance(),
            TEST_NOW,
        )
        .unwrap();

    assert_eq!(store.list_projects(None, 1, 49).unwrap().items, ["demo"]);
    assert!(
        store
            .list_project_addresses("demo", None, 1, 50)
            .unwrap()
            .items
            .is_empty()
    );
    assert!(store.list_projects(None, 1, 50).unwrap().items.is_empty());
}

#[test]
fn installation_files_contain_no_secret_or_predictable_name() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("visible-project/default/API_TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"needle-secret-value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    for needle in [
        b"visible-project".as_slice(),
        b"API_TOKEN".as_slice(),
        b"needle-secret-value".as_slice(),
    ] {
        assert_installation_tree_excludes(&root, needle);
    }
}

fn assert_installation_tree_excludes(root: &Path, needle: &[u8]) {
    let mut directories = vec![root.to_owned()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            assert!(
                !path
                    .as_os_str()
                    .as_encoded_bytes()
                    .windows(needle.len())
                    .any(|window| window == needle),
                "secret coordinate appeared in a file name"
            );
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                directories.push(path);
            } else if file_type.is_file() {
                let bytes = fs::read(path).unwrap();
                assert!(
                    !bytes.windows(needle.len()).any(|window| window == needle),
                    "secret material appeared in a vault file"
                );
            }
        }
    }
}

#[test]
fn one_worker_owns_the_database() {
    let (_directory, root, first) = store();
    let second = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(second, Err(VaultError::Database(_))));
    drop(first);
}

#[test]
fn sealing_one_store_handle_invalidates_every_clone() {
    let (_directory, _root, store) = store();
    let clone = store.clone();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();

    clone.seal();

    assert!(store.is_sealed());
    assert!(store.is_shutdown_complete());
    assert!(matches!(
        store.get_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            10,
        ),
        Err(VaultError::WorkerUnavailable)
    ));
    assert!(matches!(
        clone.put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"replacement",
            None,
            &provenance(),
            TEST_NOW,
        ),
        Err(VaultError::WorkerUnavailable)
    ));
}

#[test]
fn protected_chain_detects_snapshot_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    execute_database_mutation(&root, "UPDATE document_snapshots SET envelope = X'00'");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(
        reopened,
        Err(VaultError::Signature | VaultError::InvalidData(_))
    ));
}

#[test]
fn protected_chain_detects_missing_history() {
    let (_directory, root, store) = store();
    put_two_generations(&store);
    drop(store);
    execute_database_mutation(
        &root,
        "DELETE FROM protected_commits WHERE previous_commit_id IS NULL",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn protected_chain_detects_a_missing_document_row() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    // An external SQLite writer need not enable foreign keys. Removing
    // only the current document row used to leave a valid signed chain
    // and snapshot behind while making the secret silently disappear.
    execute_database_mutation(&root, "DELETE FROM documents");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    let Err(VaultError::InvalidData(message)) = reopened else {
        panic!("a missing current document must not open");
    };
    assert!(
        message.contains("missing document"),
        "unexpected rejection: {message}"
    );
}

#[test]
fn protected_chain_detects_rolled_back_head() {
    let (_directory, root, store) = store();
    put_two_generations(&store);
    drop(store);
    execute_database_mutation(
        &root,
        "UPDATE store_meta
         SET value = (
             SELECT previous_commit_id FROM protected_commits
             WHERE commit_id = store_meta.value
         )
         WHERE key = 'current-commit-head'",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn protected_chain_detects_a_rolled_back_document() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"first",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    let first_wrapped_dek = database_blobs(&root, "SELECT wrapped_dek FROM documents")
        .pop()
        .unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"second",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);
    // Every global check still passes after this: the chain, the row-set
    // counts, and the document's agreement with the commit it points at,
    // including that generation's key epoch and wrapped key. Only the
    // document itself has been rewound a generation.
    execute_database_mutation(
        &root,
        &format!(
            "UPDATE documents
                SET generation = 1,
                    key_epoch = 1,
                    wrapped_dek = X'{}',
                    current_commit_id = (
                        SELECT commit_id FROM protected_commits
                        WHERE document_id = documents.document_id AND generation = 1
                    )
              WHERE generation = 2",
            hex::encode(&first_wrapped_dek)
        ),
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    let Err(VaultError::InvalidData(message)) = reopened else {
        panic!("a rolled-back document must not open");
    };
    assert!(
        message.contains("newest protected commit"),
        "unexpected rejection: {message}"
    );
}

#[test]
fn compaction_bounds_the_chain_and_keeps_every_document_readable() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    let namespaces: [&[u8]; 2] = [b"first", b"second"];
    let mut latest = [String::new(), String::new()];
    for generation in 0..=MAX_RETAINED_COMMITS {
        let index = generation % namespaces.len();
        let value = generation.to_string();
        store
            .put_at(
                DocumentKind::SecretSpecProviderCache,
                namespaces[index],
                &address,
                value.as_bytes(),
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
        latest[index] = value;
    }
    drop(store);

    // Compaction leaves exactly one commit and one snapshot per document,
    // rather than one of each per write.
    let documents = u64::try_from(namespaces.len()).unwrap();
    for table in ["protected_commits", "document_snapshots", "documents"] {
        assert_eq!(
            database_count(&root, &format!("SELECT COUNT(*) FROM {table}")),
            documents,
            "{table} was not compacted"
        );
    }

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    for (namespace, expected) in namespaces.iter().zip(&latest) {
        assert_eq!(
            store
                .get_at(
                    DocumentKind::SecretSpecProviderCache,
                    namespace,
                    &address,
                    10
                )
                .unwrap()
                .unwrap()
                .as_slice(),
            expected.as_bytes()
        );
    }
}

#[test]
fn a_compacted_chain_still_detects_snapshot_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    for generation in 0..=MAX_RETAINED_COMMITS {
        store
            .put_at(
                DocumentKind::SecretSpecProviderCache,
                b"secretspec",
                &address,
                generation.to_string().as_bytes(),
                None,
                &provenance(),
                TEST_NOW,
            )
            .unwrap();
    }
    drop(store);
    execute_database_mutation(&root, "UPDATE document_snapshots SET envelope = X'00'");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(
        reopened,
        Err(VaultError::Signature | VaultError::InvalidData(_))
    ));
}

#[test]
fn protected_chain_detects_document_kind_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);
    execute_database_mutation(&root, "UPDATE documents SET document_kind = 'invalid-kind'");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn protected_chain_detects_document_vault_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);
    execute_database_mutation(
        &root,
        "UPDATE documents SET vault_id = X'01010101010101010101010101010101'",
    );

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn protected_chain_detects_commit_record_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentKind::SecretSpecProviderCache,
            b"secretspec",
            &address,
            b"value",
            None,
            &provenance(),
            TEST_NOW,
        )
        .unwrap();
    drop(store);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let database = turso::Builder::new_local(root.join(DATABASE_FILE).to_str().unwrap())
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();
        let mut rows = connection
            .query("SELECT commit_id, record FROM protected_commits", ())
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        let commit_id = row_blob(&row, 0).unwrap();
        let mut record: ProtectedCommit =
            serde_json::from_slice(&row_blob(&row, 1).unwrap()).unwrap();
        record.signature[0] ^= 1;
        drop(rows);
        connection
            .execute(
                "UPDATE protected_commits SET record = ?1 WHERE commit_id = ?2",
                params![serde_json::to_vec(&record).unwrap(), commit_id],
            )
            .await
            .unwrap();
    });

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::Signature)));
}
