use std::fs;
use std::path::Path;

use super::*;
use crate::vault::store::chain::ProtectedCommit;
use crate::vault::{DocumentKind, Provenance, SecretAddress, ServiceReason, Vault, VaultStore};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn put(worker: &mut StoreWorker, value: &[u8]) {
    let scope = DocumentKind::SecretSpecProviderCache;
    let partition = b"state-test";
    let address = SecretAddress::new("token", None).unwrap();
    let provenance = Provenance::service(ServiceReason::Expiry);
    let context = worker.context(&provenance, 10);
    worker
        .put(
            worker.document_id(scope, partition),
            scope,
            partition,
            &address,
            value,
            None,
            &context,
        )
        .await
        .unwrap();
}

async fn signed_legacy_generation(
    worker: &mut StoreWorker,
    value: &[u8],
    previous: Option<[u8; 32]>,
) -> (ProtectedCommit, Vec<u8>) {
    put(worker, value).await;
    let head_bytes =
        query_optional_blob(&worker.connection, "SELECT record FROM document_heads", ())
            .await
            .unwrap()
            .unwrap();
    let head: CurrentHead = serde_json::from_slice(&head_bytes).unwrap();
    let snapshot = query_optional_blob(
        &worker.connection,
        "SELECT envelope FROM document_snapshots",
        (),
    )
    .await
    .unwrap()
    .unwrap();
    let signer = worker
        .secrets
        .signer(
            worker.device.installation_id(),
            worker.device.device_vault_id(),
        )
        .unwrap();
    let commit = ProtectedCommit::new(
        CommitContents {
            previous_commit_id: previous,
            vault_id: head.vault_id,
            document_id: head.document_id,
            scope: head.scope,
            generation: head.generation,
            key_epoch: head.key_epoch,
            wrapped_key_digest: head.wrapped_key_digest,
            snapshot_digest: head.snapshot_digest,
            next_eviction: head.next_eviction,
            device_key_id: head.device_key_id,
        },
        &signer,
    )
    .unwrap();
    (commit, snapshot)
}

async fn leave_unused_pages(worker: &StoreWorker, unused_bytes: u64) {
    if unused_bytes != 0 {
        worker
            .connection
            .execute("CREATE TABLE ballast(payload BLOB)", ())
            .await
            .unwrap();
        worker
            .connection
            .execute(
                "INSERT INTO ballast VALUES (zeroblob(?1))",
                [to_i64(unused_bytes).unwrap()],
            )
            .await
            .unwrap();
        worker
            .connection
            .execute("DROP TABLE ballast", ())
            .await
            .unwrap();
    }
}

/// Manufacture the previous released format from independently signed fixture
/// generations. Never invoke the new verifier to bless a legacy record.
async fn legacy_fixture(root: &Path, generations: usize, unused_bytes: u64) {
    let mut worker = StoreWorker::open(root, Vault::create_for_test(root).unwrap())
        .await
        .unwrap();
    let mut previous = None;
    let mut retained = Vec::new();
    for generation in 0..generations {
        let (commit, snapshot) =
            signed_legacy_generation(&mut worker, generation.to_string().as_bytes(), previous)
                .await;
        previous = Some(commit.commit_id);
        retained.push((commit, snapshot));
    }
    worker.connection.execute("CREATE TABLE protected_commits(commit_id BLOB PRIMARY KEY NOT NULL, previous_commit_id BLOB, document_id BLOB NOT NULL, generation INTEGER NOT NULL, record BLOB NOT NULL)", ()).await.unwrap();
    worker
        .connection
        .execute("DELETE FROM document_snapshots", ())
        .await
        .unwrap();
    for (commit, snapshot) in retained {
        worker
            .connection
            .execute(
                "INSERT INTO protected_commits VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    commit.commit_id.to_vec(),
                    commit.previous_commit_id.map(|id| id.to_vec()),
                    commit.document_id.as_bytes().to_vec(),
                    to_i64(commit.generation).unwrap(),
                    serde_json::to_vec(&commit).unwrap()
                ],
            )
            .await
            .unwrap();
        worker
            .connection
            .execute(
                "INSERT INTO document_snapshots VALUES (?1, ?2, ?3)",
                params![
                    commit.document_id.as_bytes().to_vec(),
                    to_i64(commit.generation).unwrap(),
                    snapshot
                ],
            )
            .await
            .unwrap();
    }
    worker
        .connection
        .execute(
            "UPDATE documents SET current_commit_id=?1",
            [previous.unwrap().to_vec()],
        )
        .await
        .unwrap();
    worker
        .connection
        .execute(
            "UPDATE store_meta SET value=?1 WHERE key='current-commit-head'",
            [previous.unwrap().to_vec()],
        )
        .await
        .unwrap();
    worker
        .connection
        .execute(
            "UPDATE store_meta SET value=?1 WHERE key='schema-version'",
            [SCHEMA_VERSION.to_be_bytes().to_vec()],
        )
        .await
        .unwrap();
    worker
        .connection
        .execute(
            "DELETE FROM store_meta WHERE key='current-state-manifest'",
            (),
        )
        .await
        .unwrap();
    worker
        .connection
        .execute("DROP TABLE document_heads", ())
        .await
        .unwrap();
    leave_unused_pages(&worker, unused_bytes).await;
    worker.checkpoint().await.unwrap();
}

async fn open_without_state_initialization(root: &Path) -> StoreWorker {
    let opened =
        crate::vault::store::bootstrap::open_store(root, Vault::unseal_for_test(root).unwrap())
            .await
            .unwrap();
    let verifying_key =
        crate::vault::signature::PreparedVerifyingKey::new(opened.device.public_signing_key())
            .unwrap();
    StoreWorker {
        connection: opened.connection,
        device: opened.device,
        secrets: opened.secrets,
        lock_file: opened.lock_file,
        verified: VerifiedStoreState::default(),
        verifying_key,
    }
}

#[test]
fn legacy_migration_preserves_current_values_and_history() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        legacy_fixture(&root, 3, 0).await;
        let mut worker = StoreWorker::open(&root, Vault::unseal_for_test(&root).unwrap())
            .await
            .unwrap();
        assert_eq!(
            read_schema_version(&worker.connection).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        assert_eq!(
            query_count(
                &worker.connection,
                "SELECT COUNT(*) FROM document_snapshots",
                ()
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            query_count(
                &worker.connection,
                "SELECT COUNT(*) FROM document_heads",
                ()
            )
            .await
            .unwrap(),
            1
        );
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
        put(&mut worker, b"after migration").await;
    });
    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    let address = SecretAddress::new("token", None).unwrap();
    assert_eq!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"state-test",
                &address,
                10
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"after migration"
    );
    assert_eq!(
        store
            .list_history(
                DocumentKind::SecretSpecProviderCache,
                b"state-test",
                Some(&address),
                None,
                8
            )
            .unwrap()
            .items
            .len(),
        4
    );
}

#[test]
fn legacy_migration_refuses_tampered_retired_ciphertext() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        legacy_fixture(&root, 65, 0).await;
        let worker = open_without_state_initialization(&root).await;
        worker
            .connection
            .execute(
                "UPDATE document_snapshots SET envelope=X'00' WHERE generation=1",
                (),
            )
            .await
            .unwrap();
        worker.checkpoint().await.unwrap();
    });
    assert!(VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err());
    runtime().block_on(async {
        let worker = open_without_state_initialization(&root).await;
        assert_eq!(
            read_schema_version(&worker.connection).await.unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(
            query_count(
                &worker.connection,
                "SELECT COUNT(*) FROM protected_commits",
                ()
            )
            .await
            .unwrap(),
            65
        );
    });
}

#[test]
fn interrupted_migration_repack_resumes_and_preserves_state() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    let database = root.join(crate::vault::DATABASE_FILE);
    runtime().block_on(async {
        legacy_fixture(&root, 3, 65 * 1024 * 1024).await;
        let mut worker = open_without_state_initialization(&root).await;
        worker.migrate_current_state().await.unwrap();
        assert!(worker.read_manifest().await.unwrap().0.repack_pending);
        assert_eq!(
            read_schema_version(&worker.connection).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        // Closing here simulates exiting after the schema commit, before cleanup.
    });
    let before = fs::metadata(&database).unwrap().len();
    runtime().block_on(async {
        let worker = StoreWorker::open(&root, Vault::unseal_for_test(&root).unwrap())
            .await
            .unwrap();
        assert!(!worker.read_manifest().await.unwrap().0.repack_pending);
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
        assert!(fs::metadata(&database).unwrap().len() < before / 2);
    });
    let after = fs::metadata(&database).unwrap().len();
    runtime().block_on(async {
        let _worker = StoreWorker::open(&root, Vault::unseal_for_test(&root).unwrap())
            .await
            .unwrap();
    });
    assert_eq!(fs::metadata(&database).unwrap().len(), after);
}

#[test]
fn repeated_large_updates_reuse_turso_pages_and_retain_one_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        for generation in 0..200 {
            put(
                &mut worker,
                &vec![u8::try_from(generation).unwrap(); 256 * 1024],
            )
            .await;
            assert_eq!(
                query_count(
                    &worker.connection,
                    "SELECT COUNT(*) FROM document_snapshots",
                    ()
                )
                .await
                .unwrap(),
                1
            );
            assert_eq!(
                query_count(
                    &worker.connection,
                    "SELECT COUNT(*) FROM document_heads",
                    ()
                )
                .await
                .unwrap(),
                1
            );
        }
        let live = query_count(
            &worker.connection,
            "SELECT SUM(length(envelope)) FROM document_snapshots",
            (),
        )
        .await
        .unwrap();
        let physical = fs::metadata(root.join(crate::vault::DATABASE_FILE))
            .unwrap()
            .len();
        assert!(
            physical <= 4 * live + 1024 * 1024,
            "{physical} physical bytes for {live} live bytes"
        );
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
    });
}

#[test]
fn manifest_authenticates_migration_flag_and_signature() {
    for field in ["repack_pending", "signature"] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        runtime().block_on(async {
            let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
                .await
                .unwrap();
            put(&mut worker, b"value").await;
            let bytes = worker.read_manifest().await.unwrap().1;
            let mut manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if field == "repack_pending" {
                manifest[field] = true.into();
            } else {
                let value = manifest[field][0].as_u64().unwrap();
                manifest[field][0] = (value ^ 1).into();
            }
            worker
                .connection
                .execute(
                    "UPDATE store_meta SET value=?1 WHERE key='current-state-manifest'",
                    [serde_json::to_vec(&manifest).unwrap()],
                )
                .await
                .unwrap();
            assert!(worker.verify_state_anchor().await.is_err());
            worker.checkpoint().await.unwrap();
        });
        assert!(VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err());
    }
}

#[test]
fn failed_manifest_write_rolls_back_snapshot_and_head_together() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"committed").await;
        let manifest = worker.read_manifest().await.unwrap().1;
        let sql = format!(
            "CREATE TABLE restricted_meta(key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL,
             CHECK(key <> 'current-state-manifest' OR value = X'{}'));
             INSERT INTO restricted_meta SELECT key, value FROM store_meta;
             DROP TABLE store_meta;
             ALTER TABLE restricted_meta RENAME TO store_meta;",
            hex::encode(&manifest)
        );
        worker.connection.execute_batch(&sql).await.unwrap();
        let scope = DocumentKind::SecretSpecProviderCache;
        let partition = b"state-test";
        let address = SecretAddress::new("token", None).unwrap();
        let provenance = Provenance::service(ServiceReason::Expiry);
        let context = worker.context(&provenance, 10);
        let id = worker.document_id(scope, partition);
        let before = worker.verified.head;
        assert!(
            worker
                .put(
                    id,
                    scope,
                    partition,
                    &address,
                    b"must not commit",
                    None,
                    &context
                )
                .await
                .is_err()
        );
        assert_eq!(worker.verified.head, before);
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
        assert_eq!(
            worker
                .get(id, scope, partition, &address, 10)
                .await
                .unwrap()
                .unwrap()
                .value
                .as_slice(),
            b"committed"
        );
    });
    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    let address = SecretAddress::new("token", None).unwrap();
    assert_eq!(
        store
            .get_at(
                DocumentKind::SecretSpecProviderCache,
                b"state-test",
                &address,
                10
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"committed"
    );
}

#[cfg(feature = "personal-sync")]
#[test]
fn unchanged_pairing_commands_leave_the_manifest_and_generation_untouched() {
    use super::super::{PairingCommand, SyncCommand, SyncReply};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        let SyncReply::Group(group) = worker
            .personal_sync(SyncCommand::Pairing(PairingCommand::Initialize {
                endpoint: [9; 32],
                name: "idempotence test".into(),
            }))
            .await
            .unwrap()
        else {
            panic!("expected group")
        };
        let before = worker.verified.head;
        for _ in 0..20 {
            worker
                .personal_sync(SyncCommand::Pairing(PairingCommand::Accept(group.clone())))
                .await
                .unwrap();
        }
        assert_eq!(worker.verified.head, before);
        worker
            .personal_sync(SyncCommand::Pairing(PairingCommand::Invite))
            .await
            .unwrap();
        let invitation_revision = worker.verified.head;
        assert_ne!(invitation_revision, before);
        worker
            .personal_sync(SyncCommand::Pairing(PairingCommand::Invite))
            .await
            .unwrap();
        assert_eq!(worker.verified.head, invitation_revision);
        worker
            .personal_sync(SyncCommand::Pairing(PairingCommand::Cancel))
            .await
            .unwrap();
        let cancelled_revision = worker.verified.head;
        assert_ne!(cancelled_revision, invitation_revision);
        worker
            .personal_sync(SyncCommand::Pairing(PairingCommand::Cancel))
            .await
            .unwrap();
        assert_eq!(worker.verified.head, cancelled_revision);
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
    });
}

#[test]
fn replaying_a_complete_old_document_cannot_match_the_current_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"old value").await;
        worker
            .connection
            .execute_batch(
                "CREATE TABLE old_documents AS SELECT * FROM documents;
             CREATE TABLE old_heads AS SELECT * FROM document_heads;
             CREATE TABLE old_snapshots AS SELECT * FROM document_snapshots;",
            )
            .await
            .unwrap();
        put(&mut worker, b"new value").await;
        worker
            .connection
            .execute_batch(
                "DELETE FROM document_snapshots; DELETE FROM document_heads; DELETE FROM documents;
             INSERT INTO documents SELECT * FROM old_documents;
             INSERT INTO document_heads SELECT * FROM old_heads;
             INSERT INTO document_snapshots SELECT * FROM old_snapshots;
             DROP TABLE old_documents; DROP TABLE old_heads; DROP TABLE old_snapshots;",
            )
            .await
            .unwrap();
        // The replayed per-document state is internally consistent, but its
        // membership no longer matches the independently signed global root.
        assert!(matches!(
            worker.verify_current_state().await,
            Err(VaultError::Signature)
        ));
        assert!(worker.verify_live_inventory().await.is_err());
        worker.checkpoint().await.unwrap();
    });
    assert!(VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).is_err());
}

#[test]
fn failed_migration_keeps_the_legacy_schema_and_all_retained_generations() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        legacy_fixture(&root, 3, 0).await;
        let mut worker = open_without_state_initialization(&root).await;
        worker
            .connection
            .execute_batch(
                "CREATE TABLE restricted_meta(key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL,
             CHECK(key <> 'current-state-manifest'));
             INSERT INTO restricted_meta SELECT key, value FROM store_meta;
             DROP TABLE store_meta; ALTER TABLE restricted_meta RENAME TO store_meta;",
            )
            .await
            .unwrap();
        assert!(worker.migrate_current_state().await.is_err());
        assert_eq!(
            read_schema_version(&worker.connection).await.unwrap(),
            SCHEMA_VERSION
        );
        assert_eq!(
            query_count(
                &worker.connection,
                "SELECT COUNT(*) FROM protected_commits",
                ()
            )
            .await
            .unwrap(),
            3
        );
        assert_eq!(
            query_count(
                &worker.connection,
                "SELECT COUNT(*) FROM document_snapshots",
                ()
            )
            .await
            .unwrap(),
            3
        );
        let legacy = worker.verify_chain_in_snapshot().await.unwrap();
        assert_eq!(legacy.documents.len(), 1);
        // Remove only the fault-injection constraint and retry the same vault.
        worker
            .connection
            .execute_batch(
                "CREATE TABLE normal_meta(key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
             INSERT INTO normal_meta SELECT key, value FROM store_meta;
             DROP TABLE store_meta; ALTER TABLE normal_meta RENAME TO store_meta;",
            )
            .await
            .unwrap();
        worker.initialize_current_state().await.unwrap();
        assert_eq!(
            read_schema_version(&worker.connection).await.unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        assert!(worker.verify_current_state().await.unwrap() == worker.verified);
    });
}
