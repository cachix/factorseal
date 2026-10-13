use std::future::Future;
use std::sync::Arc;
use std::task::Poll;
use std::{fs, thread};

use turso::params;

use super::*;
use crate::vault::store::worker::COMMAND_QUEUE;
use crate::vault::{DocumentKind, Provenance, SecretAddress, ServiceReason, Vault, VaultStore};

const TEST_NOW: u64 = 10;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[cfg(feature = "personal-sync")]
fn initialize_sync_group(store: &VaultStore) -> crate::personal::sync::VerifiedGroup {
    let super::super::SyncReply::Group(group) = store
        .personal_sync(super::super::SyncCommand::Pairing(
            super::super::PairingCommand::Initialize {
                endpoint: [9; 32],
                name: "maintenance test".into(),
            },
        ))
        .unwrap()
    else {
        panic!("expected initialized group")
    };
    group
}

async fn add_unused_space(worker: &StoreWorker, bytes: u64) {
    worker
        .connection
        .execute("CREATE TABLE ballast (payload BLOB)", ())
        .await
        .unwrap();
    worker
        .connection
        .execute(
            "INSERT INTO ballast VALUES (zeroblob(?))",
            [i64::try_from(bytes).unwrap()],
        )
        .await
        .unwrap();
    worker
        .connection
        .execute("DROP TABLE ballast", ())
        .await
        .unwrap();
    worker.checkpoint().await.unwrap();
}

async fn put(worker: &mut StoreWorker, value: &[u8]) {
    let scope = DocumentKind::LocalKeyring;
    let partition = b"maintenance";
    let id = worker.document_id(scope, partition);
    let address = SecretAddress::new("token", None).unwrap();
    let provenance = Provenance::service(ServiceReason::Expiry);
    let context = worker.context(&provenance, TEST_NOW);
    worker
        .put(id, scope, partition, &address, value, None, &context)
        .await
        .unwrap();
}

#[test]
fn space_threshold_requires_both_64_mib_and_half_the_pages() {
    let floor = MIN_UNUSED_BYTES / 4096;
    assert!(!needs_compaction(floor * 2, floor - 1, 4096).unwrap());
    assert!(!needs_compaction(floor * 2 + 1, floor, 4096).unwrap());
    assert!(needs_compaction(floor * 2, floor, 4096).unwrap());
    assert!(needs_compaction(floor + 100, floor, 4096).unwrap());
    assert!(!needs_compaction(0, 0, 4096).unwrap());
    assert!(needs_compaction(1, 2, 4096).is_err());
    assert!(needs_compaction(u64::MAX, u64::MAX, 4096).is_err());
}

#[test]
fn physical_compaction_shrinks_the_file_and_preserves_history_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"first").await;
        put(&mut worker, b"second").await;
        add_unused_space(&worker, MIN_UNUSED_BYTES).await;
        let before = fs::metadata(root.join(crate::vault::DATABASE_FILE))
            .unwrap()
            .len();
        assert!(before >= MIN_UNUSED_BYTES);
        worker.reclaim_unused_space().await.unwrap();
        assert!(
            fs::metadata(root.join(crate::vault::DATABASE_FILE))
                .unwrap()
                .len()
                < before / 2
        );
        worker.verify_unchanged_store().await.unwrap();
        assert_eq!(worker.verified.chain_length, 2);
        // The same live connection must remain usable after the page rewrite.
        put(&mut worker, b"third").await;
    });
    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    let address = SecretAddress::new("token", None).unwrap();
    assert_eq!(
        store
            .get_at(
                DocumentKind::LocalKeyring,
                b"maintenance",
                &address,
                TEST_NOW
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"third"
    );
    assert_eq!(
        store
            .list_history(
                DocumentKind::LocalKeyring,
                b"maintenance",
                Some(&address),
                None,
                8
            )
            .unwrap()
            .items
            .len(),
        3
    );
}

#[test]
fn small_unused_space_is_left_for_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"value").await;
        add_unused_space(&worker, MIN_UNUSED_BYTES / 4).await;
        let before = fs::metadata(root.join(crate::vault::DATABASE_FILE))
            .unwrap()
            .len();
        worker.reclaim_unused_space().await.unwrap();
        assert_eq!(
            fs::metadata(root.join(crate::vault::DATABASE_FILE))
                .unwrap()
                .len(),
            before
        );
    });
}

#[test]
fn physical_compaction_rejects_live_rollback_instead_of_blessing_it() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap()).await.unwrap();
        put(&mut worker, b"first").await;
        put(&mut worker, b"second").await;
        add_unused_space(&worker, MIN_UNUSED_BYTES).await;
        worker.connection.execute("DELETE FROM protected_commits WHERE rowid = (SELECT MAX(rowid) FROM protected_commits)", ()).await.unwrap();
        assert!(worker.reclaim_unused_space().await.is_err());
    });
}

#[test]
fn dropping_an_io_yielding_vacuum_keeps_the_connection_usable() {
    let directory = tempfile::tempdir().unwrap();
    runtime().block_on(async {
        for boundary in [1, 2, 4, 8, 16, 32, 64, 128] {
            let path = directory.path().join(format!("vacuum-{boundary}.db"));
            let database = turso::Builder::new_local(path.to_str().unwrap())
                .experimental_vacuum(true)
                .with_io_impl(Arc::new(turso::core::MemoryYieldIO::new()))
                .build()
                .await
                .unwrap();
            let connection = database.connect().unwrap();
            connection
                .execute(
                    "CREATE TABLE payloads (id INTEGER PRIMARY KEY, value BLOB)",
                    (),
                )
                .await
                .unwrap();
            for id in 0..4 {
                connection
                    .execute(
                        "INSERT INTO payloads VALUES (?, ?)",
                        params![id, vec![u8::try_from(id).unwrap(); 1024 * 1024]],
                    )
                    .await
                    .unwrap();
            }
            let mut vacuum = Box::pin(connection.execute("VACUUM", ()));
            // Force cancellation at several real I/O boundaries, independent
            // of whether the host filesystem normally completes synchronously.
            let mut yielded = false;
            for _ in 0..boundary {
                let pending =
                    std::future::poll_fn(|cx| Poll::Ready(vacuum.as_mut().poll(cx).is_pending()))
                        .await;
                yielded |= pending;
                if !pending {
                    break;
                }
            }
            assert!(
                yielded,
                "fixture must exercise an in-flight VACUUM I/O boundary"
            );
            drop(vacuum);
            assert!(connection.is_autocommit().unwrap());
            let mut rows = connection
                .query("SELECT id, value FROM payloads ORDER BY id", ())
                .await
                .unwrap();
            for id in 0..4 {
                let row = rows.next().await.unwrap().unwrap();
                assert_eq!(row.get_value(0).unwrap(), turso::Value::Integer(id));
                assert_eq!(
                    row.get_value(1).unwrap(),
                    turso::Value::Blob(vec![u8::try_from(id).unwrap(); 1024 * 1024])
                );
            }
            assert!(rows.next().await.unwrap().is_none());
            drop(rows);
            connection
                .execute("INSERT INTO payloads VALUES (5, X'CAFE')", ())
                .await
                .unwrap();
            connection.execute("VACUUM", ()).await.unwrap();
            assert_eq!(
                query_count(&connection, "SELECT COUNT(*) FROM payloads", ())
                    .await
                    .unwrap(),
                5
            );
        }
    });
}

#[test]
fn idle_maintenance_yields_to_commands_and_sealing() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"value").await;
        add_unused_space(&worker, MIN_UNUSED_BYTES).await;
        let (sender, receiver) = mpsc::sync_channel(COMMAND_QUEUE);
        let status = WorkerStatus::default();
        let mut maintenance = Box::pin(run_idle(&worker, &receiver, &status));
        std::future::poll_fn(|cx| {
            assert!(maintenance.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        sender.send(Command::Shutdown).unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(matches!(maintenance.await, Some(Command::Shutdown)));
        worker.verify_unchanged_store().await.unwrap();

        let mut maintenance = Box::pin(run_idle(&worker, &receiver, &status));
        std::future::poll_fn(|cx| {
            assert!(maintenance.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        status.sealed.store(true, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(maintenance.await.is_none());
        worker.verify_unchanged_store().await.unwrap();
        assert!(run_idle(&worker, &receiver, &status).await.is_none());
    });
}

#[test]
fn automatic_compaction_waits_until_after_open_and_idle() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("vault");
    runtime().block_on(async {
        let mut worker = StoreWorker::open(&root, Vault::create_for_test(&root).unwrap())
            .await
            .unwrap();
        put(&mut worker, b"value").await;
        add_unused_space(&worker, MIN_UNUSED_BYTES + 1024 * 1024).await;
    });
    let database = root.join(crate::vault::DATABASE_FILE);
    let before = fs::metadata(&database).unwrap().len();
    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    assert_eq!(
        fs::metadata(&database).unwrap().len(),
        before,
        "opening must not repack the file"
    );
    #[cfg(feature = "personal-sync")]
    let group = initialize_sync_group(&store);
    let started = Instant::now();
    let mut last_write = started;
    let mut updated = false;
    while fs::metadata(&database).unwrap().len() >= before / 2 {
        // Desktop regularly polls status, including expiry and revision.
        // Unchanged background polls must not postpone physical compaction.
        store.purge_expired_at(TEST_NOW).unwrap();
        store
            .get_many(
                DocumentKind::Authorization,
                b"background-grants",
                &[SecretAddress::new("grant", None).unwrap()],
                TEST_NOW,
            )
            .unwrap();
        store.export_revision().unwrap();
        #[cfg(feature = "personal-sync")]
        {
            let revision = store.export_revision().unwrap();
            store
                .personal_sync(super::super::SyncCommand::Pairing(
                    super::super::PairingCommand::Accept(group.clone()),
                ))
                .unwrap();
            assert_eq!(store.export_revision().unwrap(), revision);
        }
        // A mutating command can be a no-op. Its category must not reset
        // inactivity when the protected state remains unchanged.
        assert!(
            !store
                .delete(
                    DocumentKind::LocalKeyring,
                    b"maintenance",
                    &SecretAddress::new("missing", None).unwrap(),
                    &Provenance::service(ServiceReason::Expiry),
                    TEST_NOW,
                )
                .unwrap()
        );
        store
            .get_at(
                DocumentKind::LocalKeyring,
                b"maintenance",
                &SecretAddress::new("token", None).unwrap(),
                TEST_NOW,
            )
            .unwrap();
        if !updated && started.elapsed() >= Duration::from_secs(2) {
            store
                .put_at(
                    DocumentKind::LocalKeyring,
                    b"maintenance",
                    &SecretAddress::new("token", None).unwrap(),
                    b"updated",
                    None,
                    &Provenance::service(ServiceReason::Expiry),
                    TEST_NOW,
                )
                .unwrap();
            last_write = Instant::now();
            updated = true;
        }
        assert!(
            started.elapsed()
                < IDLE_BEFORE_COMPACTION + SPACE_CHECK_INTERVAL + Duration::from_secs(15),
            "idle worker did not reclaim space"
        );
        // Leave a realistic gap between polls. Under CPU contention a queued
        // command can cancel the first attempt; allow the scheduled retry.
        thread::sleep(Duration::from_millis(250));
    }
    assert!(updated);
    assert!(last_write.elapsed() >= IDLE_BEFORE_COMPACTION.saturating_sub(Duration::from_secs(1)));
    assert_eq!(
        store
            .get_at(
                DocumentKind::LocalKeyring,
                b"maintenance",
                &SecretAddress::new("token", None).unwrap(),
                TEST_NOW
            )
            .unwrap()
            .unwrap()
            .as_slice(),
        b"updated"
    );
}
