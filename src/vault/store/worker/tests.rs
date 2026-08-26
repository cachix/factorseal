use super::*;
use crate::vault::Vault;

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

fn put_two_generations(store: &VaultStore) -> SecretAddress {
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"first",
            None,
        )
        .unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"second",
            None,
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
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"classified",
            None,
        )
        .unwrap();
    assert_eq!(
        store
            .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 10,)
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
            .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 10,)
            .unwrap()
            .unwrap()
            .as_slice(),
        b"classified"
    );
    assert!(
        store
            .delete(DocumentScope::DeviceCache, b"secretspec", &address)
            .unwrap()
    );
    assert!(
        !store
            .delete(DocumentScope::DeviceCache, b"secretspec", &address)
            .unwrap()
    );
}

#[test]
fn batch_mutation_commits_related_records_in_one_generation() {
    let (_directory, root, store) = store();
    let first = SecretAddress::new("secret-service/item/first", None).unwrap();
    let index = SecretAddress::new("secret-service/index", None).unwrap();
    store
        .mutate(
            DocumentScope::DeviceLocal,
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
                .get_at(DocumentScope::DeviceLocal, b"secret-service", &address, 10)
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
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"short-lived",
            Some(50),
        )
        .unwrap();
    assert_eq!(store.purge_expired_at(49).unwrap(), 0);
    assert_eq!(store.purge_expired_at(50).unwrap(), 1);
    drop(store);

    let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    assert!(
        store
            .get_at(DocumentScope::DeviceCache, b"secretspec", &address, 50,)
            .unwrap()
            .is_none()
    );
}

#[test]
fn installation_files_contain_no_secret_or_predictable_name() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("visible-project/default/API_TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"needle-secret-value",
            None,
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
fn protected_chain_detects_snapshot_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"value",
            None,
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
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"value",
            None,
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
    put_two_generations(&store);
    drop(store);
    // Every global check still passes after this: the chain, the row-set
    // counts, and the document's agreement with the commit it points at.
    // Only the document itself has been rewound a generation.
    execute_database_mutation(
        &root,
        "UPDATE documents
            SET generation = 1,
                current_commit_id = (
                    SELECT commit_id FROM protected_commits
                    WHERE document_id = documents.document_id AND generation = 1
                )
          WHERE generation = 2",
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
                DocumentScope::DeviceCache,
                namespaces[index],
                &address,
                value.as_bytes(),
                None,
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
                .get_at(DocumentScope::DeviceCache, namespace, &address, 10)
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
                DocumentScope::DeviceCache,
                b"secretspec",
                &address,
                generation.to_string().as_bytes(),
                None,
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
fn protected_chain_detects_missing_change() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"value",
            None,
        )
        .unwrap();
    drop(store);
    execute_database_mutation(&root, "DELETE FROM document_changes");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::Signature)));
}

#[test]
fn protected_chain_detects_document_scope_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"value",
            None,
        )
        .unwrap();
    drop(store);
    execute_database_mutation(&root, "UPDATE documents SET scope = 'device-local'");

    let reopened = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap());
    assert!(matches!(reopened, Err(VaultError::InvalidData(_))));
}

#[test]
fn protected_chain_detects_commit_record_tamper() {
    let (_directory, root, store) = store();
    let address = SecretAddress::new("demo/default/TOKEN", None).unwrap();
    store
        .put_at(
            DocumentScope::DeviceCache,
            b"secretspec",
            &address,
            b"value",
            None,
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
