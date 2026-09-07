use super::*;
use crate::personal::sync::CiphertextSpool;
use crate::vault::{SecretAddress, UnsealLeasePolicy, Vault, VaultService, VaultStore};

struct Device {
    dir: tempfile::TempDir,
    store: VaultStore,
}
impl Device {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        let store = VaultStore::open(&root, Vault::create_for_test(&root).unwrap()).unwrap();
        Self { dir, store }
    }
    fn restart(&mut self) {
        self.store.seal();
        let root = self.dir.path().join("vault");
        self.store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
    }
    fn identity(&self) -> MemberPublicKeys {
        let SyncReply::Identity(keys) = self.store.personal_sync(SyncCommand::Identity).unwrap()
        else {
            panic!()
        };
        keys
    }
    fn configure(&self, membership: &Membership) {
        self.store
            .personal_sync(SyncCommand::Configure(membership.clone()))
            .unwrap();
    }
    fn put(&self, item: &PersonalSecret) {
        self.store
            .put_at(
                DocumentKind::LocalKeyring,
                PERSONAL_SECRET_NAMESPACE,
                &SecretAddress::new(&item.id, None).unwrap(),
                &item.encode().unwrap(),
                None,
                &Provenance::Redacted,
                10,
            )
            .unwrap();
    }
    fn read(&self, id: &str) -> VaultResult<Option<PersonalSecret>> {
        self.store
            .get_at(
                DocumentKind::LocalKeyring,
                PERSONAL_SECRET_NAMESPACE,
                &SecretAddress::new(id, None).unwrap(),
                10,
            )?
            .map(|bytes| {
                PersonalSecret::decode_current(bytes.as_slice()).map_err(|_| VaultError::Conflict)
            })
            .transpose()
    }
    fn prepare(&self) -> Vec<u8> {
        let SyncReply::Prepared(Some((bytes, _))) =
            self.store.personal_sync(SyncCommand::Prepare).unwrap()
        else {
            panic!()
        };
        bytes
    }
    fn stored(&self, bytes: &[u8], membership: &Membership) {
        let id = VerifiedPacket::verify(bytes, membership).unwrap().id();
        self.store.personal_sync(SyncCommand::Stored(id)).unwrap();
    }
    fn receive(&self, bytes: &[u8]) -> ReceiveOutcome {
        let SyncReply::Received(outcome) = self
            .store
            .personal_sync(SyncCommand::Receive(bytes.to_vec()))
            .unwrap()
        else {
            panic!()
        };
        outcome
    }
    fn status(&self) -> SyncStatus {
        let SyncReply::Status(status) = self.store.personal_sync(SyncCommand::Status).unwrap()
        else {
            panic!()
        };
        status
    }
    fn service(&self) -> VaultService {
        VaultService::new(self.store.clone(), 10, UnsealLeasePolicy::default()).unwrap()
    }
}

fn group(devices: &[&Device]) -> Membership {
    Membership::new(
        [7; 16],
        1,
        devices.iter().map(|device| device.identity()).collect(),
    )
    .unwrap()
}

#[test]
fn real_vault_edits_cross_a_locked_courier_and_apply_after_restart() {
    let mut a = Device::new();
    let b = Device::new();
    let mut c = Device::new();
    let membership = group(&[&a, &b, &c]);
    for device in [&a, &b, &c] {
        device.configure(&membership);
    }
    let identity = a.identity();
    a.restart();
    assert_eq!(a.identity(), identity);
    let mut item = PersonalSecret::generic("My password".into(), "first".into());
    a.put(&item);
    a.store
        .put_at(
            DocumentKind::LocalKeyring,
            b"device-only",
            &SecretAddress::new("factor", None).unwrap(),
            b"never replicate",
            None,
            &Provenance::Redacted,
            10,
        )
        .unwrap();
    let first = a.prepare();
    a.restart(); // Crash after vault preparation, before the spool received bytes.
    assert_eq!(a.prepare(), first);
    item.title = "Renamed while publication was pending".into();
    a.put(&item);
    assert_eq!(
        a.prepare(),
        first,
        "retry must not re-encrypt or change an already prepared packet"
    );
    a.store.seal();
    b.store.seal();
    let courier = b.dir.path().join("ciphertext");
    let id = {
        let mut spool = CiphertextSpool::open(&courier, 8 * 1024 * 1024).unwrap();
        spool.put(&first, &membership).unwrap()
    };
    c.restart();
    let spool = CiphertextSpool::open(&courier, 8 * 1024 * 1024).unwrap();
    let packet = spool.get(id, &membership).unwrap();
    assert_eq!(packet.as_bytes(), first);
    assert_eq!(
        c.service()
            .apply_personal_sync(&spool, None, 1)
            .unwrap()
            .applied,
        1
    );
    assert_eq!(c.status().applied_packets, 1);
    assert_eq!(c.read(&item.id).unwrap().unwrap().title, "My password");
    c.restart();
    assert_eq!(c.receive(&first), ReceiveOutcome::Duplicate);
    a.restart(); // Crash after spool fsync, before vault publication confirmation.
    assert_eq!(a.prepare(), first);
    a.stored(&first, &membership);
    assert_eq!(
        a.status().pending_publications,
        1,
        "old receipt must not clear a newer edit"
    );
    let second = a.prepare();
    a.stored(&second, &membership);
    assert_eq!(a.status().pending_publications, 0);
    assert_eq!(c.receive(&second), ReceiveOutcome::Applied);
    assert_eq!(c.receive(&first), ReceiveOutcome::Duplicate);
    assert_eq!(c.read(&item.id).unwrap().unwrap(), item);
    assert!(
        c.store
            .get_at(
                DocumentKind::LocalKeyring,
                b"device-only",
                &SecretAddress::new("factor", None).unwrap(),
                10
            )
            .unwrap()
            .is_none()
    );
    a.store
        .delete(
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
            &SecretAddress::new(&item.id, None).unwrap(),
            &Provenance::Redacted,
            10,
        )
        .unwrap();
    let deleted = a.prepare();
    assert_eq!(c.receive(&deleted), ReceiveOutcome::Applied);
    c.restart();
    assert_eq!(c.receive(&second), ReceiveOutcome::Duplicate);
    assert!(c.read(&item.id).unwrap().is_none());
    assert_eq!(
        c.status().pending_publications,
        0,
        "received revisions are forwarded as ciphertext, not reauthored"
    );
}

#[test]
fn concurrent_edit_delete_is_preserved_and_explicit_resolution_converges() {
    let a = Device::new();
    let mut b = Device::new();
    let membership = group(&[&a, &b]);
    a.configure(&membership);
    b.configure(&membership);
    let mut item = PersonalSecret::generic("Original".into(), "secret".into());
    a.put(&item);
    let original = a.prepare();
    a.stored(&original, &membership);
    b.receive(&original);
    item.title = "A's offline edit".into();
    a.put(&item);
    b.store
        .delete(
            DocumentKind::LocalKeyring,
            PERSONAL_SECRET_NAMESPACE,
            &SecretAddress::new(&item.id, None).unwrap(),
            &Provenance::Redacted,
            10,
        )
        .unwrap();
    let edit = a.prepare();
    a.stored(&edit, &membership);
    let deleted = b.prepare();
    b.stored(&deleted, &membership);
    assert_eq!(a.receive(&deleted), ReceiveOutcome::Conflict);
    assert_eq!(b.receive(&edit), ReceiveOutcome::Conflict);
    b.restart();
    assert!(matches!(b.read(&item.id), Err(VaultError::Conflict)));
    assert_eq!(b.status().conflicted_items, 1);
    assert_eq!(b.status().conflict_packets, 1);
    assert_eq!(
        b.store.list_vault_entries(None, 8, 10).unwrap().items.len(),
        1
    );
    assert!(
        b.store
            .put_at(
                DocumentKind::LocalKeyring,
                PERSONAL_SECRET_NAMESPACE,
                &SecretAddress::new(&item.id, None).unwrap(),
                &item.encode().unwrap(),
                None,
                &Provenance::Redacted,
                10
            )
            .is_err()
    );
    let service = b.service();
    let choices = service.personal_sync_conflicts(&item.id).unwrap();
    assert_eq!(choices.values.len(), 2);
    assert!(choices.values.iter().any(Option::is_none));
    assert!(
        choices
            .values
            .iter()
            .any(|choice| choice.as_ref() == Some(&item))
    );
    let expected = choices.heads;
    assert!(
        service
            .resolve_personal_sync(&item.id, &expected[..1].to_vec(), None)
            .is_err()
    );
    service
        .resolve_personal_sync(&item.id, &expected, None)
        .unwrap();
    assert_eq!(b.status().conflicted_items, 0);
    assert_eq!(b.status().conflict_packets, 0);
    let resolution = b.prepare();
    assert_eq!(a.receive(&resolution), ReceiveOutcome::Applied);
    assert!(a.read(&item.id).unwrap().is_none());
    assert_eq!(a.status().conflicted_items, 0);
    assert_eq!(a.receive(&edit), ReceiveOutcome::Duplicate);
    assert_eq!(b.receive(&deleted), ReceiveOutcome::Duplicate);
    assert!(a.read(&item.id).unwrap().is_none());
}

#[test]
fn spool_failure_preserves_pending_publication_and_sealing_blocks_sync() {
    let mut a = Device::new();
    let membership = group(&[&a]);
    a.configure(&membership);
    let item = PersonalSecret::generic("Secret".into(), "value".into());
    a.put(&item);
    let tiny_path = a.dir.path().join("tiny");
    let mut tiny = CiphertextSpool::open(&tiny_path, 1).unwrap();
    let service = a.service();
    assert!(service.publish_personal_sync(&mut tiny, 1).is_err());
    let before = service.personal_sync_status().unwrap();
    assert_eq!(before.pending_publications, 1);
    assert!(before.prepared_packet.is_some());
    drop(service);
    a.restart();
    let mut spool = CiphertextSpool::open(&a.dir.path().join("spool"), 4 * 1024 * 1024).unwrap();
    let service = a.service();
    assert_eq!(service.publish_personal_sync(&mut spool, 1).unwrap(), 1);
    assert_eq!(
        spool.inventory(None, 8).unwrap(),
        vec![before.prepared_packet.unwrap()]
    );
    assert_eq!(
        service.personal_sync_status().unwrap().pending_publications,
        0
    );
    assert_eq!(service.publish_personal_sync(&mut spool, 1).unwrap(), 0);
    assert!(service.receive_personal_sync(b"untrusted garbage").is_err());
    assert!(
        !a.store.is_sealed(),
        "remote garbage is not a local integrity failure"
    );
    a.store.seal();
    assert!(service.personal_sync_identity().is_err());
    assert!(service.personal_sync_status().is_err());
}

#[test]
fn membership_changes_republish_current_heads_and_reject_stale_packets() {
    let a = Device::new();
    let b = Device::new();
    let initial = group(&[&a]);
    a.configure(&initial);
    let item = PersonalSecret::generic("Secret".into(), "value".into());
    a.put(&item);
    let old = a.prepare();
    a.stored(&old, &initial);
    let next = Membership::new(initial.group(), 2, vec![a.identity(), b.identity()]).unwrap();
    a.configure(&next);
    b.configure(&next);
    assert!(
        a.store
            .personal_sync(SyncCommand::Configure(initial))
            .is_err()
    );
    assert!(a.store.personal_sync(SyncCommand::Receive(old)).is_err());
    assert_eq!(a.status().pending_publications, 1);
    let packet = a.prepare();
    assert_eq!(b.receive(&packet), ReceiveOutcome::Applied);
    assert_eq!(b.read(&item.id).unwrap().unwrap(), item);
}

#[test]
fn history_capacity_failure_keeps_the_previous_value_and_publication() {
    let a = Device::new();
    let membership = group(&[&a]);
    a.configure(&membership);
    let mut item = PersonalSecret::generic("First".into(), "x".repeat(300_000));
    a.put(&item);
    item.title = "Second".into();
    a.put(&item);
    let prepared = a.prepare();
    item.title = "Must not commit".into();
    assert!(
        a.store
            .put_at(
                DocumentKind::LocalKeyring,
                PERSONAL_SECRET_NAMESPACE,
                &SecretAddress::new(&item.id, None).unwrap(),
                &item.encode().unwrap(),
                None,
                &Provenance::Redacted,
                10
            )
            .is_err()
    );
    assert_eq!(a.read(&item.id).unwrap().unwrap().title, "Second");
    assert_eq!(a.prepare(), prepared);
}
