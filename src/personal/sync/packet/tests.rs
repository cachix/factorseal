use super::*;
use crate::personal::{PersonalSecret, replica::PersonalReplica, sync::CiphertextSpool};

fn update() -> PersonalUpdate {
    let item = PersonalSecret::generic(
        "Personal account".into(),
        "a secret that must stay encrypted".into(),
    );
    let mut replica = PersonalReplica::new(&item.id, b"test-author").unwrap();
    replica.set(Some(&item), None).unwrap();
    replica.update().unwrap()
}

fn membership(identities: &[&ReaderIdentity]) -> Membership {
    Membership::new(
        [7; 16],
        1,
        identities
            .iter()
            .map(|identity| identity.public_keys().clone())
            .collect(),
    )
    .unwrap()
}

#[test]
fn three_devices_exchange_identical_ciphertext_through_a_keyless_courier() {
    let a = ReaderIdentity::generate().unwrap();
    let b = ReaderIdentity::generate().unwrap();
    let c = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a, &b, &c]);
    let update = update();
    let packet = a.seal_update(&update, &group).unwrap();
    assert!(!String::from_utf8_lossy(packet.as_bytes()).contains("Personal account"));
    assert!(
        !String::from_utf8_lossy(packet.as_bytes()).contains("a secret that must stay encrypted")
    );
    assert_eq!(
        packet
            .open(&a, &group)
            .unwrap()
            .replica()
            .unwrap()
            .values()
            .unwrap(),
        update.replica().unwrap().values().unwrap()
    );
    assert_eq!(
        packet
            .open(&b, &group)
            .unwrap()
            .replica()
            .unwrap()
            .values()
            .unwrap(),
        update.replica().unwrap().values().unwrap()
    );
    drop(a);
    drop(b); // Neither sender nor courier reader keys exist during storage/forwarding.

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("courier");
    let mut spool = CiphertextSpool::open(&path, 4 * MAX_PACKET_BYTES as u64).unwrap();
    let id = spool.put(packet.as_bytes(), &group).unwrap();
    assert_eq!(spool.put(packet.as_bytes(), &group).unwrap(), id);
    assert_eq!(spool.inventory(None, 128).unwrap(), vec![id]);
    assert!(spool.inventory(Some(id), 128).unwrap().is_empty());
    assert!(CiphertextSpool::open(&path, 4 * MAX_PACKET_BYTES as u64).is_err());
    drop(spool);
    let spool = CiphertextSpool::open(&path, 4 * MAX_PACKET_BYTES as u64).unwrap();
    let delivered = spool.get(id, &group).unwrap();
    assert_eq!(delivered.as_bytes(), packet.as_bytes());
    assert_eq!(
        delivered
            .open(&c, &group)
            .unwrap()
            .replica()
            .unwrap()
            .values()
            .unwrap(),
        update.replica().unwrap().values().unwrap()
    );
}

#[test]
fn encryption_is_randomized_and_only_authorized_recipients_can_open() {
    let a = ReaderIdentity::generate().unwrap();
    let b = ReaderIdentity::generate().unwrap();
    let outsider = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a, &b]);
    let update = update();
    let first = a.seal_update(&update, &group).unwrap();
    let second = a.seal_update(&update, &group).unwrap();
    assert_ne!(first.id(), second.id());
    assert_ne!(first.packet.body.ciphertext, second.packet.body.ciphertext);
    assert!(first.open(&outsider, &group).is_err());
    assert!(outsider.seal_update(&update, &group).is_err());
    let next = Membership::new([7; 16], 2, vec![a.public_keys().clone()]).unwrap();
    assert!(first.open(&b, &next).is_err());
    assert!(VerifiedPacket::verify(first.as_bytes(), &next).is_err());
    let new_packet = a.seal_update(&update, &next).unwrap();
    assert!(new_packet.open(&b, &next).is_err());
    assert_eq!(
        new_packet
            .open(&a, &next)
            .unwrap()
            .replica()
            .unwrap()
            .values()
            .unwrap(),
        update.replica().unwrap().values().unwrap()
    );
}

#[test]
fn every_signed_component_is_bound_and_noncanonical_encodings_are_rejected() {
    let a = ReaderIdentity::generate().unwrap();
    let b = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a, &b]);
    let packet = a.seal_update(&update(), &group).unwrap();
    let mutations: &[fn(&mut Packet)] = &[
        |packet| packet.body.context.group[0] ^= 1,
        |packet| packet.body.context.epoch += 1,
        |packet| packet.body.context.membership[0] ^= 1,
        |packet| packet.body.context.author.0[0] ^= 1,
        |packet| packet.body.context.operation[0] ^= 1,
        |packet| packet.body.context.suite = "none".into(),
        |packet| packet.body.context.recipients.reverse(),
        |packet| packet.body.nonce[0] ^= 1,
        |packet| packet.body.ciphertext[0] ^= 1,
        |packet| packet.body.keys[0].wrapped[0] ^= 1,
        |packet| packet.body.keys[0].encapsulated[0] ^= 1,
        |packet| packet.body.keys[0].recipient.0[0] ^= 1,
        |packet| packet.body.keys.reverse(),
        |packet| packet.signature[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed: Packet = serde_json::from_slice(packet.as_bytes()).unwrap();
        mutate(&mut changed);
        assert!(VerifiedPacket::verify(&encode(&changed).unwrap(), &group).is_err());
    }
    let mut whitespace = packet.as_bytes().to_vec();
    whitespace.push(b'\n');
    assert!(VerifiedPacket::verify(&whitespace, &group).is_err());
    assert!(VerifiedPacket::verify(&vec![b' '; MAX_PACKET_BYTES + 1], &group).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(packet.as_bytes()).unwrap();
    unknown["extra"] = true.into();
    assert!(VerifiedPacket::verify(&encode(&unknown).unwrap(), &group).is_err());
}

#[test]
fn tombstones_round_trip_and_payload_identity_mismatches_fail() {
    let a = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a]);
    let item = PersonalSecret::generic("Deleted account".into(), "old value".into());
    let mut replica = PersonalReplica::new(&item.id, b"writer").unwrap();
    replica.set(Some(&item), None).unwrap();
    replica.set(None, None).unwrap();
    let update = replica.update().unwrap();
    let received = a
        .seal_update(&update, &group)
        .unwrap()
        .open(&a, &group)
        .unwrap();
    assert_eq!(received.replica().unwrap().values().unwrap(), vec![None]);
    assert_eq!(received.replica().unwrap().heads(), replica.heads());
    assert!(PersonalUpdate::new(item.id.clone(), Vec::new()).is_err());
}

#[test]
fn spool_enforces_quota_and_rejects_corruption_without_replacing_good_data() {
    let a = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a]);
    let packet = a.seal_update(&update(), &group).unwrap();
    let another = a.seal_update(&update(), &group).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("spool");
    let mut spool = CiphertextSpool::open(&path, packet.as_bytes().len() as u64).unwrap();
    let id = spool.put(packet.as_bytes(), &group).unwrap();
    assert!(spool.put(another.as_bytes(), &group).is_err());
    assert_eq!(spool.put(packet.as_bytes(), &group).unwrap(), id);
    assert_eq!(spool.inventory(None, 128).unwrap(), vec![id]);
    let mut corrupt = packet.as_bytes().to_vec();
    corrupt[0] ^= 1;
    std::fs::write(path.join(format!("{id}.packet")), &corrupt).unwrap();
    assert!(spool.get(id, &group).is_err());
    assert!(spool.put(packet.as_bytes(), &group).is_err());
    assert_eq!(
        std::fs::read(path.join(format!("{id}.packet"))).unwrap(),
        corrupt
    );
}

#[test]
fn orphan_tempfiles_consume_quota_but_never_appear_in_inventory() {
    let a = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a]);
    let packet = a.seal_update(&update(), &group).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("spool");
    let mut spool = CiphertextSpool::open(&path, packet.as_bytes().len() as u64).unwrap();
    std::fs::write(path.join(".tmp-orphan"), b"unfinished write").unwrap();
    assert!(spool.inventory(None, 128).unwrap().is_empty());
    assert!(spool.put(packet.as_bytes(), &group).is_err());
}

#[test]
fn membership_rejects_duplicate_and_invalid_public_keys() {
    let a = ReaderIdentity::generate().unwrap();
    assert!(
        Membership::new(
            [7; 16],
            1,
            vec![a.public_keys().clone(), a.public_keys().clone()]
        )
        .is_err()
    );
    let mut bad = a.public_keys().clone();
    bad.encryption.truncate(1);
    assert!(Membership::new([7; 16], 1, vec![bad]).is_err());
    assert!(Membership::new([7; 16], 0, vec![a.public_keys().clone()]).is_err());
    assert!(Membership::new([0; 16], 1, vec![a.public_keys().clone()]).is_err());
}

#[test]
fn a_valid_signature_does_not_make_an_invalid_key_package_decryptable() {
    let a = ReaderIdentity::generate().unwrap();
    let group = membership(&[&a]);
    let packet = a.seal_update(&update(), &group).unwrap();
    let mut malformed: Packet = serde_json::from_slice(packet.as_bytes()).unwrap();
    malformed.body.keys[0].wrapped[0] ^= 1;
    malformed.signature =
        signature::sign(&a.signing_seed, &malformed.signed_bytes().unwrap()).unwrap();
    let verified = VerifiedPacket::verify(&encode(&malformed).unwrap(), &group).unwrap();
    assert!(verified.open(&a, &group).is_err());
}

#[cfg(unix)]
#[test]
fn spool_rejects_symlinks_and_shared_directories() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    let spool = CiphertextSpool::open(&target, MAX_PACKET_BYTES as u64).unwrap();
    drop(spool);
    let link = directory.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(CiphertextSpool::open(&link, MAX_PACKET_BYTES as u64).is_err());
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(CiphertextSpool::open(&target, MAX_PACKET_BYTES as u64).is_err());
}
