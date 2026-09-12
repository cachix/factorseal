use super::*;

#[test]
fn automerge_preserves_offline_heads_and_resolves_them_causally() {
    let mut item = PersonalSecret::generic("Original".into(), "first password".into());
    let mut a = PersonalReplica::new(&item.id, b"a").unwrap();
    a.set(Some(&item), None).unwrap();
    let initial = a.update().unwrap();
    let mut b = PersonalReplica::from_update(&initial, b"b").unwrap();
    let mut c = PersonalReplica::from_update(&initial, b"c").unwrap();
    item.title = "A offline".into();
    a.set(Some(&item), None).unwrap();
    b.set(None, None).unwrap();
    let edit = a.update().unwrap();
    let deletion = b.update().unwrap();
    assert!(a.merge(&deletion).unwrap());
    assert!(b.merge(&edit).unwrap());
    assert_eq!(a.heads(), b.heads());
    assert_eq!(a.values().unwrap().len(), 2);
    assert!(a.values().unwrap().contains(&None));
    assert!(
        !a.merge(&initial).unwrap(),
        "late ancestors cannot resurrect old values"
    );
    assert!(a.set(Some(&item), None).is_err());
    let expected = a.heads();
    item.title = "C offline".into();
    c.set(Some(&item), None).unwrap();
    a.merge(&c.update().unwrap()).unwrap();
    assert!(
        a.set(None, Some(&expected)).is_err(),
        "stale decisions must not overwrite a third edit"
    );
    let current = a.heads();
    a.set(None, Some(&current)).unwrap();
    let resolution = a.update().unwrap();
    b.merge(&resolution).unwrap();
    c.merge(&resolution).unwrap();
    assert_eq!(a.heads(), b.heads());
    assert_eq!(a.heads(), c.heads());
    assert_eq!(b.values().unwrap(), vec![None]);
    let reloaded = PersonalReplica::load(&item.id, &a.save().unwrap(), b"restarted").unwrap();
    assert_eq!(reloaded.values().unwrap(), vec![None]);
    assert!(
        resolution.changes.len() > 1,
        "Automerge history must survive local snapshot projection"
    );
}

#[test]
fn every_historical_operation_is_personal_and_dependencies_are_complete() {
    let item = PersonalSecret::generic("Personal".into(), "value".into());
    let mut doc = AutoCommit::new();
    doc.put(ROOT, "device-key", b"not personal".to_vec())
        .unwrap();
    doc.commit();
    doc.delete(ROOT, "device-key").unwrap();
    doc.commit();
    doc.put(ROOT, VALUE, item.encode().unwrap().to_vec())
        .unwrap();
    doc.commit();
    let changes = doc
        .get_changes(&[])
        .iter()
        .map(|c| c.raw_bytes().to_vec())
        .collect();
    assert!(
        PersonalUpdate::new(item.id.clone(), changes).is_err(),
        "even hidden historical fields must be rejected"
    );
    let mut good = PersonalReplica::new(&item.id, b"writer").unwrap();
    good.set(Some(&item), None).unwrap();
    good.set(None, None).unwrap();
    let update = good.update().unwrap();
    assert!(PersonalUpdate::new("different-item".into(), update.changes.clone()).is_err());
    assert!(PersonalUpdate::new(item.id.clone(), vec![update.changes[1].clone()]).is_err());
    let mut repeated = update.changes.clone();
    repeated.push(update.changes[0].clone());
    assert!(PersonalUpdate::new(item.id.clone(), repeated).is_err());
    assert!(
        PersonalUpdate::new(item.id.clone(), vec![good.document.save()]).is_err(),
        "network inputs cannot trigger document decompression"
    );
}

#[test]
fn native_winner_resolution_is_valid_but_register_deletion_is_not() {
    let mut item = PersonalSecret::generic("Original".into(), "password".into());
    let mut a = PersonalReplica::new(&item.id, b"a").unwrap();
    a.set(Some(&item), None).unwrap();
    let mut b = PersonalReplica::from_update(&a.update().unwrap(), b"b").unwrap();
    item.title = "Changed".into();
    a.set(Some(&item), None).unwrap();
    b.set(None, None).unwrap();
    a.merge(&b.update().unwrap()).unwrap();
    let automerge::Value::Scalar(winner) = a.document.get(ROOT, VALUE).unwrap().unwrap().0 else {
        panic!()
    };
    let chosen = decode_value(&item.id, &winner).unwrap();
    let heads = a.heads();
    a.set(chosen.as_ref(), Some(&heads)).unwrap();
    let update = a.update().unwrap();
    assert!(update.changes.iter().any(|bytes| {
        matches!(
            Change::from_bytes(bytes.clone())
                .unwrap()
                .decode()
                .operations[0]
                .action,
            automerge::legacy::OpType::Delete
        )
    }));
    assert_eq!(update.replica().unwrap().values().unwrap(), vec![chosen]);

    let mut erased = AutoCommit::new();
    erased
        .put(ROOT, VALUE, item.encode().unwrap().to_vec())
        .unwrap();
    erased.commit();
    erased.delete(ROOT, VALUE).unwrap();
    erased.commit();
    erased
        .put(ROOT, VALUE, item.encode().unwrap().to_vec())
        .unwrap();
    erased.commit();
    let changes = erased
        .get_changes(&[])
        .iter()
        .map(|change| change.raw_bytes().to_vec())
        .collect();
    assert!(
        PersonalUpdate::new(item.id.clone(), changes).is_err(),
        "a later put cannot disguise deletion of the whole register"
    );
}

#[test]
fn a_change_whose_checksum_does_not_match_its_hash_is_rejected() {
    let item = PersonalSecret::generic("Original".into(), "first password".into());
    let mut a = PersonalReplica::new(&item.id, b"a").unwrap();
    a.set(Some(&item), None).unwrap();
    let update = a.update().unwrap();
    assert!(PersonalUpdate::new(item.id.clone(), update.changes.clone()).is_ok());
    // Automerge loads a change with a wrong header checksum, but its change
    // graph later looks the change up by the declared hash and panics in
    // debug builds. The fuzzer found exactly that input.
    let mut corrupted = update.changes.clone();
    corrupted[0][4] ^= 0x01;
    assert!(PersonalUpdate::new(item.id.clone(), corrupted).is_err());
}
