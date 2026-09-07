use super::*;
use crate::personal::{
    PersonalSecret,
    replica::PersonalReplica,
    sync::{ReaderIdentity, TransportBinding},
};
use iroh::endpoint::presets;

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}
fn server(courier: CiphertextCourier, endpoint: Endpoint) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = courier.serve_one(&endpoint).await;
        }
    })
}
#[tokio::test]
async fn offline_sender_via_restarted_storage_only_node() {
    let a = endpoint().await;
    let b = endpoint().await;
    let c = endpoint().await;
    let reader = ReaderIdentity::generate().unwrap();
    let receiver = ReaderIdentity::generate().unwrap();
    let genesis = reader
        .create_group(*a.id().as_bytes(), "Laptop".into())
        .unwrap();
    let mut bindings = genesis.transports().to_vec();
    bindings.push(TransportBinding {
        endpoint: *b.id().as_bytes(),
        reader: None,
        name: "Storage".into(),
    });
    bindings.push(TransportBinding {
        endpoint: *c.id().as_bytes(),
        reader: Some(receiver.public_keys().id()),
        name: "Phone".into(),
    });
    let group = reader
        .advance_group(
            &genesis,
            vec![reader.public_keys().clone(), receiver.public_keys().clone()],
            bindings,
            None,
        )
        .unwrap();
    let item = PersonalSecret::generic("Account".into(), "never plaintext on courier".into());
    let mut replica = PersonalReplica::new(&item.id, b"test").unwrap();
    replica.set(Some(&item), None).unwrap();
    let packet = reader
        .seal_update(&replica.update().unwrap(), group.membership())
        .unwrap();
    drop(reader);
    let dir = tempfile::tempdir().unwrap();
    let mut spool = CiphertextSpool::open(&dir.path().join("a"), 8 * 1024 * 1024).unwrap();
    spool.put(packet.as_bytes(), group.membership()).unwrap();
    let source = CiphertextCourier::new(group.clone(), spool);
    let middle = CiphertextCourier::new(
        group.clone(),
        CiphertextSpool::open(&dir.path().join("b"), 8 * 1024 * 1024).unwrap(),
    );
    let task = server(source, a.clone());
    assert_eq!(
        middle.pull_page(&b, a.addr(), None).await.unwrap().stored,
        1
    );
    task.abort();
    let _ = task.await;
    a.close().await;
    drop(middle);
    let middle = CiphertextCourier::new(
        group.clone(),
        CiphertextSpool::open(&dir.path().join("b"), 8 * 1024 * 1024).unwrap(),
    );
    let task = server(middle, b.clone());
    let destination = CiphertextCourier::new(
        group.clone(),
        CiphertextSpool::open(&dir.path().join("c"), 8 * 1024 * 1024).unwrap(),
    );
    assert_eq!(
        destination
            .pull_page(&c, b.addr(), None)
            .await
            .unwrap()
            .stored,
        1
    );
    assert_eq!(
        destination
            .pull_page(&c, b.addr(), None)
            .await
            .unwrap()
            .stored,
        1
    );
    let restored = destination
        .with_spool(|spool, membership| spool.get(packet.id(), membership))
        .unwrap();
    assert_eq!(restored.as_bytes(), packet.as_bytes());
    assert_eq!(
        restored
            .open(&receiver, group.membership())
            .unwrap()
            .replica()
            .unwrap()
            .values()
            .unwrap(),
        vec![Some(item)]
    );
    task.abort();
    let _ = task.await;
    b.close().await;
    c.close().await;
}
#[tokio::test]
async fn unauthorized_endpoint_and_stale_epoch_are_rejected() {
    let a = endpoint().await;
    let b = endpoint().await;
    let reader = ReaderIdentity::generate().unwrap();
    let group = reader
        .create_group(*a.id().as_bytes(), "Laptop".into())
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let courier = CiphertextCourier::new(
        group.clone(),
        CiphertextSpool::open(&dir.path().join("a"), 8 * 1024 * 1024).unwrap(),
    );
    let task = server(courier.clone(), a.clone());
    let request = || Request {
        group: group.digest().unwrap(),
        operation: Operation::Inventory { after: None },
    };
    assert!(rpc(&b, a.addr(), request()).await.is_err());
    let mut bindings = group.transports().to_vec();
    bindings.push(TransportBinding {
        endpoint: *b.id().as_bytes(),
        reader: None,
        name: "Storage".into(),
    });
    let next = reader
        .advance_group(
            &group,
            group.membership().members().to_vec(),
            bindings,
            None,
        )
        .unwrap();
    courier.update_group(next.clone()).unwrap();
    assert!(rpc(&b, a.addr(), request()).await.is_err());
    assert!(matches!(
        rpc(
            &b,
            a.addr(),
            Request {
                group: next.digest().unwrap(),
                operation: Operation::Inventory { after: None }
            }
        )
        .await
        .unwrap(),
        Response::Inventory(_)
    ));
    let removed = reader
        .advance_group(
            &next,
            group.membership().members().to_vec(),
            group.transports().to_vec(),
            None,
        )
        .unwrap();
    courier.update_group(removed).unwrap();
    assert!(
        rpc(
            &b,
            a.addr(),
            Request {
                group: next.digest().unwrap(),
                operation: Operation::Inventory { after: None }
            }
        )
        .await
        .is_err()
    );
    assert!(courier.update_group(group).is_err());
    task.abort();
    let _ = task.await;
    a.close().await;
    b.close().await;
}
