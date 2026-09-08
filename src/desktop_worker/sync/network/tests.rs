use super::*;
use crate::personal::{PERSONAL_SECRET_NAMESPACE, PersonalSecret};
use crate::vault::{Provenance, VaultStore};
use crate::{DocumentKind, SecretAddress, UnsealLeasePolicy, Vault, VaultService};
struct Device {
    root: tempfile::TempDir,
    service: Arc<VaultService>,
    inner: Arc<Inner>,
    task: tokio::task::JoinHandle<()>,
}
impl Device {
    async fn new(item: Option<&PersonalSecret>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let vault = root.path().join("vault");
        let store = VaultStore::open(&vault, Vault::create_for_test(&vault).unwrap()).unwrap();
        if let Some(item) = item {
            store
                .put_at(
                    DocumentKind::LocalKeyring,
                    PERSONAL_SECRET_NAMESPACE,
                    &SecretAddress::new(&item.id, None).unwrap(),
                    &item.encode().unwrap(),
                    None,
                    &Provenance::Redacted,
                    100,
                )
                .unwrap();
        }
        store.seal();
        let service = Arc::new(
            VaultService::open(
                &vault,
                Vault::unseal_for_test(&vault).unwrap(),
                100,
                UnsealLeasePolicy::default(),
            )
            .unwrap(),
        );
        let host = Arc::clone(&service);
        let endpoint = Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec(), PAIR_ALPN.to_vec(), GROUP_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let inner = Arc::new(Inner {
            endpoint,
            root: root.path().into(),
            host: Arc::new(move |command| command.execute(&host).map_err(err)),
            group: Mutex::new(None),
            courier: Mutex::new(None),
            spare: Mutex::new(Some(
                CiphertextSpool::open(&root.path().join("packets"), 256 * 1024 * 1024).unwrap(),
            )),
            apply_cursor: Mutex::new(None),
            view: Mutex::new(View::default()),
            gate: tokio::sync::Mutex::new(()),
            refresh: tokio::sync::Notify::new(),
            peers: Mutex::new(std::collections::BTreeMap::default()),
        });
        let task = tokio::spawn(Arc::clone(&inner).listen());
        Self {
            root,
            service,
            inner,
            task,
        }
    }
    fn know(&self, other: &Self) {
        self.inner.peers.lock().unwrap().insert(
            *other.inner.endpoint.id().as_bytes(),
            other.inner.endpoint.addr(),
        );
    }
    async fn pair(&self, other: &Self) {
        let other_before = other
            .inner
            .group()
            .map_or(1, |group| group.membership().members().len());
        let before = self
            .inner
            .group()
            .map_or(1, |group| group.membership().members().len());
        self.inner
            .action(Action::Invite("Laptop".into()))
            .await
            .unwrap();
        let invitation = self
            .inner
            .view
            .lock()
            .unwrap()
            .state
            .invitation
            .clone()
            .unwrap();
        other
            .inner
            .action(Action::Join {
                ticket: invitation.ticket().unwrap(),
                name: "Phone".into(),
            })
            .await
            .unwrap();
        self.inner.local().await.unwrap();
        let request = self
            .inner
            .view
            .lock()
            .unwrap()
            .state
            .request
            .clone()
            .unwrap();
        assert_eq!(
            request.verification_code().unwrap(),
            other
                .inner
                .view
                .lock()
                .unwrap()
                .state
                .request
                .as_ref()
                .unwrap()
                .verification_code()
                .unwrap()
        );
        assert_eq!(
            self.inner
                .group()
                .map_or(1, |group| group.membership().members().len()),
            before
        );
        assert!(
            self.inner
                .action(Action::Approve(request.id().unwrap()))
                .await
                .is_err()
        );
        other
            .inner
            .action(Action::ApproveJoin(request.id().unwrap()))
            .await
            .unwrap();
        self.inner.local().await.unwrap();
        self.inner
            .action(Action::Approve(request.id().unwrap()))
            .await
            .unwrap();
        other.inner.local().await.unwrap();
        assert!(!other.inner.view.lock().unwrap().state.joining);
        assert_eq!(
            other.service.personal_sync_status().unwrap().readers,
            before + other_before
        );
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        self.task.abort();
        let _ = self.service.seal();
    }
}

#[test]
fn refresh_acknowledges_and_coalesces_while_background_work_is_busy() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let device = runtime.block_on(Device::new(None));
    let inner = Arc::clone(&device.inner);
    // Hold the background work gate beyond the response deadline used by this
    // test. Refresh must return without waiting for that work or any peers.
    let guard = runtime.block_on(inner.gate.lock());
    let manager = Manager {
        runtime: Some(runtime),
        inner: Arc::clone(&inner),
    };
    let (sent, received) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        for _ in 0..3 {
            let view = manager.action(Action::Refresh).unwrap();
            assert_eq!(view.endpoint, *manager.inner.endpoint.id().as_bytes());
        }
        sent.send(()).unwrap();
        manager
    });
    let response = received.recv_timeout(Duration::from_secs(2));
    drop(guard);
    let manager = worker.join().unwrap();
    response.expect("refresh waited for background work");
    manager.runtime.as_ref().unwrap().block_on(async {
        tokio::time::timeout(Duration::from_secs(1), inner.refresh.notified())
            .await
            .expect("refresh did not wake the background loop");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), inner.refresh.notified())
                .await
                .is_err(),
            "repeated refreshes queued extra work"
        );
    });
}

#[tokio::test]
async fn approved_pairing_and_sealed_courier_deliver_after_sender_disconnects() {
    let item =
        PersonalSecret::generic("Personal account".into(), "encrypted over every hop".into());
    let a = Device::new(Some(&item)).await;
    let b = Device::new(None).await;
    let c = Device::new(None).await;
    for (one, two) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        one.know(two);
    }
    assert!(
        rpc(
            &c.inner.endpoint,
            a.inner.endpoint.addr(),
            Request::Group(None)
        )
        .await
        .is_err()
    );
    a.pair(&b).await;
    b.service.seal().unwrap();
    assert!(b.service.personal_sync_status().is_err());
    a.pair(&c).await;
    let Response::Group(latest) = rpc(
        &b.inner.endpoint,
        a.inner.endpoint.addr(),
        Request::Group(None),
    )
    .await
    .unwrap() else {
        panic!()
    };
    b.inner.install(latest.verified().unwrap()).unwrap();
    a.inner.local().await.unwrap();
    let middle = b.inner.courier().unwrap();
    assert!(
        middle
            .pull_page(&b.inner.endpoint, a.inner.endpoint.addr(), None)
            .await
            .unwrap()
            .stored
            > 0
    );
    a.service.seal().unwrap();
    a.inner.endpoint.close().await;
    let destination = c.inner.courier().unwrap();
    assert!(
        destination
            .pull_page(&c.inner.endpoint, b.inner.endpoint.addr(), None)
            .await
            .unwrap()
            .stored
            > 0
    );
    c.inner.local().await.unwrap();
    let values = c.service.personal_sync_conflicts(&item.id).unwrap().values;
    assert_eq!(values, vec![Some(item)]);
    assert_eq!(c.service.personal_sync_status().unwrap().readers, 3);
    assert!(b.service.personal_sync_status().is_err());
}
#[tokio::test]
async fn stolen_request_cannot_be_staged_by_another_transport_endpoint() {
    let a = Device::new(None).await;
    let b = Device::new(None).await;
    let c = Device::new(None).await;
    b.know(&a);
    a.inner
        .action(Action::Invite("Laptop".into()))
        .await
        .unwrap();
    let invitation = a
        .inner
        .view
        .lock()
        .unwrap()
        .state
        .invitation
        .clone()
        .unwrap();
    b.inner
        .action(Action::Join {
            ticket: invitation.ticket().unwrap(),
            name: "Phone".into(),
        })
        .await
        .unwrap();
    let request = b.inner.view.lock().unwrap().state.request.clone().unwrap();
    assert!(
        rpc(
            &c.inner.endpoint,
            a.inner.endpoint.addr(),
            Request::Stage(request)
        )
        .await
        .is_err()
    );
    let introduction = a
        .inner
        .view
        .lock()
        .unwrap()
        .state
        .introduction
        .clone()
        .unwrap();
    assert!(
        rpc(
            &c.inner.endpoint,
            a.inner.endpoint.addr(),
            Request::Update(introduction)
        )
        .await
        .is_err()
    );
    assert_eq!(a.service.personal_sync_status().unwrap().readers, 0);
    a.inner.action(Action::Cancel).await.unwrap();
    assert!(b.inner.local().await.is_err());
}

#[tokio::test]
async fn stale_sealed_device_accepts_enrollment_from_new_peer_after_controller_disconnects() {
    let a = Device::new(None).await;
    let b = Device::new(None).await;
    let c = Device::new(None).await;
    b.know(&a);
    c.know(&a);
    a.pair(&b).await;
    b.service.seal().unwrap();
    a.pair(&c).await;
    a.service.seal().unwrap();
    a.inner.endpoint.close().await;
    assert_eq!(b.inner.group().unwrap().membership().members().len(), 2);
    let Response::Group(public) = rpc(
        &c.inner.endpoint,
        b.inner.endpoint.addr(),
        Request::Update(PublicGroup::new(&c.inner.group().unwrap()).unwrap()),
    )
    .await
    .unwrap() else {
        panic!()
    };
    assert_eq!(public.verified().unwrap().membership().members().len(), 3);
    assert_eq!(b.inner.group().unwrap().membership().members().len(), 3);
    assert!(b.service.personal_sync_status().is_err());
}

#[tokio::test]
async fn populated_groups_merge_from_non_founders_and_offline_peers_catch_up() {
    let first = PersonalSecret::generic("Same title".into(), "First group's secret".into());
    let second = PersonalSecret::generic("Same title".into(), "Second group's secret".into());
    let a = Device::new(Some(&first)).await;
    let b = Device::new(Some(&second)).await;
    let c = Device::new(None).await;
    let d = Device::new(None).await;
    for one in [&a, &b, &c, &d] {
        for two in [&a, &b, &c, &d] {
            one.know(two);
        }
    }
    a.pair(&c).await;
    b.pair(&d).await;
    c.inner.exchange().await;
    c.inner.local().await.unwrap();
    d.inner.exchange().await;
    d.inner.local().await.unwrap();
    a.service.seal().unwrap();
    b.service.seal().unwrap();
    // Neither approving device founded its original group.
    c.pair(&d).await;
    c.inner.exchange().await;
    d.inner.exchange().await;
    c.inner.local().await.unwrap();
    d.inner.local().await.unwrap();
    for device in [&c, &d] {
        for item in [&first, &second] {
            assert_eq!(
                device
                    .service
                    .personal_sync_conflicts(&item.id)
                    .unwrap()
                    .values
                    .iter()
                    .map(Option::as_ref)
                    .collect::<Vec<_>>(),
                vec![Some(item)]
            );
        }
    }
    for device in [&a, &b] {
        assert_eq!(
            device.inner.group().unwrap().membership().members().len(),
            4
        );
        assert!(device.service.personal_sync_status().is_err());
        let public = device.inner.group().unwrap();
        let path = device.root.path().join("vault");
        let reopened = VaultService::open(
            &path,
            Vault::unseal_for_test(&path).unwrap(),
            100,
            UnsealLeasePolicy::default(),
        )
        .unwrap();
        reopened.accept_personal_sync_group(public).unwrap();
        assert_eq!(reopened.personal_sync_status().unwrap().readers, 4);
        reopened.seal().unwrap();
    }
}
#[tokio::test]
async fn introduction_cancellation_keeps_membership_unconfigured_and_can_change_direction() {
    let a = Device::new(None).await;
    let b = Device::new(None).await;
    a.know(&b);
    b.know(&a);
    a.inner.action(Action::Invite("A".into())).await.unwrap();
    assert_eq!(a.service.personal_sync_status().unwrap().readers, 0);
    a.inner.action(Action::Cancel).await.unwrap();
    assert!(a.inner.group().is_none());
    assert!(
        a.service
            .personal_sync_pairing_status()
            .unwrap()
            .introduction
            .is_none()
    );
    b.pair(&a).await;
}
