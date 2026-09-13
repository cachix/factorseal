//! Exercise logind wire types and subscriptions on the isolated CI session bus.
use super::*;
use std::collections::HashMap;
use std::io::Read;

const MANAGER_PATH: &str = "/org/freedesktop/login1";
const SESSION_PATH: &str = "/org/freedesktop/login1/session/test";
const MANAGER_INTERFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_INTERFACE: &str = "org.freedesktop.login1.Session";
type Session = (String, u32, String, String, OwnedObjectPath);

struct Manager {
    sessions: Arc<Mutex<Vec<Session>>>,
    inhibitors: Arc<Mutex<Vec<UnixStream>>>,
}

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl Manager {
    fn inhibit(&self, what: &str, who: &str, why: &str, mode: &str) -> OwnedFd {
        assert_eq!(
            (what, who, why, mode),
            (
                "sleep:shutdown",
                "Factorseal",
                "Lock hardware-unwrapped secrets",
                "delay"
            )
        );
        let (local, remote) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        self.inhibitors.lock().unwrap().push(local);
        std::os::fd::OwnedFd::from(remote).into()
    }

    fn list_sessions(&self) -> Vec<Session> {
        self.sessions.lock().unwrap().clone()
    }

    fn get_session(&self, id: &str) -> OwnedObjectPath {
        assert!(!id.is_empty());
        self.sessions.lock().unwrap().first().map_or_else(
            || SESSION_PATH.try_into().unwrap(),
            |session| session.4.clone(),
        )
    }
}

struct SessionProperties(Arc<AtomicBool>);

#[zbus::interface(name = "org.freedesktop.login1.Session")]
impl SessionProperties {
    #[zbus(property)]
    fn locked_hint(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

async fn monitor() -> LinuxLifecycleConnection {
    let connection = zbus::connection::Builder::session()
        .unwrap()
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
        .unwrap();
    LinuxLifecycleConnection::with_connection(connection, Arc::new(LifecycleSignal::new()))
        .await
        .unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one isolated logind instance covers the complete lifecycle sequence"
)]
async fn logind_wire_events_and_inhibitor_lifetime() {
    // Never impersonate logind on a developer's actual session/system bus.
    if std::env::var_os("FACTORSEAL_TEST_PRIVATE_DBUS").is_none() {
        return;
    }
    let sessions = Arc::new(Mutex::new(vec![(
        "test".to_owned(),
        getuid().as_raw(),
        "user".to_owned(),
        "seat0".to_owned(),
        SESSION_PATH.try_into().unwrap(),
    )]));
    let inhibitors = Arc::new(Mutex::new(Vec::new()));
    let locked = Arc::new(AtomicBool::new(false));
    let server = zbus::connection::Builder::session()
        .unwrap()
        .name("org.freedesktop.login1")
        .unwrap()
        .serve_at(
            MANAGER_PATH,
            Manager {
                sessions: Arc::clone(&sessions),
                inhibitors: Arc::clone(&inhibitors),
            },
        )
        .unwrap()
        .serve_at(SESSION_PATH, SessionProperties(Arc::clone(&locked)))
        .unwrap()
        .build()
        .await
        .unwrap();

    for (member, starting, seals) in [
        ("PrepareForSleep", true, true),
        ("PrepareForSleep", false, true),
        ("PrepareForShutdown", true, true),
        ("PrepareForShutdown", false, false),
    ] {
        let mut monitor = monitor().await;
        assert!(!monitor.signal.requested());
        server
            .emit_signal(
                None::<&str>,
                MANAGER_PATH,
                MANAGER_INTERFACE,
                member,
                &starting,
            )
            .await
            .unwrap();
        monitor.process(Duration::from_secs(2)).await.unwrap();
        assert_eq!(monitor.signal.requested(), seals, "{member}({starting})");
    }

    let mut monitor = monitor().await;
    let impostor = Connection::session().await.unwrap();
    // Even directly addressed signals must pass the unique-sender filter.
    impostor
        .emit_signal(
            monitor.connection.unique_name(),
            SESSION_PATH,
            SESSION_INTERFACE,
            "Lock",
            &(),
        )
        .await
        .unwrap();
    monitor.process(Duration::from_millis(50)).await.unwrap();
    assert!(!monitor.signal.requested());
    server
        .emit_signal(
            None::<&str>,
            "/org/freedesktop/login1/session/other",
            SESSION_INTERFACE,
            "Lock",
            &(),
        )
        .await
        .unwrap();
    monitor.process(Duration::from_secs(2)).await.unwrap();
    assert!(!monitor.signal.requested());
    server
        .emit_signal(None::<&str>, SESSION_PATH, SESSION_INTERFACE, "Lock", &())
        .await
        .unwrap();
    monitor.process(Duration::from_secs(2)).await.unwrap();
    assert!(monitor.signal.requested());
    assert!(monitor.signal.arm().is_err());
    let mut inhibitor = inhibitors.lock().unwrap().pop().unwrap();
    assert_eq!(
        inhibitor.read(&mut [0]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(monitor);
    assert_eq!(inhibitor.read(&mut [0]).unwrap(), 0);

    for value in [false, true] {
        let mut monitor = self::monitor().await;
        let changed = HashMap::from([("LockedHint", OwnedValue::from(value))]);
        server
            .emit_signal(
                None::<&str>,
                SESSION_PATH,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(SESSION_INTERFACE, changed, Vec::<String>::new()),
            )
            .await
            .unwrap();
        monitor.process(Duration::from_secs(2)).await.unwrap();
        assert_eq!(monitor.signal.requested(), value);
    }

    locked.store(true, Ordering::Release);
    assert!(
        self::monitor().await.signal.requested(),
        "startup must inspect LockedHint"
    );
    locked.store(false, Ordering::Release);
    let mut monitor = self::monitor().await;
    sessions.lock().unwrap().clear();
    server
        .emit_signal(
            None::<&str>,
            MANAGER_PATH,
            MANAGER_INTERFACE,
            "SessionRemoved",
            &("test", OwnedObjectPath::try_from(SESSION_PATH).unwrap()),
        )
        .await
        .unwrap();
    monitor.process(Duration::from_secs(2)).await.unwrap();
    assert!(monitor.signal.requested());
    if !SESSION_ID_ENVIRONMENT
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|value| !value.is_empty()))
    {
        assert!(monitor.session_paths.lock().unwrap().is_empty());
    }
    drop(monitor);

    let mut monitor = self::monitor().await;
    server.release_name("org.freedesktop.login1").await.unwrap();
    assert!(
        monitor.process(Duration::from_secs(2)).await.is_err(),
        "losing logind must fail closed"
    );
    drop(monitor);
    server.request_name("org.freedesktop.login1").await.unwrap();
    let mut monitor = self::monitor().await;
    monitor.connection.clone().close().await.unwrap();
    assert!(
        monitor.process(Duration::from_secs(2)).await.is_err(),
        "bus loss must fail closed"
    );
}
