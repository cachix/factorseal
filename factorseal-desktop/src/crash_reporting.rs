//! Desktop owns network delivery; the key-owning CLI worker only writes local
//! reports. Sentry's protocol types are used without installing global SDK hooks.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factorseal::diagnostics::{Incident, desktop_incidents};
use sentry::protocol::{Breadcrumb, Event, Exception, Level};
use sentry::types::Dsn;
use serde::{Deserialize, Serialize};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const RETRY_SECONDS: u64 = 60;
const PROJECT_DSN: &str = include_str!("../sentry-dsn.txt");
static ENABLED: AtomicBool = AtomicBool::new(true);
static CONFIGURED: AtomicBool = AtomicBool::new(false);
static UPLOADER: OnceLock<std::thread::Thread> = OnceLock::new();

struct Configuration {
    dsn: Dsn,
    environment: String,
}

impl Configuration {
    fn parse(dsn: Option<&str>, environment: Option<&str>) -> io::Result<Option<Self>> {
        let Some(dsn) = dsn.filter(|dsn| !dsn.trim().is_empty()) else {
            return Ok(None);
        };
        let dsn: Dsn = dsn
            .parse()
            .map_err(|_| io::Error::other("invalid Sentry DSN"))?;
        if dsn.envelope_api_url().scheme() != "https" || dsn.secret_key().is_some() {
            return Err(io::Error::other(
                "Sentry requires an HTTPS DSN with a public key only",
            ));
        }
        let environment =
            environment
                .filter(|value| !value.is_empty())
                .unwrap_or(if cfg!(debug_assertions) {
                    "development"
                } else {
                    "production"
                });
        if environment.len() > 64
            || !environment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            return Err(io::Error::other("invalid Sentry environment label"));
        }
        Ok(Some(Self {
            dsn,
            environment: environment.to_owned(),
        }))
    }

    fn from_environment() -> io::Result<Option<Self>> {
        // A present but empty runtime value explicitly disables an embedded DSN.
        let dsn = setting(
            "SENTRY_DSN",
            embedded_dsn(option_env!("FACTORSEAL_SENTRY_DSN"), cfg!(debug_assertions)),
        )?;
        let environment = setting(
            "SENTRY_ENVIRONMENT",
            option_env!("FACTORSEAL_SENTRY_ENVIRONMENT"),
        )?;
        Self::parse(dsn.as_deref(), environment.as_deref())
    }
}

fn embedded_dsn(build_override: Option<&str>, debug: bool) -> Option<&str> {
    // Developer builds stay local unless explicitly configured. Release builds
    // work out of the box, including Cargo builds outside the Nix packaging.
    build_override.or_else(|| (!debug).then(|| PROJECT_DSN.trim()))
}

fn setting(name: &str, embedded: Option<&str>) -> io::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(embedded.map(str::to_owned)),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(io::Error::other("invalid Sentry configuration encoding"))
        }
    }
}

pub(crate) fn configured() -> bool {
    CONFIGURED.load(Ordering::Acquire)
}

/// Explicit submissions are independent of the automatic crash preference.
pub(crate) fn submit_issue(description: &str) -> io::Result<String> {
    if !configured() {
        return Err(io::Error::other("Sentry submission unavailable"));
    }
    let id = factorseal::diagnostics::report_issue(description)?;
    if let Some(thread) = UPLOADER.get() {
        thread.unpark();
    }
    Ok(id)
}

pub(crate) fn issue_sent(id: &str) -> io::Result<bool> {
    let path = factorseal::diagnostics::directory()?.join("sentry-delivery.json");
    let bytes = factorseal::security::read_private_file(&path, 16 * 1024)?;
    let state: DeliveryState = serde_json::from_slice(&bytes)?;
    Ok(state.sent.iter().any(|sent| sent == id))
}

pub(crate) fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
    if let Some(thread) = UPLOADER.get() {
        thread.unpark();
    }
}

/// Stop scheduling sends on normal application shutdown without waiting on HTTP.
/// A crash exits immediately; its durable report is delivered next launch.
pub(crate) struct Guard(Arc<AtomicBool>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        if let Some(thread) = UPLOADER.get() {
            thread.unpark();
        }
    }
}

pub(crate) fn start(enabled: bool) -> io::Result<Option<Guard>> {
    set_enabled(enabled);
    let Some(config) = Configuration::from_environment()? else {
        return Ok(None);
    };
    let directory = factorseal::diagnostics::directory()?;
    let state_path = directory.join("sentry-delivery.json");
    let state = DeliveryState::load(&state_path, &config.dsn.to_string())?;
    let stopped = Arc::new(AtomicBool::new(false));
    CONFIGURED.store(true, Ordering::Release);
    let stop_worker = Arc::clone(&stopped);
    let worker = std::thread::Builder::new()
        .name("factorseal-crash-upload".to_owned())
        .spawn(move || {
            let result = run(&directory, &config, state, &stop_worker, &ENABLED);
            CONFIGURED.store(false, Ordering::Release);
            if result.is_err() {
                // Neither the DSN nor HTTP bodies/errors enter application logs.
                eprintln!("factorseal-desktop: automatic crash submission unavailable");
            }
        })
        .inspect_err(|_| CONFIGURED.store(false, Ordering::Release))?;
    let _ = UPLOADER.set(worker.thread().clone());
    Ok(Some(Guard(stopped)))
}

#[derive(Serialize, Deserialize)]
struct DeliveryState {
    target: String,
    first_enabled_ms: u64,
    sent: Vec<String>,
    next_attempt_ms: u64,
}

impl DeliveryState {
    fn load(path: &Path, target: &str) -> io::Result<Self> {
        let previous = match factorseal::security::read_private_file(path, 16 * 1024) {
            Ok(bytes) => Some(serde_json::from_slice::<Self>(&bytes)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(previous) = previous.filter(|state| state.target == target) {
            return Ok(previous);
        }
        let state = Self {
            target: target.to_owned(),
            first_enabled_ms: now_ms(),
            sent: Vec::new(),
            next_attempt_ms: 0,
        };
        // Do not retroactively upload reports from before Sentry was configured.
        state.save(path)?;
        Ok(state)
    }

    fn save(&self, path: &Path) -> io::Result<()> {
        factorseal::security::write_private_file(path, &serde_json::to_vec(self)?)
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn run(
    directory: &Path,
    config: &Configuration,
    mut state: DeliveryState,
    stopped: &AtomicBool,
    automatic: &AtomicBool,
) -> io::Result<()> {
    let state_path = directory.join("sentry-delivery.json");
    let transport = HttpTransport::new(&config.dsn)?;
    while !stopped.load(Ordering::Acquire) {
        if now_ms() >= state.next_attempt_ms {
            let incidents = desktop_incidents(directory)?;
            deliver(
                &incidents,
                config,
                &mut state,
                &state_path,
                |body| transport.send(body),
                |incident| {
                    (incident.report.state == "user_report" || automatic.load(Ordering::Acquire))
                        && !stopped.load(Ordering::Acquire)
                },
            )?;
        }
        std::thread::park_timeout(POLL_INTERVAL);
    }
    Ok(())
}

fn deliver(
    incidents: &[Incident],
    config: &Configuration,
    state: &mut DeliveryState,
    state_path: &Path,
    mut send: impl FnMut(Vec<u8>) -> Result<Duration, Duration>,
    enabled: impl Fn(&Incident) -> bool,
) -> io::Result<()> {
    state
        .sent
        .retain(|id| incidents.iter().any(|incident| &incident.id == id));
    for incident in incidents {
        if !enabled(incident) {
            continue;
        }
        if incident.report.recorded_ms < state.first_enabled_ms || state.sent.contains(&incident.id)
        {
            continue;
        }
        let body = envelope(incident, &config.environment)?;
        match send(body) {
            Ok(delay) => {
                state.sent.push(incident.id.clone());
                state.next_attempt_ms =
                    now_ms().saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX));
                if !delay.is_zero() {
                    state.save(state_path)?;
                    break;
                }
            }
            Err(delay) => {
                state.next_attempt_ms =
                    now_ms().saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX));
                state.save(state_path)?;
                break;
            }
        }
        state.save(state_path)?;
    }
    Ok(())
}

struct HttpTransport {
    client: reqwest::blocking::Client,
    url: reqwest::Url,
    auth: String,
}

impl HttpTransport {
    fn new(dsn: &Dsn) -> io::Result<Self> {
        let builder = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!cfg!(test))
            .user_agent("factorseal-desktop-crash-reporter");
        #[cfg(test)]
        let builder = builder.no_proxy();
        let client = builder
            .build()
            .map_err(|_| io::Error::other("could not initialize crash transport"))?;
        Ok(Self {
            client,
            url: dsn.envelope_api_url(),
            auth: dsn.to_auth(Some("factorseal-desktop")).to_string(),
        })
    }

    fn send(&self, body: Vec<u8>) -> Result<Duration, Duration> {
        let response = self
            .client
            .post(self.url.clone())
            .header("X-Sentry-Auth", &self.auth)
            .header("Content-Type", "application/x-sentry-envelope")
            .body(body)
            .send()
            .map_err(|_| Duration::from_secs(RETRY_SECONDS))?;
        // Respect the longest server-requested delay conservatively across
        // categories, including custom Sentry quotas. Never spin on rejection.
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let quota_delay = response
            .headers()
            .get("X-Sentry-Rate-Limits")
            .and_then(|value| value.to_str().ok())
            .into_iter()
            .flat_map(|value| value.split(','))
            .filter_map(|limit| limit.trim().split(':').next()?.parse::<f64>().ok())
            .filter(|delay| delay.is_finite() && *delay >= 0.)
            .filter_map(|delay| Duration::try_from_secs_f64(delay).ok())
            .max()
            .unwrap_or_default();
        let delay = Duration::from_secs(retry_after).max(quota_delay);
        if response.status().is_success() {
            Ok(delay)
        } else {
            Err(delay.max(Duration::from_secs(RETRY_SECONDS)))
        }
    }
}

fn crash_exception(report: &factorseal::diagnostics::Report) -> Exception {
    let mut stacktrace = report
        .backtrace
        .as_deref()
        .and_then(sentry::integrations::backtrace::parse_stacktrace);
    if let Some(stacktrace) = &mut stacktrace {
        for frame in &mut stacktrace.frames {
            // Source basenames and symbols suffice for diagnosis; build-host
            // paths, locals, source snippets, and machine identity stay local.
            frame.abs_path = None;
            frame.in_app = frame.function.as_ref().map(|function| {
                function.starts_with("factorseal")
                    && !function.starts_with("factorseal::diagnostics")
            });
        }
    }
    Exception {
        ty: if report.state == "panic" {
            "RustPanic"
        } else {
            "VaultWorkerExit"
        }
        .to_owned(),
        value: Some(
            if report.state == "panic" {
                "Rust panic (payload omitted)"
            } else {
                "Vault worker exited unsuccessfully"
            }
            .to_owned(),
        ),
        stacktrace,
        ..Exception::default()
    }
}

fn envelope(incident: &Incident, environment: &str) -> io::Result<Vec<u8>> {
    let report = &incident.report;
    let mut event = Event {
        event_id: incident
            .id
            .parse()
            .map_err(|_| io::Error::other("invalid incident ID"))?,
        timestamp: UNIX_EPOCH
            .checked_add(Duration::from_millis(report.recorded_ms))
            .unwrap_or(UNIX_EPOCH),
        platform: "rust".into(),
        level: Level::Error,
        release: Some(format!("factorseal@{}", report.version).into()),
        environment: Some(environment.to_owned().into()),
        exception: if report.state == "user_report" {
            Vec::new()
        } else {
            vec![crash_exception(report)]
        }
        .into(),
        ..Event::default()
    };
    if report.state == "user_report" {
        event.message = Some("User-reported issue".to_owned());
        if let Some(description) = &report.issue_description {
            event
                .extra
                .insert("issue_description".to_owned(), description.clone().into());
        }
    }
    for (key, value) in [
        ("component", &report.component),
        ("os", &report.os),
        ("architecture", &report.architecture),
        ("report_kind", &report.state),
    ] {
        event.tags.insert(key.to_owned(), value.clone());
    }
    event
        .extra
        .insert("process_id".to_owned(), report.process_id.into());
    if let Some(location) = &report.panic_location {
        event
            .extra
            .insert("panic_location".to_owned(), location.clone().into());
    }
    event.breadcrumbs = report
        .events
        .iter()
        .map(|entry| {
            let mut crumb = Breadcrumb {
                timestamp: UNIX_EPOCH
                    .checked_add(Duration::from_millis(entry.timestamp_ms))
                    .unwrap_or(UNIX_EPOCH),
                category: Some(entry.scope.clone()),
                message: Some(entry.operation.clone()),
                level: if entry.outcome == "error" {
                    Level::Error
                } else {
                    Level::Info
                },
                ..Breadcrumb::default()
            };
            crumb
                .data
                .insert("outcome".to_owned(), entry.outcome.clone().into());
            if let Some(elapsed) = entry.elapsed_ms {
                crumb.data.insert("elapsed_ms".to_owned(), elapsed.into());
            }
            if let Some(exit) = &entry.child_exit {
                crumb.data.insert(
                    "child_exit".to_owned(),
                    serde_json::to_value(exit).unwrap_or_default(),
                );
            }
            crumb
        })
        .collect::<Vec<_>>()
        .into();
    let mut bytes = Vec::new();
    sentry::Envelope::from(event).to_writer(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    fn config() -> Configuration {
        Configuration::parse(Some("https://public@example.com/42"), Some("test"))
            .unwrap()
            .unwrap()
    }

    const LIVE_TEST: &str = "crash_reporting::tests::live_sentry_submission";
    const LIVE_CHILD: &str = "FACTORSEAL_SENTRY_TEST_CHILD";

    fn live_submission_child(mode: &str) {
        factorseal::diagnostics::initialize("desktop").unwrap();
        factorseal::diagnostics::event("diagnostics", "sentry_integration_test", "start");
        assert!(
            mode != "panic",
            "controlled Sentry integration test; payload must remain local"
        );
        let _guard = start(mode != "manual").unwrap().expect("Sentry configured");
        let id = if mode == "manual" {
            submit_issue("Live integration test of manual issue submission.").unwrap()
        } else {
            desktop_incidents(&factorseal::diagnostics::directory().unwrap())
                .unwrap()
                .into_iter()
                .find(|incident| incident.report.state == "panic")
                .expect("panic saved by the previous process")
                .id
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            if issue_sent(&id).unwrap() {
                println!("Sentry accepted {mode} event: {id}");
                break;
            }
            assert!(configured(), "Sentry uploader stopped");
            assert!(
                std::time::Instant::now() < deadline,
                "Sentry did not acknowledge the report before the deadline"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        factorseal::diagnostics::finish(true);
    }

    /// Explicit, opt-in check against a real project. Normal test runs never send.
    #[test]
    #[ignore = "sends two real Sentry events; requires an explicit SENTRY_DSN"]
    fn live_sentry_submission() {
        if let Ok(mode) = std::env::var(LIVE_CHILD) {
            live_submission_child(&mode);
            return;
        }
        let dsn =
            std::env::var("SENTRY_DSN").expect("set SENTRY_DSN explicitly for this live check");
        let dsn = Configuration::parse(Some(&dsn), Some("integration-test"))
            .unwrap()
            .expect("set a nonempty SENTRY_DSN for this live check")
            .dsn
            .to_string();
        let directory = tempfile::tempdir().unwrap();
        for mode in ["manual", "panic", "restart"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", LIVE_TEST, "--ignored", "--nocapture"])
                .env(LIVE_CHILD, mode)
                .env("SENTRY_DSN", &dsn)
                .env("SENTRY_ENVIRONMENT", "integration-test")
                .env("FACTORSEAL_DIAGNOSTICS_DIR", directory.path())
                .output()
                .unwrap();
            if mode == "panic" {
                assert!(!output.status.success());
                let reports = desktop_incidents(directory.path()).unwrap();
                let crash = reports
                    .iter()
                    .find(|incident| incident.report.state == "panic")
                    .unwrap();
                let body = envelope(crash, "integration-test").unwrap();
                assert!(!String::from_utf8_lossy(&body).contains("payload must remain local"));
            } else {
                assert!(
                    output.status.success(),
                    "{mode} child failed: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
        }
        let state =
            DeliveryState::load(&directory.path().join("sentry-delivery.json"), &dsn).unwrap();
        assert_eq!(state.sent.len(), 2);
    }

    fn incident(recorded_ms: u64) -> Incident {
        Incident {
            id: "a31fb23a-e54f-4dea-928f-034953eaaf4c".to_owned(),
            report: serde_json::from_value(serde_json::json!({
                "schema_version": 1, "component": "desktop", "version": "0.1.0",
                "os": "linux", "architecture": "x86_64", "process_id": 123,
                "started_ms": 1000, "recorded_ms": recorded_ms, "state": "panic",
                "events": [{ "timestamp_ms": 1100, "scope": "desktop_unlock", "operation": "worker_started", "outcome": "error", "elapsed_ms": 12 }],
                "panic_location": "app.rs:42:7",
                "backtrace": "   0: factorseal_desktop::app::open\n             at /home/sentinel-private-build-path/app.rs:42:7\n",
                "panic_payload": "sentinel-secret-panic",
                "issue_description": "sentinel-unrelated-issue-description",
                "environment": {"PASSWORD": "sentinel-secret-env"},
                "argv": ["sentinel-secret-argument"]
            })).unwrap(),
        }
    }

    #[test]
    fn release_defaults_and_explicit_overrides_preserve_local_only_builds() {
        assert!(embedded_dsn(None, true).is_none());
        let release = embedded_dsn(None, false).unwrap();
        let config = Configuration::parse(Some(release), None).unwrap().unwrap();
        assert_eq!(config.dsn.project_id().to_string(), "4512036870684672");
        assert_eq!(embedded_dsn(Some(""), false), Some(""));
        assert_eq!(embedded_dsn(Some(""), true), Some(""));
        for debug in [true, false] {
            assert_eq!(
                embedded_dsn(Some("https://custom@example.com/42"), debug),
                Some("https://custom@example.com/42")
            );
        }
    }

    #[test]
    fn configuration_is_optional_and_validates_without_echoing_the_dsn() {
        assert!(Configuration::parse(None, None).unwrap().is_none());
        assert!(Configuration::parse(Some(""), None).unwrap().is_none());
        assert!(
            Configuration::parse(Some("https://public@example.com/42"), Some("production"))
                .unwrap()
                .is_some()
        );
        for dsn in [
            "invalid-sentinel",
            "http://public@example.com/42",
            "https://public:sentinel@example.com/42",
        ] {
            let error = Configuration::parse(Some(dsn), None).err().unwrap();
            assert!(!error.to_string().contains("sentinel"));
        }
        assert!(
            Configuration::parse(Some("https://public@example.com/42"), Some("invalid label"))
                .is_err()
        );
    }

    #[test]
    fn envelope_has_stable_identity_original_stack_and_sanitized_logs() {
        let incident = incident(1200);
        let bytes = envelope(&incident, "test").unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("sentinel-"), "{text}");
        assert!(!text.contains("server_name"));
        assert!(!text.contains("request"));
        let envelope = sentry::Envelope::from_slice(&bytes).unwrap();
        let event = envelope.event().unwrap();
        assert_eq!(event.event_id.to_string(), incident.id);
        assert_eq!(event.timestamp, UNIX_EPOCH + Duration::from_millis(1200));
        assert_eq!(event.release.as_deref(), Some("factorseal@0.1.0"));
        let frame = &event.exception.values[0]
            .stacktrace
            .as_ref()
            .unwrap()
            .frames[0];
        assert_eq!(
            frame.function.as_deref(),
            Some("factorseal_desktop::app::open")
        );
        assert_eq!(frame.filename.as_deref(), Some("app.rs"));
        assert_eq!(frame.lineno, Some(42));
        assert_eq!(
            event.breadcrumbs.values[0].message.as_deref(),
            Some("worker_started")
        );
        assert_eq!(event.breadcrumbs.values[0].data["elapsed_ms"], 12);
    }

    #[test]
    fn only_acknowledged_reports_are_marked_sent_and_retries_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delivery.json");
        let config = config();
        let mut state = DeliveryState::load(&path, &config.dsn.to_string()).unwrap();
        let mut manual = incident(state.first_enabled_ms);
        "user_report".clone_into(&mut manual.report.state);
        manual.report.issue_description =
            Some("Search is empty after unlocking.\nExpected saved entries.".to_owned());
        let reports = [manual];
        let mut first_body = Vec::new();
        deliver(
            &reports,
            &config,
            &mut state,
            &path,
            |body| {
                assert!(
                    String::from_utf8_lossy(&body).contains("Search is empty after unlocking.")
                );
                first_body = body;
                Err(Duration::from_mins(2))
            },
            |_| true,
        )
        .unwrap();
        assert!(state.sent.is_empty());
        let mut restarted = DeliveryState::load(&path, &config.dsn.to_string()).unwrap();
        assert!(restarted.next_attempt_ms > now_ms());
        assert_eq!(restarted.first_enabled_ms, state.first_enabled_ms);
        deliver(
            &reports,
            &config,
            &mut restarted,
            &path,
            |body| {
                assert_eq!(body, first_body);
                Ok(Duration::ZERO)
            },
            |_| true,
        )
        .unwrap();
        let mut acknowledged = DeliveryState::load(&path, &config.dsn.to_string()).unwrap();
        assert_eq!(acknowledged.sent, vec![reports[0].id.clone()]);
        deliver(
            &reports,
            &config,
            &mut acknowledged,
            &path,
            |_| panic!("already delivered"),
            |_| true,
        )
        .unwrap();
        factorseal::security::read_private_file(&path, 16 * 1024).unwrap();
    }

    #[test]
    fn disabled_delivery_and_local_only_history_do_not_send() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delivery.json");
        let config = config();
        let mut state = DeliveryState::load(&path, &config.dsn.to_string()).unwrap();
        let old = [incident(state.first_enabled_ms - 1)];
        deliver(
            &old,
            &config,
            &mut state,
            &path,
            |_| panic!("old history"),
            |_| true,
        )
        .unwrap();
        let current = [incident(state.first_enabled_ms)];
        deliver(
            &current,
            &config,
            &mut state,
            &path,
            |_| panic!("disabled"),
            |_| false,
        )
        .unwrap();
        assert!(state.sent.is_empty());
    }

    fn mock_server(response: impl Into<String>) -> (Dsn, std::thread::JoinHandle<Vec<u8>>) {
        let response = response.into();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let dsn = format!("http://public@{}/42", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("mock accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            let header_end = loop {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
                if let Some(index) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let length: usize = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .unwrap()
                .1
                .trim()
                .parse()
                .unwrap();
            while request.len() < header_end + length {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0);
                request.extend_from_slice(&chunk[..read]);
            }
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (dsn, thread)
    }

    #[test]
    fn http_posts_sentry_envelopes_and_obeys_quotas_and_redirect_rejections() {
        for (response, accepted, delay) in [
            (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                true,
                0,
            ),
            (
                "HTTP/1.1 200 OK\r\nX-Sentry-Rate-Limits: 120:error:organization\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                true,
                120,
            ),
            (
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 180\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
                180,
            ),
            (
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                false,
                60,
            ),
        ] {
            let (dsn, server) = mock_server(response);
            let result = HttpTransport::new(&dsn)
                .unwrap()
                .send(envelope(&incident(1200), "test").unwrap());
            assert_eq!(result.is_ok(), accepted);
            assert_eq!(
                result.unwrap_or_else(|delay| delay),
                Duration::from_secs(delay)
            );
            let request = server.join().unwrap();
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /api/42/envelope/ HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("x-sentry-auth: sentry")
            );
            assert!(request.contains("application/x-sentry-envelope"));
            assert!(!request.contains("sentinel-"));
        }
    }
    #[test]
    fn redirects_never_receive_the_envelope_or_authentication_header() {
        let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let (dsn, server) = mock_server(format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{}/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            destination.local_addr().unwrap()
        ));
        assert!(
            HttpTransport::new(&dsn)
                .unwrap()
                .send(envelope(&incident(1200), "test").unwrap())
                .is_err()
        );
        server.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn manual_report_sends_with_automatic_reporting_off_and_leaves_crashes_pending() {
        let directory = tempfile::tempdir().unwrap();
        let (dsn, server) =
            mock_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let target = dsn.to_string();
        let state_path = directory.path().join("sentry-delivery.json");
        let state = DeliveryState::load(&state_path, &target).unwrap();
        let crash = incident(state.first_enabled_ms);
        let mut manual = incident(state.first_enabled_ms);
        manual.id = "22e491be-6f38-44f6-aa72-b099faf4ad55".to_owned();
        "user_report".clone_into(&mut manual.report.state);
        manual.report.issue_description =
            Some("Search shows no results.\nExpected café credentials.".to_owned());
        manual.report.backtrace = None;
        manual.report.panic_location = None;
        for report in [&crash, &manual] {
            factorseal::security::write_private_file(
                &directory.path().join(format!("crash-{}.json", report.id)),
                &serde_json::to_vec(&report.report).unwrap(),
            )
            .unwrap();
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stopped);
        let path = directory.path().to_owned();
        let worker = std::thread::spawn(move || {
            run(
                &path,
                &Configuration {
                    dsn,
                    environment: "test".to_owned(),
                },
                state,
                &stop_worker,
                &AtomicBool::new(false),
            )
            .unwrap();
        });
        let request = server.join().unwrap();
        stopped.store(true, Ordering::Release);
        worker.thread().unpark();
        worker.join().unwrap();
        let body_start = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let received = sentry::Envelope::from_slice(&request[body_start..]).unwrap();
        let event = received.event().unwrap();
        assert_eq!(event.message.as_deref(), Some("User-reported issue"));
        assert!(event.exception.values.is_empty());
        assert_eq!(event.tags["report_kind"], "user_report");
        assert_eq!(
            event.extra["issue_description"],
            "Search shows no results.\nExpected café credentials."
        );
        assert_eq!(
            event.breadcrumbs.values[0].message.as_deref(),
            Some("worker_started")
        );
        assert_eq!(
            DeliveryState::load(&state_path, &target).unwrap().sent,
            vec![manual.id]
        );
    }

    #[test]
    fn background_uploader_delivers_a_saved_incident_and_persists_the_receipt() {
        let directory = tempfile::tempdir().unwrap();
        let (dsn, server) =
            mock_server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let target = dsn.to_string();
        let state_path = directory.path().join("sentry-delivery.json");
        let state = DeliveryState::load(&state_path, &target).unwrap();
        let incident = incident(state.first_enabled_ms);
        factorseal::security::write_private_file(
            &directory.path().join(format!("crash-{}.json", incident.id)),
            &serde_json::to_vec(&incident.report).unwrap(),
        )
        .unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop_worker = Arc::clone(&stopped);
        let path = directory.path().to_owned();
        let worker = std::thread::spawn(move || {
            run(
                &path,
                &Configuration {
                    dsn,
                    environment: "test".to_owned(),
                },
                state,
                &stop_worker,
                &AtomicBool::new(true),
            )
            .unwrap();
        });
        let request = server.join().unwrap();
        stopped.store(true, Ordering::Release);
        worker.thread().unpark();
        worker.join().unwrap();
        assert!(String::from_utf8_lossy(&request).contains("worker_started"));
        assert_eq!(
            DeliveryState::load(&state_path, &target).unwrap().sent,
            vec![incident.id]
        );
    }
}
