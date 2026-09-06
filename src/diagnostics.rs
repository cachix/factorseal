//! Local, bounded diagnostics for product processes. Callers supply only static
//! operation names and outcomes, never errors, secrets, arguments, or metadata.
//! Panic payloads and thread names are deliberately excluded from reports.
//! Manual issue reports additionally contain the description the user submits.

use std::backtrace::Backtrace;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const MAX_EVENTS: usize = 128;
const MAX_REPORTS_PER_KIND: usize = 20;
const MAX_REPORT_BYTES: u64 = 256 * 1024;
pub const MAX_ISSUE_DESCRIPTION_CHARS: usize = 4000;
static REPORTER: OnceLock<Reporter> = OnceLock::new();

struct Reporter {
    directory: PathBuf,
    id: String,
    component: String,
    report: Mutex<Report>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp_ms: u64,
    pub scope: String,
    pub operation: String,
    pub outcome: String,
    pub elapsed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_exit: Option<ChildExit>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChildExit {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u8,
    pub component: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    pub process_id: u32,
    pub started_ms: u64,
    #[serde(default)]
    pub recorded_ms: u64,
    pub state: String,
    pub events: VecDeque<Event>,
    #[serde(default)]
    pub security_events: Vec<crate::security::events::SecurityEvent>,
    pub panic_location: Option<String>,
    pub backtrace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_description: Option<String>,
}

impl Report {
    fn new(component: &str) -> Self {
        Self {
            schema_version: 1,
            component: component.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            process_id: std::process::id(),
            started_ms: timestamp_ms(),
            recorded_ms: timestamp_ms(),
            state: "running".to_owned(),
            events: VecDeque::new(),
            security_events: Vec::new(),
            panic_location: None,
            backtrace: None,
            issue_description: None,
        }
    }

    fn push(&mut self, event: Event) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

fn timestamp_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Platform-local diagnostics directory, independent of the vault directory.
/// The override is useful for support, tests, and isolated installations.
pub fn directory() -> io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("FACTORSEAL_DIAGNOSTICS_DIR") {
        if path.is_empty() {
            return Err(io::Error::other("diagnostics directory is empty"));
        }
        return Ok(PathBuf::from(path));
    }
    directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .map(|dirs| dirs.data_local_dir().join("diagnostics"))
        .ok_or_else(|| io::Error::other("could not determine the diagnostics directory"))
}

/// Install once, before accepting secrets. Failure leaves normal application
/// behavior intact; entry points should display the initialization error.
pub fn initialize(component: &'static str) -> io::Result<()> {
    let reporter = Reporter::new(directory()?, component)?;
    REPORTER
        .set(reporter)
        .map_err(|_| io::Error::other("diagnostics already initialized"))?;
    // Replacing the default hook prevents arbitrary panic payloads from leaking
    // into stderr/journald. Never wait for the event mutex from a panic hook.
    std::panic::set_hook(Box::new(|info| {
        if let Some(reporter) = REPORTER.get() {
            let location = info.location().map(|location| {
                let file = Path::new(location.file())
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                format!("{file}:{}:{}", location.line(), location.column())
            });
            if reporter.panic_report(location).is_err() {
                eprintln!("factorseal: could not save panic report");
            }
        }
        eprintln!("factorseal: Rust panic; see local diagnostics (panic payload omitted)");
    }));
    event("process", "start", "ok");
    Ok(())
}

/// Persist a lifecycle event with the most recent in-memory operation logs.
pub fn event(scope: &'static str, operation: &'static str, outcome: &'static str) {
    record(scope, operation, outcome, None, true);
}

/// Keep an operation timing in the bounded log without disk I/O on hot paths.
pub fn timing(
    scope: &'static str,
    operation: &'static str,
    outcome: &'static str,
    elapsed: std::time::Duration,
) {
    record(
        scope,
        operation,
        outcome,
        Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
        false,
    );
}

fn record(scope: &str, operation: &str, outcome: &str, elapsed_ms: Option<u64>, persist: bool) {
    let Some(reporter) = REPORTER.get() else {
        return;
    };
    let Ok(mut report) = reporter.report.lock() else {
        return;
    };
    report.push(Event {
        timestamp_ms: timestamp_ms(),
        scope: scope.to_owned(),
        operation: operation.to_owned(),
        outcome: outcome.to_owned(),
        elapsed_ms,
        child_exit: None,
    });
    if persist {
        let _ = reporter.save("session", &report);
    }
}

/// Record a supervised child's exit, including its PID for correlating reports.
pub fn child_exit(process_id: u32, status: std::process::ExitStatus) {
    let Some(reporter) = REPORTER.get() else {
        return;
    };
    let Ok(mut report) = reporter.report.lock() else {
        return;
    };
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    report.push(Event {
        timestamp_ms: timestamp_ms(),
        scope: "worker".to_owned(),
        operation: "exit".to_owned(),
        outcome: if status.success() { "ok" } else { "error" }.to_owned(),
        elapsed_ms: None,
        child_exit: Some(ChildExit {
            process_id,
            exit_code: status.code(),
            signal,
        }),
    });
    let _ = reporter.save("session", &report);
    if !status.success() {
        let mut incident = report.clone();
        "child_failed".clone_into(&mut incident.state);
        let _ = reporter.save("crash", &incident);
    }
}

/// Record a normal return or a handled process failure before `process::exit`.
pub fn finish(success: bool) {
    let Some(reporter) = REPORTER.get() else {
        return;
    };
    let Ok(mut report) = reporter.report.lock() else {
        return;
    };
    // A caught/background panic remains visible even if main later returns.
    if report.state != "panic" {
        if success { "finished" } else { "failed" }.clone_into(&mut report.state);
    }
    let _ = reporter.save("session", &report);
}

/// Save the current Desktop log for an explicitly requested issue submission.
/// This snapshots the log without changing the running session's state.
pub fn report_issue(description: &str) -> io::Result<String> {
    REPORTER
        .get()
        .ok_or_else(|| io::Error::other("diagnostics unavailable"))?
        .report_issue(description)
}

/// Shared validation for the issue form and its durable submission boundary.
pub fn validate_issue_description(description: &str) -> Result<(), &'static str> {
    if description.trim().is_empty() {
        return Err("Please describe what went wrong before sending.");
    }
    if description.chars().count() > MAX_ISSUE_DESCRIPTION_CHARS {
        return Err("Please keep the description to 4,000 characters or fewer.");
    }
    Ok(())
}

impl Reporter {
    fn new(directory: PathBuf, component: &str) -> io::Result<Self> {
        fs::create_dir_all(&directory)?;
        if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(io::Error::other(
                "diagnostics path must be a directory, not a link",
            ));
        }
        // Every report and export uses the shared owner-only file writer on
        // Unix and Windows; directory permissions are not relied upon.
        let reporter = Self {
            directory,
            id: format!("{:020}-{}", timestamp_ms(), uuid::Uuid::new_v4()),
            component: component.to_owned(),
            report: Mutex::new(Report::new(component)),
        };
        reporter.save("session", &Report::new(component))?;
        Ok(reporter)
    }

    fn report_issue(&self, description: &str) -> io::Result<String> {
        validate_issue_description(description).map_err(io::Error::other)?;
        if self.component != "desktop" {
            return Err(io::Error::other("issue submission requires Desktop"));
        }
        let mut snapshot = self
            .report
            .lock()
            .map_err(|_| io::Error::other("diagnostics unavailable"))?
            .clone();
        "user_report".clone_into(&mut snapshot.state);
        snapshot.panic_location = None;
        snapshot.backtrace = None;
        snapshot.issue_description = Some(description.trim().to_owned());
        self.save("crash", &snapshot)
    }

    fn save(&self, kind: &str, report: &Report) -> io::Result<String> {
        let mut snapshot = report.clone();
        snapshot.security_events = crate::security::events::snapshot();
        snapshot.recorded_ms = timestamp_ms();
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        if bytes.len() as u64 > MAX_REPORT_BYTES {
            return Err(io::Error::other("diagnostic report exceeds size limit"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let name = if kind == "session" {
            format!("session-{}.json", self.id)
        } else {
            // Preserve each incident, including multiple worker failures or
            // caught panics within the same long-lived Desktop session.
            format!("crash-{}-{id}.json", self.id)
        };
        crate::security::write_private_file(&self.directory.join(name), &bytes)?;
        prune(&self.directory, kind)?;
        Ok(id)
    }

    fn panic_report(&self, location: Option<String>) -> io::Result<()> {
        let mut report = if let Ok(mut report) = self.report.try_lock() {
            "panic".clone_into(&mut report.state);
            report.clone()
        } else {
            // A panic during logging must still produce a report, without
            // blocking on a poisoned or already-held lock.
            Report::new(&self.component)
        };
        "panic".clone_into(&mut report.state);
        report.panic_location = location;
        let mut backtrace = Backtrace::force_capture().to_string();
        let mut end = backtrace.len().min(64 * 1024);
        while !backtrace.is_char_boundary(end) {
            end -= 1;
        }
        backtrace.truncate(end);
        report.backtrace = Some(backtrace);
        self.save("crash", &report).map(|_| ())
    }
}

fn report_paths(directory: &Path, kind: &str) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&format!("{kind}-"))
            && name.ends_with(".json")
            && entry.file_type()?.is_file()
        {
            match entry.metadata() {
                Ok(metadata) => paths.push((metadata.modified()?, entry.path())),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    paths.sort();
    Ok(paths.into_iter().map(|(_, path)| path).collect())
}

fn prune(directory: &Path, kind: &str) -> io::Result<()> {
    let paths = report_paths(directory, kind)?;
    let excess = paths.len().saturating_sub(MAX_REPORTS_PER_KIND);
    for path in paths.into_iter().take(excess) {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// A persisted incident with a stable identity for retrying remote delivery.
pub struct Incident {
    pub id: String,
    pub report: Report,
}

/// Read bounded Desktop/worker incidents only. CLI and agent reports are never
/// candidates for Desktop submission. Ignore malformed files individually.
pub fn desktop_incidents(directory: &Path) -> io::Result<Vec<Incident>> {
    let mut incidents = Vec::new();
    for path in report_paths(directory, "crash")?
        .into_iter()
        .rev()
        .take(MAX_REPORTS_PER_KIND)
    {
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(id) = name
            .get(name.len().saturating_sub(36)..)
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
        else {
            continue;
        };
        let Ok(bytes) = crate::security::read_private_file(&path, MAX_REPORT_BYTES) else {
            continue;
        };
        let Ok(report) = serde_json::from_slice::<Report>(&bytes) else {
            continue;
        };
        if report.schema_version == 1
            && matches!(report.component.as_str(), "desktop" | "desktop-worker")
            && (matches!(report.state.as_str(), "panic" | "child_failed")
                || (report.component == "desktop" && report.state == "user_report"))
        {
            incidents.push(Incident {
                id: id.to_string(),
                report,
            });
        }
    }
    Ok(incidents)
}

/// Export recent reports as a single private JSON file for review and sharing.
/// Nothing is uploaded. Missing files from concurrent retention are skipped;
/// malformed or non-private files fail the export instead of being included.
pub fn export(destination: &Path) -> io::Result<()> {
    event("diagnostics", "export", "start");
    export_from(&directory()?, destination)
}

fn export_from(directory: &Path, destination: &Path) -> io::Result<()> {
    let mut reports = Vec::<Report>::new();
    for kind in ["session", "crash"] {
        for path in report_paths(directory, kind)?
            .into_iter()
            .rev()
            .take(MAX_REPORTS_PER_KIND)
        {
            let bytes = match crate::security::read_private_file(&path, MAX_REPORT_BYTES) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            reports.push(serde_json::from_slice(&bytes)?);
        }
    }
    crate::security::write_private_file(
        destination,
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "exported_ms": timestamp_ms(),
            "reports": reports,
        }))?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_and_retention_are_bounded_and_exports_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let reporter = Reporter::new(dir.path().to_owned(), "test").unwrap();
        let mut report = Report::new("test");
        for index in 0..MAX_EVENTS + 10 {
            report.push(Event {
                timestamp_ms: index as u64,
                scope: "test".into(),
                operation: "start".into(),
                outcome: "ok".into(),
                elapsed_ms: None,
                child_exit: None,
            });
        }
        assert_eq!(report.events.len(), MAX_EVENTS);
        assert_eq!(report.events.front().unwrap().timestamp_ms, 10);
        reporter.save("session", &report).unwrap();
        for index in 0..MAX_REPORTS_PER_KIND + 5 {
            crate::security::write_private_file(
                &dir.path().join(format!("crash-{index:020}.json")),
                &serde_json::to_vec(&report).unwrap(),
            )
            .unwrap();
        }
        prune(dir.path(), "crash").unwrap();
        assert_eq!(
            report_paths(dir.path(), "crash").unwrap().len(),
            MAX_REPORTS_PER_KIND
        );
        let output = dir.path().join("export.json");
        export_from(dir.path(), &output).unwrap();
        let bytes = crate::security::read_private_file(&output, 10 * 1024 * 1024).unwrap();
        let bundle: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            bundle["reports"].as_array().unwrap().len(),
            MAX_REPORTS_PER_KIND + 1
        );
    }

    #[test]
    fn manual_issue_snapshots_desktop_logs_without_changing_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let reporter = Reporter::new(dir.path().to_owned(), "desktop").unwrap();
        reporter.report.lock().unwrap().push(Event {
            timestamp_ms: timestamp_ms(),
            scope: "desktop_unlock".into(),
            operation: "worker_started".into(),
            outcome: "ok".into(),
            elapsed_ms: Some(12),
            child_exit: None,
        });
        assert!(reporter.report_issue(" \n\t ").is_err());
        assert!(
            reporter
                .report_issue(&"x".repeat(MAX_ISSUE_DESCRIPTION_CHARS + 1))
                .is_err()
        );
        assert!(desktop_incidents(dir.path()).unwrap().is_empty());
        let id = reporter
            .report_issue("  Search stays empty after unlocking.\nExpected my saved entries.  ")
            .unwrap();
        let reports = desktop_incidents(dir.path()).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].id, id);
        assert_eq!(reports[0].report.state, "user_report");
        assert_eq!(reports[0].report.events[0].operation, "worker_started");
        assert!(reports[0].report.panic_location.is_none());
        assert!(reports[0].report.backtrace.is_none());
        assert_eq!(
            reports[0].report.issue_description.as_deref(),
            Some("Search stays empty after unlocking.\nExpected my saved entries.")
        );
        assert_eq!(reporter.report.lock().unwrap().state, "running");
        assert!(reporter.report.lock().unwrap().issue_description.is_none());
        assert!(validate_issue_description(&"é".repeat(MAX_ISSUE_DESCRIPTION_CHARS)).is_ok());
        assert!(
            Reporter::new(dir.path().to_owned(), "cli")
                .unwrap()
                .report_issue("An issue")
                .is_err()
        );
    }

    #[test]
    fn panic_reporting_does_not_deadlock_when_logging_lock_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let reporter = Reporter::new(dir.path().to_owned(), "test").unwrap();
        let _guard = reporter.report.lock().unwrap();
        reporter.panic_report(Some("test.rs:1:1".into())).unwrap();
        let bytes = fs::read(&report_paths(dir.path(), "crash").unwrap()[0]).unwrap();
        let report: Report = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report.state, "panic");
        assert!(report.backtrace.is_some());
    }

    #[test]
    fn panic_hook_captures_thread_panics_without_payload_or_arguments() {
        const CHILD: &str = "FACTORSEAL_TEST_CRASH_CHILD";
        const TEST: &str =
            "diagnostics::tests::panic_hook_captures_thread_panics_without_payload_or_arguments";
        if std::env::var_os(CHILD).is_some_and(|value| value == "exit") {
            std::process::exit(23);
        }
        if std::env::var_os(CHILD).is_some() {
            initialize("test-child").unwrap();
            event("worker", "start", "ok");
            let mut worker = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST])
                .env(CHILD, "exit")
                .spawn()
                .unwrap();
            let status = worker.wait().unwrap();
            child_exit(worker.id(), status);
            let _ = std::thread::spawn(|| panic!("sentinel-secret-panic-payload")).join();
            finish(true);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                TEST,
                "--nocapture",
                "--skip",
                "sentinel-secret-argument",
            ])
            .env(CHILD, "1")
            .env("FACTORSEAL_DIAGNOSTICS_DIR", dir.path())
            .env("SECRET_SENTINEL", "sentinel-secret-environment")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("sentinel-secret"));
        let paths = report_paths(dir.path(), "crash").unwrap();
        assert_eq!(paths.len(), 2);
        let reports: Vec<Report> = paths
            .iter()
            .map(|path| {
                let bytes = fs::read(path).unwrap();
                assert!(!String::from_utf8_lossy(&bytes).contains("sentinel-secret"));
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect();
        assert!(reports.iter().any(|report| report.state == "child_failed"));
        let report = reports
            .into_iter()
            .find(|report| report.state == "panic")
            .unwrap();
        assert_eq!(report.component, "test-child");
        assert_eq!(
            report
                .events
                .back()
                .unwrap()
                .child_exit
                .as_ref()
                .unwrap()
                .exit_code,
            Some(23)
        );
        assert!(report.panic_location.unwrap().contains("diagnostics.rs:"));
    }

    #[test]
    fn malformed_reports_do_not_replace_an_existing_export() {
        let dir = tempfile::tempdir().unwrap();
        crate::security::write_private_file(&dir.path().join("crash-invalid.json"), b"invalid")
            .unwrap();
        let destination = dir.path().join("export.json");
        fs::write(&destination, b"previous export").unwrap();
        assert!(export_from(dir.path(), &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"previous export");
    }

    #[test]
    fn desktop_submission_reads_only_private_desktop_incidents() {
        let directory = tempfile::tempdir().unwrap();
        for component in ["desktop", "desktop-worker", "cli", "agent"] {
            let reporter = Reporter::new(directory.path().to_owned(), component).unwrap();
            let mut report = Report::new(component);
            "panic".clone_into(&mut report.state);
            reporter.save("crash", &report).unwrap();
        }
        let incidents = desktop_incidents(directory.path()).unwrap();
        assert_eq!(incidents.len(), 2);
        assert!(incidents.iter().all(|incident| {
            uuid::Uuid::parse_str(&incident.id).is_ok()
                && incident.report.recorded_ms > 0
                && incident.report.component.starts_with("desktop")
        }));
        let invalid = directory
            .path()
            .join(format!("crash-{}.json", uuid::Uuid::new_v4()));
        crate::security::write_private_file(&invalid, b"malformed report").unwrap();
        assert_eq!(desktop_incidents(directory.path()).unwrap().len(), 2);
    }
}
