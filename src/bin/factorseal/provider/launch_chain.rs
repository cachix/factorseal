//! Executables that launched the provider, for display in approval prompts.
//!
//! SecretSpec starts the provider, so its parent is `secretspec` and the
//! grandparent is the program that ran `secretspec`. The vault's caller is
//! the provider itself; this chain tells the person approving which program
//! actually asked. It is read from the process table and is not verified: a
//! process ID can be reused after its process exits, and on Windows a process
//! can be created with an arbitrary parent.

/// Parent and grandparent: `secretspec` and whatever ran it.
const DEPTH: usize = 2;
/// Matches the vault's bound on one declared application component.
const MAX_ENTRY_BYTES: usize = 4 * 1024;

/// Nearest first. Stops at the first process that cannot be read.
pub(super) fn launch_chain() -> Vec<String> {
    let mut chain = Vec::new();
    let mut process = std::process::id();
    while chain.len() < DEPTH {
        let Some((parent, executable)) = parent_executable(process) else {
            break;
        };
        let executable = super::without_verbatim_prefix(&executable);
        if executable.is_empty() || executable.len() > MAX_ENTRY_BYTES {
            break;
        }
        chain.push(executable);
        process = parent;
    }
    chain
}

#[cfg(target_os = "linux")]
fn parent_executable(process: u32) -> Option<(u32, String)> {
    let status = std::fs::read_to_string(format!("/proc/{process}/status")).ok()?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|parent| *parent != 0)?;
    // The executable link is unreadable for another user's process; its
    // command name is still visible.
    let executable = std::fs::read_link(format!("/proc/{parent}/exe"))
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .or_else(|| {
            std::fs::read_to_string(format!("/proc/{parent}/comm"))
                .ok()
                .map(|name| name.trim_end().to_owned())
        })?;
    Some((parent, executable))
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn parent_executable(process: u32) -> Option<(u32, String)> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let mut system = System::new();
    let process = Pid::from_u32(process);
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[process]),
        true,
        ProcessRefreshKind::nothing(),
    );
    let parent = system.process(process)?.parent()?;
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[parent]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let parent_process = system.process(parent)?;
    // An elevated parent's image path is unreadable; its name is not.
    let executable = parent_process
        .exe()
        .and_then(|path| path.to_str())
        .map(str::to_owned)
        .or_else(|| parent_process.name().to_str().map(str::to_owned))?;
    Some((parent.as_u32(), executable))
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn parent_executable(_process: u32) -> Option<(u32, String)> {
    None
}
