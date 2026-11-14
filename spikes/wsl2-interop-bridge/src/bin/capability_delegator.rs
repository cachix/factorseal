//! Throwaway launch-time capability delegator. See ../../README.md.
//!
//! Spawns `wsl.exe` as an ordinary child process with redirected stdio and
//! hands the launched process a random capability over that redirected
//! stdin, then reads back what it echoes on stdout. Validates the
//! achievable version of "hand the WSL2 process something at launch time
//! with no separate discovery/auth step" -- see the README for why this is
//! stdio redirection through `wsl.exe`, not literal file-descriptor
//! inheritance across the VM boundary, which isn't possible.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let usage =
        "usage: capability-delegator <distro> <path to capability-receiver inside the distro>";
    let distro = args.next().ok_or_else(|| std::io::Error::other(usage))?;
    let receiver_path = args.next().ok_or_else(|| std::io::Error::other(usage))?;

    let mut capability = [0u8; 32];
    getrandom::fill(&mut capability).map_err(|e| std::io::Error::other(e.to_string()))?;
    let capability_hex = hex::encode(capability);
    println!("minted capability: {capability_hex}");

    let mut child = Command::new("wsl.exe")
        .args(["-d", &distro, "--", &receiver_path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        stdin.write_all(capability_hex.as_bytes())?;
        // Dropping `stdin` here closes the pipe, so the receiver's read
        // reaches end-of-file instead of blocking for more input.
    }

    let mut response = String::new();
    child
        .stdout
        .take()
        .expect("stdout was piped")
        .read_to_string(&mut response)?;
    child.wait()?;

    println!("received back: {response}");
    if response.trim() == capability_hex {
        println!("MATCH: the capability round-tripped through wsl.exe's redirected stdio");
    } else {
        println!("MISMATCH: something altered the capability in transit");
    }

    Ok(())
}
