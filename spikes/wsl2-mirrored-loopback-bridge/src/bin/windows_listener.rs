//! Throwaway loopback TCP listener for the mirrored-networking spike. See
//! ../../README.md and ../../TOKEN-DESIGN.md. Intended to run on the
//! Windows host, but there is nothing platform-specific here — it's plain
//! `std::net` plus a file write.

use std::io::{Read, Write};
use std::net::TcpListener;

/// Arbitrary private-range port both sides must agree on. Nothing about
/// this specific number matters.
const PORT: u16 = 51027;

const TOKEN_BYTES: usize = 32;

/// Length-independent, secret-independent-branch comparison. Both sides
/// always exchange exactly `TOKEN_BYTES`, so there's no length side-channel
/// to worry about beyond this.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn write_token(token: &[u8; TOKEN_BYTES]) -> std::io::Result<std::path::PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| std::io::Error::other("LOCALAPPDATA is not set"))?;
    let dir = std::path::Path::new(&local_app_data).join("Factorseal-spike");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("wsl-bridge-token");
    std::fs::write(&path, hex::encode(token))?;
    Ok(path)
}

fn main() -> std::io::Result<()> {
    let mut token = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|e| std::io::Error::other(e.to_string()))?;
    let token_path = write_token(&token)?;
    println!("wrote token to {}", token_path.display());

    let listener = TcpListener::bind(("127.0.0.1", PORT))?;
    println!("listening on 127.0.0.1:{PORT}; waiting for one connection...");

    let (mut stream, peer) = listener.accept()?;
    println!("client connected from {peer}");

    let mut received_token = [0u8; TOKEN_BYTES];
    stream.read_exact(&mut received_token)?;
    if !constant_time_eq(&received_token, &token) {
        println!("token mismatch; closing connection without a response");
        return Ok(());
    }
    println!("token verified");

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = String::from_utf8_lossy(&buf[..n]);
    println!("received: {received}");

    let reply = format!("host-echo: {received}");
    stream.write_all(reply.as_bytes())?;

    Ok(())
}
