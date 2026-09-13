//! Throwaway loopback TCP listener for the mirrored-networking spike. See
//! ../../README.md. Intended to run on the Windows host, but there is
//! nothing platform-specific here — it's plain `std::net`.

use std::io::{Read, Write};
use std::net::TcpListener;

/// Arbitrary private-range port both sides must agree on. Nothing about
/// this specific number matters.
const PORT: u16 = 51027;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", PORT))?;
    println!("listening on 127.0.0.1:{PORT}; waiting for one connection...");

    let (mut stream, peer) = listener.accept()?;
    println!("client connected from {peer}");

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let received = String::from_utf8_lossy(&buf[..n]);
    println!("received: {received}");

    let reply = format!("host-echo: {received}");
    stream.write_all(reply.as_bytes())?;

    Ok(())
}
