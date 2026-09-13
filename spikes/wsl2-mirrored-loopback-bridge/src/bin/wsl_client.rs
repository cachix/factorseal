//! Throwaway loopback TCP client for the mirrored-networking spike. See
//! ../../README.md. Intended to run inside WSL2, but there is nothing
//! platform-specific here — it's plain `std::net`.

use std::io::{Read, Write};
use std::net::TcpStream;

/// Must match `PORT` in `windows_listener.rs`.
const PORT: u16 = 51027;

fn main() -> std::io::Result<()> {
    println!("connecting to 127.0.0.1:{PORT}...");
    let mut stream = TcpStream::connect(("127.0.0.1", PORT))?;

    let message = b"hello from wsl2 over mirrored loopback";
    stream.write_all(message)?;
    println!("sent: {}", String::from_utf8_lossy(message));

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    println!("received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
