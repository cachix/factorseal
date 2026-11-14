//! Throwaway loopback TCP client for the mirrored-networking spike. See
//! ../../README.md and ../../TOKEN-DESIGN.md. Intended to run inside WSL2,
//! but there is nothing platform-specific here — it's plain `std::net` plus
//! a file read.

use std::io::{Read, Write};
use std::net::TcpStream;

/// Must match `PORT` in `windows_listener.rs`.
const PORT: u16 = 51027;

const TOKEN_BYTES: usize = 32;

fn read_token(path: &str) -> std::io::Result<[u8; TOKEN_BYTES]> {
    let hex_token = std::fs::read_to_string(path)?;
    let bytes = hex::decode(hex_token.trim())
        .map_err(|_| std::io::Error::other("token file does not contain valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| std::io::Error::other("token file is not 32 bytes"))
}

fn main() -> std::io::Result<()> {
    let token_path = std::env::args().nth(1).ok_or_else(|| {
        std::io::Error::other(
            "usage: wsl-client <path to token file, e.g. /mnt/c/Users/<you>/AppData/Local/Factorseal-spike/wsl-bridge-token>",
        )
    })?;
    let token = read_token(&token_path)?;
    println!("read token from {token_path}");

    println!("connecting to 127.0.0.1:{PORT}...");
    let mut stream = TcpStream::connect(("127.0.0.1", PORT))?;

    stream.write_all(&token)?;

    let message = b"hello from wsl2 over mirrored loopback";
    stream.write_all(message)?;
    println!("sent: {}", String::from_utf8_lossy(message));

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    println!("received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
