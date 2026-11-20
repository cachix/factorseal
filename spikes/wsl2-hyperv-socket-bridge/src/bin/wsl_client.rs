//! Throwaway Hyper-V Sockets (AF_VSOCK) client. See ../../README.md.

/// Must match `PORT` in `windows_listener.rs`.
const PORT: u32 = 0x0000_5A17;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::{Read, Write};
    use vsock::{VMADDR_CID_HOST, VsockStream};

    println!("connecting to host over AF_VSOCK, port 0x{PORT:08X}...");
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, PORT)?;

    let message = b"hello from wsl2";
    stream.write_all(message)?;
    println!("sent: {}", String::from_utf8_lossy(message));

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    println!("received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("wsl-client only runs inside a WSL2 (Linux) guest; see ../../README.md");
    std::process::exit(1);
}
