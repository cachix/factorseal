//! Throwaway identity-probe client. See ../../README.md.
//! Deliberately trivial: the point is to build one `.exe` and run it from
//! two different places (native PowerShell, then WSL2 interop) so the
//! listener's report can be compared between the two runs.

const PORT: u16 = 51099;

fn main() -> std::io::Result<()> {
    use std::io::Write;
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(("127.0.0.1", PORT))?;
    stream.write_all(b"hello from identity-probe-client")?;
    Ok(())
}
