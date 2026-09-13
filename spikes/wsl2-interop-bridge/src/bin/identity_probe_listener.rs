//! Throwaway peer-identity probe. See ../../README.md.
//!
//! Binds a loopback TCP listener and, on each connection, resolves the
//! connecting peer's owning PID via `GetExtendedTcpTable`, then that
//! process's SID and on-disk executable (path + SHA-256) -- the same
//! category of Win32 introspection `src/vault/windows.rs` uses for the
//! real named-pipe transport (PID -> process handle -> token -> SID;
//! PID -> process handle -> image path -> file hash). Run the matching
//! `identity-probe-client` once natively and once via WSL2 interop, and
//! compare the two reports.
#![cfg_attr(windows, allow(unsafe_code))]

const PORT: u16 = 51099;

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    /// `GetExtendedTcpTable` stores each row's port in the low 16 bits of a
    /// `u32`, in network byte order despite the field being declared as a
    /// plain DWORD -- a well-documented quirk of this API, not something
    /// compiling or cross-compiling this file can catch. If the resolved
    /// PID below looks wrong, this is the first place to suspect.
    fn table_port(raw: u32) -> u16 {
        u16::from_be((raw & 0xFFFF) as u16)
    }

    fn table_addr(raw: u32) -> Ipv4Addr {
        Ipv4Addr::from(raw.to_ne_bytes())
    }

    /// Two-call pattern: ask for the required size, then fetch into a
    /// buffer of that size. `MIB_TCPTABLE_OWNER_PID::table` is a
    /// fixed one-element array standing in for a C flexible array member;
    /// the real rows are read out of the raw buffer by hand below.
    fn fetch_tcp_table() -> std::io::Result<Vec<u8>> {
        let mut size: u32 = 0;
        // SAFETY: passing `None` for the table pointer with `size` as the
        // buffer-length in/out parameter is the documented way to query
        // the required buffer size; no memory is written.
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        let mut buffer = vec![0u8; size as usize];
        // SAFETY: `buffer` is sized by the call above and outlives this
        // call; `GetExtendedTcpTable` writes at most `size` bytes into it.
        let status = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
                false,
                AF_INET.0.into(),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(buffer)
    }

    /// Finds the PID owning the local TCP endpoint matching `local_addr`
    /// (the accepted connection's peer address -- from this side that's
    /// the *local* address of the row we're looking for, the client's own
    /// socket). Prints every decoded row along the way as a fallback: if
    /// the byte-order handling above is subtly wrong, the printed table
    /// can still be compared by eye against `netstat -ano`.
    fn owning_pid(local_addr: SocketAddr) -> std::io::Result<Option<u32>> {
        let buffer = fetch_tcp_table()?;
        // SAFETY: `buffer` was sized and filled by `fetch_tcp_table` to
        // hold a valid `MIB_TCPTABLE_OWNER_PID` header immediately
        // followed by `dwNumEntries` `MIB_TCPROW_OWNER_PID` rows in
        // place, per the documented layout of this API's output buffer.
        unsafe {
            let header = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            let count = (*header).dwNumEntries;
            let rows = buffer
                .as_ptr()
                .add(std::mem::size_of::<u32>())
                .cast::<MIB_TCPROW_OWNER_PID>();
            let mut found = None;
            for i in 0..i64::from(count) {
                let row = *rows.offset(i as isize);
                let addr = table_addr(row.dwLocalAddr);
                let port = table_port(row.dwLocalPort);
                println!(
                    "  tcp row: {addr}:{port} (remote port {}) pid {}",
                    table_port(row.dwRemotePort),
                    row.dwOwningPid
                );
                if SocketAddr::from((addr, port)) == local_addr {
                    found = Some(row.dwOwningPid);
                }
            }
            Ok(found)
        }
    }

    fn hash_process_executable(pid: u32) -> std::io::Result<(String, String, [u8; 32])> {
        use sha2::{Digest, Sha256};

        // SAFETY: `pid` came from the OS's own TCP table; opening it with
        // limited query rights fails safely if it no longer exists.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let mut path_buf = vec![0u16; 32768];
        let mut path_len = path_buf.len() as u32;
        // SAFETY: `path_buf` is sized above and `path_len` communicates
        // that size in; the call writes at most that many UTF-16 units.
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(path_buf.as_mut_ptr()),
                &mut path_len,
            )
        }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        let path = String::from_utf16_lossy(&path_buf[..path_len as usize]);

        let mut token = HANDLE::default();
        // SAFETY: `process` is a valid, open handle from `OpenProcess`
        // above; `token` is initialized on success.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

        let mut needed: u32 = 0;
        // SAFETY: passing `None` with `needed` as an out-parameter is the
        // documented way to query the required buffer size; expected to
        // return an error code for "buffer too small", which is ignored.
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        }
        let mut token_info = vec![0u8; needed as usize];
        // SAFETY: `token_info` is sized by the call above.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(token_info.as_mut_ptr().cast()),
                needed,
                &mut needed,
            )
        }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        // SAFETY: `token_info` holds a valid `TOKEN_USER` per the
        // successful call above.
        let sid = unsafe { (*token_info.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        let mut sid_string = PWSTR::null();
        // SAFETY: `sid` was read from a live token above; `sid_string` is
        // allocated by the call on success and freed via `LocalFree` below.
        unsafe { ConvertSidToStringSidW(sid, &mut sid_string) }
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        // SAFETY: `sid_string` is a valid, null-terminated wide string
        // from the call above, not yet freed.
        let sid_text = unsafe { sid_string.to_string() }
            .map_err(|_| std::io::Error::other("SID string was not valid UTF-16"))?;
        // SAFETY: frees the buffer `ConvertSidToStringSidW` allocated;
        // `sid_string` is not used again afterward.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid_string.as_ptr().cast())));
        }

        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher)?;
        let digest: [u8; 32] = hasher.finalize().into();

        // SAFETY: both handles were opened above and are not used again.
        unsafe {
            let _ = CloseHandle(token);
            let _ = CloseHandle(process);
        }

        Ok((path, sid_text, digest))
    }

    let listener = TcpListener::bind(("127.0.0.1", PORT))?;
    println!("listening on 127.0.0.1:{PORT}; waiting for one connection...");

    let (mut stream, peer) = listener.accept()?;
    println!("client connected from {peer}");
    println!(
        "decoded TCP table rows (compare against `netstat -ano` if the match below looks wrong):"
    );

    let pid = owning_pid(peer)?
        .ok_or_else(|| std::io::Error::other("no TCP table row matched the connecting peer"))?;
    println!("resolved owning PID: {pid}");

    let (path, sid, digest) = hash_process_executable(pid)?;
    println!("executable path: {path}");
    println!("SID: {sid}");
    println!("SHA-256: {}", hex::encode(digest));

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    println!("received: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("identity-probe-listener only runs on Windows; see ../../README.md");
    std::process::exit(1);
}
