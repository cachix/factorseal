//! Throwaway Hyper-V Sockets listener. See ../../README.md.
#![cfg_attr(windows, allow(unsafe_code))]

/// Arbitrary private port both sides must agree on. Kept out of the
/// low range WSL2 reserves for its own built-in services.
const PORT: u32 = 0x0000_5A17;

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use windows::Win32::Networking::WinSock::{
        AF_HYPERV, SEND_RECV_FLAGS, SOCK_STREAM, SOCKADDR, SOCKET, WSACleanup, WSADATA,
        WSAGetLastError, WSAStartup, accept, bind, closesocket, listen, recv, send, socket,
    };
    use windows::core::GUID;

    // `windows-rs` 0.61's win32metadata does not carry `hvsocket.h`, so the
    // address family constant is the only piece it exposes; the struct and
    // well-known GUIDs below are hand-transcribed from that header
    // (https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/hvsocket.h),
    // checked against Microsoft Learn's "Make your own integration services"
    // guide.

    /// `SOCKADDR_HV` from `hvsocket.h`. Field order and types (including the
    /// `u16` `Reserved` padding after `Family`) must match exactly, since
    /// this is read as raw bytes by `bind`/`accept`.
    #[repr(C)]
    struct SockaddrHv {
        family: u16,
        reserved: u16,
        vm_id: GUID,
        service_id: GUID,
    }

    /// Accept connections from any child partition (i.e. any WSL2 distro on
    /// this host), per `HV_GUID_CHILDREN` in `hvsocket.h`.
    const HV_GUID_CHILDREN: GUID = GUID::from_values(
        0x90db_8b89,
        0x0d35,
        0x4f79,
        [0x8c, 0xe9, 0x49, 0xea, 0x0a, 0xc8, 0xb7, 0xcd],
    );

    /// Hyper-V Sockets' well-known port-compatibility `ServiceId` template
    /// (`HV_GUID_VSOCK_TEMPLATE` in `hvsocket.h`):
    /// `xxxxxxxx-FACB-11E6-BD58-64006A7986D3`, with the leading group
    /// replaced by the port. This is what Linux's `AF_VSOCK` layer produces
    /// internally for a given port, so both sides agree without either one
    /// hard-coding a GUID literal.
    fn service_id_from_port(port: u32) -> GUID {
        GUID::from_values(
            port,
            0xFACB,
            0x11E6,
            [0xBD, 0x58, 0x64, 0x00, 0x6A, 0x79, 0x86, 0xD3],
        )
    }

    fn last_error() -> std::io::Error {
        std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }.0)
    }

    let mut wsa_data = WSADATA::default();
    if unsafe { WSAStartup(0x0202, &mut wsa_data) } != 0 {
        return Err(last_error());
    }

    let sock: SOCKET = unsafe { socket(i32::from(AF_HYPERV), SOCK_STREAM, 0) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;

    let addr = SockaddrHv {
        family: AF_HYPERV,
        reserved: 0,
        vm_id: HV_GUID_CHILDREN,
        service_id: service_id_from_port(PORT),
    };
    let addr_ptr = std::ptr::from_ref(&addr).cast::<SOCKADDR>();
    if unsafe { bind(sock, addr_ptr, std::mem::size_of::<SockaddrHv>() as i32) } != 0 {
        return Err(last_error());
    }

    if unsafe { listen(sock, 1) } != 0 {
        return Err(last_error());
    }

    println!(
        "listening on AF_HYPERV, HV_GUID_CHILDREN, service id for port 0x{PORT:08X}; waiting for one connection..."
    );

    let client: SOCKET = unsafe { accept(sock, None, None) }
        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
    println!("client connected");

    let mut buf = [0u8; 1024];
    let n = unsafe { recv(client, &mut buf, SEND_RECV_FLAGS(0)) };
    if n < 0 {
        return Err(last_error());
    }
    let received = String::from_utf8_lossy(&buf[..n as usize]);
    println!("received: {received}");

    let reply = format!("windows-host-echo: {received}");
    let sent = unsafe { send(client, reply.as_bytes(), SEND_RECV_FLAGS(0)) };
    if sent < 0 {
        return Err(last_error());
    }

    unsafe {
        closesocket(client);
        closesocket(sock);
        WSACleanup();
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows-listener only runs on Windows; see ../../README.md");
    std::process::exit(1);
}
