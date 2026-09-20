//! Focus an existing Niri window without unmapping its Wayland surface.
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    os::unix::net::UnixStream,
    time::Duration,
};

use serde_json::{Value, json};

pub(super) fn focus_desktop() -> bool {
    focus().unwrap_or(false)
}

fn focus() -> anyhow::Result<bool> {
    let path = std::env::var_os("NIRI_SOCKET").ok_or_else(|| anyhow::anyhow!("Not using Niri"))?;
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let mut socket = BufReader::new(stream);
    let windows = request(&mut socket, &json!("Windows"))?;
    let Some(id) = desktop_id(&windows, std::process::id()) else {
        return Ok(false);
    };
    let reply = request(&mut socket, &json!({"Action": {"FocusWindow": {"id": id}}}))?;
    Ok(reply == json!({"Ok": "Handled"}))
}

fn desktop_id(reply: &Value, pid: u32) -> Option<u64> {
    reply
        .get("Ok")?
        .get("Windows")?
        .as_array()?
        .iter()
        .find_map(|window| {
            (window.get("pid").and_then(Value::as_u64) == Some(u64::from(pid))
                && window.get("app_id").and_then(Value::as_str) == Some("dev.factorseal.Desktop"))
            .then(|| window.get("id").and_then(Value::as_u64))
            .flatten()
        })
}

fn request(socket: &mut BufReader<UnixStream>, value: &Value) -> anyhow::Result<Value> {
    serde_json::to_writer(socket.get_mut(), value)?;
    socket.get_mut().write_all(b"\n")?;
    let mut reply = String::new();
    socket.take(1024 * 1024).read_line(&mut reply)?;
    anyhow::ensure!(reply.ends_with('\n'), "Incomplete Niri reply");
    Ok(serde_json::from_str(&reply)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_targets_only_this_process_and_the_desktop_window() {
        let reply = json!({"Ok": {"Windows": [
            {"id": 1, "pid": 100, "app_id": "dev.factorseal.Desktop"},
            {"id": 2, "pid": 200, "app_id": "dev.factorseal.Access"},
            {"id": 3, "pid": 200, "app_id": "dev.factorseal.Desktop"}
        ]}});
        assert_eq!(desktop_id(&reply, 200), Some(3));
        assert_eq!(desktop_id(&reply, 300), None);
        assert_eq!(desktop_id(&json!({"Err": "unavailable"}), 200), None);
    }
}
