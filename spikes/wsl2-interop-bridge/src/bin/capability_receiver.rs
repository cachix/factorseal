//! Throwaway capability receiver. See ../../README.md.
//!
//! Runs inside WSL2, launched directly by `capability-delegator` via
//! `wsl.exe`. Reads whatever `capability-delegator` wrote to this
//! process's stdin and echoes it back on stdout. There is no connection to
//! establish and nothing to authenticate here: holding this process's own
//! stdin *is* the credential, because the only way to have received
//! anything on it was to have been launched by the trusted delegator.

use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    std::io::stdout().write_all(input.as_bytes())?;
    Ok(())
}
