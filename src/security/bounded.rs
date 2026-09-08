//! One deadline covering every partial read and write of a whole frame.
//!
//! Starting a fresh deadline inside each helper let one peer spend the bound
//! once per partial transfer instead of once per frame. The vault transport
//! and the isolated helper channels share these loops, so the retry policy
//! for nonblocking streams is written once.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const RETRY_INTERVAL: Duration = Duration::from_millis(2);

#[derive(Clone, Copy)]
pub(crate) struct IoBudget<'a> {
    deadline: Instant,
    cancelled: Option<&'a AtomicBool>,
}

impl IoBudget<'_> {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            // An unrepresentable deadline fails closed rather than panicking.
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            cancelled: None,
        }
    }

    pub(crate) fn exhausted(self) -> bool {
        Instant::now() >= self.deadline
            || self
                .cancelled
                .is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    /// Time left before the deadline, for callers that can sleep in the
    /// kernel until the stream is ready instead of retrying on an interval.
    #[cfg(all(unix, feature = "personal-sync-network"))]
    pub(crate) fn remaining(self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    #[cfg(feature = "vault")]
    pub(crate) fn capped(mut self, deadline: Option<Instant>) -> Self {
        if let Some(deadline) = deadline {
            self.deadline = self.deadline.min(deadline);
        }
        self
    }

    pub(crate) fn expired(operation: &'static str) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("local IPC {operation} deadline exceeded"),
        )
    }
}

#[cfg(feature = "vault")]
impl<'a> IoBudget<'a> {
    pub(crate) fn cancelled_by(mut self, flag: Option<&'a AtomicBool>) -> Self {
        self.cancelled = flag;
        self
    }
}

/// One successful read within `budget`, retrying while the stream has nothing
/// yet. A zero-byte read is end of file on Unix; a nonblocking Windows pipe
/// reports "nothing to read yet" the same way and a closed pipe as an error,
/// so a zero-byte read there is retried until the budget ends.
pub(crate) fn read_bounded(
    reader: &mut impl Read,
    bytes: &mut [u8],
    budget: IoBudget,
) -> io::Result<usize> {
    loop {
        if budget.exhausted() {
            return Err(IoBudget::expired("read"));
        }
        match reader.read(bytes) {
            Ok(0) if cfg!(windows) && !bytes.is_empty() => std::thread::sleep(RETRY_INTERVAL),
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

/// One successful write within `budget`. A nonblocking Windows pipe reports a
/// full buffer as a successful zero-byte write, mirroring the read side.
pub(crate) fn write_bounded(
    writer: &mut impl Write,
    bytes: &[u8],
    budget: IoBudget,
) -> io::Result<usize> {
    loop {
        if budget.exhausted() {
            return Err(IoBudget::expired("write"));
        }
        match writer.write(bytes) {
            Ok(0) if cfg!(windows) && !bytes.is_empty() => std::thread::sleep(RETRY_INTERVAL),
            Ok(written) => return Ok(written),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn read_exact_bounded(
    reader: &mut impl Read,
    mut bytes: &mut [u8],
    budget: IoBudget,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match read_bounded(reader, bytes, budget)? {
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            read => bytes = &mut bytes[read..],
        }
    }
    Ok(())
}

pub(crate) fn write_all_bounded(
    writer: &mut impl Write,
    mut bytes: &[u8],
    budget: IoBudget,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match write_bounded(writer, bytes, budget)? {
            0 => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            written => bytes = &bytes[written..],
        }
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stalled;
    impl Read for Stalled {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
    impl Write for Stalled {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_exhausted_budget_fails_closed_instead_of_retrying() {
        let budget = IoBudget::new(Duration::ZERO);
        let mut bytes = [0; 4];
        let error = read_exact_bounded(&mut Stalled, &mut bytes, budget).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let error = write_all_bounded(&mut Stalled, &bytes, budget).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        #[cfg(all(unix, feature = "personal-sync-network"))]
        assert_eq!(budget.remaining(), Duration::ZERO);
    }

    #[test]
    fn partial_transfers_complete_within_one_budget() {
        struct Trickle(Vec<u8>);
        impl Read for Trickle {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || bytes.is_empty() {
                    return Ok(0);
                }
                bytes[0] = self.0.remove(0);
                Ok(1)
            }
        }
        let budget = IoBudget::new(Duration::from_mins(1));
        let mut bytes = [0; 3];
        read_exact_bounded(&mut Trickle(vec![1, 2, 3]), &mut bytes, budget).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        // A zero-byte read is retried on Windows, where it means "no data yet".
        #[cfg(unix)]
        assert_eq!(
            read_exact_bounded(&mut Trickle(vec![1]), &mut bytes, budget)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
