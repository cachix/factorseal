//! Physical space reclamation after the unlocked store becomes idle.

use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::task::Poll;
use std::time::{Duration, Instant};

use super::{Command, StoreWorker, WorkerStatus};
use crate::vault::store::database::{database_error, query_count};
use crate::vault::{VaultError, VaultResult};

pub(super) const IDLE_BEFORE_COMPACTION: Duration = Duration::from_secs(30);
pub(super) const SPACE_CHECK_INTERVAL: Duration = Duration::from_mins(1);
const MIN_UNUSED_BYTES: u64 = 64 * 1024 * 1024;

/// Require both meaningful savings and at least half the file to be unused.
/// The ratio limits rewrite work relative to reclaimed space; the byte floor
/// leaves small databases alone and lets deleted pages be reused by writes.
fn needs_compaction(pages: u64, unused_pages: u64, page_size: u64) -> VaultResult<bool> {
    if unused_pages > pages || page_size == 0 {
        return Err(VaultError::InvalidData(
            "invalid database page counts".to_owned(),
        ));
    }
    let unused_bytes = unused_pages
        .checked_mul(page_size)
        .ok_or_else(|| VaultError::InvalidData("database page count overflow".to_owned()))?;
    Ok(unused_bytes >= MIN_UNUSED_BYTES && unused_pages >= pages - unused_pages)
}

impl StoreWorker {
    async fn reclaim_unused_space(&self) -> VaultResult<()> {
        // Yield between phases even when the engine serves every page from
        // cache synchronously, so queued work is checked before repacking.
        tokio::task::yield_now().await;
        let pages = query_count(&self.connection, "PRAGMA page_count", ()).await?;
        let unused_pages = query_count(&self.connection, "PRAGMA freelist_count", ()).await?;
        let page_size = query_count(&self.connection, "PRAGMA page_size", ()).await?;
        if !needs_compaction(pages, unused_pages, page_size)? {
            return Ok(());
        }

        // Never replace our authenticated in-memory state with freshly read
        // SQL state. Repacking must preserve every protected row, including
        // history, and must not bless live/offline rollback or corruption.
        self.verify_unchanged_store().await?;
        tokio::task::yield_now().await;
        self.connection
            .execute("VACUUM", ())
            .await
            .map_err(database_error)?;
        self.verify_unchanged_store().await?;
        Ok(())
    }

    async fn verify_unchanged_store(&self) -> VaultResult<()> {
        let verified = self.verify_commit_chain().await?;
        if verified != self.verified {
            return Err(VaultError::Signature);
        }
        Ok(())
    }
}

/// The owner thread remains the sole database user. Dropping an interrupted
/// VACUUM future releases its statement and lets Turso abort/clean up its
/// internal transaction. Cancellation is cooperative at phase and engine I/O
/// boundaries, including when the ordinary filesystem backend completes I/O
/// synchronously. No maintenance runs during open or teardown.
pub(super) async fn run_idle(
    worker: &StoreWorker,
    receiver: &mpsc::Receiver<Command>,
    status: &WorkerStatus,
) -> Option<Command> {
    let started = Instant::now();
    let mut maintenance = Box::pin(worker.reclaim_unused_space());
    let mut wake = Box::pin(tokio::time::sleep(Duration::from_millis(20)));
    std::future::poll_fn(|cx| {
        if status.is_sealed() {
            crate::timing::record(
                "store_maintenance",
                "reclaim_unused_space",
                started,
                "cancelled",
            );
            return Poll::Ready(None);
        }
        // Check before every poll, including cooperative phase yields. The
        // timer also wakes us when only the command queue or seal flag changes.
        match receiver.try_recv() {
            Ok(command) => {
                crate::timing::record(
                    "store_maintenance",
                    "reclaim_unused_space",
                    started,
                    "cancelled",
                );
                return Poll::Ready(Some(command));
            }
            Err(mpsc::TryRecvError::Disconnected) => return Poll::Ready(None),
            Err(mpsc::TryRecvError::Empty) => {}
        }
        match maintenance.as_mut().poll(cx) {
            Poll::Ready(result) => {
                crate::timing::record_result(
                    "store_maintenance",
                    "reclaim_unused_space",
                    started,
                    &result,
                );
                if result.is_err() {
                    crate::security::events::record(
                        crate::security::events::Kind::IntegrityFailure,
                    );
                    status.sealed.store(true, Ordering::Release);
                }
                Poll::Ready(None)
            }
            Poll::Pending => {
                if wake.as_mut().poll(cx).is_ready() {
                    wake.as_mut()
                        .reset(tokio::time::Instant::now() + Duration::from_millis(20));
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
        }
    })
    .await
}

#[cfg(all(test, feature = "hardware"))]
mod tests;
