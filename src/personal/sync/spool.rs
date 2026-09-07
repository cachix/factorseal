//! Bounded, durable storage for signature-checked ciphertext, with no reader keys.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use super::{Membership, PacketId, VerifiedPacket, invalid, packet::MAX_PACKET_BYTES};
use crate::{
    security,
    vault::{VaultError, VaultResult},
};

const MAX_OBJECTS: usize = 4096;

/// Single-owner store suitable for a locked device or a storage-only node.
/// Receipts from this store establish ciphertext possession, not application.
pub struct CiphertextSpool {
    root: PathBuf,
    quota: u64,
    _lock: File,
}

impl CiphertextSpool {
    /// Open/create a private directory. A separate file lock serializes quota
    /// checks and publication across processes. Do not use the vault directory.
    pub fn open(root: &Path, quota: u64) -> VaultResult<Self> {
        if quota == 0 {
            return Err(invalid());
        }
        if !root.exists() {
            create_root(root).map_err(storage)?;
        }
        validate_root(root)?;
        let path = root.join(".lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = security::regular::open_regular(&path, &mut options).map_err(storage)?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(storage)?;
        let spool = Self {
            root: root.to_owned(),
            quota,
            _lock: lock,
        };
        if spool.used_bytes()? > quota {
            return Err(VaultError::Protocol(
                "ciphertext spool exceeds its quota".into(),
            ));
        }
        Ok(spool)
    }

    /// Verify against current public membership, then publish atomically. Return
    /// only after file/directory synchronization has completed where supported.
    pub fn put(&mut self, bytes: &[u8], membership: &Membership) -> VaultResult<PacketId> {
        let packet = VerifiedPacket::verify(bytes, membership)?;
        let id = packet.id();
        let path = self.path(id);
        if path.try_exists().map_err(storage)? {
            if self.get(id, membership)?.as_bytes() != bytes {
                return Err(invalid());
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            security::regular::open_regular(&path, &mut options)
                .map_err(storage)?
                .sync_all()
                .map_err(storage)?;
            #[cfg(unix)]
            File::open(&self.root)
                .map_err(storage)?
                .sync_all()
                .map_err(storage)?;
            return Ok(id);
        }
        let used = self.used_bytes()?;
        if bytes.len() as u64 > self.quota.saturating_sub(used)
            || fs::read_dir(&self.root).map_err(storage)?.count() > MAX_OBJECTS
        {
            return Err(VaultError::Protocol("ciphertext spool is full".into()));
        }
        security::write_private_file(&path, bytes).map_err(storage)?;
        Ok(id)
    }

    pub fn get(&self, id: PacketId, membership: &Membership) -> VaultResult<VerifiedPacket> {
        let bytes = security::read_private_file(&self.path(id), MAX_PACKET_BYTES as u64)
            .map_err(storage)?;
        let packet = VerifiedPacket::verify(&bytes, membership)?;
        if packet.id() != id {
            return Err(invalid());
        }
        Ok(packet)
    }

    /// Sorted ciphertext addresses, paginated without needing secret values.
    pub fn inventory(&self, after: Option<PacketId>, limit: usize) -> VaultResult<Vec<PacketId>> {
        if limit == 0 || limit > 128 {
            return Err(invalid());
        }
        let mut ids = self
            .packet_files()?
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        ids.sort_by_key(|id| id.0);
        ids.retain(|id| after.is_none_or(|after| id.0 > after.0));
        ids.truncate(limit);
        Ok(ids)
    }

    fn path(&self, id: PacketId) -> PathBuf {
        self.root.join(format!("{id}.packet"))
    }

    fn used_bytes(&self) -> VaultResult<u64> {
        // Also validates recognized packet names. Orphan temporary files consume
        // real disk space and remain charged until explicit cleanup.
        self.packet_files()?;
        let mut total = 0_u64;
        let mut count = 0;
        for entry in fs::read_dir(&self.root).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            if entry.file_name() == ".lock" {
                continue;
            }
            count += 1;
            if count > MAX_OBJECTS {
                return Err(invalid());
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(storage)?;
            if !metadata.is_file() || metadata.len() > MAX_PACKET_BYTES as u64 {
                return Err(invalid());
            }
            total = total.checked_add(metadata.len()).ok_or_else(invalid)?;
        }
        Ok(total)
    }

    fn packet_files(&self) -> VaultResult<Vec<(PacketId, u64)>> {
        validate_root(&self.root)?;
        let mut files = Vec::new();
        let mut count = 0;
        for entry in fs::read_dir(&self.root).map_err(storage)? {
            count += 1;
            if count > MAX_OBJECTS + 1 {
                return Err(invalid());
            }
            let entry = entry.map_err(storage)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(invalid)?;
            if name == ".lock" {
                continue;
            }
            let Some(id) = name.strip_suffix(".packet") else {
                // A crash can leave an unpublished tempfile. used_bytes charges
                // it against quota; inventory never presents it as delivered.
                if name.starts_with(".tmp") {
                    continue;
                }
                return Err(invalid());
            };
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            let id = PacketId(
                hex::decode(id)
                    .map_err(|_| invalid())?
                    .try_into()
                    .map_err(|_| invalid())?,
            );
            let metadata = fs::symlink_metadata(entry.path()).map_err(storage)?;
            if !metadata.is_file() || metadata.len() > MAX_PACKET_BYTES as u64 {
                return Err(invalid());
            }
            files.push((id, metadata.len()));
            if files.len() > MAX_OBJECTS {
                return Err(invalid());
            }
        }
        Ok(files)
    }
}

// Takes ownership to serve directly as a map_err adapter.
#[allow(clippy::needless_pass_by_value)]
fn storage(error: io::Error) -> VaultError {
    VaultError::Database(format!("ciphertext spool: {error}"))
}

#[cfg(unix)]
fn create_root(root: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(root)
}

#[cfg(windows)]
fn create_root(root: &Path) -> io::Result<()> {
    security::windows::create_owner_only_directory(root)
}

#[cfg(not(any(unix, windows)))]
fn create_root(_root: &Path) -> io::Result<()> {
    Err(io::Error::other("unsupported private directory platform"))
}

fn validate_root(root: &Path) -> VaultResult<()> {
    let metadata = fs::symlink_metadata(root).map_err(storage)?;
    if !metadata.is_dir() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no arguments or memory preconditions.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    security::windows::validate_owner_only_directory(root).map_err(storage)?;
    Ok(())
}
