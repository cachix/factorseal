use std::collections::hash_map::DefaultHasher;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fs2::FileExt as _;

pub(crate) enum Instance {
    Primary {
        _lock: File,
        activations: smol::channel::Receiver<()>,
    },
    Secondary,
}

pub(crate) fn acquire(root: &Path, request_activation: bool) -> Result<Instance, String> {
    let (lock_path, activation_path) = instance_paths(root)?;
    let file = open_private_file(&lock_path)?;
    if let Err(error) = file.try_lock_exclusive() {
        if error.raw_os_error() != fs2::lock_contended_error().raw_os_error() {
            return Err(error.to_string());
        }
        if request_activation {
            signal_activation(&activation_path)?;
        }
        return Ok(Instance::Secondary);
    }

    let watcher = open_private_file(&activation_path)?;
    watcher.set_len(0).map_err(|error| error.to_string())?;
    let (sender, activations) = smol::channel::bounded(4);
    std::thread::Builder::new()
        .name("factorseal-desktop-activation".to_owned())
        .spawn(move || watch(&watcher, &sender))
        .map_err(|error| error.to_string())?;
    Ok(Instance::Primary {
        _lock: file,
        activations,
    })
}

fn signal_activation(path: &Path) -> Result<(), String> {
    let mut file = open_private_file(path)?;
    file.set_len(0).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    file.write_all(b"open\n")
        .and_then(|()| file.sync_data())
        .map_err(|error| error.to_string())
}

fn watch(file: &File, sender: &smol::channel::Sender<()>) {
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let requested = file.metadata().is_ok_and(|metadata| metadata.len() != 0);
        if !requested {
            continue;
        }
        let _ = file.set_len(0);
        if sender.try_send(()).is_err() && sender.is_closed() {
            break;
        }
    }
}

fn instance_paths(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let absolute = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|error| error.to_string())?
            .join(root)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| "the vault path has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut hasher = DefaultHasher::new();
    absolute.hash(&mut hasher);
    let identifier = format!("{:016x}", hasher.finish());
    Ok((
        parent.join(format!(".factorseal-desktop-{identifier}.lock")),
        parent.join(format!(".factorseal-desktop-{identifier}.activate")),
    ))
}

fn open_private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_instance_requests_activation() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("vault");
        let Instance::Primary { _lock, activations } = acquire(&root, false).unwrap() else {
            panic!("first instance was not primary");
        };
        assert!(matches!(acquire(&root, true).unwrap(), Instance::Secondary));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if activations.try_recv().is_ok() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "activation timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
