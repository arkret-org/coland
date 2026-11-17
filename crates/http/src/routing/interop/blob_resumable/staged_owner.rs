//! Native ownership of this node's unfinished tus resources.
//! The empty lock file contains no authority, lifecycle phase or private body.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use arkret_wire::ActorId;

const LOCK_FILE: &str = ".writer";

pub(super) struct OwnerGuard {
    directory: PathBuf,
    _file: File,
}

fn invalid(detail: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, detail)
}

pub(super) fn owner_key(actor: &ActorId) -> std::io::Result<String> {
    let canonical = actor
        .canonical_key()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(arkret_canonical::sha256_hex(canonical.as_bytes()))
}

fn is_owner_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl OwnerGuard {
    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }
    /// The writer opens its existing resource owner before checking the
    /// Account's current private-write gate. E commits its negative projection
    /// first, releases PG, then tries this same native owner.
    pub(super) async fn acquire(
        root: PathBuf,
        actor: ActorId,
        create: bool,
        wait: bool,
    ) -> std::io::Result<Option<Self>> {
        let key = owner_key(&actor)?;
        Self::acquire_key(root, key, create, wait).await
    }

    pub(super) async fn acquire_key(
        root: PathBuf,
        key: String,
        create: bool,
        wait: bool,
    ) -> std::io::Result<Option<Self>> {
        tokio::task::spawn_blocking(move || Self::acquire_sync(&root, &key, create, wait))
            .await
            .map_err(std::io::Error::other)?
    }

    fn acquire_sync(
        root: &Path,
        key: &str,
        create: bool,
        wait: bool,
    ) -> std::io::Result<Option<Self>> {
        if !is_owner_key(key) {
            return Err(invalid("invalid native tus owner key"));
        }
        if create {
            std::fs::create_dir_all(root)?;
        }
        if !root.try_exists()? {
            return Ok(None);
        }
        let root = std::fs::canonicalize(root)?;
        let directory = root.join(key);
        if create {
            std::fs::create_dir_all(&directory)?;
        }
        if !directory.try_exists()? {
            return Ok(None);
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid("native tus owner is not a real local directory"));
        }
        let actual = std::fs::canonicalize(&directory)?;
        if actual == root || !actual.starts_with(&root) {
            return Err(invalid("native tus owner escaped the configured root"));
        }
        let lock_path = directory.join(LOCK_FILE);
        if lock_path.try_exists()? {
            let metadata = std::fs::symlink_metadata(&lock_path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid("native tus owner lock is not a real file"));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            // Directory creation is controlled above. An existing native
            // directory may be a crash residue from before first lock-file
            // creation; all concurrent opens choose this same persistent inode.
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        if wait {
            file.lock()?;
        } else {
            match file.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "native tus owner still has actual IO",
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
        }
        Ok(Some(Self {
            directory,
            _file: file,
        }))
    }

    /// This blocking job owns the actual OS resource until every native file
    /// operation has ended. Dropping the HTTP future does not release it early.
    pub(super) async fn run<T, F>(self, operation: F) -> std::io::Result<(Self, T)>
    where
        T: Send + 'static,
        F: FnOnce(&Path) -> std::io::Result<T> + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let result = operation(&self.directory)?;
            Ok((self, result))
        })
        .await
        .map_err(std::io::Error::other)?
    }
}

pub(super) async fn io<T, F>(guard: &mut Option<OwnerGuard>, operation: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&Path) -> std::io::Result<T> + Send + 'static,
{
    let owned = guard
        .take()
        .ok_or_else(|| invalid("native tus owner was not acquired"))?;
    let (owned, result) = owned.run(operation).await?;
    *guard = Some(owned);
    Ok(result)
}

/// Root enumeration is only the existing native staging owner catalog. It
/// never scans backend Blob keys or supplies a canonical source/permission.
pub(super) async fn directories(root: PathBuf) -> std::io::Result<Vec<String>> {
    tokio::task::spawn_blocking(move || {
        if !root.try_exists()? {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let key = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid tus owner filename"))?;
            if !is_owner_key(&key)
                || !entry.file_type()?.is_dir()
                || entry.file_type()?.is_symlink()
            {
                return Err(invalid("unknown entry in native tus owner catalog"));
            }
            keys.push(key);
        }
        keys.sort();
        Ok(keys)
    })
    .await
    .map_err(std::io::Error::other)?
}

pub(super) fn is_lock_file(name: &str) -> bool {
    name == LOCK_FILE
}

#[cfg(test)]
#[path = "staged_owner_tests.rs"]
mod tests;
