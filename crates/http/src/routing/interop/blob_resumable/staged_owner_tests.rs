//! Real native files and OS ownership, using the production staged mutations.
//! These tests do not claim authenticated HTTP/accepted-E/physical-Blob credit.

use super::super::{
    StagedUpload, append_staged, create_staged, data_path, erase_owner_directory, meta_path,
    write_meta_atomic,
};
use super::*;

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("coland-tus-owner-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(std::fs::canonicalize(path).unwrap())
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let parent = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        if self.0 != parent && self.0.starts_with(parent) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn actor(station: &str) -> ActorId {
    ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        arkret_wire::DidCoreId::new(station).unwrap(),
    ))
}

fn metadata(actor: &ActorId) -> StagedUpload {
    StagedUpload {
        upload_id: "same-resource-id".into(),
        declared_size_bytes: 5,
        offset_bytes: 4,
        upload_metadata: std::collections::HashMap::from([(
            "encryption".into(),
            Some("null".into()),
        )]),
        created_by: actor.clone(),
        created_at: "2026-11-17T00:00:00.000Z".into(),
        expires_at: "2026-11-18T00:00:00.000Z".into(),
    }
}

#[tokio::test]
async fn full_creator_separates_same_principal_accounts_and_erasure_preserves_other_source() {
    let root = Directory::new();
    let first = actor("ak:did_core:web:first.example");
    let second = actor("ak:did_core:web:second.example");
    assert_ne!(owner_key(&first).unwrap(), owner_key(&second).unwrap());
    for creator in [&first, &second] {
        let guard = OwnerGuard::acquire(root.0.clone(), creator.clone(), true, true)
            .await
            .unwrap()
            .unwrap();
        let meta = metadata(creator);
        guard
            .run(move |dir| create_staged(dir, &meta, b"ABCD"))
            .await
            .unwrap();
    }
    let guard = OwnerGuard::acquire(root.0.clone(), first.clone(), false, false)
        .await
        .unwrap()
        .unwrap();
    guard
        .run(move |dir| {
            erase_owner_directory(dir, &first)?;
            assert!(!data_path(dir, "same-resource-id").try_exists()?);
            assert!(!meta_path(dir, "same-resource-id").try_exists()?);
            Ok(())
        })
        .await
        .unwrap();
    let guard = OwnerGuard::acquire(root.0.clone(), second.clone(), false, false)
        .await
        .unwrap()
        .unwrap();
    let (_, bytes) = guard
        .run(|dir| std::fs::read(data_path(dir, "same-resource-id")))
        .await
        .unwrap();
    assert_eq!(bytes, b"ABCD");
}

struct AfterNativeGuardDrop(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for AfterNativeGuardDrop {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            let _ = done.send(());
        }
    }
}

#[tokio::test]
async fn disconnected_caller_keeps_actual_writer_owned_until_cold_drain_can_erase() {
    let root = Directory::new();
    let creator = actor("ak:did_core:web:first.example");
    let guard = OwnerGuard::acquire(root.0.clone(), creator.clone(), true, true)
        .await
        .unwrap()
        .unwrap();
    let meta = metadata(&creator);
    let (started, at_writer) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let (ended, after_native_drop) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        guard
            .run(move |dir| {
                let _ = started.send(());
                wait.recv().map_err(std::io::Error::other)?;
                create_staged(dir, &meta, b"ABCD")?;
                // The tuple returned by OwnerGuard::run drops its actual guard
                // before this value, even when the canceled caller lost the result.
                Ok(AfterNativeGuardDrop(Some(ended)))
            })
            .await
    });
    at_writer.await.unwrap();
    caller.abort();
    let Err(cancelled) = caller.await else {
        panic!("controlled caller must be canceled");
    };
    assert!(cancelled.is_cancelled());
    let actual = OwnerGuard::acquire(root.0.clone(), creator.clone(), false, false).await;
    assert!(matches!(actual,Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    release.send(()).unwrap();
    after_native_drop.await.unwrap();
    // Reopening the native owner uses no old HTTP handle or process lock map.
    let cold = OwnerGuard::acquire(root.0.clone(), creator.clone(), false, false)
        .await
        .unwrap()
        .unwrap();
    cold.run(move |dir| {
        assert_eq!(std::fs::read(data_path(dir, "same-resource-id"))?, b"ABCD");
        erase_owner_directory(dir, &creator)?;
        assert!(!data_path(dir, "same-resource-id").try_exists()?);
        assert!(!meta_path(dir, "same-resource-id").try_exists()?);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn interrupted_append_recovers_only_unaccepted_tail_and_wrong_creator_stops_erasure() {
    let root = Directory::new();
    let creator = actor("ak:did_core:web:first.example");
    let other = actor("ak:did_core:web:second.example");
    let guard = OwnerGuard::acquire(root.0.clone(), creator.clone(), true, true)
        .await
        .unwrap()
        .unwrap();
    guard
        .run(move |dir| {
            use std::io::Write as _;
            let mut meta = metadata(&creator);
            create_staged(dir, &meta, b"ABCD")?;
            // Deliberate crash residue, not an accepted upload/source or fake E.
            let mut interrupted = OpenOptions::new()
                .append(true)
                .open(data_path(dir, &meta.upload_id))?;
            interrupted.write_all(b"unaccepted tail")?;
            drop(interrupted);
            append_staged(dir, &mut meta, b"E")?;
            assert_eq!(std::fs::read(data_path(dir, &meta.upload_id))?, b"ABCDE");
            assert_eq!(meta.offset_bytes, 5);
            meta.created_by = other;
            write_meta_atomic(dir, &meta)?;
            assert!(erase_owner_directory(dir, &creator).is_err());
            assert_eq!(std::fs::read(data_path(dir, &meta.upload_id))?, b"ABCDE");
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn mkdir_only_crash_residue_recovers_the_same_native_lock_before_drain() {
    let root = Directory::new();
    let creator = actor("ak:did_core:web:first.example");
    let directory = root.0.join(owner_key(&creator).unwrap());
    std::fs::create_dir(&directory).unwrap();
    assert!(!directory.join(LOCK_FILE).try_exists().unwrap());
    let cold = OwnerGuard::acquire(root.0.clone(), creator.clone(), false, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        std::fs::metadata(directory.join(LOCK_FILE)).unwrap().len(),
        0
    );
    let other = OwnerGuard::acquire(root.0.clone(), creator.clone(), true, false).await;
    assert!(matches!(other,Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    cold.run(move |dir| erase_owner_directory(dir, &creator))
        .await
        .unwrap();
}
