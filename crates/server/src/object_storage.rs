//! Object storage abstraction for user-uploaded bytes.
//!
//! Database rows store object metadata and an object key. The bytes live
//! behind this trait so deployments can choose local disk or an S3-compatible
//! object store without changing HTTP handlers or persistence code.

use std::ops::Range;
use std::path::Path as FsPath;
use std::sync::Arc;

use bytes::Bytes;
use coland_http::config::ObjectStorageConfig;
use coland_services::delivery::ObjectStoragePort;
use futures_util::stream::BoxStream;
use futures_util::{StreamExt as _, TryStreamExt as _};
use object_store::aws::AmazonS3Builder;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use object_store::{GetOptions, ObjectStore, ObjectStoreExt};
use tokio::io::AsyncReadExt as _;

#[derive(Debug, thiserror::Error)]
pub enum ObjectStorageError {
    #[error("invalid object key: {0}")]
    InvalidKey(String),
    #[error("object storage IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("object storage error: {0}")]
    Store(#[from] object_store::Error),
}

pub type ObjectStorageResult<T> = Result<T, ObjectStorageError>;

pub fn build_object_storage(
    config: &ObjectStorageConfig,
) -> anyhow::Result<Arc<dyn ObjectStoragePort>> {
    match config {
        ObjectStorageConfig::Local { root, prefix } => {
            std::fs::create_dir_all(root)?;
            let store = LocalFileSystem::new_with_prefix(root)?;
            Ok(Arc::new(ObjectStoreStorage {
                backend_name: "local",
                prefix: prefix.clone(),
                store: Arc::new(store),
            }))
        }
        ObjectStorageConfig::S3Compatible {
            bucket,
            region,
            endpoint,
            access_key_id,
            secret_access_key,
            session_token,
            prefix,
            force_path_style,
            allow_http,
            skip_signature,
        } => {
            let mut builder = AmazonS3Builder::new()
                .with_bucket_name(bucket)
                .with_region(region)
                .with_virtual_hosted_style_request(!force_path_style)
                .with_allow_http(*allow_http)
                .with_skip_signature(*skip_signature);
            if let Some(endpoint) = endpoint {
                builder = builder.with_endpoint(endpoint);
            }
            if let (Some(access_key_id), Some(secret_access_key)) =
                (access_key_id, secret_access_key)
            {
                builder = builder
                    .with_access_key_id(access_key_id)
                    .with_secret_access_key(secret_access_key);
            }
            if let Some(session_token) = session_token {
                builder = builder.with_token(session_token);
            }
            Ok(Arc::new(ObjectStoreStorage {
                backend_name: "s3",
                prefix: prefix.clone(),
                store: Arc::new(builder.build()?),
            }))
        }
    }
}

struct ObjectStoreStorage {
    backend_name: &'static str,
    prefix: String,
    store: Arc<dyn ObjectStore>,
}

const MULTIPART_UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;

#[async_trait::async_trait]
impl ObjectStoragePort for ObjectStoreStorage {
    fn backend_name(&self) -> String {
        self.backend_name.to_owned()
    }

    fn object_key_for_sha256(&self, sha256: &str) -> String {
        let key = format!("sha256/{sha256}");
        if self.prefix.is_empty() {
            key
        } else {
            format!("{}/{key}", self.prefix)
        }
    }

    async fn put(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        async {
            let path = object_path(key)?;
            self.store.put(&path, bytes.into()).await?;
            Ok(())
        }
        .await
        .map_err(|error: ObjectStorageError| error.to_string())
    }

    async fn put_file(&self, key: &str, file_path: &FsPath) -> Result<(), String> {
        async {
            let path = object_path(key)?;
            let len = tokio::fs::metadata(file_path).await?.len();
            if len <= MULTIPART_UPLOAD_CHUNK_BYTES as u64 {
                let bytes = tokio::fs::read(file_path).await?;
                self.store.put(&path, bytes.into()).await?;
                return Ok(());
            }

            let mut file = tokio::fs::File::open(file_path).await?;
            let mut upload = self.store.put_multipart(&path).await?;
            let mut buffer = vec![0u8; MULTIPART_UPLOAD_CHUNK_BYTES];
            loop {
                let read = file.read(&mut buffer).await?;
                if read == 0 {
                    break;
                }
                if let Err(error) = upload.put_part(buffer[..read].to_vec().into()).await {
                    let _ = upload.abort().await;
                    return Err(ObjectStorageError::Store(error));
                }
            }
            if let Err(error) = upload.complete().await {
                let _ = upload.abort().await;
                return Err(ObjectStorageError::Store(error));
            }
            Ok(())
        }
        .await
        .map_err(|error: ObjectStorageError| error.to_string())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        async {
            let path = object_path(key)?;
            Ok(self.store.get(&path).await?.bytes().await?.to_vec())
        }
        .await
        .map_err(|error: ObjectStorageError| error.to_string())
    }

    async fn get_range_stream(
        &self,
        key: &str,
        range: Range<u64>,
    ) -> Result<BoxStream<'static, Result<Bytes, String>>, String> {
        async {
            let path = object_path(key)?;
            let result = self
                .store
                .get_opts(&path, GetOptions::new().with_range(Some(range)))
                .await?;
            Ok(result
                .into_stream()
                .map_err(|error| ObjectStorageError::Store(error).to_string())
                .boxed())
        }
        .await
        .map_err(|error: ObjectStorageError| error.to_string())
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        async {
            let path = object_path(key)?;
            self.store.delete(&path).await?;
            Ok(())
        }
        .await
        .map_err(|error: ObjectStorageError| error.to_string())
    }
}

fn object_path(key: &str) -> ObjectStorageResult<ObjectPath> {
    let key = key.trim();
    if key.is_empty() || key.starts_with('/') || key.contains('\\') || key.contains("..") {
        return Err(ObjectStorageError::InvalidKey(key.to_owned()));
    }
    Ok(ObjectPath::from(key))
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn local_storage_round_trips_bytes_with_prefix() {
        let root = std::env::temp_dir().join(format!("coland-object-storage-{}", Uuid::new_v4()));
        let config = ObjectStorageConfig::Local {
            root: root.clone(),
            prefix: "tenant-a".to_owned(),
        };
        let storage = build_object_storage(&config).unwrap();
        let key = storage.object_key_for_sha256(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );

        storage
            .put(&key, b"hello-object-storage".to_vec())
            .await
            .unwrap();

        assert_eq!(storage.backend_name(), "local");
        assert_eq!(
            key,
            "tenant-a/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            storage.get(&key).await.unwrap(),
            b"hello-object-storage".to_vec()
        );
        let streamed = storage
            .get_range_stream(&key, 6..12)
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(streamed, b"object".to_vec());

        storage.delete(&key).await.unwrap();
        assert!(storage.get(&key).await.is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
