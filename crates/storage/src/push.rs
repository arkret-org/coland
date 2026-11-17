use super::{PersistenceResult, Value, async_trait};
/// Authenticated push registration storage.
#[async_trait]
pub trait PushDeviceStore: Send + Sync {
    async fn register(
        &self,
        authorization: &crate::DeviceRevocationGateSelector,
        device: Value,
    ) -> PersistenceResult<()>;
    async fn unregister(
        &self,
        actor: &arkret_wire::AccountId,
        device_id: &str,
        push_key: Option<&str>,
        app_id: Option<&str>,
    ) -> PersistenceResult<usize>;
    async fn snapshot_all(&self) -> PersistenceResult<Vec<Value>>;
}
