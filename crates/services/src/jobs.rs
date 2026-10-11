use std::sync::Arc;

use arkret_identifiers::DidCoreId;
use arkret_wire::ActorId;

pub const INTERNAL_IDEMPOTENCY_OPERATION: &str = "coland://internal/idempotency";
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::ServiceResult;

#[async_trait]
pub trait MaintenancePort: Send + Sync {
    async fn prune_expired_idempotency(&self, now: DateTime<Utc>) -> ServiceResult<usize>;
    async fn idempotency_record(
        &self,
        principal_id: &DidCoreId,
        key: &str,
    ) -> ServiceResult<Option<IdempotencyState>>;
    async fn idempotency_record_scoped(
        &self,
        authenticated_actor: &ActorId,
        operation_id: &str,
        key: &str,
    ) -> ServiceResult<Option<IdempotencyState>>;
    async fn store_idempotency_record(&self, record: IdempotencyState) -> ServiceResult<()>;
}

#[async_trait]
pub trait RuntimeHealthPort: Send + Sync {
    async fn database_ready(&self) -> bool;
    fn storage_mode(&self) -> &'static str;
    fn migrations_applied(&self) -> bool;
    fn database_configured(&self) -> bool;
    fn database_pool_in_use(&self) -> u32;
}

pub use coland_storage::IdempotencyRecord as IdempotencyState;

#[derive(Clone)]
pub struct JobsService {
    maintenance: Arc<dyn MaintenancePort>,
    runtime_health: Arc<dyn RuntimeHealthPort>,
}

impl JobsService {
    pub fn new(
        maintenance: Arc<dyn MaintenancePort>,
        runtime_health: Arc<dyn RuntimeHealthPort>,
    ) -> Self {
        Self {
            maintenance,
            runtime_health,
        }
    }

    pub async fn database_ready(&self) -> bool {
        self.runtime_health.database_ready().await
    }

    pub fn storage_mode(&self) -> &'static str {
        self.runtime_health.storage_mode()
    }

    pub fn migrations_applied(&self) -> bool {
        self.runtime_health.migrations_applied()
    }

    pub fn database_configured(&self) -> bool {
        self.runtime_health.database_configured()
    }

    pub fn database_pool_in_use(&self) -> u32 {
        self.runtime_health.database_pool_in_use()
    }

    pub async fn prune_expired_idempotency(&self, now: DateTime<Utc>) -> ServiceResult<usize> {
        self.maintenance.prune_expired_idempotency(now).await
    }

    pub async fn idempotency_record(
        &self,
        principal_id: &DidCoreId,
        key: &str,
    ) -> ServiceResult<Option<IdempotencyState>> {
        self.maintenance.idempotency_record(principal_id, key).await
    }
    pub async fn scoped_idempotency_record(
        &self,
        authenticated_actor: &ActorId,
        operation_id: &str,
        key: &str,
    ) -> ServiceResult<Option<IdempotencyState>> {
        self.maintenance
            .idempotency_record_scoped(authenticated_actor, operation_id, key)
            .await
    }
    pub async fn store_idempotency_record(&self, record: IdempotencyState) -> ServiceResult<()> {
        self.maintenance.store_idempotency_record(record).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StaticMaintenance;

    struct StaticRuntimeHealth;

    #[async_trait]
    impl RuntimeHealthPort for StaticRuntimeHealth {
        async fn database_ready(&self) -> bool {
            true
        }

        fn storage_mode(&self) -> &'static str {
            "memory"
        }

        fn migrations_applied(&self) -> bool {
            true
        }

        fn database_configured(&self) -> bool {
            false
        }

        fn database_pool_in_use(&self) -> u32 {
            0
        }
    }

    #[async_trait]
    impl MaintenancePort for StaticMaintenance {
        async fn prune_expired_idempotency(&self, _now: DateTime<Utc>) -> ServiceResult<usize> {
            Ok(3)
        }
        async fn idempotency_record(
            &self,
            _principal_id: &DidCoreId,
            _key: &str,
        ) -> ServiceResult<Option<IdempotencyState>> {
            Ok(None)
        }
        async fn idempotency_record_scoped(
            &self,
            _authenticated_actor: &ActorId,
            _operation_id: &str,
            _key: &str,
        ) -> ServiceResult<Option<IdempotencyState>> {
            Ok(None)
        }
        async fn store_idempotency_record(&self, _record: IdempotencyState) -> ServiceResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn maintenance_step_is_independent_from_the_scheduler() {
        let service = JobsService::new(Arc::new(StaticMaintenance), Arc::new(StaticRuntimeHealth));
        assert_eq!(
            service
                .prune_expired_idempotency(Utc::now())
                .await
                .expect("prune idempotency"),
            3
        );
    }
}
