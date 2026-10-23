use arkret_identity::service_identity::StoredDidCoreIdentity;
use diesel_async::AsyncConnection;

use super::{
    Jsonb, OptionalExtension, PersistenceError, PersistenceResult, PgPool, QueryableByName,
    RunQueryDsl, SINGLETON_ID, ServiceIdentityStore, Text, Value, async_trait, sql_query,
};
pub struct PgServiceIdentityStore {
    pub pool: PgPool,
}
#[derive(QueryableByName)]
struct ServiceIdentityRow {
    #[diesel(sql_type = Jsonb)]
    identity: Value,
}

impl TryFrom<ServiceIdentityRow> for StoredDidCoreIdentity {
    type Error = PersistenceError;

    fn try_from(row: ServiceIdentityRow) -> Result<Self, Self::Error> {
        let identity: StoredDidCoreIdentity = serde_json::from_value(row.identity)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        identity
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        Ok(identity)
    }
}
#[async_trait]
impl ServiceIdentityStore for PgServiceIdentityStore {
    async fn get(&self) -> PersistenceResult<Option<StoredDidCoreIdentity>> {
        let mut conn = crate::pg_db(&self.pool);
        sql_query("SELECT identity FROM service_identity WHERE id = $1")
            .bind::<Text, _>(SINGLETON_ID)
            .get_result::<ServiceIdentityRow>(&mut conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(StoredDidCoreIdentity::try_from)
            .transpose()
    }

    async fn put(&self, identity: StoredDidCoreIdentity) -> PersistenceResult<()> {
        identity
            .validate()
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let value = serde_json::to_value(&identity)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?;
        let mut conn = crate::pg_conn(&self.pool).await?;
        conn.transaction::<_,crate::PgTransactionError,_>(async move |conn| {
            if identity.registration_receipt.provider_id==identity.identity.service_id {
                crate::webvh::commit_service_mapping_in_connection(conn,&identity,false).await?;
            }
            sql_query("INSERT INTO service_identity (id,identity) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET identity=EXCLUDED.identity")
                .bind::<Text,_>(SINGLETON_ID).bind::<Jsonb,_>(&value).execute(conn).await?;
            Ok(())
        }).await.map_err(crate::PgTransactionError::into_persistence)
    }
}
