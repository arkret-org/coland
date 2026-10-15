//! Durable private mapping with subject and alias uniqueness.

use arkret_models_collaboration::call_invitation::CallMediaRosterIdentity;
use arkret_wire::{ActorId, CallId, DeviceId, RealmId};
use async_trait::async_trait;
use coland_storage::{CallMediaSubjectStore, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::RunQueryDsl;

pub struct PgCallMediaSubjectStore {
    pub pool: crate::PgPool,
}

#[derive(QueryableByName)]
struct IdentityRow {
    #[diesel(sql_type = Jsonb)]
    roster_identity: serde_json::Value,
}

#[async_trait]
impl CallMediaSubjectStore for PgCallMediaSubjectStore {
    async fn accepted_binding_key(
        &self,
        realm: &RealmId,
        call: &CallId,
        digest: &arkret_wire::Hash,
        issuer: &arkret_wire::DidUrl,
    ) -> PersistenceResult<Option<[u8; 32]>> {
        use diesel::OptionalExtension;
        #[derive(QueryableByName)]
        struct KeyRow {
            #[diesel(sql_type = diesel::sql_types::Binary)]
            public_key: Vec<u8>,
        }
        let mut conn = crate::pg_conn(&self.pool).await?;
        let row = sql_query("SELECT k.public_key FROM call_media_binding_keys k JOIN realm_commits c ON c.commit_id=k.accepted_commit_id WHERE k.realm_id=$1 AND k.call_id=$2 AND k.binding_digest=$3 AND k.issuer_kid=$4 AND c.realm_id=k.realm_id")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str())
            .bind::<Text,_>(digest.as_str()).bind::<Text,_>(issuer.as_str())
            .get_result::<KeyRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        row.map(|row| {
            row.public_key.try_into().map_err(|_| {
                PersistenceError::Internal(
                    "accepted participant issuer key has invalid length".into(),
                )
            })
        })
        .transpose()
    }

    async fn establish_identity(
        &self,
        realm: &RealmId,
        call: &CallId,
        actor: &ActorId,
        device: &DeviceId,
        candidate: &CallMediaRosterIdentity,
    ) -> PersistenceResult<CallMediaRosterIdentity> {
        let mut conn = crate::pg_conn(&self.pool).await?;
        let row = sql_query("INSERT INTO call_media_subjects (realm_id,call_id,subject_actor_id,subject_device_id,roster_identity) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (realm_id,call_id,subject_actor_id,subject_device_id) DO UPDATE SET roster_identity=call_media_subjects.roster_identity RETURNING roster_identity")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(actor).map_err(PersistenceError::database)?)
            .bind::<Text,_>(device.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(candidate).map_err(PersistenceError::database)?)
            .get_result::<IdentityRow>(&mut *conn).await.map_err(PersistenceError::database)?;
        serde_json::from_value(row.roster_identity).map_err(PersistenceError::database)
    }
}
