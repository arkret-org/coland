//! Current subject-control transport identity and durable replay prevention.
use arkret_models_integration::RealmActorControlHttpMetadata;
use arkret_wire::DidCoreId;
use coland_storage::{AppletControlCarrier, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::json;

fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("unauthenticated: {detail}"))
}

pub(crate) async fn carrier(
    conn: &mut AsyncPgConnection,
    metadata: &RealmActorControlHttpMetadata,
    governor: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AppletControlCarrier> {
    metadata.validate().map_err(denied)?;
    let current = current_carrier(conn, &metadata.actor_id, governor, at).await?;
    if current.control_ref != metadata.control_ref {
        return Err(denied("control source is no longer current"));
    }
    Ok(current)
}

pub(crate) async fn current_carrier(
    conn: &mut AsyncPgConnection,
    actor: &arkret_wire::ActorId,
    governor: &DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<AppletControlCarrier> {
    actor.validate().map_err(denied)?;
    let subject = actor
        .as_realm_actor_id()
        .ok_or_else(|| denied("Realm actor required"))?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &subject.realm_id).await?;
    #[derive(QueryableByName)]
    struct Authority {
        #[diesel(sql_type=Text)]
        service_id: String,
        #[diesel(sql_type=BigInt)]
        generation: i64,
    }
    let authority =
        sql_query("SELECT service_id,generation FROM realm_authorities WHERE realm_id=$1")
            .bind::<Text, _>(subject.realm_id.as_str())
            .get_result::<Authority>(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
    if authority.service_id != governor.as_str() {
        return Err(denied("destination is not the current Realm governor"));
    }
    let control = crate::realm_actor_control_source::current(conn, actor).await?;
    let document = crate::realm_actor_control_source::document(conn, actor, &control, at).await?;
    let key = arkret_identity::public_key_material_from_document(
        &document,
        &control.value.control_method_kid,
    )
    .map_err(denied)?;
    Ok(AppletControlCarrier {
        actor_id: actor.clone(),
        control_ref: control.source,
        verification_method: control.value.control_method_kid,
        public_key: key.ed25519_bytes().map_err(denied)?,
        governance_service_id: governor.clone(),
        governance_generation: u64::try_from(authority.generation).map_err(denied)?,
    })
}

pub(crate) async fn consume_nonce(
    conn: &mut AsyncPgConnection,
    expected: &AppletControlCarrier,
    metadata: &RealmActorControlHttpMetadata,
    retain_until: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let now = chrono::Utc::now();
    let maximum = arkret_signatures::http_signature::HTTP_SIGNATURE_MAX_LIFETIME_SECONDS
        + arkret_signatures::http_signature::HTTP_SIGNATURE_CREATED_SKEW_SECONDS;
    if retain_until <= now || retain_until > now + chrono::Duration::seconds(maximum) {
        return Err(denied("control signature window is not current"));
    }
    let actual = carrier(conn, metadata, &expected.governance_service_id, now).await?;
    if &actual != expected {
        return Err(denied("control identity changed while verifying transport"));
    }
    sql_query("DELETE FROM realm_actor_control_nonces WHERE actor_id=$1 AND retain_until<=$2")
        .bind::<Jsonb, _>(json!(metadata.actor_id))
        .bind::<Timestamptz, _>(now)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let written = sql_query("INSERT INTO realm_actor_control_nonces(actor_id,nonce,consumed_at,retain_until) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind::<Jsonb,_>(json!(metadata.actor_id)).bind::<Text,_>(&metadata.nonce)
        .bind::<Timestamptz,_>(now).bind::<Timestamptz,_>(retain_until)
        .execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(denied("control nonce already consumed"));
    }
    Ok(())
}
