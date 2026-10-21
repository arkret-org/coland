//! Immutable creation completion and replaceable, durable delivery attempts.
use arkret_models_integration::AppletManagedActorAuthoringContext;
use arkret_wire::{AppletId, CommittedEventRef, DidCoreId, Event, Hash, RealmCommit};
use coland_storage::{
    AppletAuthoringCompletion, AppletAuthoringDelivery, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Nullable, Text, Timestamptz};
use diesel::{OptionalExtension as _, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn invalid(message: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {message}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(PersistenceError::database)
}

#[derive(QueryableByName)]
pub(crate) struct CompletionRow {
    #[diesel(sql_type=Text)]
    pub applet_id: String,
    #[diesel(sql_type=Text)]
    pub request_digest: String,
    #[diesel(sql_type=Text)]
    pub realm_id: String,
    #[diesel(sql_type=Jsonb)]
    pub actor_id: Value,
    #[diesel(sql_type=Jsonb)]
    pub creation_ref: Value,
    #[diesel(sql_type=Text)]
    pub destination_id: String,
    #[diesel(sql_type=Jsonb)]
    pub recipient_package: Value,
}
impl CompletionRow {
    pub(crate) fn decode(self) -> PersistenceResult<AppletAuthoringCompletion> {
        Ok(AppletAuthoringCompletion {
            applet_id: self.applet_id.parse().map_err(PersistenceError::database)?,
            request_digest: self
                .request_digest
                .parse()
                .map_err(PersistenceError::database)?,
            realm_id: self.realm_id.parse().map_err(PersistenceError::database)?,
            actor_id: decode(self.actor_id)?,
            creation_ref: decode(self.creation_ref)?,
            recipient_package: decode(self.recipient_package)?,
            destination_id: self
                .destination_id
                .parse()
                .map_err(PersistenceError::database)?,
        })
    }
}

pub(crate) async fn retain(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    digest: &Hash,
) -> PersistenceResult<()> {
    let candidate = crate::realm_actor_control::creation(event)?
        .ok_or_else(|| invalid("completion requires a creation"))?;
    let creation = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let package = sql_query("SELECT record->'package' AS value FROM applet_installations WHERE applet_id=$1 AND effective_scope_key=$2")
        .bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(coland_storage::applet_effective_scope_key(&candidate.creation_scope)?)
        .get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let package: arkret_models_integration::AppletPackage = decode(package.value)?;
    if package.service_id != candidate.service_id || package.applet_id != candidate.applet_id {
        return Err(invalid(
            "completion recipient package differs from accepted creation",
        ));
    }
    let written = sql_query("INSERT INTO applet_authoring_completions(applet_id,request_digest,realm_id,actor_id,creation_ref,destination_id,recipient_package,accepted_at,next_attempt_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(candidate.applet_id.as_str()).bind::<Text,_>(digest.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Jsonb,_>(json!(candidate.actor_id)).bind::<Jsonb,_>(json!(creation)).bind::<Text,_>(candidate.service_id.as_str())
        .bind::<Jsonb,_>(json!(package)).bind::<Timestamptz,_>(commit.committed_at).execute(conn).await.map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(invalid("creation completion already exists"));
    }
    Ok(())
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct AttemptRow {
    #[diesel(sql_type=Nullable<Jsonb>)]
    delivery_attempt: Option<Value>,
    #[diesel(sql_type=Nullable<Text>)]
    delivery_digest: Option<String>,
}

pub(crate) async fn prepare(
    conn: &mut AsyncPgConnection,
    completion: &AppletAuthoringCompletion,
    governor: &DidCoreId,
    caller: &coland_storage::RealmActorMaterialCaller,
    sign: coland_storage::RealmActorMaterialSigner<'_>,
) -> PersistenceResult<AppletAuthoringDelivery> {
    crate::realm_actor_control::require_current_governor(conn, &completion.realm_id, governor)
        .await?;
    crate::realm_management_archive::require_unfrozen(conn, &completion.realm_id).await?;
    let row = sql_query("SELECT delivery_attempt,delivery_digest FROM applet_authoring_completions WHERE applet_id=$1 AND request_digest=$2 AND realm_id=$3 AND actor_id=$4 AND creation_ref=$5 AND destination_id=$6 AND recipient_package=$7 AND delivered_at IS NULL FOR UPDATE")
        .bind::<Text,_>(completion.applet_id.as_str()).bind::<Text,_>(completion.request_digest.as_str()).bind::<Text,_>(completion.realm_id.as_str())
        .bind::<Jsonb,_>(json!(completion.actor_id)).bind::<Jsonb,_>(json!(completion.creation_ref)).bind::<Text,_>(completion.destination_id.as_str()).bind::<Jsonb,_>(json!(completion.recipient_package))
        .get_result::<AttemptRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(|| invalid("completion no longer pending"))?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let coland_storage::RealmActorMaterialCaller::Service { service_id, .. } = caller else {
        return Err(invalid("completion recipient must be its Service"));
    };
    if service_id != &completion.destination_id {
        return Err(invalid("completion recipient changed"));
    }
    // Retries never re-run authoring. A fresh read rechecks the current manager
    // and signs the same accepted Event/Commit/fact at the current governance cut.
    let request = arkret_models_integration::RealmActorMaterialRequest::Event {
        actor_id: completion.actor_id.clone(),
        request_nonce: format!("{}{}", uuid::Uuid::now_v7(), uuid::Uuid::now_v7()),
        target: completion.creation_ref.clone(),
    };
    let material =
        crate::realm_actor_material::read(conn, &request, caller, governor, sign).await?;
    let arkret_models_integration::RealmActorMaterialResult::Event { event, .. } = &material.result
    else {
        return Err(invalid("completion material is not an Event"));
    };
    let candidate = crate::realm_actor_control::creation(event)?
        .ok_or_else(|| invalid("completion original is not creation"))?;
    if candidate.applet_id != completion.applet_id
        || candidate.actor_id != completion.actor_id
        || candidate.service_id != completion.destination_id
    {
        return Err(invalid("completion original identity changed"));
    }
    // Routing was frozen with the accepted creation. Uninstalling or replacing
    // the business installation does not redirect this private receipt.
    let package = &completion.recipient_package;
    if package.service_id != completion.destination_id
        || !package.endpoint_policy.endpoints.iter().any(|endpoint| {
            endpoint.path == "/_arkret/edge/applet/transactions"
                && endpoint.method == arkret_models_integration::AppletEndpointMethod::Post
                && endpoint.auth
                    == Some(arkret_models_integration::AppletEndpointAuth::WebhookSignature)
        })
    {
        return Err(invalid(
            "original completion recipient endpoint is unavailable",
        ));
    }
    let delivery = if let Some(prior) = row.delivery_attempt {
        if row.delivery_digest.as_deref()
            != Some(
                arkret_canonical::canonical_sha256(&prior)
                    .map_err(PersistenceError::database)?
                    .as_str(),
            )
        {
            return Err(invalid("delivery digest differs"));
        }
        let prior: AppletAuthoringDelivery = decode(prior)?;
        if prior.source_id == *governor
            && prior.context.material.governance_generation == material.governance_generation
            && prior.context.material.authority_ref == material.authority_ref
            && prior.endpoint == package.base_url
            && prior.context.material.expires_at > now + chrono::Duration::seconds(20)
        {
            if json!(prior.context.material.result) != json!(material.result) {
                return Err(invalid("completion original changed"));
            }
            prior
        } else {
            fresh(
                governor,
                &completion.destination_id,
                &package.base_url,
                material,
            )
        }
    } else {
        fresh(
            governor,
            &completion.destination_id,
            &package.base_url,
            material,
        )
    };
    let value = json!(delivery);
    let digest = arkret_canonical::canonical_sha256(&value).map_err(PersistenceError::database)?;
    sql_query("UPDATE applet_authoring_completions SET delivery_attempt=$3,delivery_digest=$4,next_attempt_at=$5 WHERE applet_id=$1 AND request_digest=$2")
        .bind::<Text,_>(completion.applet_id.as_str()).bind::<Text,_>(completion.request_digest.as_str()).bind::<Jsonb,_>(value).bind::<Text,_>(digest)
        .bind::<Timestamptz,_>(now + chrono::Duration::seconds(30)).execute(conn).await.map_err(PersistenceError::database)?;
    Ok(delivery)
}

fn fresh(
    governor: &DidCoreId,
    destination: &DidCoreId,
    endpoint: &str,
    material: arkret_models_integration::RealmActorMaterialOutcome,
) -> AppletAuthoringDelivery {
    AppletAuthoringDelivery {
        source_id: governor.clone(),
        destination_id: destination.clone(),
        endpoint: endpoint.to_owned(),
        idempotency_key: uuid::Uuid::now_v7().to_string(),
        context: AppletManagedActorAuthoringContext { material },
    }
}

pub(crate) async fn acknowledge(
    conn: &mut AsyncPgConnection,
    applet: &AppletId,
    request: &Hash,
    governor: &DidCoreId,
    digest: &Hash,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let row = sql_query("SELECT to_jsonb(realm_id) AS value FROM applet_authoring_completions WHERE applet_id=$1 AND request_digest=$2")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(request.as_str()).get_result::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let realm = decode(row.value)?;
    crate::realm_actor_control::require_current_governor(conn, &realm, governor).await?;
    crate::realm_management_archive::require_unfrozen(conn, &realm).await?;
    let updated = sql_query("UPDATE applet_authoring_completions SET delivered_at=COALESCE(delivered_at,$4) WHERE applet_id=$1 AND request_digest=$2 AND delivery_digest=$3 AND delivery_attempt->>'source_id'=$5")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(request.as_str()).bind::<Text,_>(digest.as_str()).bind::<Timestamptz,_>(at).bind::<Text,_>(governor.as_str()).execute(conn).await.map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(invalid(
            "completion acknowledgement differs from current attempt",
        ));
    }
    Ok(())
}
