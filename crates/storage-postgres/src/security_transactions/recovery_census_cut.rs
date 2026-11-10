//! Freeze native discovery obligations with the replacement authorization.
//!
//! This is deliberately not inventory preparation: a pending forward or claim
//! cannot prove activation, absence of old leaves, or a winning cleanup. A
//! coordinator must reconcile these originals, later outcomes and predecessor
//! obligations before publishing the one complete private inventory.

use arkret_models_crypto::{
    ContentEndpoint, ContentRecoveryPreparation, KeyPackagesClaimRequestBody,
};
use arkret_wire::{ActorId, CommittedEventRef, Event, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Nullable, Text};
use diesel::{QueryableByName, sql_query};
use horme::RunQueryDsl as _;
use serde_json::{Value, json};

use crate::{AsyncPgConnection, JsonPayloadRow};

fn unavailable(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "revision_unavailable: recovery census cut {detail}"
    ))
}

#[derive(QueryableByName)]
struct ClaimSource {
    #[diesel(sql_type = Text)]
    source_id: String,
    #[diesel(sql_type = Text)]
    claim_request_id: String,
    #[diesel(sql_type = Text)]
    request_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_body: Value,
}

async fn put(
    conn: &mut AsyncPgConnection,
    episode: &ContentRecoveryPreparation,
    kind: &str,
    identity: impl serde::Serialize,
    scope: Option<&ScopeRef>,
    source: Value,
) -> PersistenceResult<()> {
    let key = arkret_canonical::canonical_sha256(&identity).map_err(unavailable)?;
    let scope = scope
        .map(serde_json::to_value)
        .transpose()
        .map_err(unavailable)?;
    sql_query("INSERT INTO content_recovery_census_sources(authorization_event_ref,source_kind,source_key,effective_scope,source) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(episode.replacement.authorization_event_ref.as_str())
        .bind::<Text,_>(kind).bind::<Text,_>(&key).bind::<Nullable<Jsonb>,_>(&scope)
        .bind::<Jsonb,_>(&source).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    let row = sql_query("SELECT jsonb_build_object('scope',effective_scope,'source',source) AS payload FROM content_recovery_census_sources WHERE authorization_event_ref=$1 AND source_kind=$2 AND source_key=$3 FOR SHARE")
        .bind::<Text,_>(episode.replacement.authorization_event_ref.as_str())
        .bind::<Text,_>(kind).bind::<Text,_>(&key).get_result::<JsonPayloadRow>(&mut *conn)
        .await.map_err(PersistenceError::database)?;
    if row.payload != json!({"scope": scope, "source": source}) {
        return Err(unavailable("an immutable source identity changed"));
    }
    Ok(())
}

async fn claims(
    conn: &mut AsyncPgConnection,
    episode: &ContentRecoveryPreparation,
    kind: &str,
    rows: Vec<ClaimSource>,
) -> PersistenceResult<()> {
    let account = episode
        .replacement
        .actor_id
        .as_account_id()
        .ok_or_else(|| unavailable("Human episode has no full Account"))?;
    for row in rows {
        let request: KeyPackagesClaimRequestBody =
            serde_json::from_value(row.request_body.clone()).map_err(unavailable)?;
        // Shape and signed target coordinates stay meaningful after expiry.
        // Current authorization is not substituted for the archived original.
        request.validate_shape().map_err(unavailable)?;
        if request.service_binding.source_id.as_str() != row.source_id
            || request.claim_request_id.as_str() != row.claim_request_id
            || arkret_canonical::canonical_sha256(&request).map_err(unavailable)?
                != row.request_digest
            || (kind == "outgoing_claim" && request.requester_account_id.as_ref() != Some(account))
            || (kind == "incoming_claim" && request.target_account_id.as_ref() != Some(account))
        {
            return Err(unavailable(
                "claim original differs from its native identity",
            ));
        }
        put(
            conn,
            episode,
            kind,
            (&row.source_id, &row.claim_request_id),
            Some(&request.effective_scope),
            json!({
                "source_id": row.source_id,
                "claim_request_id": row.claim_request_id,
                "request_digest": row.request_digest,
            }),
        )
        .await?;
    }
    Ok(())
}

/// The recovery unit holds its native subject PCR lock. These are immutable
/// locations to reconcile, not a claim that the complete census is available.
/// Empty results leave the episode pending just like nonempty results do.
pub(super) async fn retain(
    conn: &mut AsyncPgConnection,
    episode: &ContentRecoveryPreparation,
) -> PersistenceResult<()> {
    let actor = &episode.replacement.actor_id;
    let actor_json = serde_json::to_value(actor).map_err(unavailable)?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| unavailable("requires a Human Account"))?;
    let account_json = serde_json::to_value(account).map_err(unavailable)?;
    let admissions = sql_query("SELECT jsonb_build_object('admission_key',h.admission_key,'effective_scope',h.effective_scope,'genesis_event_ref',h.genesis_event_ref,'binding',h.binding,'first_source',h.first_source) AS payload FROM content_endpoint_admission_history h WHERE h.binding->'actor_id'=$1")
        .bind::<Jsonb,_>(&actor_json).get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in admissions {
        let binding: ContentEndpoint =
            serde_json::from_value(row.payload["binding"].clone()).map_err(unavailable)?;
        let scope: ScopeRef =
            serde_json::from_value(row.payload["effective_scope"].clone()).map_err(unavailable)?;
        let source: CommittedEventRef =
            serde_json::from_value(row.payload["first_source"].clone()).map_err(unavailable)?;
        binding.validate().map_err(unavailable)?;
        if &binding.actor_id != actor
            || source.stream_ref
                != arkret_wire::CommitStreamRef::from_scope(&scope, None).map_err(unavailable)?
        {
            return Err(unavailable(
                "admission source differs from its subject or scope",
            ));
        }
        let key = row.payload["admission_key"].clone();
        let locator = json!({
            "admission_key": key,
            "genesis_event_ref": row.payload["genesis_event_ref"],
            "first_source": source,
        });
        put(conn, episode, "admission", &key, Some(&scope), locator).await?;
    }
    let outgoing = sql_query("SELECT source_id,claim_request_id,request_digest,request_body FROM ordinary_keypackage_claim_sources WHERE actor_id=$1")
        .bind::<Jsonb,_>(&actor_json).get_results::<ClaimSource>(&mut *conn).await.map_err(PersistenceError::database)?;
    claims(conn, episode, "outgoing_claim", outgoing).await?;
    let incoming = sql_query("SELECT source_id,claim_request_id,request_digest,request_body FROM keypackage_claim_sources WHERE request_body->'target_account_id'=$1")
        .bind::<Jsonb,_>(&account_json).get_results::<ClaimSource>(&mut *conn).await.map_err(PersistenceError::database)?;
    claims(conn, episode, "incoming_claim", incoming).await?;
    // A source may have been signed before a crash that prevented transport
    // enqueue, a destination outcome, replication or current-tree install.
    let forwards = sql_query("SELECT jsonb_build_object('evidence_ref',s.evidence_ref,'event',e.envelope) AS payload FROM account_device_signer_evidence s JOIN canonical_events e ON e.pk=s.forward_event_pk WHERE s.principal_id=$1 AND s.station_id=$2 AND e.kind IN ('ak.mls.genesis','ak.mls.commit')")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str())
        .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in forwards {
        let event: Event =
            serde_json::from_value(row.payload["event"].clone()).map_err(unavailable)?;
        let producer = event
            .account_device_producer()
            .map_err(unavailable)?
            .ok_or_else(|| unavailable("forward lacks its original Device producer"))?;
        if producer.account_id != *account {
            return Err(unavailable("forward original belongs to another subject"));
        }
        let key = row.payload["evidence_ref"].clone();
        // The original and Service history remain in the durable native
        // archive; each episode pins their identity without copying the bytes.
        let locator = json!({"evidence_ref": key, "event_ref": event.event_id});
        put(
            conn,
            episode,
            "outgoing_event",
            &key,
            Some(&event.scope_ref),
            locator,
        )
        .await?;
    }
    // Preserve all unsatisfied episodes, including those whose old leaves have
    // disappeared. This association does not restore their former read rights.
    let predecessors = sql_query("SELECT jsonb_build_object('authorization_event_ref',authorization_event_ref,'replacement',replacement,'pcr_cut',pcr_cut) AS payload FROM content_recovery_episodes WHERE actor_id=$1 AND authorization_event_ref<>$2 AND security_completed_at IS NULL FOR SHARE")
        .bind::<Jsonb,_>(&actor_json).bind::<Text,_>(episode.replacement.authorization_event_ref.as_str())
        .get_results::<JsonPayloadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    for row in predecessors {
        let replacement: ContentEndpoint =
            serde_json::from_value(row.payload["replacement"].clone()).map_err(unavailable)?;
        if replacement.actor_id != ActorId::account(account.clone())
            || row.payload["authorization_event_ref"].as_str()
                != Some(replacement.authorization_event_ref.as_str())
        {
            return Err(unavailable("predecessor has another episode or subject"));
        }
        let key = &replacement.authorization_event_ref;
        put(conn, episode, "predecessor", key, None, row.payload).await?;
    }
    Ok(())
}
