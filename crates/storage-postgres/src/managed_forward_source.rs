//! Exact private creation and current sources from the origin's locked native cut.
use arkret_models_collaboration::authority_commit::*;
use arkret_wire::{ActorId, Event};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "device_unauthorized: managed forward source: {error}"
    ))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(invalid)
}
/// Determine the complete ordered writer lock set before reading a source cut.
pub(super) async fn lock_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> Result<(), crate::PgTransactionError> {
    let Some(producer) = event.account_device_producer().map_err(invalid)? else {
        return Ok(());
    };
    let cut = crate::account_device_signer_evidence::forward_source::current_cut(
        conn,
        &producer.account_id,
        &producer.device_id,
    )
    .await?
    .ok_or_else(|| {
        PersistenceError::Conflict(
            "temporarily_unavailable: forward Device PCR is unavailable".into(),
        )
    })?;
    let mut realms = std::collections::BTreeSet::from([cut.authority.realm_id]);
    let rows=sql_query("SELECT e.envelope AS value FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.kind='ak.applet.managed_actor.provision' AND e.state='committed' AND e.envelope#>'{payload,actor_id}'=$1")
        .bind::<Jsonb,_>(json!(ActorId::account(producer.account_id))).load::<Row>(&mut *conn).await?;
    if rows.len() > 1 {
        return Err(invalid("conflicting original provisions").into());
    }
    for row in rows {
        let event: Event = decode(row.value)?;
        realms.insert(event.realm_id);
    }
    for realm in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &realm).await?;
    }
    Ok(())
}

pub(super) async fn require_non_managed(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> Result<(), crate::PgTransactionError> {
    if crate::pcr_applet_device_authority::for_event_in_connection(conn, event, chrono::Utc::now())
        .await?
        .is_some()
    {
        return Err(invalid(
            "managed producer requires the complete private request retention unit",
        )
        .into());
    }
    Ok(())
}

pub(super) fn event(request: &PeerAuthoritySubmitRequest) -> PersistenceResult<&Event> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => Ok(&v.event_submission.event),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => Ok(&v.mls_submission.commit_event),
        _ => Err(invalid("source requested for a non-forward branch")),
    }
}
pub(super) fn managed(
    request: &PeerAuthoritySubmitRequest,
) -> Option<&ForwardManagedActorProvenance> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => {
            v.producer_managed_provenance.as_ref()
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => {
            v.producer_managed_provenance.as_ref()
        }
        _ => None,
    }
}
pub(super) fn device(
    request: &PeerAuthoritySubmitRequest,
) -> PersistenceResult<&arkret_models_identity::ForwardAccountDeviceSignerEvidence> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => v.producer_device_evidence.as_ref(),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => v.producer_device_evidence.as_ref(),
        _ => None,
    }
    .ok_or_else(|| invalid("forward request has no Device evidence"))
}
pub(super) fn bind(
    request: &PeerAuthoritySubmitRequest,
    source: Option<ForwardManagedActorProvenance>,
) -> PeerAuthoritySubmitRequest {
    let mut request = request.clone();
    match &mut request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => {
            v.producer_device_evidence = None;
            v.producer_managed_provenance = source;
        }
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => {
            v.producer_device_evidence = None;
            v.producer_managed_provenance = source;
        }
        _ => {}
    }
    request
}
pub(super) fn digest(request: &PeerAuthoritySubmitRequest) -> PersistenceResult<arkret_wire::Hash> {
    match request {
        PeerAuthoritySubmitRequest::AuthorityForwardEvent(v) => authority_forward_body_digest(v),
        PeerAuthoritySubmitRequest::AuthorityForwardMls(v) => authority_forward_body_digest(v),
        _ => return Err(invalid("non-forward digest")),
    }
    .map_err(invalid)
}
