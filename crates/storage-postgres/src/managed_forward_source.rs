//! Exact private creation and current sources from the origin's locked native cut.
use arkret_models_collaboration::authority_commit::*;
use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{ActorId, Event, EventId, ScopeRef};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
struct Row {
    #[diesel(sql_type=Jsonb)]
    value: Value,
    #[diesel(sql_type=Jsonb)]
    commit: Value,
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "device_unauthorized: managed forward source: {error}"
    ))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(invalid)
}
fn reference(event: &Event, role: &str) -> PersistenceResult<EventId> {
    let refs = event
        .semantic_refs
        .iter()
        .filter(|r| r.critical && r.role == role)
        .collect::<Vec<_>>();
    let [reference] = refs.as_slice() else {
        return Err(invalid("original critical reference is not unique"));
    };
    reference.id.as_str().parse().map_err(invalid)
}
async fn original(
    conn: &mut AsyncPgConnection,
    id: &EventId,
) -> PersistenceResult<ManagedCreationAcceptedEvent> {
    let row=sql_query("SELECT e.envelope AS value,c.commit_json AS commit FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id WHERE e.envelope->>'event_id'=$1 AND e.state='committed'")
        .bind::<Text,_>(id.as_str()).get_result::<Row>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||invalid("original accepted Event/Commit is missing"))?;
    Ok(ManagedCreationAcceptedEvent {
        event: decode(row.value)?,
        commit: decode(row.commit)?,
    })
}

/// Determine the complete ordered writer lock set before reading a source cut.
pub(super) async fn lock_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> Result<(), crate::PgTransactionError> {
    let Some(producer) = event.account_device_producer().map_err(invalid)? else {
        return Ok(());
    };
    let cut = crate::pcr_device_status_reader::confirmed_pcr_device_status_cut_in_connection(
        conn,
        &producer.account_id,
        &producer.device_id,
        chrono::Utc::now(),
    )
    .await?
    .ok_or_else(|| invalid("Device PCR is unavailable"))?;
    let mut realms = std::collections::BTreeSet::from([cut.authority.realm_id]);
    let rows=sql_query("SELECT e.envelope AS value,c.commit_json AS commit FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.kind='ak.applet.managed_actor.provision' AND e.state='committed' AND e.envelope#>'{payload,actor_id}'=$1")
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

pub(super) async fn prepare(
    conn: &mut AsyncPgConnection,
    event: &Event,
    history: Option<&AuthenticatedServiceResolution>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ForwardManagedActorProvenance>, crate::PgTransactionError> {
    let Some(authority) = crate::pcr_applet_device_authority::for_event_in_connection(
        conn,
        event,
        chrono::Utc::now(),
    )
    .await?
    else {
        if history.is_some() {
            return Err(invalid("non-managed producer has an extra Service source").into());
        }
        return Ok(None);
    };
    let history =
        history.ok_or_else(|| invalid("original Service method history is unavailable"))?;
    let profile=sql_query("SELECT p.value,c.commit_json AS commit FROM actor_profile_current_results p JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position WHERE p.realm_id=$1 AND p.actor_id=$2 AND p.scope_ref=$3 FOR SHARE OF p")
        .bind::<Text,_>(authority.pcr_realm_id.as_str()).bind::<Jsonb,_>(json!(event.actor_id))
        .bind::<Jsonb,_>(json!(ScopeRef::Realm{realm_id:authority.pcr_realm_id.clone()})).get_result::<Row>(&mut *conn).await?;
    let profile_value: arkret_models_identity::ActorProfile = decode(profile.value)?;
    let profile_id = profile_value
        .id
        .clone()
        .ok_or_else(|| invalid("identity Profile has no immutable id"))?;
    let created_profile = original(
        conn,
        &EventId::from_token_bytes(profile_id.token_bytes()).map_err(invalid)?,
    )
    .await?;
    let accountability =
        original(conn, &reference(&created_profile.event, "accountability")?).await?;
    let provision = original(
        conn,
        &reference(&accountability.event, "applet_managed_actor_provision")?,
    )
    .await?;
    let grant: AccountabilityGrantPayload = decode(json!(accountability.event.payload))?;
    let scopes = grant
        .accountability_scope
        .normalized_set()
        .map_err(invalid)?;
    let current=sql_query("SELECT a.value,c.commit_json AS commit FROM identity_accountability_current_results a JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position WHERE a.realm_id=$1 AND a.issuer_id=$2 AND a.subject_id=$3 AND a.accountability_scope=$4 FOR SHARE OF a")
        .bind::<Text,_>(accountability.event.realm_id.as_str()).bind::<Text,_>(grant.issuer_id.as_str())
        .bind::<Text,_>(grant.subject_id.as_str()).bind::<Jsonb,_>(json!(scopes)).get_result::<Row>(&mut *conn).await?;
    let resolution =
        crate::pcr_applet_device::current_resolution_in_connection(conn, &authority.account_id)
            .await?;
    let pcr_genesis = original(conn, &resolution.genesis_event.event_id).await?;
    let profile_commit: arkret_wire::RealmCommit = decode(profile.commit)?;
    let accountability_commit: arkret_wire::RealmCommit = decode(current.commit)?;
    let value: arkret_models_collaboration::governance::accountability::AccountabilityProjection =
        decode(current.value)?;
    let expires_at = (at + chrono::Duration::minutes(5))
        .min(authority.expires_at)
        .min(
            value
                .expires_at
                .unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC),
        );
    if value.grant_status!=arkret_models_collaboration::governance::accountability::AccountabilityGrantStatus::Active
        || chrono::Utc::now()<value.not_before || chrono::Utc::now()>=expires_at { return Err(invalid("original endorsement is not currently active").into()); }
    let source = ForwardManagedActorProvenance {
        creation: ManagedCreationOriginals {
            provision,
            pcr_genesis,
            accountability,
            profile: created_profile,
        },
        service_resolution: history.clone(),
        current: ManagedIdentityCurrent {
            profile: ManagedProfileCurrent {
                realm_id: authority.pcr_realm_id,
                result: ManagedIdentityResult {
                    selector: ManagedProfileSelector::ActorProfile {
                        actor_profile_id: profile_id,
                    },
                    source_stream_ref: profile_commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: profile_commit.commit_id.clone(),
                        stream_position: profile_commit.stream_position,
                    },
                    value: profile_value,
                },
                commit: profile_commit,
            },
            accountability: ManagedAccountabilityCurrent {
                realm_id: accountability_commit.realm_id.clone(),
                result: ManagedIdentityResult {
                    selector: ManagedAccountabilitySelector::IdentityAccountability {
                        issuer_id: grant.issuer_id,
                        subject_id: grant.subject_id,
                        accountability_scope: scopes,
                    },
                    source_stream_ref: accountability_commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: accountability_commit.commit_id.clone(),
                        stream_position: accountability_commit.stream_position,
                    },
                    value,
                },
                commit: accountability_commit,
            },
            expires_at,
        },
    };
    source.validate().map_err(|error| {
        PersistenceError::Conflict(format!(
            "{}: {error}",
            error
                .error_code()
                .unwrap_or(arkret_wire::ErrorCode::DeviceUnauthorized)
        ))
    })?;
    for original in source.creation.entries() {
        arkret_identity::authenticated_service_document_at(
            history,
            &authority.source_service_id,
            original.event.created_at,
        )
        .map_err(invalid)?;
    }
    Ok(Some(source))
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
