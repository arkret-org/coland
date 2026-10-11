//! Exact Service-owned Applet authority material at one read-only MVCC cut.
use arkret_models_collaboration::applet_installation_authority::{
    AppletAuthorityMaterialOutcome, AppletAuthorityMaterialRequestBody, AppletCommittedEvent,
};
use arkret_models_collaboration::events_payloads::CapabilityGrantPayload;
use arkret_models_collaboration::exact_current_results::{
    CapabilityGrantExactCurrentRow, CapabilityGrantExactCurrentSelector,
    CapabilityGrantExactCurrentSelectorKind, ExactCurrentResultEntry,
    ExactCurrentResultsReadOutcome,
};
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{
    ActorId, AppletId, CommitStreamHead, CommitStreamRef, CommittedEventFullView, DidCoreId,
    EventId, EventKind, GrantId,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::capability_grant_current_results::{CapabilityGrantCurrentResultReadRow, decode_row};

fn unavailable() -> PersistenceError {
    PersistenceError::Conflict(
        "failed_precondition: requested Applet authority material unavailable".into(),
    )
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(PersistenceError::database)
}
#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct AcceptedRow {
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: Value,
}
#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type=BigInt)]
    generation: i64,
    #[diesel(sql_type=Text)]
    service_id: String,
}

async fn accepted(
    conn: &mut AsyncPgConnection,
    event_id: &EventId,
) -> PersistenceResult<CommittedEventFullView> {
    let row=sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<Binary,_>(event_id.token_bytes().to_vec()).get_result::<AcceptedRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
    let full = CommittedEventFullView {
        event: decode(row.envelope)?,
        commit: decode(row.commit_json)?,
    };
    if &full.event.event_id != event_id
        || full.commit.event_ref != *event_id
        || full.commit.realm_id != full.event.realm_id
        || full.commit.stream_ref
            != CommitStreamRef::from_scope(&full.event.scope_ref, Some(full.event.realm_id.clone()))
                .map_err(PersistenceError::database)?
    {
        return Err(unavailable());
    }
    let suite = full
        .event
        .event_id
        .event_digest()
        .digest_suite()
        .map_err(PersistenceError::database)?;
    full.event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(PersistenceError::database)?;
    full.commit
        .validate_content_address()
        .map_err(PersistenceError::database)?;

    Ok(full)
}

async fn portable(
    conn: &mut AsyncPgConnection,
    full: CommittedEventFullView,
) -> PersistenceResult<AppletCommittedEvent> {
    let evidence =
        crate::account_device_committed_evidence::read(conn, &full.event, &full.commit).await?;
    let full = AppletCommittedEvent {
        event: full.event,
        commit: full.commit,
        producer_device_evidence: evidence,
    };
    full.validate_structural()
        .map_err(PersistenceError::database)?;
    Ok(full)
}

pub(crate) async fn read(
    conn: &mut AsyncPgConnection,
    applet: &AppletId,
    service: &DidCoreId,
    station: &DidCoreId,
    request: &AppletAuthorityMaterialRequestBody,
) -> PersistenceResult<AppletAuthorityMaterialOutcome> {
    if !(1..=64).contains(&request.grant_ids.len())
        || request
            .grant_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != request.grant_ids.len()
        || matches!(
            &request.effective_scope,
            arkret_wire::ScopeRef::RealmGenesis | arkret_wire::ScopeRef::Sidecar { .. }
        )
    {
        return Err(unavailable());
    }
    let realm = request.effective_scope.realm_id();
    let scope_key = coland_storage::applet_effective_scope_key(&request.effective_scope)?;
    let install=sql_query("SELECT i.record AS value FROM applet_installations i JOIN applet_managed_identities d ON d.applet_id=i.applet_id AND d.target_station_id=$3 WHERE i.applet_id=$1 AND i.effective_scope_key=$2 AND d.record#>>'{initial_package,service_id}'=$4")
        .bind::<Text,_>(applet.as_str()).bind::<Text,_>(scope_key).bind::<Text,_>(station.as_str()).bind::<Text,_>(service.as_str()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
    if install
        .value
        .pointer("/package/service_id")
        .and_then(Value::as_str)
        != Some(service.as_str())
    {
        return Err(unavailable());
    }
    // Audit provenance follows the original accepted parent, never the latest
    // mutable installation. A replaced installation may remain a read boundary
    // for this Service while its old grants carry only historical authority.
    let mut source_registration: Option<CommittedEventFullView> = None;
    for id in &request.grant_ids {
        let event_id =
            EventId::from_token_bytes(id.token_bytes()).map_err(PersistenceError::database)?;
        let original = accepted(conn, &event_id).await?;
        let payload: CapabilityGrantPayload = decode(
            serde_json::to_value(&original.event.payload).map_err(PersistenceError::database)?,
        )?;
        let binding = payload
            .grant
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::AuthorityControl
                    && c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
            })
            .collect::<Vec<_>>();
        if original.event.kind != EventKind::CapabilityGrant
            || original.event.scope_ref != request.effective_scope
            || !matches!(&payload.grant.subject,CapabilitySubject::Actor(actor) if actor==&ActorId::service(service.clone()))
            || binding.len() != 1
            || binding[0].applet_id.as_ref() != Some(applet)
            || binding[0].executed_by.as_ref() != Some(&ActorId::service(service.clone()))
        {
            return Err(unavailable());
        }
        let epoch = binding[0]
            .registration_epoch
            .as_ref()
            .ok_or_else(unavailable)?;
        // Only positions in the same exact Commit stream are compared. The
        // registration accepted immediately before this parent is its source
        // anchor, including after an epoch was replaced and later restored.
        let row=sql_query("SELECT r.envelope,rc.commit_json FROM realm_commits gc JOIN canonical_events g ON g.pk=gc.event_pk JOIN realm_commits rc ON rc.stream_key=gc.stream_key AND rc.stream_position<gc.stream_position JOIN canonical_events r ON r.pk=rc.event_pk JOIN applet_registration_instances a ON a.accepted_commit_id=rc.commit_id AND a.registration_event_ref=r.envelope->>'event_id' WHERE g.id=$1 AND g.state='committed' AND r.state='committed' AND r.kind='ak.applet.registration' AND r.envelope->'scope_ref'=$2 AND a.applet_id=$3 AND r.envelope#>>'{payload,service_id}'=$4 AND r.envelope#>>'{payload,registration_epoch}'=$5 ORDER BY rc.stream_position DESC LIMIT 1")
            .bind::<Binary,_>(event_id.token_bytes().to_vec()).bind::<Jsonb,_>(serde_json::to_value(&request.effective_scope).map_err(PersistenceError::database)?)
            .bind::<Text,_>(applet.as_str()).bind::<Text,_>(service.as_str()).bind::<Text,_>(epoch.as_str())
            .get_result::<AcceptedRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
        let registration = CommittedEventFullView {
            event: decode(row.envelope)?,
            commit: decode(row.commit_json)?,
        };
        let registration = accepted(conn, &registration.event.event_id).await?;
        if source_registration
            .as_ref()
            .is_some_and(|source| source.event.event_id != registration.event.event_id)
        {
            return Err(unavailable());
        }
        source_registration = Some(registration);
    }
    let registration = portable(conn, source_registration.ok_or_else(unavailable)?).await?;
    let registration_payload: AppletRegistrationPayload = decode(
        serde_json::to_value(&registration.event.payload).map_err(PersistenceError::database)?,
    )?;
    if registration.event.kind != EventKind::AppletRegistration
        || registration.event.scope_ref != request.effective_scope
        || registration_payload.applet_id != *applet
        || registration_payload.service_id != *service
    {
        return Err(unavailable());
    }
    let tenure = sql_query("SELECT generation,service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(unavailable)?;
    if tenure.service_id != station.as_str() {
        return Err(unavailable());
    }
    let generation = u64::try_from(tenure.generation).map_err(PersistenceError::database)?;
    let scope = CommitStreamRef::from_scope(&request.effective_scope, None)
        .map_err(PersistenceError::database)?;
    let stream_key = crate::authority_commit::stream_key(&scope)?;
    let head=sql_query("SELECT commit_json AS value FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1")
        .bind::<Text,_>(stream_key).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
    let head: arkret_wire::RealmCommit = decode(head.value)?;
    let effective_head = CommitStreamHead {
        stream_ref: head.stream_ref,
        stream_position: head.stream_position,
        commit_id: head.commit_id,
    };
    let mut grant_events = Vec::with_capacity(request.grant_ids.len());
    let mut current_results = Vec::with_capacity(request.grant_ids.len());
    let actor = ActorId::service(service.clone());
    for id in &request.grant_ids {
        let current=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 AND grant_id=$2")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(id.as_str()).get_result::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(unavailable)?;
        let current = decode_row(current)?;
        let current_full = accepted(conn, &current.source.event_id).await?;
        if current_full.commit.commit_id != current.source.commit_id
            || current_full.commit.stream_ref != current.source.stream_ref
            || current_full.commit.stream_position != current.source.stream_position
        {
            return Err(unavailable());
        }
        match current.status {
            coland_storage::CapabilityGrantCurrentStatus::Active
                if current_full.event.kind == EventKind::CapabilityGrant
                    && current_full.event.event_id.token_bytes() == id.token_bytes() => {}
            coland_storage::CapabilityGrantCurrentStatus::Revoked
                if current_full.event.kind == EventKind::CapabilityRevoke
                    && current_full
                        .event
                        .payload
                        .get("grant_id")
                        .and_then(Value::as_str)
                        == Some(id.as_str()) => {}
            coland_storage::CapabilityGrantCurrentStatus::Relinquished
                if current_full.event.kind == EventKind::CapabilityRelinquish
                    && current_full
                        .event
                        .payload
                        .get("grant_id")
                        .and_then(Value::as_str)
                        == Some(id.as_str()) => {}
            _ => return Err(unavailable()),
        }
        let event_id =
            EventId::from_token_bytes(id.token_bytes()).map_err(PersistenceError::database)?;
        let original = accepted(conn, &event_id).await?;
        let original = portable(conn, original).await?;
        let payload: CapabilityGrantPayload = decode(
            serde_json::to_value(&original.event.payload).map_err(PersistenceError::database)?,
        )?;
        let bindings = payload
            .grant
            .constraints
            .iter()
            .filter(|c| {
                c.constraint_kind == GrantConstraintKind::AuthorityControl
                    && c.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
            })
            .collect::<Vec<_>>();
        if original.event.kind != EventKind::CapabilityGrant
            || GrantId::from_event_id(&original.event.event_id) != *id
            || original.event.scope_ref != request.effective_scope
            || current.source.stream_ref != scope
            || !matches!(&payload.grant.subject,CapabilitySubject::Actor(subject) if subject==&actor)
            || !matches!(&current.value.subject, CapabilitySubject::Actor(subject) if subject == &actor)
            || bindings.len() != 1
            || bindings[0].applet_id.as_ref() != Some(applet)
            || bindings[0].executed_by.as_ref() != Some(&actor)
            || bindings[0].registration_epoch.as_ref()
                != Some(&registration_payload.registration_epoch)
            || payload.grant.actions != current.value.actions
            || payload.grant.constraints != current.value.constraints
            || payload.grant.resources != current.value.resources
            || payload.grant.issuer_id != current.value.issuer_id
            || payload.grant.issuer_authority_refs != current.value.issuer_authority_refs
        {
            return Err(unavailable());
        }
        let selector = CapabilityGrantExactCurrentSelector {
            kind: CapabilityGrantExactCurrentSelectorKind::CapabilityGrant,
            grant_id: id.clone(),
        };
        let present = ExactCurrentResultsReadOutcome::Present {
            realm_id: realm.clone(),
            governance_generation: generation,
            effective_stream_head: effective_head.clone(),
            entry: ExactCurrentResultEntry::CapabilityGrant(CapabilityGrantExactCurrentRow {
                selector: selector.clone(),
                source_stream_ref: current.source.stream_ref,
                revision: current.revision,
                value: current.value,
            }),
        };
        grant_events.push(original);
        current_results.push(present);
    }
    let outcome = AppletAuthorityMaterialOutcome {
        applet_id: applet.clone(),
        effective_scope: request.effective_scope.clone(),
        registration,
        grant_events,
        current_results,
    };
    outcome
        .validate_structural()
        .map_err(PersistenceError::database)?;
    Ok(outcome)
}
