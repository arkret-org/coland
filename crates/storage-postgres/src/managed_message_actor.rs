//! Accepted Applet Service proof and managed Message identity at one write cut.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_integration::AppletRegistrationPayload;
use arkret_wire::{ActorId, Event, EventKind, GrantId};
use coland_storage::{AppletEventProducerGuard, PersistenceError, PersistenceResult};
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

use crate::capability_grant_current_results::{
    CapabilityGrantCurrentResultReadRow, RealmAuthorityRootReadRow, decode_authority_root,
    decode_row, grant_is_active_at, validate_ancestor_graph,
};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
fn denied(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
pub(crate) async fn registration(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<AppletRegistrationPayload> {
    let applet = event
        .applet_id
        .as_ref()
        .ok_or_else(|| denied("Applet producer has no applet_id"))?;
    let service = service_for_event(conn, event).await?;
    registration_for_scope(conn, &event.realm_id, applet, &service).await
}

pub(crate) async fn registration_for_scope(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    applet: &arkret_wire::AppletId,
    service: &arkret_wire::DidCoreId,
) -> PersistenceResult<AppletRegistrationPayload> {
    let row=sql_query("SELECT r.value FROM applet_registration_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.applet_id=$2 AND r.service_id=$3 AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position AND e.kind='ak.applet.registration' AND e.state='committed' FOR SHARE OF r")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(applet.as_str()).bind::<Text,_>(service.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("Applet has no accepted current registration"))?;
    serde_json::from_value(row.value).map_err(PersistenceError::database)
}

/// Resolve the executor against an accepted registration without changing the
/// Event carrier. Native Service authors have no delegated executed_by field.
pub(crate) fn registered_executor(
    event: &Event,
    registration: &AppletRegistrationPayload,
) -> PersistenceResult<ActorId> {
    let service = ActorId::service(registration.service_id.clone());
    if (event.actor_id == service && event.executed_by.is_none())
        || event.executed_by.as_ref() == Some(&service)
    {
        Ok(service)
    } else {
        Err(denied(
            "Applet Event is not authored or executed by its exact Service",
        ))
    }
}

/// The caller supplies a fresh DID document, not a verified flag. The current
/// registration evidence re-binds its whole material and producer method here.
pub(crate) fn prepare_applet_producer_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a Event,
    guard: &'a AppletEventProducerGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = PersistenceResult<
                    arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
                >,
            > + Send
            + 'a,
    >,
> {
    crate::boxed_future(|| async move {
        // Preparation resolves the producer's immutable signing fact. The
        // accepting transaction checks business grants with its prepared votes.
        if matches!(
            event.kind,
            EventKind::RealmActorRecoveryBegin | EventKind::RealmActorControlReset
        ) {
            return crate::realm_actor_control::recovery_service_fact(conn, event, guard, at).await;
        }
        let (fact, _) = require_applet_producer_inner(conn, event, guard, at, None).await?;
        Ok(fact.into())
    })
}

type QualifiedAppletProducer = (
    arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact,
    Vec<crate::approval_admission::QualifiedApproval>,
);

pub(crate) fn require_applet_producer_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a Event,
    guard: &'a AppletEventProducerGuard,
    commit: &'a arkret_wire::RealmCommit,
    prepared: Option<&'a coland_storage::EventApprovalCommit>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = PersistenceResult<QualifiedAppletProducer>> + Send + 'a>,
> {
    crate::boxed_future(|| async move {
        if matches!(
            event.kind,
            EventKind::RealmActorRecoveryBegin | EventKind::RealmActorControlReset
        ) {
            return Ok((
                crate::realm_actor_control::recovery_service_fact(
                    conn,
                    event,
                    guard,
                    commit.committed_at,
                )
                .await?,
                Vec::new(),
            ));
        }
        let (fact, approvals) = require_applet_producer_inner(
            conn,
            event,
            guard,
            commit.committed_at,
            Some((commit, prepared)),
        )
        .await?;
        Ok((fact.into(), approvals))
    })
}

async fn require_applet_producer_inner(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletEventProducerGuard,
    at: chrono::DateTime<chrono::Utc>,
    acceptance: Option<(
        &arkret_wire::RealmCommit,
        Option<&coland_storage::EventApprovalCommit>,
    )>,
) -> PersistenceResult<(
    arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
    Vec<crate::approval_admission::QualifiedApproval>,
)> {
    let mut accepted = Vec::new();
    let effective_scope = crate::realm_actor_control::effective_scope(event)?;
    let creation = crate::realm_actor_control::creation(event)?;
    let registration = registration(conn, event).await?;
    let service = ActorId::service(registration.service_id.clone());
    let executor = registered_executor(event, &registration)?;
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&guard.service_did_document)
        .map_err(denied)?;
    let scope = coland_storage::applet_effective_scope_key(&effective_scope)?;
    let install=sql_query("SELECT i.record AS value FROM applet_installations i JOIN applet_registration_current_results r ON r.realm_id=$3 AND r.applet_id=i.applet_id AND r.service_id=i.service_id JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref AND a.registration_event_ref=i.record#>>'{registration_event,event_id}' WHERE i.applet_id=$1 AND i.effective_scope_key=$2 AND i.service_id=$4 FOR UPDATE OF i")
        .bind::<Text,_>(registration.applet_id.as_str()).bind::<Text,_>(scope).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(registration.service_id.as_str())
        .get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("Applet is not installed on this exact scope"))?;
    if install
        .value
        .pointer("/package/registration_epoch")
        .and_then(Value::as_str)
        != Some(registration.registration_epoch.as_str())
        || install
            .value
            .get("revoked_at")
            .is_some_and(|value| !value.is_null())
        || !matches!(
            install.value.get("status").and_then(Value::as_str),
            Some("installed" | "partially_installed")
        )
    {
        return Err(denied("Applet installation epoch is not active"));
    }
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| denied("Applet Event producer proof is absent"))?;
    if proof.verification_method != registration.webhook_auth.key_ref {
        return Err(denied(
            "Applet producer method differs from accepted registration",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(denied)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| PersistenceError::Conflict(format!("signature_invalid: {error}")))?;
    event
        .verify_producer_proof_self_consistency(suite)
        .map_err(|error| PersistenceError::Conflict(format!("signature_invalid: {error}")))?;
    let key = arkret_identity::public_key_material_from_document(
        &guard.service_did_document,
        &proof.verification_method,
    )
    .map_err(denied)?;
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(denied)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(|error| PersistenceError::Conflict(format!("signature_invalid: {error}")))?;
    let grant_id = event
        .authorization_ref
        .as_ref()
        .ok_or_else(|| denied("Applet authorization_ref absent"))?
        .as_str()
        .parse::<GrantId>()
        .map_err(denied)?;
    let rows=sql_query("SELECT realm_id,grant_id,status,current_event_id,current_commit_id,current_stream_ref,current_stream_position,value FROM capability_grant_current_results WHERE realm_id=$1 ORDER BY grant_id FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).load::<CapabilityGrantCurrentResultReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut grants = BTreeMap::new();
    for row in rows {
        let record = decode_row(row)?;
        grants.insert(record.grant_id, record.value);
    }
    let grant = grants
        .get(&grant_id)
        .ok_or_else(|| denied("Applet authorization grant has no accepted current"))?;
    // Only this exact installation contract binds a Service producer to its
    // installed authority pair. The generic grant evaluator retains distinct
    // Account and Service identities.
    let native_service = event.actor_id == service && event.executed_by.is_none();
    if event.kind == EventKind::AppletBridgeError {
        let payload: arkret_models_integration::AppletBridgeErrorPayload = serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(denied)?;
        if !native_service
            || payload.applet_id != registration.applet_id
            || payload.realm_id != event.realm_id
        {
            return Err(denied(
                "bridge audit must bind its exact native Service installation",
            ));
        }
    }
    // Grant authority belongs to the actual original producer. A Service
    // executing an Account-shaped Event cannot borrow that Account's terminal
    // child; this is the same coordinate used by the SDK Applet admission.
    let grant_actor = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    if grant_actor != &event.actor_id {
        let account_self = matches!(
            event.kind.as_str(),
            arkret_wire::CapabilityActionId::INVITE_ACCEPT
                | arkret_wire::event_kind_str::PROFILE_CREATE
                | arkret_wire::event_kind_str::PROFILE_UPDATE
                | arkret_wire::CapabilityActionId::CAPABILITY_RELINQUISH
        ) || (event.kind == EventKind::MemberState
            && event.payload.get("member_id")
                == serde_json::to_value(&event.actor_id).ok().as_ref());
        if account_self {
            return Err(denied(
                "Applet Service cannot sign the managed Account's own consent or identity control",
            ));
        }
    }
    // Closing one's own accepted terminal child is issuer control. It does
    // not spend or revive a revoked/expired business parent.
    let revoking_own_child = if native_service && event.kind == EventKind::CapabilityRevoke {
        let payload: arkret_models_collaboration::events_payloads::CapabilityRevokePayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(denied)?;
        if let Some(target) = grants.get(&payload.grant_id) {
            target.issuer_id == service
                && target.issuer_authority_refs.iter().all(|source| matches!(source,
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant { .. }))
                && target.issuer_authority_refs.iter().any(|source| matches!(source,
                    arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {grant_id:parent}
                        if parent==&grant_id))
                && crate::capability_grant_current_results::managed_subject_role(
                    conn,
                    event,
                    &target.subject,
                    &target.issuer_id,
                    at,
                )
                .await?
                .is_some()
        } else {
            false
        }
    } else {
        false
    };
    if (!grant_is_active_at(grant, at) && !revoking_own_child)
        || !matches!(&grant.subject,CapabilitySubject::Actor(actor) if actor==grant_actor)
    {
        return Err(PersistenceError::Conflict(
            "capability_denied: Applet authorization grant is not active for the exact original producer".into(),
        ));
    }
    if matches!(
        event.kind,
        EventKind::MessageCreate | EventKind::MemberState | EventKind::AppletBridgeError
    ) && !arkret_schema::capability_actions_for_event_kind(event.kind.as_str())
        .filter(|descriptor| {
            descriptor.required_evaluator_checks.is_empty()
                || (event.kind == EventKind::AppletBridgeError
                    && native_service
                    && descriptor.required_evaluator_checks == ["active_applet_registration_exact"])
        })
        .any(|descriptor| {
            grant
                .actions
                .iter()
                .any(|action| action == descriptor.action.as_str())
        })
    {
        return Err(denied(
            "Applet authorization grant does not authorize this Event action",
        ));
    }
    let resource = match &effective_scope {
        arkret_wire::ScopeRef::Realm { realm_id } => {
            arkret_wire::WireResourceSelector::realm(realm_id.clone())
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
        _ => {
            return Err(denied(
                "Applet producer has no supported exact installation scope",
            ));
        }
    };
    if !grant
        .resources
        .iter()
        .any(|candidate| candidate.is_exact_scope(&effective_scope))
    {
        return Err(denied(
            "Applet authorization grant does not name its exact installation scope",
        ));
    }
    if !grant.constraints.iter().any(|constraint| {
        constraint.constraint_kind == GrantConstraintKind::AuthorityControl
            && constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority)
            && constraint.applet_id.as_ref() == Some(&registration.applet_id)
            && constraint.executed_by.as_ref() == Some(&service)
            && constraint.registration_epoch.as_ref() == Some(&registration.registration_epoch)
    }) {
        return Err(denied(
            "Applet authorization grant lacks the exact Service and registration epoch binding",
        ));
    }
    if matches!(
        event.kind,
        EventKind::MessageCreate | EventKind::MemberState | EventKind::AppletBridgeError
    ) {
        let actions = arkret_schema::capability_actions_for_event_kind(event.kind.as_str())
            .filter(|descriptor| {
                descriptor.required_evaluator_checks.is_empty()
                    || (event.kind == EventKind::AppletBridgeError
                        && native_service
                        && descriptor.required_evaluator_checks
                            == ["active_applet_registration_exact"])
            })
            .map(|descriptor| descriptor.action.as_str())
            .collect::<Vec<_>>();
        let facts = coland_storage::OperationFacts {
            applet_id: Some(registration.applet_id.to_string()),
            // A native Service write has no delegated executed_by carrier.
            // Both native and delegated producers were bound to this exact
            // Service above; the Applet constraint evaluates that executor.
            executed_by: Some(executor),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            strand_id: event
                .payload
                .get("strand_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            track: event
                .payload
                .get("track_name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            object_kind: (event.kind == EventKind::MessageCreate).then(|| "message".to_owned()),
            ..Default::default()
        };
        if let Some((commit, prepared)) = acceptance {
            accepted.extend(
                crate::boxed_future(|| {
                    require_producer_grant(
                        conn,
                        event,
                        commit,
                        prepared,
                        grant,
                        grant_actor,
                        &actions,
                        &resource,
                        &facts,
                    )
                })
                .await?,
            );
        }
    }
    if let Some(candidate) = creation.as_ref() {
        let action = match candidate.actor_role {
            arkret_models_integration::RealmActorCreatePayloadActorRole::Bot => {
                "ak.applet.bot.provision"
            }
            arkret_models_integration::RealmActorCreatePayloadActorRole::Ghost => {
                "ak.applet.ghost.provision"
            }
        };
        if !native_service {
            return Err(denied(
                "creation requires its exact Service provisioning permission",
            ));
        }
        if !grant.actions.iter().any(|value| value == action) {
            return Err(PersistenceError::Conflict(
                "capability_denied: creation requires its exact Service provisioning permission"
                    .into(),
            ));
        }
        let facts = coland_storage::OperationFacts {
            applet_id: Some(registration.applet_id.to_string()),
            executed_by: Some(service.clone()),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            ..Default::default()
        };
        if let Some((commit, prepared)) = acceptance {
            accepted.extend(
                require_producer_grant(
                    conn,
                    event,
                    commit,
                    prepared,
                    grant,
                    &service,
                    &[action],
                    &resource,
                    &facts,
                )
                .await?,
            );
            // Creation is private, but its actual creation scope still consumes
            // the independent Realm governance quorum at this accepting cut.
            accepted.extend(
                crate::approval_admission::require_governance(
                    conn,
                    event,
                    commit,
                    prepared,
                    arkret_wire::CapabilityActionId::from_wire(action)
                        .ok_or_else(|| denied("creation action is unregistered"))?,
                    &resource,
                    &facts,
                    std::slice::from_ref(&grant_id),
                )
                .await?,
            );
        }
    }
    let delegated_audit = !native_service
        && event.actor_id.as_account_id().is_some()
        && arkret_models_collaboration::authority_commit::is_audit_paired_event_slot(event)
            .map_err(denied)?
        && grant.issuer_id == event.actor_id;
    // A native Account's explicit delegation to the exact registered Service
    // is not a managed Account terminal child. Its scoped business grant and
    // approvals are rechecked independently by the registered unit's cut.
    if !native_service && !delegated_audit {
        let [
            arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {
                grant_id: parent_id,
            },
        ] = grant.issuer_authority_refs.as_slice()
        else {
            return Err(denied("managed Actor grant lacks exact Service parent"));
        };
        let parent = grants
            .get(parent_id)
            .ok_or_else(|| denied("managed Actor parent absent"))?;
        if !matches!(&parent.subject,CapabilitySubject::Actor(actor) if actor==&service)
            || grant.issuer_id != service
        {
            return Err(denied("managed Actor permission source differs"));
        }
        let facts = coland_storage::OperationFacts {
            applet_id: Some(registration.applet_id.to_string()),
            executed_by: Some(service.clone()),
            registration_epoch: Some(registration.registration_epoch.to_string()),
            ..Default::default()
        };
        let actions = grant.actions.iter().map(String::as_str).collect::<Vec<_>>();
        if let Some((commit, prepared)) = acceptance {
            accepted.extend(
                crate::boxed_future(|| {
                    require_producer_grant(
                        conn, event, commit, prepared, parent, &service, &actions, &resource,
                        &facts,
                    )
                })
                .await?,
            );
        }
    }
    let root=sql_query("SELECT realm_id,controller_actor_id,controller_epoch,authority_generation,authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<RealmAuthorityRootReadRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if !revoking_own_child {
        validate_ancestor_graph(
            &GrantId::from_event_id(&event.event_id),
            &grant_id,
            &grants,
            &decode_authority_root(root)?,
            &event.realm_id,
            at,
            &mut BTreeSet::new(),
            0,
        )?;
    }
    #[derive(diesel::QueryableByName)]
    struct CommitSource {
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let registration_ref = install
        .value
        .pointer("/registration_event/event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("exact installation registration anchor absent"))?;
    let registration_commit = sql_query("SELECT c.commit_json FROM applet_registration_instances a JOIN realm_commits c ON c.commit_id=a.accepted_commit_id WHERE a.realm_id=$1 AND a.applet_id=$2 AND a.registration_event_ref=$3")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(registration.applet_id.as_str()).bind::<Text,_>(registration_ref).get_result::<CommitSource>(&mut *conn).await.map_err(PersistenceError::database)?;
    let authorization_event = grant_id.as_str().replacen("ak:grant:", "ak:event:", 1);
    let grant_commit = sql_query("SELECT c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.envelope->>'event_id'=$1 AND e.realm_id=$2 AND e.kind='ak.capability.grant' AND e.state='committed'")
        .bind::<Text,_>(authorization_event).bind::<Text,_>(event.realm_id.as_str()).get_result::<CommitSource>(&mut *conn).await.map_err(PersistenceError::database)?;
    let coordinate = |row: CommitSource| -> PersistenceResult<arkret_wire::CommittedEventRef> {
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(row.commit_json).map_err(PersistenceError::database)?;
        Ok(arkret_wire::CommittedEventRef {
            event_id: commit.event_ref,
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        })
    };
    let fact = arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor: service,
        verification_method: proof.verification_method.clone(),
        key: arkret_models_identity::ServiceHistoricalSigningKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                key.ed25519_bytes().map_err(denied)?,
            ))
            .map_err(denied)?,
            applet_id: registration.applet_id.clone(),
            registration_epoch: registration.registration_epoch.clone(),
            registration_ref: coordinate(registration_commit)?,
            authorization_ref: coordinate(grant_commit)?,
            effective_scope: effective_scope.clone(),
        },
        accepted_at: arkret_canonical::normalize_timestamp_canonical(at),
    };
    fact.validate_event_binding(event, suite).map_err(denied)?;
    Ok((fact, accepted))
}

#[expect(
    clippy::too_many_arguments,
    reason = "The exact producer grant is evaluated on the accepting Event cut."
)]
pub(crate) async fn require_producer_grant(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    actor: &ActorId,
    actions: &[&str],
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    let (accepted, reservations) = crate::boxed_future(|| {
        evaluate_producer_grant(
            conn, event, commit, prepared, grant, actor, actions, target, facts, false,
        )
    })
    .await?;
    if !reservations.is_empty() && grant.issuer_authority_refs.iter().any(|source|
        !matches!(source,arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::RealmRoot { .. })) {
        return Err(denied("source quota needs its complete ancestor authority consumer"));
    }
    if !crate::capability_quota::try_reserve_in_connection(
        conn,
        &reservations,
        event.event_id.as_str(),
    )
    .await?
    {
        return Err(PersistenceError::Conflict(
            "rate_limited: Applet source quota is exhausted".into(),
        ));
    }
    Ok(accepted)
}

#[expect(
    clippy::too_many_arguments,
    reason = "The original grant, actual source subject and operation stay bound to one accepting cut."
)]
pub(crate) async fn evaluate_producer_grant(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    actor: &ActorId,
    actions: &[&str],
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
    authority_source: bool,
) -> PersistenceResult<(
    Vec<crate::approval_admission::QualifiedApproval>,
    Vec<coland_storage::QuotaReservation>,
)> {
    let (markers, accepted, missing) = crate::boxed_future(|| {
        prepare_producer_grant_approvals(
            conn, event, commit, prepared, grant, actions, target, facts,
        )
    })
    .await?;
    let operation = coland_storage::AuthorizationOperation {
        actor,
        actions,
        target,
        at: commit.committed_at,
        facts,
    };
    let evaluation = if authority_source {
        coland_storage::evaluate_authority_sources_with_verified_approvals(
            &operation,
            std::iter::once(grant),
            &markers,
        )
    } else {
        coland_storage::evaluate_grants_with_verified_approvals(
            &operation,
            std::iter::once(grant),
            &markers,
        )
    };
    if matches!(evaluation, coland_storage::GrantEvaluation::RequiresReview) && missing {
        return Err(PersistenceError::Conflict(
            "approval_required: Applet producer grant approval is not satisfied".into(),
        ));
    }
    if let coland_storage::GrantEvaluation::Allowed(mut satisfied) = evaluation
        && let Some(satisfied) = satisfied.pop()
    {
        return Ok((accepted, satisfied.reservations));
    }
    Err(denied(
        "Applet producer grant constraints do not permit this action",
    ))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Detached evidence remains bound to its original grant and actual operation."
)]
async fn prepare_producer_grant_approvals(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    grant: &arkret_models_collaboration::governance::grant_constraint::CapabilityGrant,
    actions: &[&str],
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
) -> PersistenceResult<(
    Vec<coland_storage::VerifiedGrantApproval>,
    Vec<crate::approval_admission::QualifiedApproval>,
    bool,
)> {
    let mut markers = Vec::new();
    let mut accepted = Vec::new();
    let mut missing = false;
    for action in actions
        .iter()
        .filter_map(|action| arkret_wire::CapabilityActionId::from_wire(action))
    {
        match crate::grant_approval_admission::require_grant_approvals(
            conn, event, commit, prepared, grant, action, target, facts,
        )
        .await
        {
            Ok(requirements) => {
                for requirement in requirements {
                    markers.push(coland_storage::VerifiedGrantApproval {
                        grant_id: requirement.grant_id,
                        constraint_digest: requirement.constraint_digest,
                        action,
                    });
                    accepted.extend(requirement.accepted);
                }
            }
            Err(PersistenceError::Conflict(detail)) if detail.starts_with("approval_required:") => {
                missing = true;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((markers, accepted, missing))
}

/// A referenced source cannot bypass another effective grant's global refusal.
/// This check counts no positive allow path and reserves no quota.
#[expect(
    clippy::too_many_arguments,
    reason = "Global source refusals preserve their own immutable proof and actual holder."
)]
pub(crate) async fn require_source_global_refusals(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    grants: &[&arkret_models_collaboration::governance::grant_constraint::CapabilityGrant],
    actor: &ActorId,
    actions: &[&str],
    target: &arkret_wire::WireResourceSelector,
    facts: &coland_storage::OperationFacts,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    let mut markers = Vec::new();
    let mut accepted = Vec::new();
    let mut missing = false;
    for grant in grants {
        let (proved, qualified, unproved) = crate::boxed_future(|| {
            prepare_producer_grant_approvals(
                conn, event, commit, prepared, grant, actions, target, facts,
            )
        })
        .await?;
        markers.extend(proved);
        accepted.extend(qualified);
        missing |= unproved;
    }
    let evaluation = coland_storage::evaluate_authority_sources_with_verified_approvals(
        &coland_storage::AuthorizationOperation {
            actor,
            actions,
            target,
            at: commit.committed_at,
            facts,
        },
        grants.iter().copied(),
        &markers,
    );
    if matches!(evaluation, coland_storage::GrantEvaluation::RequiresReview) && missing {
        return Err(PersistenceError::Conflict(
            "approval_required: an effective source grant requires review".into(),
        ));
    }
    match evaluation {
        coland_storage::GrantEvaluation::Denied => {
            return Err(PersistenceError::Conflict(
                "capability_denied: an effective source grant has a global deny".into(),
            ));
        }
        coland_storage::GrantEvaluation::Quarantined
        | coland_storage::GrantEvaluation::RequiresReview => {
            return Err(denied(
                "an effective source grant requires quarantine or review",
            ));
        }
        _ => {}
    }
    Ok(accepted)
}

pub(crate) async fn require_managed_actor_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let registration = registration(conn, event).await?;
    let service = ActorId::service(registration.service_id.clone());
    if event.executed_by.is_none() {
        let authority =
            crate::realm_actor_device_authority::for_event_in_connection(conn, event, at)
                .await
                .map_err(crate::PgTransactionError::into_persistence)?
                .ok_or_else(|| denied("managed Account has no accepted native Device producer"))?;
        if authority.source_service_id != registration.service_id
            || event.applet_id.as_ref() != Some(&authority.applet_id)
            || event.payload.contains_key("agent_context")
        {
            return Err(denied(
                "native managed identity differs from its Applet Service",
            ));
        }
    } else if event.executed_by.as_ref() != Some(&service)
        || event.payload.contains_key("agent_context")
    {
        return Err(denied(
            "managed Message executor is not its accepted Service",
        ));
    }
    let applet = event
        .applet_id
        .as_ref()
        .ok_or_else(|| denied("managed identity has no Applet"))?;
    crate::boxed_future(|| {
        require_managed_identity_in_connection(conn, &event.actor_id, applet, &registration, at)
    })
    .await
}

/// Accepted native identity only. This does not authenticate an Event producer
/// or confer membership, Device scopes, grant authority or public serving.
pub(crate) async fn require_managed_identity_in_connection(
    conn: &mut AsyncPgConnection,
    actor_id: &ActorId,
    applet_id: &arkret_wire::AppletId,
    registration: &AppletRegistrationPayload,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let subject = actor_id
        .as_realm_actor_id()
        .ok_or_else(|| denied("managed identity must be Realm-owned"))?;
    let candidate = crate::realm_actor_control::creation_source(conn, actor_id).await?;
    if &candidate.applet_id != applet_id || applet_id != &registration.applet_id {
        return Err(denied("Realm identity differs from the current Applet"));
    }
    let (manager, _) = crate::realm_actor_control::current_source(
        conn,
        actor_id,
        serde_json::json!({"kind":"realm_actor_manager","actor_id":actor_id}),
    )
    .await?;
    if manager["service_id"] != serde_json::json!(registration.service_id) {
        return Err(denied("Realm manager differs from current registration"));
    }
    for gate in ["owner", "governance"] {
        let (status, _) = crate::realm_actor_control::current_source(
            conn,
            actor_id,
            serde_json::json!({"kind":"realm_actor_status","actor_id":actor_id,"gate":gate}),
        )
        .await?;
        if status != "active" {
            return Err(denied(format!("Realm identity {gate} gate is not active")));
        }
    }
    let _ = (subject, at);
    Ok(())
}

pub(crate) async fn service_for_event(
    conn: &mut AsyncPgConnection,
    event: &Event,
) -> PersistenceResult<arkret_wire::DidCoreId> {
    if event.kind == arkret_wire::EventKind::RealmActorManagerChange {
        let change: arkret_models_integration::RealmActorManagerChangePayload =
            serde_json::from_value(
                serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
            )
            .map_err(PersistenceError::database)?;
        return Ok(change.new_service_id);
    }
    if let ActorId::Service { service_id } = event.executed_by.as_ref().unwrap_or(&event.actor_id) {
        return Ok(service_id.clone());
    }
    if matches!(&event.actor_id, ActorId::Realm { .. }) {
        let (value, _) = crate::realm_actor_control::current_source(
            conn,
            &event.actor_id,
            serde_json::json!({"kind":"realm_actor_manager","actor_id":event.actor_id}),
        )
        .await?;
        let manager: arkret_models_integration::RealmActorManagerValue =
            serde_json::from_value(value).map_err(PersistenceError::database)?;
        return Ok(manager.service_id);
    }
    Err(denied("Applet Event has no accepted Service executor"))
}
