//! Accepted Applet Service proof and managed Message identity at one write cut.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload;
use arkret_models_collaboration::governance::grant_constraint::{
    CapabilitySubject, GrantConstraintKind, GrantConstraintSubkind,
};
use arkret_models_identity::ActorProfile;
use arkret_models_integration::{
    AppletManagedActorProvisionPayload, AppletManagedActorRole, AppletRegistrationPayload,
};
use arkret_wire::{ActorId, Event, EventId, EventKind, GrantId};
use coland_storage::{AppletEventProducerGuard, PersistenceError, PersistenceResult};
use diesel::sql_types::{Binary, Jsonb, Text};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
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
#[derive(diesel::QueryableByName)]
struct EventRow {
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
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
    let row=sql_query("SELECT r.value FROM applet_registration_current_results r JOIN realm_commits c ON c.commit_id=r.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.applet_id=$2 AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position AND e.kind='ak.applet.registration' AND e.state='committed' FOR SHARE OF r")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(applet.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
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
pub(crate) fn require_applet_producer_in_connection<'a>(
    conn: &'a mut AsyncPgConnection,
    event: &'a Event,
    guard: &'a AppletEventProducerGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = PersistenceResult<
                    arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact,
                >,
            > + Send
            + 'a,
    >,
> {
    // Ordinary Human commits must not inherit the Service admission frame.
    Box::pin(require_applet_producer_inner(conn, event, guard, at))
}

async fn require_applet_producer_inner(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &AppletEventProducerGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact> {
    let registration = registration(conn, event).await?;
    let service = ActorId::service(registration.service_id.clone());
    if let Some(account) = event.actor_id.as_account_id() {
        let managed = sql_query("SELECT to_jsonb(c) AS value FROM managed_authority_claims c WHERE actor_id=$1 AND station_id=$2 FOR SHARE")
            .bind::<Text, _>(account.principal_id.as_str())
            .bind::<Text, _>(account.station_id.as_str())
            .get_result::<ValueRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
        if managed.is_some() {
            return Err(denied(
                "Service key cannot sign a managed Account's own Event",
            ));
        }
    }
    let executor = registered_executor(event, &registration)?;
    registration
        .manifest
        .registration_epoch_evidence
        .validate_against_did_document(&guard.service_did_document)
        .map_err(denied)?;
    let scope = coland_storage::applet_effective_scope_key(&event.scope_ref)?;
    let install=sql_query("SELECT i.record AS value FROM applet_installations i JOIN applet_registration_current_results r ON r.realm_id=$3 AND r.applet_id=i.applet_id JOIN applet_registration_instances a ON a.realm_id=r.realm_id AND a.applet_id=r.applet_id AND a.instance_event_ref=r.instance_event_ref AND a.registration_event_ref=i.record#>>'{registration_event,event_id}' WHERE i.applet_id=$1 AND i.effective_scope_key=$2 FOR UPDATE OF i")
        .bind::<Text,_>(registration.applet_id.as_str()).bind::<Text,_>(scope).bind::<Text,_>(event.realm_id.as_str())
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
                && matches!(target.issuer_authority_refs.as_slice(),
                    [arkret_models_collaboration::governance::grant_constraint::IssuerAuthorityRef::Grant {grant_id:parent}]
                        if parent==&grant_id)
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
        return Err(denied(
            "Applet authorization grant is not active for the exact original producer",
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
    let resource = match &event.scope_ref {
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
        .any(|candidate| candidate == &resource)
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
        let evaluation = coland_storage::evaluate_grants(
            &coland_storage::AuthorizationOperation {
                actor: grant_actor,
                actions: &actions,
                target: &resource,
                at,
                facts: &facts,
            },
            std::iter::once(grant),
        );
        if evaluation.unreserved().is_empty() {
            return Err(denied(
                "referenced Applet grant constraints are not satisfied without unresolved quota",
            ));
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
        if coland_storage::evaluate_grants(
            &coland_storage::AuthorizationOperation {
                actor: &service,
                actions: &actions,
                target: &resource,
                at,
                facts: &facts,
            },
            std::iter::once(parent),
        )
        .unreserved()
        .is_empty()
        {
            return Err(denied(
                "managed Actor parent current constraints unavailable",
            ));
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
            effective_scope: event.scope_ref.clone(),
        },
        accepted_at: arkret_canonical::normalize_timestamp_canonical(at),
    };
    fact.validate_event_binding(event, suite).map_err(denied)?;
    Ok(fact)
}

async fn accepted_event(conn: &mut AsyncPgConnection, id: &EventId) -> PersistenceResult<Event> {
    let row=sql_query("SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed' AND c.realm_id=e.realm_id")
        .bind::<Binary,_>(id.token_bytes().to_vec()).get_result::<EventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("managed identity anchor has no accepted Event/Commit"))?;
    serde_json::from_value(row.envelope).map_err(PersistenceError::database)
}
fn exact_ref(event: &Event, role: &str) -> PersistenceResult<EventId> {
    let refs = event
        .semantic_refs
        .iter()
        .filter(|reference| reference.role == role && reference.critical)
        .collect::<Vec<_>>();
    if refs.len() != 1 {
        return Err(denied(
            "managed identity requires one exact critical anchor",
        ));
    }
    refs[0].id.as_str().parse().map_err(denied)
}

pub(crate) async fn require_managed_actor_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let registration = registration(conn, event).await?;
    let account = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| denied("managed Message actor is not an Account"))?;
    let inactive=sql_query("SELECT to_jsonb(EXISTS(SELECT 1 FROM account_lifecycle l JOIN accounts a ON a.pk=l.account_pk WHERE a.principal_id=$1 AND a.station_id=$2 AND l.state<>'active')) AS value")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).get_result::<ValueRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if inactive.value.as_bool() != Some(false) {
        return Err(denied("managed Account lifecycle is not active"));
    }
    let service = ActorId::service(registration.service_id.clone());
    if event.executed_by.as_ref() != Some(&service) || event.payload.contains_key("agent_context") {
        return Err(denied(
            "managed Message executor is not its accepted Service",
        ));
    }
    let profiles=sql_query("SELECT p.value FROM actor_profile_current_results p JOIN realm_commits c ON c.commit_id=p.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk JOIN realm_authorities a ON a.realm_id=p.realm_id WHERE p.value->>'principal_id'=$1 AND e.envelope->'actor_id'=$2 AND a.service_id=$3 AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position AND e.state='committed' FOR SHARE OF p")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?)
        .bind::<Text,_>(account.station_id.as_str()).load::<ValueRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    if profiles.len() != 1 {
        return Err(denied(
            "managed Message requires one accepted current Profile",
        ));
    }
    let profile: ActorProfile = serde_json::from_value(profiles.into_iter().next().unwrap().value)
        .map_err(PersistenceError::database)?;
    if !matches!(
        profile.actor_kind,
        arkret_wire::ActorKind::Bot | arkret_wire::ActorKind::Integration
    ) || profile.principal_id != account.principal_id
        || profile.accountable_principal_ids != vec![registration.service_id.clone()]
        || profile
            .profile_fields
            .get("managed_by_applet")
            .and_then(Value::as_str)
            != Some(registration.applet_id.as_str())
    {
        return Err(denied(
            "managed Message Profile is outside its exact Applet identity",
        ));
    }
    let profile_id = profile
        .id
        .ok_or_else(|| denied("managed Profile has no creation Event"))?;
    let created = accepted_event(
        conn,
        &EventId::from_token_bytes(profile_id.token_bytes()).map_err(denied)?,
    )
    .await?;
    let accountability = accepted_event(conn, &exact_ref(&created, "accountability")?).await?;
    if created.kind != EventKind::ProfileCreate
        || created.actor_id != event.actor_id
        || created.applet_id != event.applet_id
        || accountability.kind != EventKind::IdentityAccountabilityGrant
    {
        return Err(denied("managed Profile accountability anchors differ"));
    }
    let grant: AccountabilityGrantPayload = serde_json::from_value(
        serde_json::to_value(&accountability.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    if grant.subject_id != account.principal_id || grant.issuer_id != registration.service_id {
        return Err(denied("managed accountability issuer or subject differs"));
    }
    if !crate::actor_profiles::accountability_holds_in_connection(
        conn,
        std::slice::from_ref(&registration.service_id),
        &account.principal_id,
        at,
    )
    .await
    .map_err(crate::PgTransactionError::into_persistence)?
    {
        return Err(denied("managed accountability is not current"));
    }
    let provision_event = accepted_event(
        conn,
        &exact_ref(&accountability, "applet_managed_actor_provision")?,
    )
    .await?;
    let provision: AppletManagedActorProvisionPayload = serde_json::from_value(
        serde_json::to_value(&provision_event.payload).map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let profile_kind_matches_role = match provision.actor_role {
        AppletManagedActorRole::Bot => profile.actor_kind == arkret_wire::ActorKind::Bot,
        AppletManagedActorRole::Ghost => profile.actor_kind == arkret_wire::ActorKind::Integration,
    };
    if provision_event.kind != EventKind::AppletManagedActorProvision
        || provision.actor_id != event.actor_id
        || provision.applet_id != registration.applet_id
        || provision.service_id != registration.service_id
        || !profile_kind_matches_role
    {
        return Err(denied(
            "managed Message provision differs from its accepted actor role",
        ));
    }
    if provision.actor_role == AppletManagedActorRole::Ghost {
        let fields: arkret_models_integration::GhostActorProfileFields = serde_json::from_value(
            serde_json::to_value(&profile.profile_fields).map_err(PersistenceError::database)?,
        )
        .map_err(denied)?;
        if provision.external_ref.as_ref() != Some(&fields.external_ref)
            || fields.managed_by_applet != provision.applet_id
        {
            return Err(denied(
                "current Ghost Profile external identity differs from its accepted provision",
            ));
        }
    }
    let genesis=sql_query("SELECT e.envelope FROM principal_resolutions p JOIN realm_commits c ON c.realm_id=p.pcr_realm_id AND c.commit_json->>'event_ref'=p.genesis_event_id JOIN canonical_events e ON e.pk=c.event_pk WHERE p.principal_id=$1 AND p.station_id=$2 AND c.stream_position=0 AND e.state='committed'")
        .bind::<Text,_>(account.principal_id.as_str()).bind::<Text,_>(account.station_id.as_str()).get_result::<EventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(||denied("managed Message has no accepted PCR genesis"))?;
    let genesis: Event =
        serde_json::from_value(genesis.envelope).map_err(PersistenceError::database)?;
    if genesis.kind != EventKind::RealmCreate
        || genesis.actor_id != event.actor_id
        || genesis.applet_id != event.applet_id
        || genesis.executed_by.as_ref() != Some(&service)
        || exact_ref(&genesis, "applet_managed_actor_provision")? != provision_event.event_id
    {
        return Err(denied(
            "managed PCR genesis does not close its exact provision",
        ));
    }
    Ok(())
}
