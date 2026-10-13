//! Station-private management review. Approved is intent, never acceptance.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, AgentPolicyTarget, ManagementReviewRequirement, Policy,
};
use arkret_models_integration::management_review::*;
use arkret_wire::{
    AccountId, ActorId, Event, EventKind, ManagementOperation, PolicyEffect, ScopeRef,
};
use chrono::{DateTime, Utc};
use coland_storage::{ApprovalHistoricalMethod, PersistenceError, PersistenceResult};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

fn refused(code: &str, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}
fn invalid(e: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(e.to_string())
}
fn hidden() -> PersistenceError {
    PersistenceError::NotFound("management review not found".into())
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct ReviewRow {
    #[diesel(sql_type=Jsonb)]
    request_body: Value,
    #[diesel(sql_type=Jsonb)]
    immutable_pins: Value,
    #[diesel(sql_type=Jsonb)]
    requirements: Value,
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Text)]
    target_digest: String,
    #[diesel(sql_type=Text)]
    status: String,
    #[diesel(sql_type=Jsonb)]
    approval_signatures: Value,
    #[diesel(sql_type=Jsonb)]
    approval_basis: Value,
    #[diesel(sql_type=Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type=Timestamptz)]
    expires_at: DateTime<Utc>,
}
impl ReviewRow {
    fn request(&self) -> PersistenceResult<ManagementReviewRequestBody> {
        serde_json::from_value(self.request_body.clone()).map_err(invalid)
    }
    fn outcome(&self) -> PersistenceResult<ManagementReviewOutcome> {
        Ok(ManagementReviewOutcome {
            request_id: self.request()?.request_id,
            target_digest: self.target_digest.parse().map_err(invalid)?,
            status: serde_json::from_value(json!(self.status)).map_err(invalid)?,
            expires_at: self.expires_at,
            approval_signatures: serde_json::from_value(self.approval_signatures.clone())
                .map_err(invalid)?,
        })
    }
}

async fn read(
    conn: &mut AsyncPgConnection,
    id: &str,
    lock: bool,
) -> PersistenceResult<Option<ReviewRow>> {
    sql_query(format!("SELECT request_body,immutable_pins,requirements,request_digest,target_digest,status,approval_signatures,approval_basis,created_at,expires_at FROM management_review_requests WHERE request_id=$1{}", if lock { " FOR UPDATE" } else { "" }))
        .bind::<Text,_>(id).get_result(conn).await.optional().map_err(PersistenceError::database)
}

/// Only original controller-authored Realm join/public-mode Events are supported.
/// Applet creation and Profile publication retain their existing fail-closed gates.
fn target(
    request: &ManagementReviewRequestBody,
) -> PersistenceResult<(&Event, AccountId, AccountId)> {
    request.validate().map_err(invalid)?;
    let ManagementReviewTarget::Event { event } = &request.target else {
        return Err(refused(
            "unsupported_feature",
            "this Station reviews only Agent join and publish Events",
        ));
    };
    arkret_schema::validate_event_for_submit(event).map_err(invalid)?;
    event
        .verify_event_id_matches_content_with_digest_suite(
            event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    if request.effective_scope != event.scope_ref
        || request.effective_scope
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || event.executed_by.is_some()
        || request.requester_actor_id != event.actor_id
    {
        return Err(refused(
            "capability_denied",
            "review target must retain its exact controller, producer and Realm scope",
        ));
    }
    let controller = event.actor_id.as_account_id().ok_or_else(hidden)?.clone();
    let agent = match (request.management_operation, &event.kind) {
        (ManagementOperation::Join, EventKind::MemberState) => {
            let payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload = serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
            let binding = payload
                .agent_controller_binding
                .as_ref()
                .ok_or_else(hidden)?;
            if payload.membership != arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join
                || binding.controller_account_id != controller
                || binding.controller_terminal_event_ref.is_some()
                || payload.membership_cause.is_some()
            { return Err(refused("capability_denied", "review target is not an original controller Agent join")); }
            payload
                .member_id
                .as_account_id()
                .ok_or_else(hidden)?
                .clone()
        }
        (ManagementOperation::Publish, EventKind::AgentInteractionSet) => {
            let payload: arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload = serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
            if payload.controller_account_id != controller
                || payload.interaction_mode
                    != arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public
            {
                return Err(refused(
                    "capability_denied",
                    "review target is not an original public intent",
                ));
            }
            payload.agent_account_id
        }
        _ => {
            return Err(refused(
                "unsupported_feature",
                "review target has no implemented management consumer",
            ));
        }
    };
    if agent == controller || agent.station_id != controller.station_id {
        return Err(refused(
            "capability_denied",
            "Agent review requires complete same-Station ownership",
        ));
    }
    Ok((event, controller, agent))
}

/// The SDK evaluator remains the effect authority. This narrow supported
/// matcher selects *all* highest-priority review requirements of each Policy.
fn requirements(
    policies: &[Policy],
    event: &Event,
    controller: &AccountId,
    agent: &AccountId,
    operation: ManagementOperation,
    at: DateTime<Utc>,
) -> PersistenceResult<Vec<ManagementReviewRequirement>> {
    use arkret_models_collaboration::governance::operation_wire::{
        PolicyResourceKind, PolicyResourceSelector,
    };
    let operation = match operation {
        ManagementOperation::Join => AgentPolicyOperation::Join,
        ManagementOperation::Publish => AgentPolicyOperation::Publish,
        _ => return Err(hidden()),
    };
    let resources = [PolicyResourceSelector {
        kind: PolicyResourceKind::Realm,
        realm_id: Some(event.realm_id.clone()),
        resource_ref: Some(event.realm_id.to_string()),
    }];
    let context = arkret_policy::agent_management::AgentManagementContext {
        realm_id: &event.realm_id,
        ownership: Some((controller, agent)),
        operation,
        content_action: None,
        resources: Some(&resources),
        at,
    };
    match arkret_policy::agent_management::evaluate_agent_management(Some(policies), &context)
        .map_err(invalid)?
    {
        PolicyEffect::Deny | PolicyEffect::Quarantine => {
            return Err(refused(
                "capability_denied",
                "management Policy rejects the candidate",
            ));
        }
        PolicyEffect::Allow => return Ok(Vec::new()),
        PolicyEffect::RequireReview => {}
    }
    let mut result = Vec::new();
    for policy in policies {
        if policy.not_before.is_some_and(|time| at < time)
            || policy.expires_at.is_some_and(|time| at >= time)
        {
            continue;
        }
        let matched = policy
            .rules
            .iter()
            .filter(|rule| {
                rule.agent_operations
                    .as_ref()
                    .is_some_and(|ops| ops.contains(&operation))
                    && match rule.agent_target.as_ref() {
                        Some(AgentPolicyTarget::All {}) => true,
                        Some(AgentPolicyTarget::Controller {
                            controller_account_id,
                        }) => controller_account_id == controller,
                        Some(AgentPolicyTarget::Agent { agent_account_id }) => {
                            agent_account_id == agent
                        }
                        None => false,
                    }
                    && rule.actions.is_none()
                    && rule.resources.as_ref().is_none_or(|selectors| {
                        selectors.iter().any(|s| {
                            s.kind == PolicyResourceKind::Realm
                                && s.realm_id.as_ref().is_none_or(|r| r == &event.realm_id)
                                && s.resource_ref
                                    .as_deref()
                                    .is_none_or(|r| r == event.realm_id.as_str())
                        })
                    })
            })
            .collect::<Vec<_>>();
        if let Some(priority) = matched.iter().map(|r| r.priority).max() {
            for rule in matched
                .iter()
                .filter(|r| r.priority == priority && r.effect == PolicyEffect::RequireReview)
            {
                result.push(rule.review_requirement.clone().ok_or_else(|| {
                    refused("failed_precondition", "review Policy lacks its requirement")
                })?);
            }
        } else if policy.default_effect == PolicyEffect::RequireReview {
            result.push(policy.default_review_requirement.clone().ok_or_else(|| {
                refused(
                    "failed_precondition",
                    "default review Policy lacks its requirement",
                )
            })?);
        }
    }
    if result.is_empty() {
        return Err(refused(
            "failed_precondition",
            "review requirement selection is unavailable",
        ));
    }
    for requirement in &result {
        requirement.validate().map_err(invalid)?;
    }
    Ok(result)
}

/// Resolve the original candidate Device from the accepted PCR, never from a
/// request key or a previously issued boolean. The existing source verifier
/// locks that PCR and binds original Event bytes, scope, key, authorization,
/// governance generation and accepted source/current Commit coordinates.
async fn producer_pin(
    conn: &mut AsyncPgConnection,
    event: &Event,
    at: DateTime<Utc>,
) -> PersistenceResult<Value> {
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(invalid)?
        .ok_or_else(hidden)?;
    let selector = crate::device_revocations::current_device_binding_in_transaction(
        conn,
        &producer.account_id.principal_id,
        &producer.account_id.station_id,
        producer.device_id.as_str(),
    )
    .await?
    .ok_or_else(hidden)?;
    let fact = crate::agent_producer_signer_keys::prepare_human_source_in_connection(
        conn, event, at, &selector,
    )
    .await?;
    // The source verifier acquired PCR current before the Device-instance lock,
    // matching the normal producer writer order.
    crate::device_revocations::lock_artifact_devices_in_transaction(conn, &[&selector]).await?;
    crate::ensure_gate_allowed_in_transaction(conn, &selector).await?;
    Ok(json!({"signer":fact,"scope":event.scope_ref,"original_proof":event.producer_proof}))
}

/// Read exact accepted controller/Agent and Policy facts under the Realm cut.
/// Full current documents and source revisions are retained, never service-row labels.
async fn pins(
    conn: &mut AsyncPgConnection,
    request: &ManagementReviewRequestBody,
    at: DateTime<Utc>,
) -> PersistenceResult<(Value, Vec<ManagementReviewRequirement>)> {
    let (event, controller, agent) = target(request)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &event.actor_id,
    )
    .await?;
    cut.require_open_lifecycle(event)?;
    cut.require_governed_member(&event.kind)?;
    let producer = producer_pin(conn, event, at).await?;
    let joined = sql_query("SELECT jsonb_build_object('membership',m.membership,'current_commit_id',m.current_commit_id,'current_stream_position',m.current_stream_position,'event',e.envelope,'commit',c.commit_json) AS value FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$2 FOR SHARE OF m")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(ActorId::account(controller.clone()).to_string()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(hidden)?;
    if joined.value["membership"] != "join" {
        return Err(hidden());
    }
    if request.management_operation == ManagementOperation::Join {
        let payload: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
            serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
        if payload
            .agent_controller_binding
            .as_ref()
            .map(|b| b.controller_membership_generation_ref.as_str())
            != joined.value["event"]["event_id"].as_str()
        {
            return Err(refused(
                "failed_precondition",
                "controller joined generation changed",
            ));
        }
    } else if crate::agent_interaction_current_results::controller_in_connection(
        conn,
        &event.realm_id,
        &agent,
        at,
    )
    .await?
    .as_ref()
        != Some(&controller)
    {
        return Err(hidden());
    }
    let ownership = crate::agent_interaction_current_results::owned_provenance_in_connection(
        conn,
        &agent,
        &controller,
        at,
        true,
    )
    .await?
    .ok_or_else(hidden)?;
    let policies =
        crate::policy_current_results::read_scoped_agent_management_policies_in_connection(
            conn,
            &event.realm_id,
            None,
        )
        .await?;
    let required = requirements(
        &policies,
        event,
        &controller,
        &agent,
        request.management_operation,
        at,
    )?;
    let policy_pins = sql_query("SELECT to_jsonb(p) AS value FROM policy_current_results p WHERE realm_id=$1 AND value->>'policy_kind'='agent' ORDER BY policy_id FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).load::<JsonRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let membership = sql_query("SELECT to_jsonb(m) AS value FROM member_state_current_results m WHERE realm_id=$1 AND member_id=$2 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(ActorId::account(agent.clone()).to_string()).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let mode = sql_query("SELECT to_jsonb(m) AS value FROM agent_interaction_current_results m WHERE realm_id=$1 AND agent_account_id=$2 FOR SHARE")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(json!(agent)).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if request.management_operation == ManagementOperation::Publish {
        let payload: arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload =
            serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
        let revision = mode.as_ref().map(|row| serde_json::from_value::<arkret_wire::CurrentRevision>(json!({"commit_id":row.value["current_commit_id"],"stream_position":row.value["current_stream_position"]}))).transpose().map_err(invalid)?;
        if revision != payload.expected_revision {
            return Err(refused(
                "failed_precondition",
                "public interaction CAS changed",
            ));
        }
    }
    Ok((
        json!({"producer":producer,"controller":controller,"agent":agent,"controller_join":joined.value,"ownership":ownership,"policies":policies,"policy_revisions":policy_pins.into_iter().map(|r|r.value).collect::<Vec<_>>(),"candidate_membership":membership.map(|r|r.value),"interaction":mode.map(|r|r.value)}),
        required,
    ))
}

async fn visible(
    conn: &mut AsyncPgConnection,
    row: &ReviewRow,
    caller: &ActorId,
    at: DateTime<Utc>,
) -> PersistenceResult<bool> {
    let request = row.request()?;
    if request.requester_actor_id == *caller {
        return Ok(true);
    }
    let (_, _, agent) = target(&request)?;
    if caller.signing_principal_id() == &agent.principal_id {
        return Ok(false);
    }
    let requirements: Vec<ManagementReviewRequirement> =
        serde_json::from_value(row.requirements.clone()).map_err(invalid)?;
    if !requirements
        .iter()
        .any(|r| r.approver_actor_ids.contains(caller))
    {
        return Ok(false);
    }
    let (event, ..) = target(&request)?;
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, &event.realm_id, caller)
            .await?;
    Ok(cut.actor_is_joined()
        && (cut.actor_is_root_controller()
            || cut.permits_unreserved_current_actions(
                &["ak.realm.admin"],
                &arkret_wire::WireResourceSelector::realm(event.realm_id.clone()),
                at,
            )))
}

fn stable_qualification(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("evaluated_at");
    }
    value
}

/// Plan all participating PCRs before taking any Realm cut. Remote resolves
/// have already completed; hold the original AA writer locks through mutation.
async fn lock_current_account_realms(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    accounts: &[AccountId],
    current: Option<&coland_storage::ManagementReviewCurrent>,
) -> PersistenceResult<std::collections::BTreeMap<AccountId, arkret_wire::RealmId>> {
    let mut pcrs = std::collections::BTreeMap::new();
    let mut realms = std::collections::BTreeSet::from([realm.clone()]);
    for account in accounts {
        let current = current.ok_or_else(|| {
            refused(
                "revision_unavailable",
                "management AA observations are unavailable",
            )
        })?;
        let mut observations = current
            .observations
            .iter()
            .filter(|observation| &observation.record().account_id == account);
        let observation = observations.next().ok_or_else(|| {
            refused(
                "revision_unavailable",
                "management participant changed after current preparation",
            )
        })?;
        if observations.next().is_some() {
            return Err(refused(
                "revision_unavailable",
                "management AA observation is not unique",
            ));
        }
        // This is a lock plan, not qualification: after locking, the accepted
        // PCR binding and its exact current AA receipt must prove the same PCR.
        let pcr = observation.record().principal_control_realm_id.clone();
        realms.insert(pcr.clone());
        pcrs.insert(account.clone(), pcr);
    }
    for held in realms {
        crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &held).await?;
    }
    Ok(pcrs)
}

async fn require_current_accounts(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    accounts: &[AccountId],
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    let pcrs = lock_current_account_realms(conn, realm, accounts, Some(current)).await?;
    for (account, pcr) in pcrs {
        if crate::morph_projection_reads::human_realm_in_connection(conn, &account).await? != pcr {
            return Err(refused(
                "revision_unavailable",
                "management human PCR changed during lock planning",
            ));
        }
        let mut observations = current
            .observations
            .iter()
            .filter(|observation| observation.record().account_id == account);
        let observation = observations.next();
        if observations.next().is_some() {
            return Err(refused(
                "revision_unavailable",
                "management AA observation is not unique",
            ));
        }
        crate::morph_projection_reads::require_accepted_human_pcr_in_connection(
            conn, &account, &pcr,
        )
        .await?;
        let status =
            crate::morph_projection_reads::require_observed_account_status_binding_in_connection(
                conn,
                &account,
                &pcr,
                &current.station_id,
                observation,
            )
            .await?;
        if status == arkret_models_collaboration::objects::account_status::AccountStatus::Active {
            // Preserve the original additional product-projection checks when
            // those mirrors exist; they never replace the native AA/PCR gate.
            crate::morph_projection_reads::require_accepted_human_identity(
                conn,
                &account,
                &pcr,
                &current.station_id,
                observation,
            )
            .await?;
        }
    }
    Ok(())
}

fn current_account_is_active(
    account: &AccountId,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<bool> {
    let mut observations = current
        .observations
        .iter()
        .filter(|observation| &observation.record().account_id == account);
    let observation = observations.next().ok_or_else(|| {
        refused(
            "revision_unavailable",
            "management AA observation is unavailable",
        )
    })?;
    if observations.next().is_some() {
        return Err(refused(
            "revision_unavailable",
            "management AA observation is not unique",
        ));
    }
    Ok(observation.record().status
        == arkret_models_collaboration::objects::account_status::AccountStatus::Active)
}

fn require_active_caller(
    caller: &ActorId,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    if !current_account_is_active(caller.as_account_id().ok_or_else(hidden)?, current)? {
        return Err(refused(
            "capability_denied",
            "management caller Account is not current active",
        ));
    }
    Ok(())
}

fn selected_approval_actor(
    row: &ReviewRow,
    principal: &arkret_wire::DidCoreId,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<ActorId> {
    let requirements: Vec<ManagementReviewRequirement> =
        serde_json::from_value(row.requirements.clone()).map_err(invalid)?;
    let actors = requirements
        .iter()
        .flat_map(|requirement| requirement.approver_actor_ids.iter())
        .filter(|actor| actor.signing_principal_id() == principal)
        .filter(|actor| {
            actor.as_account_id().is_some_and(|account| {
                current
                    .observations
                    .iter()
                    .any(|observation| &observation.record().account_id == account)
            })
        })
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if actors.len() != 1 {
        return Err(refused(
            "capability_denied",
            "approval needs one designated observed complete Account",
        ));
    }
    actors.into_iter().next().ok_or_else(hidden)
}

/// A historical approved_at root does not become invalid when its DID rotates.
/// Recheck the independent current administrator/Account lifecycle at this cut;
/// retain the verified historical key and signature without reinterpreting it.
async fn current_administrator(
    conn: &mut AsyncPgConnection,
    event: &Event,
    actor: &ActorId,
    at: DateTime<Utc>,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<Option<Value>> {
    let account = actor.as_account_id().ok_or_else(hidden)?;
    if !current_account_is_active(account, current)? {
        return Ok(None);
    }
    let Some(basis) = crate::approval_admission::qualify_actor(
        conn,
        event,
        actor,
        arkret_wire::CapabilityActionId::RealmAdmin,
        &arkret_wire::WireResourceSelector::realm(event.realm_id.clone()),
        &coland_storage::OperationFacts::default(),
        at,
        true,
    )
    .await?
    else {
        return Ok(None);
    };
    let account = actor.as_account_id().ok_or_else(hidden)?;
    let pcr = crate::morph_projection_reads::human_realm_in_connection(conn, account).await?;
    crate::morph_projection_reads::require_accepted_human_identity(
        conn,
        account,
        &pcr,
        &current.station_id,
        current
            .observations
            .iter()
            .find(|observation| &observation.record().account_id == account),
    )
    .await?;
    Ok(Some(basis))
}

async fn approvals_still_qualified(
    conn: &mut AsyncPgConnection,
    row: &ReviewRow,
    at: DateTime<Utc>,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<bool> {
    let request = row.request()?;
    let (event, ..) = target(&request)?;
    let signatures: Vec<arkret_wire::ApprovalSignature> =
        serde_json::from_value(row.approval_signatures.clone()).map_err(invalid)?;
    let bases = row
        .approval_basis
        .as_array()
        .ok_or_else(|| invalid("invalid retained approval basis"))?;
    if bases.len() != signatures.len() {
        return Err(invalid("retained votes and bases differ"));
    }
    for (signature, basis) in signatures.iter().zip(bases) {
        if basis["signature"] != json!(signature) {
            return Err(invalid("retained approval signature differs"));
        }
        let principal =
            arkret_wire::project_did_to_core_id(&signature.input.approver_did).map_err(invalid)?;
        let actor: ActorId =
            serde_json::from_value(basis["administrator_current"]["actor_id"].clone())
                .map_err(invalid)?;
        if actor.signing_principal_id() != &principal {
            return Err(invalid("retained approval Account differs from its signer"));
        }
        let qualified = current_administrator(conn, event, &actor, at, current).await?;
        if qualified.map(stable_qualification).as_ref() != Some(&basis["administrator_current"]) {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn refresh(
    conn: &mut AsyncPgConnection,
    row: &mut ReviewRow,
    at: DateTime<Utc>,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<()> {
    if !matches!(row.status.as_str(), "pending" | "approved") {
        return Ok(());
    }
    let request = row.request()?;
    let controller = request
        .requester_actor_id
        .as_account_id()
        .ok_or_else(hidden)?;
    let next = if at >= row.expires_at {
        Some("expired")
    } else if !current_account_is_active(controller, current)? {
        Some("superseded")
    } else {
        match pins(conn, &request, at).await {
            Ok((current_pins, required))
                if current_pins == row.immutable_pins && json!(required) == row.requirements =>
            {
                if approvals_still_qualified(conn, row, at, current).await? {
                    None
                } else {
                    Some("superseded")
                }
            }
            Ok(_) => Some("superseded"),
            // Incomplete/corrupt evidence is unavailable, never a proved
            // binding change or authoritative absence.
            Err(
                error @ (PersistenceError::Database(_)
                | PersistenceError::Internal(_)
                | PersistenceError::SchemaViolation(_)),
            ) => return Err(error),
            Err(PersistenceError::Conflict(detail))
                if detail.starts_with("revision_unavailable:")
                    || detail.starts_with("temporarily_unavailable:") =>
            {
                return Err(PersistenceError::Conflict(detail));
            }
            Err(_) => Some("superseded"),
        }
    };
    if let Some(next) = next {
        sql_query("UPDATE management_review_requests SET status=$2 WHERE request_id=$1 AND status IN ('pending','approved')").bind::<Text,_>(&request.request_id).bind::<Text,_>(next).execute(conn).await.map_err(PersistenceError::database)?;
        row.status = next.into();
    }
    Ok(())
}

pub(crate) async fn request_in_connection(
    conn: &mut AsyncPgConnection,
    caller: &ActorId,
    request: &ManagementReviewRequestBody,
    producer: &coland_storage::SelfProducerCommitGuard,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<ManagementReviewOutcome> {
    let (event, ..) = target(request)?;
    if caller != &request.requester_actor_id {
        return Err(hidden());
    }
    let initial = read(conn, &request.request_id, false).await?;
    let accounts = match initial.as_ref() {
        Some(row) => material_accounts(row, caller, &[])?,
        None => vec![
            caller.as_account_id().ok_or_else(hidden)?.clone(),
            request
                .requester_actor_id
                .as_account_id()
                .ok_or_else(hidden)?
                .clone(),
        ],
    };
    require_current_accounts(conn, &event.realm_id, &accounts, current).await?;
    if !accounts.is_empty() {
        require_active_caller(caller, current)?;
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let at = Utc::now();
    let digest = arkret_canonical::canonical_sha256(request).map_err(invalid)?;
    if let Some(mut row) = read(conn, &request.request_id, true).await? {
        if row.request_digest != digest {
            return Err(refused(
                "duplicate_conflict",
                "review id is bound to different immutable intent",
            ));
        }
        refresh(conn, &mut row, at, current).await?;
        return row.outcome();
    }
    crate::authority_commit::check_self_producer_guard_in_connection(conn, event, producer, at)
        .await?;
    let (pins, requirements) = pins(conn, request, at).await?;
    if requirements.is_empty() {
        return Err(refused(
            "failed_precondition",
            "candidate does not require management review",
        ));
    }
    let lifetime = requirements
        .iter()
        .map(|r| r.max_age_seconds)
        .min()
        .ok_or_else(hidden)?
        .min(86400);
    let expires_at = at + chrono::Duration::seconds(i64::try_from(lifetime).map_err(invalid)?);
    let target_digest = arkret_canonical::canonical_sha256(event).map_err(invalid)?;
    let inserted = sql_query("INSERT INTO management_review_requests(request_id,realm_id,requester_actor_key,effective_scope,management_operation,request_digest,target_digest,request_body,immutable_pins,requirements,created_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending') ON CONFLICT DO NOTHING")
        .bind::<Text,_>(&request.request_id).bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(caller.to_string()).bind::<Jsonb,_>(json!(request.effective_scope)).bind::<Text,_>(if request.management_operation==ManagementOperation::Join {"join"} else {"publish"}).bind::<Text,_>(&digest).bind::<Text,_>(&target_digest).bind::<Jsonb,_>(json!(request)).bind::<Jsonb,_>(pins).bind::<Jsonb,_>(json!(requirements)).bind::<Timestamptz,_>(at).bind::<Timestamptz,_>(expires_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(refused(
            "duplicate_conflict",
            "one nonterminal review already binds this candidate",
        ));
    }
    read(conn, &request.request_id, true)
        .await?
        .ok_or_else(hidden)?
        .outcome()
}

pub(crate) async fn status_in_connection(
    conn: &mut AsyncPgConnection,
    caller: &ActorId,
    id: &str,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<ManagementReviewOutcome> {
    let row = read(conn, id, false).await?.ok_or_else(hidden)?;
    let request = row.request()?;
    let (event, ..) = target(&request)?;
    let accounts = material_accounts(&row, caller, &[])?;
    require_current_accounts(conn, &event.realm_id, &accounts, current).await?;
    if !accounts.is_empty() {
        require_active_caller(caller, current)?;
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let mut row = read(conn, id, true).await?.ok_or_else(hidden)?;
    let at = Utc::now();
    if !visible(conn, &row, caller, at).await? {
        return Err(hidden());
    }
    refresh(conn, &mut row, at, current).await?;
    row.outcome()
}

fn review_binding<'a>(
    row: &ReviewRow,
    request: &'a ManagementReviewRequestBody,
    beneficiary: &'a ActorId,
) -> arkret_signatures::approval_signature::ManagementApprovalBinding<'a> {
    arkret_signatures::approval_signature::ManagementApprovalBinding {
        request_id: &request.request_id,
        management_operation: request.management_operation,
        effective_scope: &request.effective_scope,
        created_at: row.created_at,
        expires_at: row.expires_at,
        requester_actor_id: &request.requester_actor_id,
        target_actor_id: Some(beneficiary),
    }
}

async fn qualify(
    conn: &mut AsyncPgConnection,
    row: &ReviewRow,
    methods: &[ApprovalHistoricalMethod],
    at: DateTime<Utc>,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    let request = row.request()?;
    let (event, _, agent) = target(&request)?;
    let beneficiary = ActorId::account(agent);
    let binding = review_binding(row, &request, &beneficiary);
    let mut result = Vec::new();
    let mut principals = std::collections::BTreeSet::new();
    for method in methods {
        let vote = &method.signature;
        let control = method.native_control.as_ref().ok_or_else(|| {
            refused(
                "signature_invalid",
                "management approval needs authenticated native control history",
            )
        })?;
        if control.public_key() != &method.public_key
            || control.method() != &vote.proof.verification_method
            || control.principal()
                != &arkret_wire::project_did_to_core_id(&vote.input.approver_did)
                    .map_err(invalid)?
            || method
                .control_history
                .as_ref()
                .and_then(|v| v["verified_at"].as_str())
                != Some(
                    arkret_canonical::format_timestamp_canonical(vote.input.approved_at).as_str(),
                )
        {
            return Err(refused(
                "signature_invalid",
                "management approval history differs",
            ));
        }
        arkret_identity::principal_control::verify_native_control_management_event_approval(
            control,
            vote,
            event,
            "ak.self.events.command.submit.v1",
            vote.input.action,
            at,
            &binding,
        )
        .map_err(|_| {
            refused(
                "signature_invalid",
                "management approval does not bind original intent",
            )
        })?;
        let required_action = match request.management_operation {
            ManagementOperation::Join => arkret_wire::CapabilityActionId::AgentJoin,
            ManagementOperation::Publish => arkret_wire::CapabilityActionId::AgentPublish,
            _ => return Err(hidden()),
        };
        if vote.input.action != required_action {
            return Err(refused(
                "signature_invalid",
                "management approval action differs from its original governance operation",
            ));
        }
        let principal = control.principal();
        if principal == request.requester_actor_id.signing_principal_id()
            || principal == event.actual_signer().signing_principal_id()
            || principal == beneficiary.signing_principal_id()
        {
            return Err(refused(
                "capability_denied",
                "requester, producer and beneficiary cannot approve",
            ));
        }
        if !principals.insert(principal.clone()) {
            return Err(refused(
                "duplicate_conflict",
                "one principal cannot supply multiple management votes",
            ));
        }
        let selected_actor = selected_approval_actor(row, principal, current)?;
        let basis = current_administrator(conn, event, &selected_actor, at, current)
            .await?
            .ok_or_else(|| {
                refused(
                    "capability_denied",
                    "approver has no current scope administrator authority",
                )
            })?;
        let actor: ActorId = serde_json::from_value(basis["actor_id"].clone()).map_err(invalid)?;
        let requirements: Vec<ManagementReviewRequirement> =
            serde_json::from_value(row.requirements.clone()).map_err(invalid)?;
        if !requirements
            .iter()
            .any(|r| r.approver_actor_ids.contains(&actor))
        {
            return Err(refused(
                "capability_denied",
                "approver is not designated by a matching Policy",
            ));
        }
        result.push(crate::approval_admission::QualifiedApproval {method:method.clone(),qualification_basis:json!({"management_request_id":request.request_id,"approver_actor_id":actor,"administrator_current":basis,"immutable_pins":row.immutable_pins})});
    }
    Ok(result)
}

fn threshold_met(
    row: &ReviewRow,
    qualified: &[crate::approval_admission::QualifiedApproval],
) -> PersistenceResult<bool> {
    let requirements: Vec<ManagementReviewRequirement> =
        serde_json::from_value(row.requirements.clone()).map_err(invalid)?;
    for requirement in requirements {
        let mut distinct = std::collections::BTreeSet::new();
        for vote in qualified {
            let actor: ActorId =
                serde_json::from_value(vote.qualification_basis["approver_actor_id"].clone())
                    .map_err(invalid)?;
            if requirement.approver_actor_ids.contains(&actor) {
                distinct.insert(actor.signing_principal_id().clone());
            }
        }
        if distinct.len() < usize::try_from(requirement.threshold).map_err(invalid)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn decide_in_connection(
    conn: &mut AsyncPgConnection,
    caller: &ActorId,
    decision: &ManagementReviewDecisionRequestBody,
    methods: &[ApprovalHistoricalMethod],
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<ManagementReviewOutcome> {
    decision.validate().map_err(invalid)?;
    let initial = read(conn, &decision.request_id, false)
        .await?
        .ok_or_else(hidden)?;
    let request = initial.request()?;
    let (event, ..) = target(&request)?;
    let accounts = material_accounts(&initial, caller, &decision.approval_signatures)?;
    require_current_accounts(conn, &event.realm_id, &accounts, current).await?;
    if !accounts.is_empty() {
        require_active_caller(caller, current)?;
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let mut row = read(conn, &decision.request_id, true)
        .await?
        .ok_or_else(hidden)?;
    let at = Utc::now();
    if !visible(conn, &row, caller, at).await? {
        return Err(hidden());
    }
    refresh(conn, &mut row, at, current).await?;
    if row.status != "pending" {
        return Err(refused(
            "failed_precondition",
            "management review is no longer pending",
        ));
    }
    let next = match decision.decision {
        ManagementReviewDecision::Cancel if caller == &request.requester_actor_id => "cancelled",
        ManagementReviewDecision::Cancel => return Err(hidden()),
        ManagementReviewDecision::Reject if caller != &request.requester_actor_id => "rejected",
        ManagementReviewDecision::Reject => {
            return Err(refused(
                "capability_denied",
                "only a designated current administrator may reject",
            ));
        }
        ManagementReviewDecision::Approve => {
            if caller == &request.requester_actor_id {
                return Err(refused(
                    "capability_denied",
                    "requester cannot approve its own intent",
                ));
            }
            let mut combined: Vec<arkret_wire::ApprovalSignature> =
                serde_json::from_value(row.approval_signatures.clone()).map_err(invalid)?;
            for signature in &decision.approval_signatures {
                if !combined.contains(signature) {
                    combined.push(signature.clone());
                }
            }
            if methods.len() != combined.len()
                || methods
                    .iter()
                    .zip(&combined)
                    .any(|(m, s)| &m.signature != s)
            {
                return Err(refused(
                    "failed_precondition",
                    "decision history changed; resolve the exact current votes again",
                ));
            }
            // The HTTP adapter resolves *all* retained and newly supplied votes
            // at their original approved_at before entering this transaction.
            let qualified = qualify(conn, &row, methods, at, current).await?;
            row.approval_signatures = json!(combined);
            row.approval_basis = json!(qualified.iter().map(|vote| json!({
                "signature":vote.method.signature,
                "public_key":arkret_canonical::base64url_encode(vote.method.public_key),
                "control_history":vote.method.control_history,
                "administrator_current":stable_qualification(vote.qualification_basis["administrator_current"].clone())
            })).collect::<Vec<_>>());
            if threshold_met(&row, &qualified)? {
                "approved"
            } else {
                "pending"
            }
        }
    };
    sql_query("UPDATE management_review_requests SET status=$2,approval_signatures=$3,approval_basis=$4 WHERE request_id=$1 AND status='pending'")
        .bind::<Text,_>(&decision.request_id).bind::<Text,_>(next).bind::<Jsonb,_>(&row.approval_signatures).bind::<Jsonb,_>(&row.approval_basis).execute(conn).await.map_err(PersistenceError::database)?;
    row.status = next.into();
    row.outcome()
}

/// Select only participants actually used by this request. The private ledger
/// fixes retained votes to their complete Actor; an unrelated administrator
/// named by the Policy must not make a local threshold depend on its AA.
fn material_accounts(
    row: &ReviewRow,
    caller: &ActorId,
    new_signatures: &[arkret_wire::ApprovalSignature],
) -> PersistenceResult<Vec<AccountId>> {
    if row.status == "consumed" {
        return Ok(Vec::new());
    }
    let caller_account = caller.as_account_id().ok_or_else(hidden)?;
    let mut accounts = std::collections::BTreeSet::from([caller_account.clone()]);
    if !matches!(row.status.as_str(), "pending" | "approved") || Utc::now() >= row.expires_at {
        return Ok(accounts.into_iter().collect());
    }
    let request = row.request()?;
    let (_, controller, _) = target(&request)?;
    accounts.insert(controller);
    let retained: Vec<arkret_wire::ApprovalSignature> =
        serde_json::from_value(row.approval_signatures.clone()).map_err(invalid)?;
    let bases = row.approval_basis.as_array().ok_or_else(hidden)?;
    if retained.len() != bases.len() {
        return Err(invalid("retained votes and bases differ"));
    }
    let mut retained_actors = std::collections::BTreeMap::new();
    for (signature, basis) in retained.iter().zip(bases) {
        if basis["signature"] != json!(signature) {
            return Err(invalid("retained approval signature differs"));
        }
        let actor: ActorId =
            serde_json::from_value(basis["administrator_current"]["actor_id"].clone())
                .map_err(invalid)?;
        let principal =
            arkret_wire::project_did_to_core_id(&signature.input.approver_did).map_err(invalid)?;
        if actor.signing_principal_id() != &principal {
            return Err(invalid("retained approval Account differs from its signer"));
        }
        let account = actor.as_account_id().ok_or_else(hidden)?.clone();
        if retained_actors.insert(principal, actor).is_some() {
            return Err(invalid("retained approval principal is not unique"));
        }
        accounts.insert(account);
    }
    let requirements: Vec<ManagementReviewRequirement> =
        serde_json::from_value(row.requirements.clone()).map_err(invalid)?;
    for signature in new_signatures {
        let principal =
            arkret_wire::project_did_to_core_id(&signature.input.approver_did).map_err(invalid)?;
        let designated = requirements
            .iter()
            .flat_map(|requirement| requirement.approver_actor_ids.iter())
            .filter(|actor| actor.signing_principal_id() == &principal)
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        let actor = if let Some(retained) = retained_actors.get(&principal) {
            retained.clone()
        } else if designated.contains(caller) && caller.signing_principal_id() == &principal {
            caller.clone()
        } else if designated.len() == 1 {
            designated.into_iter().next().ok_or_else(hidden)?
        } else {
            return Err(refused(
                "capability_denied",
                "approval has no unambiguous designated complete Account",
            ));
        };
        // This selects an identity to observe. It does not qualify its current
        // administrator authority or trust a self-reported signing key.
        accounts.insert(actor.as_account_id().ok_or_else(hidden)?.clone());
    }
    Ok(accounts.into_iter().collect())
}

/// Authenticated Station-private preparation only. No refresh, terminal
/// transition or current qualification occurs before remote AA observations.
pub(crate) async fn material_in_connection(
    conn: &mut AsyncPgConnection,
    caller: &ActorId,
    id: &str,
    new_signatures: &[arkret_wire::ApprovalSignature],
) -> PersistenceResult<coland_storage::ManagementReviewMaterial> {
    let row = read(conn, id, false).await?.ok_or_else(hidden)?;
    let request = row.request()?;
    let (event, ..) = target(&request)?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let row = read(conn, id, true).await?.ok_or_else(hidden)?;
    if !visible(conn, &row, caller, Utc::now()).await? {
        return Err(hidden());
    }
    Ok(coland_storage::ManagementReviewMaterial {
        request: row.request()?,
        outcome: row.outcome()?,
        accounts: material_accounts(&row, caller, new_signatures)?,
    })
}

/// Final business admission uses this independently locked ledger, not the
/// earlier approve response. Nonce consumption happens only with the Commit.
pub(crate) async fn require_approved_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    at: DateTime<Utc>,
) -> PersistenceResult<Vec<crate::approval_admission::QualifiedApproval>> {
    let prepared = prepared.ok_or_else(|| {
        refused(
            "approval_required",
            "management review evidence is unavailable",
        )
    })?;
    if prepared.event_id != event.event_id
        || prepared.event_digest != arkret_canonical::canonical_sha256(event).map_err(invalid)?
        || prepared.committed_at != at
    {
        return Err(refused(
            "signature_invalid",
            "approval preparation differs from candidate",
        ));
    }
    let mut id = None;
    let methods = prepared
        .methods
        .iter()
        .filter(|m| {
            matches!(
                m.signature.input.approval_context,
                arkret_wire::ApprovalContext::Management { .. }
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    if methods.len() != prepared.methods.len() {
        return Err(refused(
            "signature_invalid",
            "management candidate contains unrelated approval material",
        ));
    }
    for method in &methods {
        let arkret_wire::ApprovalContext::Management { request_id, .. } =
            &method.signature.input.approval_context
        else {
            unreachable!()
        };
        if id.as_ref().is_some_and(|id| id != request_id) {
            return Err(refused(
                "signature_invalid",
                "candidate combines different management requests",
            ));
        }
        id = Some(request_id.clone());
    }
    let mut row = read(
        conn,
        id.as_deref()
            .ok_or_else(|| refused("approval_required", "management request binding is absent"))?,
        true,
    )
    .await?
    .ok_or_else(hidden)?;
    let request = row.request()?;
    let (candidate, ..) = target(&request)?;
    if json!(candidate) != json!(event) {
        return Err(refused(
            "duplicate_conflict",
            "approved candidate bytes changed",
        ));
    }
    let current = prepared.management_current.as_ref().ok_or_else(|| {
        refused(
            "revision_unavailable",
            "management current AA observations are unavailable",
        )
    })?;
    let accounts = material_accounts(&row, &event.actor_id, &[])?;
    require_current_accounts(conn, &event.realm_id, &accounts, current).await?;
    require_active_caller(&event.actor_id, current)?;
    refresh(conn, &mut row, at, current).await?;
    if row.status != "approved" {
        return Err(refused(
            "approval_required",
            "management request has no current unconsumed approval",
        ));
    }
    if json!(methods.iter().map(|m| &m.signature).collect::<Vec<_>>()) != row.approval_signatures {
        return Err(refused(
            "signature_invalid",
            "business approval signatures differ from durable decision",
        ));
    }
    for (method, basis) in methods
        .iter()
        .zip(row.approval_basis.as_array().ok_or_else(hidden)?)
    {
        if basis["public_key"] != json!(arkret_canonical::base64url_encode(method.public_key))
            || basis["control_history"] != json!(method.control_history)
        {
            return Err(refused(
                "signature_invalid",
                "accepted decision method history changed",
            ));
        }
    }
    let qualified = qualify(conn, &row, &methods, at, current).await?;
    if !threshold_met(&row, &qualified)? {
        return Err(refused(
            "approval_required",
            "current administrators do not meet every threshold",
        ));
    }
    Ok(qualified)
}

pub(crate) async fn consume_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &arkret_wire::RealmCommit,
    qualified: &[crate::approval_admission::QualifiedApproval],
) -> PersistenceResult<()> {
    if qualified.is_empty() {
        return Ok(());
    }
    let id = qualified[0].qualification_basis["management_request_id"]
        .as_str()
        .ok_or_else(hidden)?;
    crate::approval_admission::consume_and_audit(
        conn,
        event,
        commit,
        qualified,
        &json!({"management_request_id":id}),
    )
    .await?;
    let updated=sql_query("UPDATE management_review_requests SET status='consumed',accepted_commit_id=$2 WHERE request_id=$1 AND status='approved'")
        .bind::<Text,_>(id).bind::<Text,_>(commit.commit_id.as_str()).execute(conn).await.map_err(PersistenceError::database)?;
    if updated != 1 {
        return Err(refused(
            "approval_required",
            "management review consumption lost its exact pending cut",
        ));
    }
    Ok(())
}

/// Process-only authority obtained under the current governance transaction.
/// It cannot be constructed from a request, deserialized or reused for another Event.
pub(crate) struct ReviewAdmission {
    target_digest: String,
    qualified: Vec<crate::approval_admission::QualifiedApproval>,
}
impl ReviewAdmission {
    pub(crate) fn applies_to(&self, event: &Event) -> bool {
        !self.qualified.is_empty()
            && arkret_canonical::canonical_sha256(event).ok().as_ref() == Some(&self.target_digest)
    }
    pub(crate) fn methods(&self) -> &[crate::approval_admission::QualifiedApproval] {
        &self.qualified
    }
}
/// Called before the UOW takes its first business Realm cut. No remote I/O
/// occurs here; exact accepted replay is still tested before current AA gates.
pub(crate) async fn lock_candidate_current_realms_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let Some(prepared) = prepared else {
        return Ok(());
    };
    let ids = prepared
        .methods
        .iter()
        .filter_map(|method| {
            if let arkret_wire::ApprovalContext::Management { request_id, .. } =
                &method.signature.input.approval_context
            {
                Some(request_id.clone())
            } else {
                None
            }
        })
        .collect::<std::collections::BTreeSet<_>>();
    if ids.is_empty() {
        return Ok(());
    }
    if ids.len() != 1 {
        return Err(refused(
            "signature_invalid",
            "management evidence names different requests",
        ));
    }
    let id = ids.into_iter().next().ok_or_else(hidden)?;
    let row = read(conn, &id, false).await?.ok_or_else(hidden)?;
    let request = row.request()?;
    let (candidate, ..) = target(&request)?;
    if json!(candidate) != json!(event) {
        return Err(refused(
            "duplicate_conflict",
            "approved candidate bytes changed",
        ));
    }
    let required = material_accounts(&row, &event.actor_id, &[])?;
    let current = prepared.management_current.as_ref();
    if required.iter().any(|account| {
        !current.is_some_and(|current| {
            current
                .observations
                .iter()
                .any(|observation| &observation.record().account_id == account)
        })
    }) {
        return Err(refused(
            "revision_unavailable",
            "management participants changed after current preparation",
        ));
    }
    let accounts = if row.status == "consumed" {
        Vec::new()
    } else {
        current
            .ok_or_else(|| {
                refused(
                    "revision_unavailable",
                    "management AA observations are unavailable",
                )
            })?
            .observations
            .iter()
            .map(|observation| observation.record().account_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    lock_current_account_realms(conn, &event.realm_id, &accounts, current).await?;
    Ok(())
}

pub(crate) async fn prepare_admission_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    prepared: Option<&coland_storage::EventApprovalCommit>,
    at: DateTime<Utc>,
) -> PersistenceResult<Option<ReviewAdmission>> {
    if !prepared.is_some_and(|p| {
        p.methods.iter().any(|m| {
            matches!(
                m.signature.input.approval_context,
                arkret_wire::ApprovalContext::Management { .. }
            )
        })
    }) {
        return Ok(None);
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let qualified = require_approved_in_connection(conn, event, prepared, at).await?;
    Ok(Some(ReviewAdmission {
        target_digest: arkret_canonical::canonical_sha256(event).map_err(invalid)?,
        qualified,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(name: &str) -> AccountId {
        AccountId::new(
            format!("ak:did_core:web:{name}.example").parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        )
    }
    fn candidate() -> Event {
        let realm: arkret_wire::RealmId = "ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-"
            .parse()
            .unwrap();
        arkret_wire::test_support::raw_event_at(
            EventKind::MemberState.as_str(),
            ScopeRef::Realm { realm_id: realm },
            account("controller").principal_id,
            account("controller").station_id,
            json!({"member_id":ActorId::account(account("agent")),"membership":"join"}),
            "2026-10-12T00:00:00.000Z".parse().unwrap(),
        )
        .unwrap()
    }
    fn policy(event: &Event, rules: Value) -> Policy {
        serde_json::from_value(json!({
            "schema":"ak.schema.policy.v1","id":"ak:policy:0198ff00-0000-7000-8000-000000000001",
            "realm_id":event.realm_id,"policy_kind":"agent","rules":rules,"default_effect":"allow",
            "created_by":ActorId::account(account("controller")),"created_at":arkret_canonical::format_timestamp_canonical(event.created_at)
        }))
        .unwrap()
    }
    fn rule(id: &str, priority: i64, admin: &str, threshold: u64) -> Value {
        json!({"rule_id":id,"priority":priority,"kind":"agent","agent_target":{"kind":"all"},
            "agent_operations":["join","publish"],"effect":"require_review",
            "review_requirement":{"approver_actor_ids":[ActorId::account(account(admin)),ActorId::account(account("second-admin"))],"threshold":threshold,"max_age_seconds":3600}})
    }
    #[test]
    fn management_review_preserves_all_highest_priority_thresholds() {
        let event = candidate();
        let document = policy(
            &event,
            json!([
                rule("lower", 1, "lower-admin", 1),
                rule("one", 5, "one-admin", 1),
                rule("two", 5, "two-admin", 2)
            ]),
        );
        let required = requirements(
            &[document],
            &event,
            &account("controller"),
            &account("agent"),
            ManagementOperation::Join,
            event.created_at,
        )
        .unwrap();
        assert_eq!(required.len(), 2);
        assert!(required.iter().all(|r| {
            !r.approver_actor_ids
                .contains(&ActorId::account(account("lower-admin")))
        }));
        assert!(required.iter().any(|r| r.threshold == 2));
    }
    #[test]
    fn management_review_stricter_matching_deny_cannot_be_approved() {
        let event = candidate();
        let mut deny = rule("deny", 5, "admin", 1);
        deny["effect"] = json!("deny");
        deny.as_object_mut().unwrap().remove("review_requirement");
        let document = policy(&event, json!([rule("review", 5, "admin", 1), deny]));
        assert!(
            matches!(requirements(&[document],&event,&account("controller"),&account("agent"),ManagementOperation::Publish,event.created_at),Err(PersistenceError::Conflict(detail)) if detail.starts_with("capability_denied:"))
        );
    }
    #[test]
    fn management_review_nonmatching_owner_is_not_a_review_request() {
        let event = candidate();
        let mut restricted = rule("other", 0, "admin", 1);
        restricted["agent_target"] =
            json!({"kind":"controller","controller_account_id":account("other")});
        let document = policy(&event, json!([restricted]));
        assert!(
            requirements(
                &[document],
                &event,
                &account("controller"),
                &account("agent"),
                ManagementOperation::Join,
                event.created_at
            )
            .unwrap()
            .is_empty()
        );
    }
    #[test]
    fn management_review_default_selected_operation_retains_requirement() {
        let event = candidate();
        let mut nonmatching = rule("other", 0, "admin", 1);
        nonmatching["agent_target"] =
            json!({"kind":"controller","controller_account_id":account("other")});
        let mut document = policy(&event, json!([nonmatching]));
        document.default_effect = PolicyEffect::RequireReview;
        document.default_operations = Some(vec![ManagementOperation::Join]);
        document.default_review_requirement = Some(
            serde_json::from_value(rule("unused", 0, "admin", 1)["review_requirement"].clone())
                .unwrap(),
        );
        assert_eq!(
            requirements(
                &[document.clone()],
                &event,
                &account("controller"),
                &account("agent"),
                ManagementOperation::Join,
                event.created_at
            )
            .unwrap()
            .len(),
            1
        );
        assert!(
            requirements(
                &[document],
                &event,
                &account("controller"),
                &account("agent"),
                ManagementOperation::Publish,
                event.created_at
            )
            .is_err()
        );
    }
    #[test]
    fn management_review_local_observation_is_not_authority_revision() {
        let original = json!({"evaluated_at":"2026-10-12T00:00:00.000Z","membership_revision":{"commit_id":"original"},"effective_grants":[{"current_revision":"original"}]});
        let mut later = original.clone();
        later["evaluated_at"] = json!("2026-10-12T00:01:00.000Z");
        assert_eq!(
            stable_qualification(original.clone()),
            stable_qualification(later.clone())
        );
        later["effective_grants"][0]["current_revision"] = json!("changed");
        assert_ne!(stable_qualification(original), stable_qualification(later));
    }
}
