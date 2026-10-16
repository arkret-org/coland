//! Detached evidence qualification and private consumption at the accepting cut.
use arkret_wire::{
    ActorId, ApprovalSignature, CapabilityActionId, Event, RealmCommit, WireResourceSelector,
};
use coland_storage::{
    EventApprovalCommit, GrantEvaluation, OperationFacts, PersistenceError, PersistenceResult,
};
use diesel::sql_types::{Jsonb, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::realm_authorization_cut::RealmAuthorizationCut;

#[derive(QueryableByName)]
struct Member {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Jsonb)]
    membership_revision: serde_json::Value,
}

#[derive(Clone, Debug)]
pub(crate) struct QualifiedApproval {
    pub method: coland_storage::ApprovalHistoricalMethod,
    pub qualification_basis: serde_json::Value,
}

/// A registered operation target names the whole closed request. Identical
/// evidence attached to multiple applicable slots consumes its nonce once;
/// distinct evidence sharing that nonce remains a rejection.
#[derive(Default)]
pub(crate) struct BootstrapApprovalConsumption {
    operation_targets: std::collections::BTreeMap<
        (String, String, String),
        coland_storage::ApprovalHistoricalMethod,
    >,
}

impl BootstrapApprovalConsumption {
    pub(crate) fn qualify(
        &mut self,
        methods: &[coland_storage::ApprovalHistoricalMethod],
    ) -> PersistenceResult<Vec<QualifiedApproval>> {
        let mut qualified = Vec::new();
        for method in methods {
            let vote = &method.signature;
            if matches!(
                vote.input.approval_target,
                arkret_wire::ApprovalTarget::Operation
            ) {
                let context = arkret_canonical::canonical_json_string(&vote.input.approval_context)
                    .map_err(|e| error("schema_violation", e))?;
                let key = (
                    context,
                    vote.input.approver_did.to_string(),
                    vote.input.nonce.clone(),
                );
                if let Some(previous) = self.operation_targets.get(&key) {
                    if previous.signature != method.signature
                        || previous.public_key != method.public_key
                        || previous.control_history != method.control_history
                    {
                        return Err(error(
                            "approval_nonce_reused",
                            "distinct operation evidence shares one approval nonce",
                        ));
                    }
                    continue;
                }
                self.operation_targets.insert(key, method.clone());
            }
            qualified.push(QualifiedApproval {
                method: method.clone(),
                qualification_basis: serde_json::json!({"ordinary_realm_bootstrap":true,"quorum_required":false}),
            });
        }
        Ok(qualified)
    }
}

fn error(code: &str, detail: impl std::fmt::Display) -> PersistenceError {
    if code == "schema_violation" {
        return PersistenceError::SchemaViolation(detail.to_string());
    }
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

/// Verify every submitted evidence object, including evidence not needed by a
/// requirement. Extra evidence cannot smuggle malformed or unrelated signatures.
pub(crate) fn validate_candidate<'a>(
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&'a EventApprovalCommit>,
) -> PersistenceResult<&'a [coland_storage::ApprovalHistoricalMethod]> {
    validate_candidate_with_operation_digest(event, commit, prepared, None)
}

/// Founding has no dependency grant, List metadata or management request.
/// An operation approval binds the entire closed unit, with every registered
/// evidence carrier omitted, rather than a fabricated single-Event request.
pub(crate) fn validate_bootstrap_candidate(
    unit: &coland_storage::OrdinaryRealmBootstrapCommitUnit,
    index: usize,
) -> PersistenceResult<&[coland_storage::ApprovalHistoricalMethod]> {
    let transaction = &unit.transactions[index];
    let prepared = unit.event_approvals.get(index).and_then(Option::as_ref);
    let Some(prepared) = prepared else {
        return Ok(&[]);
    };
    let mut original = unit.submission.clone();
    for submitted in &mut original.events {
        submitted.approval_signatures = None;
    }
    let original = arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(original);
    let digest =
        arkret_canonical::canonical_sha256(&original).map_err(|e| error("schema_violation", e))?;
    let methods = validate_candidate_with_operation_digest(
        &transaction.event,
        &transaction.commit,
        Some(prepared),
        Some(&digest),
    )?;
    for method in &prepared.methods {
        let vote = &method.signature;
        if !matches!(
            vote.input.approval_context,
            arkret_wire::ApprovalContext::RealmGovernance {}
        ) {
            return Err(error(
                "approval_required",
                "bootstrap approval context has no applicable authority basis",
            ));
        }
        if !arkret_schema::capability_actions_for_event_kind(transaction.event.kind.as_str())
            .any(|action| action.action == vote.input.action)
        {
            return Err(error(
                "signature_invalid",
                "bootstrap approval action differs from its target Event",
            ));
        }
    }
    Ok(methods)
}

fn validate_candidate_with_operation_digest<'a>(
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&'a EventApprovalCommit>,
    operation_digest: Option<&str>,
) -> PersistenceResult<&'a [coland_storage::ApprovalHistoricalMethod]> {
    let Some(prepared) = prepared else {
        return Ok(&[]);
    };
    if prepared.event_id != event.event_id
        || prepared.committed_at != commit.committed_at
        || prepared.event_digest
            != arkret_canonical::canonical_sha256(event)
                .map_err(|e| error("schema_violation", e))?
    {
        return Err(error(
            "signature_invalid",
            "approval history does not bind this accepting cut",
        ));
    }
    let operation = prepared.carrier_binding.as_ref().map_or(
        arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        coland_storage::ApprovalCarrierBinding::operation,
    );
    let operation_digest = prepared
        .carrier_binding
        .as_ref()
        .map(|binding| binding.request_digest())
        .or(operation_digest);
    for method in &prepared.methods {
        let signature = &method.signature;
        let crypt_code = if matches!(
            signature.input.approval_context,
            arkret_wire::ApprovalContext::ListWip { .. }
        ) {
            "approval_required"
        } else {
            "signature_invalid"
        };
        signature
            .validate()
            .map_err(|e| PersistenceError::SchemaViolation(e.to_string()))?;
        if signature.input.operation != operation {
            return Err(error(
                "schema_violation",
                "approval operation has no registered Event carrier",
            ));
        }
        let key = historical_key(method, crypt_code)?;
        match signature.input.approval_target {
            arkret_wire::ApprovalTarget::Event { .. } => {
                if let Some(control) = method.native_control.as_ref() {
                    arkret_identity::principal_control::verify_native_control_event_approval(
                        control,
                        signature,
                        event,
                        operation,
                        signature.input.action,
                        commit.committed_at,
                    )
                    .map_err(|e| error(crypt_code, e))?;
                } else {
                    arkret_signatures::approval_signature::verify_event_approval_signature(
                        signature,
                        event,
                        operation,
                        signature.input.action,
                        commit.committed_at,
                        &key,
                    )
                    .map_err(|e| error(crypt_code, e))?;
                }
            }
            arkret_wire::ApprovalTarget::Operation => {
                signature
                    .input
                    .validate_approved_at(commit.committed_at)
                    .map_err(|e| error(crypt_code, e))?;
                let original = arkret_wire::EventAdmissionSubmission {
                    event: event.clone(),
                    approval_signatures: None,
                };
                let digest = match operation_digest {
                    Some(digest) => digest.to_owned(),
                    None => arkret_canonical::canonical_sha256(&original)
                        .map_err(|e| error("schema_violation", e))?,
                };
                let controller = arkret_identity::verification_method_did(
                    signature.proof.verification_method.as_str(),
                )
                .map_err(|e| error("schema_violation", e))?;
                if signature.input.realm_id != event.realm_id
                    || signature.input.initiating_actor_id != event.actor_id
                    || signature.input.request_canonical_digest.as_str() != digest
                    || (method.native_control.is_none()
                        && controller != signature.input.approver_did)
                {
                    return Err(error(
                        crypt_code,
                        "operation approval does not bind the original typed request",
                    ));
                }
                let bytes =
                    arkret_signatures::approval_signature::approval_signature_signing_bytes(
                        signature,
                    )
                    .map_err(|e| error("schema_violation", e))?;
                arkret_signatures::Ed25519DetachedJwsVerifier::new()
                    .verify_detached_jws(&signature.proof.jws, &bytes, &key)
                    .map_err(|e| error(crypt_code, e))?;
            }
        }
    }
    Ok(&prepared.methods)
}

/// Historical method qualification is shared by Event and operation targets.
fn historical_key(
    method: &coland_storage::ApprovalHistoricalMethod,
    crypt_code: &str,
) -> PersistenceResult<arkret_signatures::PublicKeyMaterial> {
    let signature = &method.signature;
    let did =
        arkret_identity::verification_method_did(signature.proof.verification_method.as_str())
            .map_err(|e| error("schema_violation", e))?;
    if let Some(control) = method.native_control.as_ref() {
        if control.principal()
            != &arkret_wire::project_did_to_core_id(&signature.input.approver_did)
                .map_err(|e| error(crypt_code, e))?
            || control.method() != &signature.proof.verification_method
            || control.public_key() != &method.public_key
            || method
                .control_history
                .as_ref()
                .and_then(|basis| basis.get("verified_at"))
                .and_then(serde_json::Value::as_str)
                != Some(
                    arkret_canonical::format_timestamp_canonical(signature.input.approved_at)
                        .as_str(),
                )
        {
            return Err(error(
                crypt_code,
                "approval native control differs from its signing-time history",
            ));
        }
    } else if did != signature.input.approver_did {
        return Err(error(crypt_code, "approval method controller differs"));
    }
    if did.method() == "key" {
        use arkret_identity::DidResolver as _;
        let document = arkret_identity::DidKeyResolver::new()
            .resolve_did_document(&did)
            .map_err(|e| error(crypt_code, e))?;
        let resolved = arkret_identity::jws::resolve_ed25519_pubkey_from_document(
            &document,
            signature.proof.verification_method.as_str(),
        )
        .map_err(|e| error(crypt_code, e))?;
        if resolved.to_bytes() != method.public_key {
            return Err(error(
                crypt_code,
                "approval key differs from immutable DID authority",
            ));
        }
    } else if did.method() != "webvh" {
        return Err(error(
            crypt_code,
            "approval method has no authenticated history",
        ));
    }
    Ok(arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: method.public_key.to_vec(),
    })
}

/// Validate every original vote against the registered creation operation.
/// This proves no voting eligibility, approval requirement or consumed nonce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_operation_candidate(
    methods: &[coland_storage::ApprovalHistoricalMethod],
    digest: &arkret_wire::Hash,
    operation: &str,
    action: CapabilityActionId,
    realm: &arkret_wire::RealmId,
    initiator: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    for method in methods {
        let vote = &method.signature;
        vote.validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        if matches!(
            vote.input.approval_context,
            arkret_wire::ApprovalContext::ListWip { .. }
        ) {
            return Err(error(
                "signature_invalid",
                "creation has no List WIP carrier",
            ));
        }
        let key = historical_key(method, "signature_invalid")?;
        if let Some(control) = method.native_control.as_ref() {
            arkret_identity::principal_control::verify_native_control_operation_approval(
                control, vote, digest, operation, action, realm, initiator, at,
            )
        } else {
            arkret_signatures::approval_signature::verify_operation_approval_signature(
                vote, digest, operation, action, realm, initiator, at, &key,
            )
        }
        .map_err(|detail| error("signature_invalid", detail))?;
    }
    Ok(())
}

/// A DID earns one vote only through a joined complete Actor's current grant,
/// with the full shared constraint evaluator on the exact action and target.
/// Governance requires an actual grant; List WIP also recognizes the registry
/// owner aggregate, without overriding a matching refusal constraint.
#[expect(
    clippy::too_many_arguments,
    reason = "Approval qualification binds the actor, approval proof, Event and confirmed authority cut."
)]
pub(crate) async fn approver_qualifies(
    conn: &mut AsyncPgConnection,
    event: &Event,
    vote: &ApprovalSignature,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    at: chrono::DateTime<chrono::Utc>,
    allow_owner: bool,
    registered_pair: bool,
) -> PersistenceResult<Option<serde_json::Value>> {
    let principal = arkret_wire::project_did_to_core_id(&vote.input.approver_did)
        .map_err(|e| error("schema_violation", e))?;
    qualify_principal(
        conn,
        event,
        &principal,
        action,
        target,
        facts,
        at,
        allow_owner,
        registered_pair,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Principal qualification keeps the approval signer and Event authority inputs tied to one transaction."
)]
pub(crate) async fn qualify_principal(
    conn: &mut AsyncPgConnection,
    event: &Event,
    principal: &arkret_wire::DidCoreId,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    at: chrono::DateTime<chrono::Utc>,
    allow_owner: bool,
    registered_pair: bool,
) -> PersistenceResult<Option<serde_json::Value>> {
    crate::boxed_future(|| {
        qualify_principal_or_actor(
            conn,
            Some(event),
            &event.realm_id,
            principal,
            action,
            target,
            facts,
            at,
            allow_owner,
            None,
            registered_pair,
            None,
        )
    })
    .await
}

/// Registered creation approval qualification never grants creation authority.
pub(crate) async fn qualify_creation_principal(
    conn: &mut AsyncPgConnection,
    creation: &crate::applet_action_approval::CreationAuthority<'_>,
    principal: &arkret_wire::DidCoreId,
    current: &coland_storage::ManagementReviewCurrent,
) -> PersistenceResult<Option<serde_json::Value>> {
    let descriptor = arkret_schema::capability_action_descriptor(creation.action);
    if descriptor
        .required_evaluator_checks
        .iter()
        .any(|check| !creation.satisfies_evaluator_check(check))
    {
        return Err(error(
            "capability_denied",
            "creation operation invariant is not satisfied",
        ));
    }
    let action = descriptor
        .approver_capability_action
        .unwrap_or(creation.action);
    let administrator_facts = OperationFacts::default();
    let facts = if descriptor.approver_capability_action.is_some() {
        &administrator_facts
    } else {
        &creation.facts
    };
    let mut qualified = qualify_principal_or_actor(
        conn,
        None,
        &creation.unit.portal_realm,
        principal,
        action,
        &creation.target,
        facts,
        creation.input.accepted_at,
        false,
        None,
        false,
        Some((creation, current)),
    )
    .await?;
    if let Some(basis) = &mut qualified {
        basis["approved_creation_action"] = serde_json::json!(creation.action);
    }
    Ok(qualified)
}

/// Exact scope administrator qualification for an operation with no Event.
pub(crate) async fn qualify_management_administrator(
    conn: &mut AsyncPgConnection,
    scope: &arkret_wire::ScopeRef,
    actor: &ActorId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<serde_json::Value>> {
    let target = match scope {
        arkret_wire::ScopeRef::Realm { realm_id } => WireResourceSelector::realm(realm_id.clone()),
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
        _ => return Err(error("capability_denied", "unsupported management scope")),
    };
    qualify_principal_or_actor(
        conn,
        None,
        scope.realm_id(),
        actor.signing_principal_id(),
        CapabilityActionId::RealmAdmin,
        &target,
        &OperationFacts::default(),
        at,
        true,
        Some(actor),
        false,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "The internal exact Actor selector does not change ordinary principal qualification."
)]
async fn qualify_principal_or_actor(
    conn: &mut AsyncPgConnection,
    event: Option<&Event>,
    realm: &arkret_wire::RealmId,
    principal: &arkret_wire::DidCoreId,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    at: chrono::DateTime<chrono::Utc>,
    allow_owner: bool,
    exact_actor: Option<&ActorId>,
    registered_pair: bool,
    creation: Option<(
        &crate::applet_action_approval::CreationAuthority<'_>,
        &coland_storage::ManagementReviewCurrent,
    )>,
) -> PersistenceResult<Option<serde_json::Value>> {
    if event.is_some_and(|event| principal == event.actor_id.signing_principal_id())
        || creation.is_some_and(|(creation, _)| {
            principal == creation.input.admin_actor_id.signing_principal_id()
        })
    {
        return Ok(None);
    }
    let members = sql_query("SELECT member_id,jsonb_build_object('commit_id',current_commit_id,'stream_position',current_stream_position) AS membership_revision FROM member_state_current_results WHERE realm_id=$1 AND membership='join'")
        .bind::<Text,_>(realm.as_str()).load::<Member>(&mut *conn).await.map_err(PersistenceError::database)?;
    for member in members {
        let actor: ActorId = serde_json::from_str(&member.member_id).map_err(|e| {
            PersistenceError::Database(format!("stored membership ActorId is invalid: {e}"))
        })?;
        if actor.signing_principal_id() != principal
            || exact_actor.is_some_and(|expected| expected != &actor)
        {
            continue;
        }
        if let Some((_, current)) = creation
            && let Some(account) = actor.as_account_id()
        {
            let mut records = current
                .observations
                .iter()
                .filter(|observation| &observation.record().account_id == account);
            let observation = records.next().ok_or_else(|| {
                error(
                    "revision_unavailable",
                    "creation approver changed after current preparation",
                )
            })?;
            if records.next().is_some() {
                return Err(error(
                    "revision_unavailable",
                    "creation approver observation is ambiguous",
                ));
            }
            if observation.record().status
                != arkret_models_collaboration::objects::account_status::AccountStatus::Active
            {
                continue;
            }
        }
        let checks = arkret_schema::capability_action_descriptor(action).required_evaluator_checks;
        if checks.iter().any(|check| match *check {
            "actor_eq_target_author" => facts.target_owner.as_ref() != Some(&actor),
            "actor_ne_watcher_actor" => event
                .and_then(|event| serde_json::to_value(&event.payload).ok())
                .and_then(|p| p.get("watcher_actor_id").cloned())
                .and_then(|v| serde_json::from_value::<ActorId>(v).ok())
                .is_none_or(|watcher| event.is_none_or(|event| watcher == event.actor_id)),
            "audit_pair_required" => !registered_pair,
            _ => creation.is_none_or(|(creation, _)| !creation.satisfies_evaluator_check(check)),
        }) {
            continue;
        }
        let cut = RealmAuthorizationCut::read(conn, realm, &actor).await?;
        let authorization =
            crate::boxed_future(|| cut.enforcing_actor_authorization_in_connection(conn, at))
                .await?;
        let actions = [action.as_str()];
        let owner_covers = allow_owner
            && authorization.agent_ceiling.is_none()
            && cut.actor_is_root_controller()
            && arkret_schema::capability_action_descriptor(action)
                .target_event_kinds
                .iter()
                .any(|kind| {
                    arkret_schema::capability_actions_for_event_kind(kind)
                        .any(|row| row.action == CapabilityActionId::RealmOwner)
                });
        let qualified = match authorization.evaluate(&actions, target, facts) {
            GrantEvaluation::Allowed(ref satisfied) => {
                if creation.is_some()
                    && !satisfied.is_empty()
                    && satisfied.iter().all(|grant| !grant.reservations.is_empty())
                {
                    return Err(error(
                        "revision_unavailable",
                        "creation approver quota eligibility is unresolved",
                    ));
                }
                !satisfied.is_empty() || owner_covers
            }
            GrantEvaluation::Unnamed | GrantEvaluation::Unsatisfied => owner_covers,
            _ => false,
        };
        if qualified {
            #[derive(QueryableByName)]
            struct RootBasis {
                #[diesel(sql_type=Jsonb)]
                value: serde_json::Value,
            }
            let root_basis=sql_query("SELECT to_jsonb(r) AS value FROM realm_authority_root_current_results r WHERE realm_id=$1")
                .bind::<Text,_>(realm.as_str()).get_result::<RootBasis>(&mut *conn).await.map_err(PersistenceError::database)?;
            let grants = authorization
                .grants
                .iter()
                .map(|grant| {
                    serde_json::json!({
                        "value":grant.grant,"current_revision":grant.revision,
                    })
                })
                .collect::<Vec<_>>();
            let mut basis = serde_json::json!({"actor_id":actor,"membership":"join","membership_revision":member.membership_revision,
                "evaluated_at":arkret_canonical::format_timestamp_canonical(at),
                "action":action,"target":target,"effective_grants":grants,"owner_aggregate":owner_covers,"realm_authority_root":root_basis.value});
            if let Some((_, current)) = creation
                && let Some(account) = actor.as_account_id()
                && let Some(observation) = current
                    .observations
                    .iter()
                    .find(|observation| &observation.record().account_id == account)
            {
                // Retain the original signed historical record, never the
                // process-local freshness observation or its Instant.
                basis["account_status_record"] = serde_json::json!(observation.record());
            }
            return Ok(Some(basis));
        }
    }
    Ok(None)
}

/// Called only after all independent requirements and canonical writes succeed
/// within the same transaction. A uniqueness race rolls back the entire target.
pub(crate) async fn consume_and_audit(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    methods: &[QualifiedApproval],
    accepted_basis: &serde_json::Value,
) -> PersistenceResult<()> {
    // The same grant-context evidence can satisfy independent grant and
    // governance requirements. Consume its nonce once and retain both bases.
    // Separate consumers may extend the same row only in this transaction;
    // an older transaction or another Event cannot reuse the nonce.
    let mut grouped = std::collections::BTreeMap::new();
    for qualified in methods {
        let vote = &qualified.method.signature;
        let context = arkret_canonical::canonical_json_string(&vote.input.approval_context)
            .map_err(|e| error("schema_violation", e))?;
        let key = (
            context,
            vote.input.approver_did.to_string(),
            vote.input.nonce.clone(),
        );
        let entry = grouped
            .entry(key)
            .or_insert_with(|| (qualified, Vec::new()));
        if entry.0.method.signature != qualified.method.signature
            || entry.0.method.public_key != qualified.method.public_key
        {
            return Err(error(
                "approval_nonce_reused",
                "distinct evidence shares one approval nonce",
            ));
        }
        let mut qualification = qualified.qualification_basis.clone();
        qualification
            .as_object_mut()
            .ok_or_else(|| {
                error(
                    "schema_violation",
                    "approval qualification must be an object",
                )
            })?
            .insert("consumer_authority_cut".to_owned(), accepted_basis.clone());
        if !entry.1.contains(&qualification) {
            entry.1.push(qualification);
        }
    }
    let event_digest =
        arkret_canonical::canonical_sha256(event).map_err(|e| error("schema_violation", e))?;
    for ((context, ..), (qualified, qualifications)) in grouped {
        let method = &qualified.method;
        let vote = &method.signature;
        let evidence = serde_json::to_value(vote).map_err(|e| error("schema_violation", e))?;
        let basis = serde_json::json!({"historical_method":vote.proof.verification_method,
            "verified_at":arkret_canonical::format_timestamp_canonical(vote.input.approved_at),
            "public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(&method.public_key),
            "authority_cut":accepted_basis,"qualifications":qualifications,"native_control_history":method.control_history});
        let inserted = sql_query("INSERT INTO event_approval_private_audit (approval_context,approver_did,nonce,event_id,event_digest,realm_id,accepted_commit_id,evidence,accepted_basis,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(approval_context,approver_did,nonce) DO UPDATE SET accepted_basis=jsonb_set(event_approval_private_audit.accepted_basis,'{qualifications}',(SELECT jsonb_agg(DISTINCT q) FROM jsonb_array_elements((event_approval_private_audit.accepted_basis->'qualifications') || (EXCLUDED.accepted_basis->'qualifications')) AS q)) WHERE event_approval_private_audit.xmin=pg_current_xact_id()::xid AND event_approval_private_audit.event_id=EXCLUDED.event_id AND event_approval_private_audit.event_digest=EXCLUDED.event_digest AND event_approval_private_audit.accepted_commit_id=EXCLUDED.accepted_commit_id AND event_approval_private_audit.evidence=EXCLUDED.evidence AND event_approval_private_audit.accepted_basis->'public_key'=EXCLUDED.accepted_basis->'public_key' AND event_approval_private_audit.accepted_basis->'native_control_history'=EXCLUDED.accepted_basis->'native_control_history' ")
            .bind::<Text,_>(&context).bind::<Text,_>(vote.input.approver_did.as_str())
            .bind::<Text,_>(&vote.input.nonce).bind::<Text,_>(event.event_id.as_str())
            .bind::<Text,_>(&event_digest).bind::<Text,_>(event.realm_id.as_str())
            .bind::<Text,_>(commit.commit_id.as_str()).bind::<Jsonb,_>(&evidence).bind::<Jsonb,_>(&basis)
            .bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        if inserted != 1 {
            return Err(error(
                "approval_nonce_reused",
                "approval nonce has already been consumed",
            ));
        }
    }
    Ok(())
}

/// List WIP is an independent fixed one-vote gate; votes from other contexts
/// cannot satisfy it. A stale revision never reaches nonce consumption.
pub(crate) async fn require_list_wip(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&EventApprovalCommit>,
    list: &arkret_wire::SpaceId,
    revision: &arkret_wire::CurrentRevision,
) -> PersistenceResult<Vec<QualifiedApproval>> {
    let methods = validate_candidate(event, commit, prepared)?;
    let target = WireResourceSelector::space(event.realm_id.clone(), list.clone());
    let facts = OperationFacts {
        object_kind: Some("space".to_owned()),
        space_id: Some(list.to_string()),
        space_kind: Some("list".to_owned()),
        ..OperationFacts::default()
    };
    let mut counted = std::collections::BTreeSet::new();
    let mut accepted = Vec::new();
    for method in methods {
        let vote = &method.signature;
        if !matches!(
            vote.input.approval_context,
            arkret_wire::ApprovalContext::ListWip { .. }
        ) {
            continue;
        }
        vote.input
            .validate_list_wip_binding(
                event,
                arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                list,
                revision,
            )
            .map_err(|e| error("approval_required", e))?;
        if let Some(basis) = approver_qualifies(
            conn,
            event,
            vote,
            CapabilityActionId::SpaceUpdate,
            &target,
            &facts,
            commit.committed_at,
            true,
            false,
        )
        .await?
            && counted.insert(
                arkret_wire::project_did_to_core_id(&vote.input.approver_did)
                    .map_err(|e| error("schema_violation", e))?,
            )
        {
            accepted.push(QualifiedApproval {
                method: method.clone(),
                qualification_basis: basis,
            });
        }
    }
    if accepted.is_empty() {
        return Err(error(
            "approval_required",
            "action=ak.strand.move effective_approval_quorum=1 counted_approvals=0",
        ));
    }
    Ok(accepted)
}

/// Governance remains a tightening layer after base capability admission. A
/// grant-context vote may count here only when it names a satisfied dependency;
/// realm-context votes cannot satisfy a grant's separate requirement.
#[expect(
    clippy::too_many_arguments,
    reason = "Governance approval verification binds the Event, current authority and qualified proofs."
)]
pub(crate) async fn require_governance(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&EventApprovalCommit>,
    action: CapabilityActionId,
    target: &WireResourceSelector,
    facts: &OperationFacts,
    dependencies: &[arkret_wire::GrantId],
) -> PersistenceResult<Vec<QualifiedApproval>> {
    let Some(quorum) = crate::policy_action_admission::current_quorum(
        conn,
        event,
        action,
        target,
        facts,
        commit.committed_at,
    )
    .await?
    else {
        return Ok(Vec::new());
    };
    let methods = validate_candidate(event, commit, prepared)?;
    let mut counted = std::collections::BTreeSet::new();
    let mut accepted = Vec::new();
    for method in methods {
        let vote = &method.signature;
        if vote.input.action != action {
            continue;
        }
        match &vote.input.approval_context {
            arkret_wire::ApprovalContext::RealmGovernance {} => {}
            arkret_wire::ApprovalContext::Grant { grant_id } if dependencies.contains(grant_id) => {
            }
            _ => continue,
        }
        if let Some(mut basis) = approver_qualifies(
            conn,
            event,
            vote,
            action,
            target,
            facts,
            commit.committed_at,
            false,
            prepared.is_some_and(|p| {
                matches!(
                    p.carrier_binding,
                    Some(coland_storage::ApprovalCarrierBinding::AuditPair { .. })
                )
            }),
        )
        .await?
            && counted.insert(
                arkret_wire::project_did_to_core_id(&vote.input.approver_did)
                    .map_err(|e| error("schema_violation", e))?,
            )
        {
            basis.as_object_mut().ok_or_else(|| error("schema_violation", "governance qualification must be an object"))?
                .insert("governance_requirement".to_owned(), serde_json::json!({
                    "action":action,"target":target,"effective_approval_quorum":quorum,
                    "evaluated_at":arkret_canonical::format_timestamp_canonical(commit.committed_at),
                }));
            accepted.push(QualifiedApproval {
                method: method.clone(),
                qualification_basis: basis,
            });
        }
    }
    if (accepted.len() as u64) < quorum {
        return Err(error(
            "approval_required",
            format!(
                "action={} effective_approval_quorum={} counted_approvals={}",
                action.as_str(),
                quorum,
                accepted.len()
            ),
        ));
    }
    Ok(accepted)
}
