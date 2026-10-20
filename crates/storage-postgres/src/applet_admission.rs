//! The closed local Applet authoring aggregate; no generic batch admission.
use arkret_models_integration::AppletRegistrationEpochEvidence;
use arkret_wire::{
    ActorId, CommitStreamHead, CommitStreamRef, DidUrl, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use coland_storage::{
    AppletAuthoringUnitOutcome, AppletAuthoringUnitWrite, AppletCommitAuthor,
    AppletResolutionAttester, AppletUnitFinalizer, AuthorityCommitTransaction,
    AuthorityCommitWriteOutcome, PersistenceError, PersistenceResult,
};

use super::{
    AsyncConnection, AsyncPgConnection, Binary, Jsonb, OptionalExtension, PgPool,
    PgTransactionError, QueryableByName, RunQueryDsl, Text, Timestamptz, Value, pg_conn, sql_query,
};

fn rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {error}"))
}
fn signature_rejected(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("signature_invalid: {error}"))
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> PersistenceResult<T> {
    serde_json::from_value(value).map_err(rejected)
}
pub(crate) fn target_station(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<&arkret_wire::DidCoreId> {
    let coland_storage::AppletAdmissionRequest::Install(body) = &input.request;
    Ok(&body.authoring_request_basis.target_station_id)
}
pub(crate) fn effective_scope(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<&ScopeRef> {
    let coland_storage::AppletAdmissionRequest::Install(body) = &input.request;
    Ok(&body.authoring_request_basis.effective_scope)
}
fn controller(method: &DidUrl) -> PersistenceResult<arkret_wire::DidCoreId> {
    let full = method
        .as_str()
        .split_once('#')
        .ok_or_else(|| rejected("method has no fragment"))?
        .0;
    arkret_wire::project_did_to_core_id(&arkret_wire::Did::new(full.to_owned()).map_err(rejected)?)
        .map_err(signature_rejected)
}
pub(crate) struct ValidatedAppletUnit {
    pub events: Vec<Event>,
    pub portal_realm: RealmId,
}
fn verify_package(
    input: &coland_storage::AppletAuthoringCandidate,
    epoch: &AppletRegistrationEpochEvidence,
) -> PersistenceResult<()> {
    input
        .package
        .validate_with_epoch_evidence(epoch)
        .map_err(rejected)?;
    let package_proof = input
        .package
        .proof
        .as_ref()
        .ok_or_else(|| rejected("package proof absent"))?;
    if controller(&package_proof.verification_method)? != input.package.controller_principal_id
        || arkret_wire::project_did_to_core_id(&input.controller_did_document.id)
            .map_err(rejected)?
            != input.package.controller_principal_id
    {
        return Err(rejected("package controller changed"));
    }
    let mut unsigned = input.package.clone();
    unsigned.proof = None;
    let package_bytes = arkret_canonical::canonical_json_bytes(&unsigned).map_err(rejected)?;
    if package_proof.payload_digest.as_str()
        != arkret_canonical::canonical::sha256_digest(&package_bytes)
    {
        return Err(rejected("package proof digest changed"));
    }
    arkret_identity::verify_jws_with_document(
        &package_bytes,
        &package_proof.jws,
        &package_proof.verification_method,
        &input.controller_did_document.id,
        &input.controller_did_document,
    )
    .map_err(signature_rejected)?;
    Ok(())
}

/// Verification is CPU work over receiver-owned public material. It returns
/// the original typed candidate result, never an authority boolean or cache.
pub(crate) async fn validate_candidate(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<ValidatedAppletUnit> {
    let input = Box::new(input.clone());
    tokio::task::spawn_blocking(move || validate_input(&input))
        .await
        .map_err(|error| {
            PersistenceError::Internal(format!("candidate verification task failed: {error}"))
        })?
}

pub(crate) fn validate_input(
    input: &coland_storage::AppletAuthoringCandidate,
) -> PersistenceResult<ValidatedAppletUnit> {
    if arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?
        != input.canonical_request_hash.as_str()
    {
        return Err(rejected("canonical request identity changed"));
    }
    input.package.validate().map_err(rejected)?;
    let coland_storage::AppletAdmissionRequest::Install(body) = &input.request;
    {
        body.e2ee_join_authorization_refs().map_err(rejected)?;
        let basis = &body.authoring_request_basis;
        basis.validate().map_err(rejected)?;
        if body.applet_package != input.package {
            return Err(rejected("installation package mirror differs"));
        }
        let epoch: AppletRegistrationEpochEvidence = decode(
            basis
                .registration_event
                .payload
                .get("manifest")
                .and_then(|m| m.get("registration_epoch_evidence"))
                .cloned()
                .ok_or_else(|| rejected("registration epoch absent"))?,
        )?;
        if basis.install_actor_id != input.admin_actor_id
            || basis.applet_id != input.package.applet_id
            || basis.service_id != input.package.service_id
            || input.package.package_digest.as_ref() != Some(&basis.package_digest)
        {
            return Err(rejected("installation immutable basis changed"));
        }
        let plan = input
            .recomputed_install_plan
            .as_ref()
            .ok_or_else(|| rejected("fresh install plan absent"))?;
        if body.plan_digest != plan.plan_digest
            || plan.compute_plan_digest().map_err(rejected)? != plan.plan_digest
            || plan.applet_id != basis.applet_id
            || plan.package_digest != basis.package_digest
            || plan.effective_scope != basis.effective_scope
            || plan.registration_epoch != input.package.registration_epoch
            || !plan.namespace_conflicts.is_empty()
        {
            return Err(rejected("install plan differs from the signed request"));
        }
        let mut expected_resource = match &basis.effective_scope {
            ScopeRef::Realm { realm_id } => {
                arkret_wire::WireResourceSelector::realm(realm_id.clone())
            }
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => {
                let mut r =
                    arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone());
                r.match_scope = Some(arkret_wire::ResourceMatchScope::Exact);
                r
            }
            _ => return Err(rejected("unsupported install scope")),
        };
        let _ = &mut expected_resource;
        let mut unique_actions = std::collections::BTreeSet::new();
        for e in &basis.capability_grant_events {
            let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
                decode(serde_json::to_value(&e.payload).map_err(rejected)?)?;
            let g = payload.grant;
            if g.issuer_id!=input.admin_actor_id || g.realm_id.as_ref()!=Some(basis.effective_scope.realm_id()) || !matches!(g.subject,arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor) if actor==&applet_grant_subject(input)) || g.resources!=vec![expected_resource.clone()] || g.actions.is_empty() || g.constraints.iter().filter(|c|c.constraint_kind==arkret_models_collaboration::governance::grant_constraint::GrantConstraintKind::AuthorityControl && c.constraint_subkind==Some(arkret_models_collaboration::governance::grant_constraint::GrantConstraintSubkind::AppletAuthority) && c.applet_id.as_ref()==Some(&input.package.applet_id) && c.executed_by.as_ref()==Some(&ActorId::service(input.package.service_id.clone())) && c.registration_epoch.as_ref()==Some(&input.package.registration_epoch)).count()!=1 {return Err(rejected("staged grant immutable authority binding differs"));}
            for action in g.actions {
                if !input.package.requested_scopes.contains(&action)
                    || !unique_actions.insert(action)
                {
                    return Err(rejected(
                        "staged grant duplicates or exceeds package requests",
                    ));
                }
            }
        }
        let approved = plan
            .approved_scopes
            .iter()
            .flat_map(|scope| scope.actions.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>();
        if unique_actions != approved {
            return Err(rejected("staged grant differs from approved plan actions"));
        }
        let derived = input.package.to_registration(&epoch).map_err(rejected)?;
        if serde_json::to_value(derived).map_err(rejected)?
            != serde_json::to_value(&basis.registration_event.payload).map_err(rejected)?
        {
            return Err(rejected("registration differs from signed package"));
        }
        let mut events = vec![basis.registration_event.clone()];
        events.extend(basis.capability_grant_events.clone());
        if events.iter().any(|e| {
            e.actor_id != input.admin_actor_id
                || e.realm_id != *basis.effective_scope.realm_id()
                || e.scope_ref != basis.effective_scope
                || e.executed_by.is_some()
        }) {
            return Err(rejected("admin Event does not bind the installation scope"));
        }
        if events[0].kind != EventKind::AppletRegistration
            || events[1..]
                .iter()
                .any(|e| e.kind != EventKind::CapabilityGrant)
            || input.admin_producer_guards.len() != events.len()
        {
            return Err(rejected("admin fixed set or producer guards changed"));
        }
        epoch
            .validate_against_did_document(&input.service_did_document)
            .map_err(rejected)?;
        verify_package(input, &epoch)?;
        for event in &events {
            event.validate_for_submit_structural().map_err(rejected)?;
        }
        return Ok(ValidatedAppletUnit {
            events,
            portal_realm: basis.effective_scope.realm_id().clone(),
        });
    }
}

#[derive(QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct CompletionRow {
    #[diesel(sql_type=Text)]
    canonical_request_hash: String,
    #[diesel(sql_type=Jsonb)]
    committed_event_refs: Value,
    #[diesel(sql_type=Jsonb)]
    response_body: Value,
}
#[derive(QueryableByName)]
struct PreviewRow {
    #[diesel(sql_type=Text)]
    request_digest: String,
    #[diesel(sql_type=Jsonb)]
    signed_request: Value,
    #[diesel(sql_type=Timestamptz)]
    expires_at: chrono::DateTime<chrono::Utc>,
}
pub(crate) async fn admit_authoring_unit(
    pool: &PgPool,
    mut input: AppletAuthoringUnitWrite,
    author: AppletCommitAuthor,
    attester: AppletResolutionAttester,
    finalize: AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    // The local observation becomes the one canonical acceptance instant
    // before any Commit is authored or same-cut evidence is evaluated.
    input.accepted_at = arkret_canonical::normalize_timestamp_canonical(input.accepted_at);
    let mut conn = pg_conn(pool).await.map_err(PersistenceError::database)?;
    (*conn)
        .transaction::<_, PgTransactionError, _>(async move |conn| {
            Box::pin(admit_in_connection(
                conn, &input, &author, &attester, &finalize,
            ))
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(PgTransactionError::into_persistence)
}
async fn accepted_pair(
    conn: &mut AsyncPgConnection,
    reference: &arkret_wire::CommittedEventRef,
) -> PersistenceResult<(Event, RealmCommit)> {
    #[derive(QueryableByName)]
    struct Pair {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let row=sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND c.commit_id=$2 AND e.state='committed'")
        .bind::<Binary,_>(reference.event_id.token_bytes().to_vec())
        .bind::<Text,_>(reference.commit_id.as_str()).get_result::<Pair>(&mut *conn).await.optional().map_err(PersistenceError::database)?.ok_or_else(||rejected("prior accepted anchor missing"))?;
    let e: Event = decode(row.envelope)?;
    let c: RealmCommit = decode(row.commit_json)?;
    if e.event_id != reference.event_id
        || c.event_ref != reference.event_id
        || &c.realm_id != reference.stream_ref.realm_id()
        || c.stream_ref != reference.stream_ref
        || c.stream_position != reference.stream_position
    {
        return Err(rejected("prior accepted anchor misbinding"));
    }
    Ok((e, c))
}
async fn stream_head(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<Option<CommitStreamHead>> {
    stream_head_for(
        conn,
        &CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
    )
    .await
}
async fn stream_head_for(
    conn: &mut AsyncPgConnection,
    stream: &CommitStreamRef,
) -> PersistenceResult<Option<CommitStreamHead>> {
    let key = crate::authority_commit::stream_key(stream)?;
    let row=sql_query("SELECT commit_json AS value FROM realm_commits WHERE stream_key=$1 ORDER BY stream_position DESC LIMIT 1 FOR UPDATE")
        .bind::<Text,_>(key).get_result::<JsonRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    row.map(|r| {
        let c: RealmCommit = decode(r.value)?;
        Ok(CommitStreamHead {
            stream_ref: c.stream_ref,
            stream_position: c.stream_position,
            commit_id: c.commit_id,
        })
    })
    .transpose()
}
async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    input: &AppletAuthoringUnitWrite,
    author: &AppletCommitAuthor,
    _attester: &AppletResolutionAttester,
    finalize: &AppletUnitFinalizer,
) -> PersistenceResult<AppletAuthoringUnitOutcome> {
    let operation = arkret_wire::ServiceOperationId::SelfAppletCommandInstallV1;
    if input.operation_id
        != operation
            .as_str()
            .strip_suffix(".v1")
            .ok_or_else(|| rejected("creation operation has no v1 identity"))?
    {
        return Err(rejected(
            "authoring operation differs from its original request purpose",
        ));
    }
    if arkret_canonical::canonical_sha256(&input.request).map_err(rejected)?
        != input.canonical_request_hash.as_str()
    {
        return Err(rejected(
            "exact retry request differs from its canonical identity",
        ));
    }
    let actor_key = input.admin_actor_id.canonical_key().map_err(rejected)?;
    let identity_lock = format!(
        "applet:{}:{}",
        input.package.applet_id,
        target_station(input)?
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&identity_lock)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    let previous=sql_query("SELECT canonical_request_hash,committed_event_refs,response_body FROM applet_authoring_units WHERE actor_key=$1 AND operation_id=$2 AND idempotency_key=$3 FOR UPDATE")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).get_result::<CompletionRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = previous {
        if row.canonical_request_hash != input.canonical_request_hash.as_str() {
            return Err(rejected(
                "idempotency payload differs from first accepted request",
            ));
        }
        return Ok(AppletAuthoringUnitOutcome {
            committed_event_refs: decode(row.committed_event_refs)?,
            response_body: row.response_body,
            replayed: true,
        });
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(
        conn,
        effective_scope(input)?.realm_id(),
    )
    .await?;
    let mut current_input = input.clone();
    current_input.accepted_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let input = &current_input;
    let validated = validate_candidate(input).await?;
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &validated.portal_realm)
        .await?;
    let admin_count = input.admin_producer_guards.len();
    if admin_count > 0 {
        let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
            conn,
            &validated.portal_realm,
            &input.admin_actor_id,
        )
        .await?;
        cut.require_open_lifecycle(&validated.events[0])?;
        if !cut.actor_is_root_controller()
            && !cut.grants_cover_any(
                &[arkret_wire::CapabilityActionId::REALM_ADMIN],
                input.accepted_at,
            )
        {
            return Err(rejected("applet_registration_unauthorized"));
        }
        for (e, guard) in validated.events[..admin_count]
            .iter()
            .zip(&input.admin_producer_guards)
        {
            crate::authority_commit::check_self_producer_guard_in_connection(
                conn,
                e,
                guard,
                input.accepted_at,
            )
            .await?;
            verify_admin_producer(conn, e, guard, input.accepted_at).await?;
        }
        {
            let coland_storage::AppletAdmissionRequest::Install(body) = &input.request;
            crate::boxed_future(|| {
                crate::applet_e2ee::require_install_policy(conn, body, input.accepted_at)
            })
            .await?;
        }
    }
    if admin_count == 0 || input.operation_approvals.is_some() {
        return Err(rejected(
            "installation requires its original administrator Events",
        ));
    }
    let mut refs = Vec::new();
    for event in &validated.events {
        let authority = crate::authority_commit::locked_authority(conn, &event.realm_id)
            .await
            .map_err(PgTransactionError::into_persistence)?
            .ok_or_else(|| rejected("local current authority unavailable"))?;
        if authority.service_id != *target_station(input)? {
            return Err(rejected("authoring unit crosses sovereign Stations"));
        }
        let stream = CommitStreamRef::from_scope(&event.scope_ref, Some(event.realm_id.clone()))
            .map_err(rejected)?;
        let head = stream_head_for(conn, &stream).await?;
        // Native installation does not exempt its ordinary Human members from
        // the original signer-fact contract. Freeze under this same locked cut,
        // bind it before Commit ID/signature, and archive only with acceptance.
        let producer_signer_fact = Box::pin(
            crate::agent_producer_signer_keys::prepare_local_account_device_source_in_connection(
                conn,
                event,
                input.accepted_at,
            ),
        )
        .await?;
        let candidate = producer_signer_fact.clone().map(Into::into);
        let device_core = if let Some(fact) = producer_signer_fact.as_ref() {
            Some(
                crate::account_device_committed_evidence::prepare_core(
                    conn,
                    event,
                    fact,
                    input.accepted_at,
                    target_station(input)?,
                )
                .await?,
            )
        } else {
            None
        };
        let (commit, device_evidence) = author(
            event,
            &authority,
            head.as_ref(),
            input.accepted_at,
            candidate.as_ref(),
            device_core.as_ref(),
        )?;
        crate::account_device_committed_evidence::validate(
            event,
            &commit,
            producer_signer_fact.as_ref(),
            device_evidence.as_ref(),
        )?;
        crate::agent_producer_signer_keys::validate_account_device_fact_binding(
            event,
            &commit,
            producer_signer_fact.as_ref(),
        )?;
        let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: input.station_public_key.to_vec(),
        };
        if commit.signature.verification_method != input.station_verification_method
            || commit.committed_at != input.accepted_at
        {
            return Err(rejected(
                "covering Commit changed Station or acceptance instant",
            ));
        }
        arkret_signatures::detached_object::verify_detached_object_signature(
            &commit.signature,
            &arkret_canonical::unsigned_value(&commit, &["signature"])
                .map_err(signature_rejected)?,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &material,
        )
        .map_err(signature_rejected)?;
        let transaction = AuthorityCommitTransaction {
            expected_authority: authority,
            event: event.clone(),
            commit: commit.clone(),
            producer_signer_fact: candidate,
            mls_state: None,
            welcomes: vec![],
            recipient_queue_capacity: 0,
        };
        crate::authority_commit::queue_event_in_connection(conn, event, input.accepted_at)
            .await
            .map_err(PgTransactionError::into_persistence)?;
        if !matches!(
            crate::authority_commit::commit_verified_applet_in_connection(conn, &transaction)
                .await
                .map_err(PgTransactionError::into_persistence)?,
            AuthorityCommitWriteOutcome::Committed
        ) {
            return Err(rejected("Applet Event was accepted outside this aggregate"));
        }
        if let Some(fact) = producer_signer_fact.as_ref() {
            crate::agent_producer_signer_keys::retain_prepared_account_device_in_connection(
                conn, event, &commit, fact,
            )
            .await?;
            crate::account_device_committed_evidence::retain(
                conn,
                &commit,
                fact,
                device_evidence
                    .as_ref()
                    .ok_or_else(|| rejected("original Device evidence absent"))?,
            )
            .await?;
        }
        if event.kind == EventKind::CapabilityGrant {
            crate::capability_grant_current_results::commit_capability_grant_current_result_in_connection(conn,event,&commit, None).await?;
        }
        crate::applet_current_results::project_applet_event_in_connection(conn, event, &commit)
            .await?;
        refs.push(arkret_wire::CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: commit.commit_id,
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
        });
    }
    let finalization = finalize(&refs)?;
    validate_finalized_refs(input, &refs, &finalization.response_body)?;
    if finalization.applet_record.applet_id != input.package.applet_id
        || finalization.applet_record.expected_record != input.expected_installation
        || finalization.applet_record.identity.expected_record != input.expected_identity
        || finalization.idempotency_record.authenticated_actor != input.admin_actor_id
        || finalization.idempotency_record.operation_id != input.operation_id
        || finalization.idempotency_record.idempotency_key != input.idempotency_key
        || finalization.idempotency_record.request_hash != input.canonical_request_hash.as_str()
        || finalization.idempotency_record.response_body != finalization.response_body
    {
        return Err(rejected("finalization changed immutable request bindings"));
    }
    crate::unit_of_work::commit_applet_record(conn, finalization.applet_record).await?;
    crate::idempotency::record_idempotency_in_connection(conn, &finalization.idempotency_record)
        .await?;
    let context_json = Value::Null;
    sql_query("INSERT INTO applet_authoring_units(actor_key,operation_id,idempotency_key,canonical_request_hash,request_digest,committed_event_refs,response_body,request_body,authoring_context,accepted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind::<Text,_>(&actor_key).bind::<Text,_>(&input.operation_id).bind::<Text,_>(&input.idempotency_key).bind::<Text,_>(input.canonical_request_hash.as_str()).bind::<Text,_>(input.request_digest.as_str()).bind::<Jsonb,_>(serde_json::to_value(&refs).map_err(rejected)?).bind::<Jsonb,_>(&finalization.response_body).bind::<Jsonb,_>(serde_json::to_value(&input.request).map_err(rejected)?).bind::<Jsonb,_>(context_json).bind::<Timestamptz,_>(input.accepted_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(AppletAuthoringUnitOutcome {
        committed_event_refs: refs,
        response_body: finalization.response_body,
        replayed: false,
    })
}

async fn verify_admin_producer(
    conn: &mut AsyncPgConnection,
    event: &Event,
    guard: &coland_storage::SelfProducerCommitGuard,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if controller(
        &event
            .producer_proof
            .as_ref()
            .ok_or_else(|| signature_rejected("unsigned admin Event"))?
            .verification_method,
    )? != *event.actor_id.signing_principal_id()
    {
        return Err(signature_rejected(
            "admin method belongs to another signing principal",
        ));
    }
    let suite =
        arkret_canonical::canonical::digest_suite(event.event_id.digest_suite_code().as_str())
            .map_err(rejected)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(rejected)?;
    match guard {
        coland_storage::SelfProducerCommitGuard::MimiFacade { .. }
        | coland_storage::SelfProducerCommitGuard::AppletManagedDevice(_) => {
            return Err(rejected(
                "this producer cannot administer an Applet installation",
            ));
        }
        coland_storage::SelfProducerCommitGuard::HumanDevice(selector)
        | coland_storage::SelfProducerCommitGuard::HumanDeviceEvidence { selector, .. } => {
            let account = event
                .actor_id
                .as_account_id()
                .ok_or_else(|| rejected("admin producer is not a full Account"))?;
            let device =
                arkret_wire::DeviceId::new(selector.device_id.clone()).map_err(rejected)?;
            crate::actor_profiles::verify_device_signer_in_connection(
                conn,
                event,
                account,
                &device,
                selector.authorization_ref.stream_ref.realm_id(),
                at,
                suite,
                "Applet admin",
            )
            .await
            .map_err(PgTransactionError::into_persistence)?;
        }
        coland_storage::SelfProducerCommitGuard::Agent {
            authorization_ref, ..
        } => {
            let (source, _) = accepted_pair(conn, authorization_ref).await?;
            let payload:arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload=decode(serde_json::to_value(&source.payload).map_err(rejected)?)?;
            let bytes = arkret_canonical::base64url_decode(payload.public_key.key.as_str())
                .map_err(rejected)?;
            let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes };
            arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
                event
                    .producer_proof
                    .as_ref()
                    .ok_or_else(|| rejected("unsigned admin"))?,
                &arkret_signatures::EventProofBuilder::new()
                    .envelope_bytes(event)
                    .map_err(signature_rejected)?,
                &event.actor_id,
                &material,
                suite,
            )
            .map_err(signature_rejected)?;
        }
    }
    Ok(())
}

fn validate_finalized_refs(
    input: &AppletAuthoringUnitWrite,
    refs: &[arkret_wire::CommittedEventRef],
    response: &Value,
) -> PersistenceResult<()> {
    match &input.request {
        coland_storage::AppletAdmissionRequest::Install(body) => {
            let outcome: arkret_models_integration::AppletInstallOutcome =
                decode(response.clone())?;
            let grants = body
                .authoring_request_basis
                .capability_grant_events
                .iter()
                .map(|e| arkret_wire::GrantId::from_event_id(&e.event_id))
                .collect::<Vec<_>>();
            if refs.first().map(|r| &r.event_id) != Some(&outcome.registration_event_ref)
                || refs.len() != 1 + grants.len()
                || outcome.applet_id != input.package.applet_id
                || outcome.registration_epoch != input.package.registration_epoch
                || outcome.capability_grant_refs != grants
                || outcome.e2ee_authorization_refs
                    != body.e2ee_join_authorization_refs().map_err(rejected)?
                || outcome.widget_policy_ref.is_some()
            {
                return Err(rejected(
                    "Service install outcome fabricates managed anchors",
                ));
            }
        }
    }
    Ok(())
}
fn applet_grant_subject(input: &coland_storage::AppletAuthoringCandidate) -> ActorId {
    ActorId::service(input.package.service_id.clone())
}
