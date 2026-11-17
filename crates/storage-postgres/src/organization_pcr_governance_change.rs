//! Finite Organization planned change at one original native authority cut.

use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, DidCoreId, Event, RealmCommit, RealmId,
};
use coland_storage::{
    AuthorityCommitWriteOutcome, OrganizationPcrGovernanceChangeAdmissionWrite, PersistenceError,
    PersistenceResult,
};
use diesel::sql_types::{Binary, Bool, Jsonb, Text};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PgTransactionError};

fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: Organization planned change {detail}"
    ))
}
fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("Organization change original: {detail}"))
}
fn authority_error(error: arkret_identity::IdentityError) -> PersistenceError {
    match error.error_code() {
        Some(code) => PersistenceError::Conflict(format!("{}: {error}", code.as_str())),
        None => refused(error),
    }
}

#[derive(QueryableByName)]
struct Canonical {
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: Value,
}

async fn inception(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<(
    arkret_identity::organization_pcr_genesis::VerifiedOrganizationPcrGenesis,
    arkret_wire::EventId,
)> {
    // A candidate shape or editable resolution cannot establish this branch.
    let row = sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1::text) AND c.stream_position=0 AND e.state='committed' AND e.kind='ak.realm.create'")
        .bind::<Text,_>(realm.as_str()).get_result::<Canonical>(&mut *conn).await.optional()
        .map_err(crate::persistence_query_error)?.ok_or_else(||refused("accepted inception is missing"))?;
    let full = arkret_wire::CommittedEventFullView {
        event: serde_json::from_value(row.envelope).map_err(corrupt)?,
        commit: serde_json::from_value(row.commit_json).map_err(corrupt)?,
    };
    let fact = crate::organization_pcr_genesis::fact_for_commit_in_connection(
        conn,
        &full.event,
        &full.commit,
    )
    .await?
    .ok_or_else(|| refused("accepted native Organization source is missing"))?;
    let verified =
        arkret_identity::organization_pcr_genesis::verify_organization_genesis_signer_fact(
            &full, &fact,
        )
        .map_err(authority_error)?;
    Ok((verified, full.event.event_id))
}

fn verify_source(
    origin: &arkret_identity::organization_pcr_genesis::VerifiedOrganizationPcrGenesis,
    request: &PeerAuthorityForwardEventRequestBody,
    source: &DidCoreId,
    entries: &[Value],
    witnesses: &[Value],
    producer: Option<&AuthenticatedServiceResolution>,
    commit: &RealmCommit,
) -> PersistenceResult<Vec<(arkret_wire::ApprovalSignature, [u8; 32])>> {
    request.validate().map_err(refused)?;
    let event = &request.event_submission.event;
    if request.mls_group_state_material.is_some()
        || request.content_backup_sources.is_some()
        || request.producer_agent_evidence.is_some()
        || request.successor_device_evidence.is_some()
        || event.actor_id.as_account_id() != Some(origin.holder())
        || event.kind != arkret_wire::EventKind::RealmGovernanceStationChange
        || commit.producer_signer_fact_digest.is_some()
    {
        return Err(refused("source differs from the one finite native Event"));
    }
    arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: commit.clone(),
    }
    .validate_shape()
    .map_err(refused)?;
    commit.verify_commit_id_matches_content().map_err(refused)?;
    let methods = arkret_identity::organization_pcr_genesis::verify_organization_pcr_governance_change_authority(
        origin, &request.event_submission, entries, witnesses, commit.committed_at,
    ).map_err(authority_error)?;
    match (event.account_device_producer().map_err(refused)?, producer) {
        (Some(device), None) if &device.account_id.station_id == source => {
            let evidence = request
                .producer_device_evidence
                .as_ref()
                .ok_or_else(|| refused("current actual Device source is missing"))?;
            let destination =
                arkret_wire::detached_signature_service_id(&commit.signature).map_err(refused)?;
            arkret_identity::account_device_signer_evidence::verify_forwarded_account_device_signer_fact(
                evidence, event, source, &destination,
                &arkret_models_collaboration::authority_commit::authority_forward_body_digest(request).map_err(refused)?,
                event.event_id.digest_suite_code().digest_suite(), commit.committed_at,
            ).map_err(authority_error)?;
        }
        (None, Some(service))
            if matches!(event.actual_signer(), arkret_wire::ActorId::Service {service_id} if service_id==source)
                && request.producer_device_evidence.is_none() =>
        {
            arkret_identity::organization_pcr_genesis::verify_organization_pcr_service_producer(
                event,
                service,
                commit.committed_at,
            )
            .map_err(authority_error)?;
        }
        _ => {
            return Err(refused(
                "authenticated Source is not the actual executor hosting source",
            ));
        }
    }
    Ok(methods)
}

fn material(write: &OrganizationPcrGovernanceChangeAdmissionWrite) -> Value {
    json!({
        "source_service_id":write.source_service_id,
        "peer_request":write.request,
        "organization_log_entries":write.organization_log_entries,
        "organization_witness_records":write.organization_witness_records,
        "producer_service_resolution":write.producer_service_resolution,
    })
}

// Match consume_and_audit's existing global nonce ordering exactly.
// All occurrences of one nonce remain in the same consumption group.
fn nonce_key(
    approval: &arkret_wire::ApprovalSignature,
) -> PersistenceResult<(String, String, String)> {
    Ok((
        arkret_canonical::canonical_json_string(&approval.input.approval_context)
            .map_err(corrupt)?,
        approval.input.approver_did.to_string(),
        approval.input.nonce.clone(),
    ))
}

fn source_owner(
    methods: &[(arkret_wire::ApprovalSignature, [u8; 32])],
) -> PersistenceResult<(String, String, String)> {
    methods
        .iter()
        .map(|(approval, _)| nonce_key(approval))
        .collect::<PersistenceResult<Vec<_>>>()?
        .into_iter()
        .min()
        .ok_or_else(|| corrupt("finite original has no approval nonce owner"))
}

#[derive(QueryableByName)]
struct Audit {
    #[diesel(sql_type=Jsonb)]
    source: Value,
    #[diesel(sql_type=Jsonb)]
    outcome: Value,
}

/// One deterministic existing nonce row retains the complete original source.
/// Every original nonce still binds its exact evidence, key and accepting cut.
async fn original(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<(
    PeerAuthorityForwardEventRequestBody,
    DidCoreId,
    AuthoritySubmitResponseBody,
)> {
    let rows = sql_query("SELECT accepted_basis#>'{authority_cut,organization_pcr_change_source}' AS source,accepted_basis#>'{authority_cut,original_outcome}' AS outcome FROM event_approval_private_audit WHERE event_id=$1 AND accepted_commit_id=$2 AND accepted_basis#>'{authority_cut,organization_pcr_change_source}' IS NOT NULL ORDER BY approval_context,approver_did,nonce")
        .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .load::<Audit>(&mut *conn).await.map_err(crate::persistence_query_error)?;
    if rows.len() != 1 {
        return Err(corrupt(
            "finite original must have exactly one complete source owner",
        ));
    }
    let first = &rows[0];
    let request: PeerAuthorityForwardEventRequestBody =
        serde_json::from_value(first.source["peer_request"].clone()).map_err(corrupt)?;
    let source: DidCoreId =
        serde_json::from_value(first.source["source_service_id"].clone()).map_err(corrupt)?;
    let entries: Vec<Value> =
        serde_json::from_value(first.source["organization_log_entries"].clone())
            .map_err(corrupt)?;
    let witnesses: Vec<Value> =
        serde_json::from_value(first.source["organization_witness_records"].clone())
            .map_err(corrupt)?;
    let producer: Option<AuthenticatedServiceResolution> =
        serde_json::from_value(first.source["producer_service_resolution"].clone())
            .map_err(corrupt)?;
    let outcome: AuthoritySubmitResponseBody =
        serde_json::from_value(first.outcome.clone()).map_err(corrupt)?;
    if request.event_submission.event != *event
        || !matches!(&outcome, AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed,commit:stored} if stored==commit)
    {
        return Err(corrupt(
            "source Event, covering Commit or first result differs",
        ));
    }
    let (origin, root_ref) = inception(conn, &event.realm_id).await?;
    // The PCR profile forbids authority reset/delegate; Station handoff keeps
    // the original authority-root source Event and never advances its epoch.
    if event.authorization_ref.as_deref() != Some(root_ref.as_str()) {
        return Err(corrupt(
            "accepted change does not bind its immutable PCR authority-root source",
        ));
    }
    let methods = verify_source(
        &origin,
        &request,
        &source,
        &entries,
        &witnesses,
        producer.as_ref(),
        commit,
    )?;
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    let owner = source_owner(&methods)?;
    for (approval, key) in &methods {
        let owns_source = nonce_key(approval)? == owner;
        let present=sql_query("SELECT EXISTS(SELECT 1 FROM event_approval_private_audit WHERE approval_context=$1 AND approver_did=$2 AND nonce=$3 AND event_id=$4 AND event_digest=$5 AND realm_id=$6 AND accepted_commit_id=$7 AND evidence=$8 AND accepted_basis->>'public_key'=$9 AND (($10::boolean AND accepted_basis#>'{authority_cut,organization_pcr_change_source}'=$11 AND accepted_basis#>'{authority_cut,original_outcome}'=$12) OR (NOT $10::boolean AND accepted_basis#>'{authority_cut,organization_pcr_change_source}' IS NULL AND accepted_basis#>'{authority_cut,original_outcome}' IS NULL))) AS present")
            .bind::<Text,_>(arkret_canonical::canonical_json_string(&approval.input.approval_context).map_err(corrupt)?)
            .bind::<Text,_>(approval.input.approver_did.as_str()).bind::<Text,_>(&approval.input.nonce)
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(arkret_canonical::canonical_sha256(event).map_err(corrupt)?)
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(approval).map_err(corrupt)?)
            .bind::<Text,_>(arkret_canonical::ed25519_pubkey_to_did_key_multibase(key))
            .bind::<Bool,_>(owns_source).bind::<Jsonb,_>(&first.source).bind::<Jsonb,_>(&first.outcome)
            .get_result::<Present>(&mut *conn).await.map_err(crate::persistence_query_error)?;
        if !present.present {
            return Err(corrupt(
                "consumed approval nonce or original basis is missing",
            ));
        }
    }
    Ok((request, source, outcome))
}

pub(crate) async fn exact_original_in_connection(
    conn: &mut AsyncPgConnection,
    incoming: &PeerAuthorityForwardEventRequestBody,
    source: &DidCoreId,
) -> PersistenceResult<Option<AuthoritySubmitResponseBody>> {
    incoming.validate().map_err(refused)?;
    let event = &incoming.event_submission.event;
    if event.kind != arkret_wire::EventKind::RealmGovernanceStationChange {
        return Err(refused("original lookup requires one native change"));
    }
    let row=sql_query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.id=$1 AND e.state='committed'")
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<Canonical>(&mut *conn)
        .await.optional().map_err(crate::persistence_query_error)?;
    let Some(row) = row else { return Ok(None) };
    let stored: Event = serde_json::from_value(row.envelope).map_err(corrupt)?;
    let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(corrupt)?;
    let (request, issuer, outcome) = original(conn, &stored, &commit).await?;
    if request.event_submission != incoming.event_submission || &issuer != source {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: finite Organization original differs".into(),
        ));
    }
    Ok(Some(outcome))
}

/// Used by frozen private source validation, never as a current authorization.
pub(crate) async fn verify_accepted_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    original(conn, event, commit).await.map(|_| ())
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &OrganizationPcrGovernanceChangeAdmissionWrite,
) -> Result<AuthoritySubmitResponseBody, PgTransactionError> {
    let tx = &write.transaction;
    let event = &tx.event;
    tx.validate().map_err(refused)?;
    if event != &write.request.event_submission.event
        || tx.producer_signer_fact.is_some()
        || tx.commit.producer_signer_fact_digest.is_some()
    {
        return Err(refused("candidate differs from the native original").into());
    }
    #[derive(QueryableByName)]
    struct Locked {
        #[diesel(sql_type=Text)]
        realm_id: String,
    }
    let locked = sql_query("SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE")
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<Locked>(&mut *conn)
        .await?;
    if locked.realm_id != event.realm_id.as_str() {
        return Err(corrupt("authority lock differs").into());
    }
    if let Some(result) =
        exact_original_in_connection(conn, &write.request, &write.source_service_id).await?
    {
        return Ok(result);
    }
    let (origin, _) = inception(conn, &event.realm_id).await?;
    let cut = crate::pcr_private_authority::lock_holder(
        conn,
        origin.holder(),
        Some(&tx.expected_authority.service_id),
    )
    .await?;
    if event.actor_id.as_account_id() != Some(origin.holder())
        || cut.realm_id != event.realm_id
        || cut.generation != tx.expected_authority.generation
        || tx.commit.previous_commit_ref.as_ref() != Some(&cut.head.commit_id)
    {
        return Err(refused("full holder, accepting authority or current head differs").into());
    }
    crate::pcr_private_authority::require_active_account_owner(conn, origin.holder()).await?;
    let methods = verify_source(
        &origin,
        &write.request,
        &write.source_service_id,
        &write.organization_log_entries,
        &write.organization_witness_records,
        write.producer_service_resolution.as_ref(),
        &tx.commit,
    )?;
    crate::organization_pcr_genesis::lock_current_native_sources(
        conn,
        &write.organization_log_entries,
        write.producer_service_resolution.as_ref(),
    )
    .await?;
    #[derive(QueryableByName)]
    struct Root {
        #[diesel(sql_type=Text)]
        authority_event_ref: String,
    }
    let root = sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_states WHERE realm_id=$1",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<Root>(&mut *conn)
    .await?;
    if event.authorization_ref.as_deref() != Some(root.authority_event_ref.as_str()) {
        return Err(refused("current root reference changed").into());
    }
    crate::pcr_private_archive::validate_export_ready(conn, origin.holder(), &event.realm_id)
        .await?;
    crate::authority_commit::queue_event_in_connection(conn, event, tx.commit.committed_at).await?;
    match crate::authority_commit::commit_verified_pcr_governance_change_in_connection(conn, tx)
        .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        _ => return Err(refused("authority/head moved before one native commit").into()),
    }
    let result = AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: tx.commit.clone(),
    };
    let source = material(write);
    let owner = source_owner(&methods)?;
    let mut first = Vec::new();
    let mut rest = Vec::new();
    for (signature, key) in methods {
        let owns_source = nonce_key(&signature)? == owner;
        let qualified = crate::approval_admission::QualifiedApproval {
            method: coland_storage::ApprovalHistoricalMethod {
                signature,
                public_key: key,
                native_control: None,
                control_history: Some(
                    json!({"log_entries":write.organization_log_entries,"witness_records":write.organization_witness_records}),
                ),
            },
            qualification_basis: json!({"organization_pcr_planned_change":true,"account_id":origin.holder()}),
        };
        if owns_source {
            first.push(qualified);
        } else {
            rest.push(qualified);
        }
    }
    // The first group is exactly the minimum generic nonce key. The generic
    // owner sorts rest as before, preserving the complete original lock order.
    crate::approval_admission::consume_and_audit(
        conn,
        event,
        &tx.commit,
        &first,
        &json!({"organization_pcr_change_source":source,"original_outcome":result}),
    )
    .await?;
    if !rest.is_empty() {
        crate::approval_admission::consume_and_audit(conn, event, &tx.commit, &rest, &json!({}))
            .await?;
    }
    verify_accepted_in_connection(conn, event, &tx.commit).await?;
    Ok(result)
}
