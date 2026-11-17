//! One-create Organization PCR admission and immutable accepted-source verification.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;
use arkret_wire::{
    AuthorityCommitStatus, AuthoritySubmitResponseBody, CommitStreamRef, DidCoreId, Event,
    RealmCommit, RealmCommitAuthorityRef, RealmId, ScopeRef,
};
use coland_storage::{
    AuthorityCommitWriteOutcome, OrganizationPcrGenesisAdmissionWrite, PersistenceError,
    PersistenceResult,
};
use diesel::sql_types::{BigInt, Binary, Bool, Jsonb, Nullable, Text, Timestamptz};
use diesel::{QueryableByName, sql_query};
use horme::{OptionalExtension as _, RunQueryDsl as _};
use serde_json::{Value, json};

use crate::{AsyncPgConnection, PgTransactionError};

fn refused(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!(
        "failed_precondition: Organization PCR genesis {detail}"
    ))
}
fn corrupt(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(format!("Organization PCR original: {detail}"))
}
fn authority_error(error: arkret_identity::IdentityError) -> PersistenceError {
    match error.error_code() {
        Some(code) => PersistenceError::Conflict(format!("{}: {error}", code.as_str())),
        None => refused(error),
    }
}

fn verify_original(
    request: &PeerAuthorityForwardEventRequestBody,
    source: &DidCoreId,
    entries: &[Value],
    witnesses: &[Value],
    producer_service: Option<&arkret_models_identity::AuthenticatedServiceResolution>,
    commit: &RealmCommit,
) -> PersistenceResult<(
    arkret_identity::organization_pcr_genesis::VerifiedOrganizationPcrGenesis,
    arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
)> {
    request.validate().map_err(refused)?;
    if !request.is_organization_pcr_genesis_candidate() {
        return Err(refused("does not match its registered carrier"));
    }
    let event = &request.event_submission.event;
    let holder = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| refused("full Account missing"))?;
    let genesis = event.as_realm_create().map_err(refused)?.object;
    let governor =
        arkret_wire::detached_signature_service_id(&commit.signature).map_err(refused)?;
    if source != &holder.station_id
        || genesis.governance_station_id != governor
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_position != 0
        || commit.previous_commit_ref.is_some()
        || commit.governance_generation != 0
        || commit.authority_ref
            != RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone())
        || event.scope_ref != ScopeRef::RealmGenesis
        || event.realm_id != RealmId::from_event_id(&event.event_id)
    {
        return Err(refused(
            "source hosting, governor or generation-zero original differs",
        ));
    }
    commit.validate_shape().map_err(refused)?;
    commit.verify_commit_id_matches_content().map_err(refused)?;
    let (authority, fact) =
        arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_source(
            request,
            source,
            entries,
            witnesses,
            producer_service,
            commit.committed_at,
        )
        .map_err(authority_error)?;
    fact.validate_commit_binding(
        &arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        },
        event.event_id.digest_suite_code().digest_suite(),
    )
    .map_err(refused)?;
    Ok((authority, fact))
}

/// The HTTP owner freshly observed and retained these complete native logs.
/// Keep that same durable cut through first acceptance; cold originals never
/// call this gate and continue using their original committed_at/source.
async fn lock_current_histories(
    conn: &mut AsyncPgConnection,
    write: &OrganizationPcrGenesisAdmissionWrite,
) -> Result<(), PgTransactionError> {
    lock_current_native_sources(
        conn,
        &write.organization_log_entries,
        write.producer_service_resolution.as_ref(),
    )
    .await
}

pub(crate) async fn lock_current_native_sources(
    conn: &mut AsyncPgConnection,
    organization_entries: &[Value],
    producer_service: Option<&arkret_models_identity::AuthenticatedServiceResolution>,
) -> Result<(), PgTransactionError> {
    let mut sources = std::collections::BTreeMap::new();
    let mut add = |entries: &[Value]| -> PersistenceResult<()> {
        let last = entries
            .last()
            .ok_or_else(|| refused("current source is empty"))?;
        let did = arkret_wire::Did::new(
            last.pointer("/state/id")
                .and_then(Value::as_str)
                .ok_or_else(|| refused("current source has no native subject"))?,
        )
        .map_err(refused)?;
        let core = arkret_wire::project_did_to_core_id(&did).map_err(refused)?;
        let head = arkret_canonical::canonical_sha256(last).map_err(corrupt)?;
        let value = (did, head, last.clone(), entries.len() as i64);
        if sources.get(&core).is_some_and(|prior| prior != &value) {
            return Err(refused("one native subject has mixed current sources"));
        }
        sources.insert(core, value);
        Ok(())
    };
    add(organization_entries)?;
    if let Some(service) = producer_service {
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries, ..
        } = &service.method_history_evidence
        else {
            return Err(refused("Service native current history is missing").into());
        };
        add(log_entries)?;
    }
    #[derive(QueryableByName)]
    struct Head {
        #[diesel(sql_type=Text)]
        head: String,
        #[diesel(sql_type=Jsonb)]
        operation: Value,
        #[diesel(sql_type=BigInt)]
        sequence: i64,
        #[diesel(sql_type=Bool)]
        document_matches: bool,
    }
    for (core, (did, expected, original, sequence)) in sources {
        // Native DID ingest/update writers use the same core exclusive lock.
        sql_query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))")
            .bind::<Text, _>(core.as_str())
            .execute(&mut *conn)
            .await?;
        let head = sql_query("SELECT e.id AS head,e.operation,e.sequence,EXISTS(SELECT 1 FROM webvh_documents d WHERE d.id=(e.operation#>>'{state,id}') AND d.key_log_head=e.id AND d.sequence=e.sequence AND d.did_document=e.operation->'state') AS document_matches FROM webvh_log_events e WHERE e.did LIKE 'did:webvh:%' AND split_part(e.did,':',3)=split_part($1,':',3) ORDER BY e.sequence DESC,e.id DESC LIMIT 1")
            .bind::<Text,_>(did.as_str()).get_result::<Head>(&mut *conn).await.optional()?;
        if !head.is_some_and(|head| {
            head.head == expected
                && head.operation == original
                && head.sequence == sequence
                && head.document_matches
        }) {
            return Err(refused("current native source differs from the durable head").into());
        }
    }
    Ok(())
}

/// Initial Account creation may legitimately start without a cache row.
/// Share the receiver's exact full-Account tuple before inspecting existence;
/// an existing owner uses the one permission owner, never a second predicate.
pub(crate) async fn require_creatable_account_owner(
    conn: &mut AsyncPgConnection,
    holder: &arkret_wire::AccountId,
) -> PersistenceResult<()> {
    crate::pcr_private_authority::lock_optional_account_private_tuple(conn, holder).await?;
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    let row = sql_query(
        "SELECT EXISTS(SELECT 1 FROM accounts WHERE principal_id=$1 AND station_id=$2) AS present",
    )
    .bind::<Text, _>(holder.principal_id.as_str())
    .bind::<Text, _>(holder.station_id.as_str())
    .get_result::<Present>(&mut *conn)
    .await
    .map_err(crate::persistence_query_error)?;
    if row.present {
        crate::pcr_private_authority::require_active_account_owner(conn, holder).await?;
    }
    Ok(())
}

#[derive(QueryableByName)]
struct Source {
    #[diesel(sql_type=Text)]
    principal_id: String,
    #[diesel(sql_type=Text)]
    station_id: String,
    #[diesel(sql_type=Text)]
    source_service_id: String,
    #[diesel(sql_type=Jsonb)]
    peer_request_json: Value,
    #[diesel(sql_type=Jsonb)]
    organization_log_entries: Value,
    #[diesel(sql_type=Jsonb)]
    organization_witness_records: Value,
    #[diesel(sql_type=Nullable<Jsonb>)]
    producer_service_resolution: Option<Value>,
    #[diesel(sql_type=Jsonb)]
    result_json: Value,
    #[diesel(sql_type=Jsonb)]
    envelope: Value,
    #[diesel(sql_type=Jsonb)]
    commit_json: Value,
}

async fn original_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
) -> PersistenceResult<
    Option<(
        PeerAuthorityForwardEventRequestBody,
        DidCoreId,
        AuthoritySubmitResponseBody,
        arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact,
    )>,
> {
    let row = sql_query("SELECT s.principal_id,s.station_id,s.source_service_id,s.peer_request_json,s.organization_log_entries,s.organization_witness_records,s.producer_service_resolution,s.result_json,e.envelope,c.commit_json FROM organization_pcr_genesis_sources s JOIN canonical_events e ON e.pk=s.event_pk AND e.state='committed' JOIN realm_commits c ON c.commit_id=s.accepted_commit_id AND c.event_pk=e.pk WHERE s.realm_id=$1")
        .bind::<Text,_>(realm.as_str()).get_result::<Source>(&mut *conn).await.optional().map_err(crate::persistence_query_error)?;
    let Some(row) = row else { return Ok(None) };
    let request: PeerAuthorityForwardEventRequestBody =
        serde_json::from_value(row.peer_request_json).map_err(corrupt)?;
    let event: Event = serde_json::from_value(row.envelope).map_err(corrupt)?;
    let commit: RealmCommit = serde_json::from_value(row.commit_json).map_err(corrupt)?;
    let result: AuthoritySubmitResponseBody =
        serde_json::from_value(row.result_json).map_err(corrupt)?;
    let source = DidCoreId::new(row.source_service_id).map_err(corrupt)?;
    let entries: Vec<Value> =
        serde_json::from_value(row.organization_log_entries).map_err(corrupt)?;
    let witnesses: Vec<Value> =
        serde_json::from_value(row.organization_witness_records).map_err(corrupt)?;
    let producer = row
        .producer_service_resolution
        .map(serde_json::from_value)
        .transpose()
        .map_err(corrupt)?;
    if request.event_submission.event != event
        || event.realm_id != *realm
        || !matches!(&result, AuthoritySubmitResponseBody::Accepted { status:AuthorityCommitStatus::Committed, commit:stored } if stored==&commit)
    {
        return Err(corrupt("Event, Commit or first result differs"));
    }
    let (authority, fact) = verify_original(
        &request,
        &source,
        &entries,
        &witnesses,
        producer.as_ref(),
        &commit,
    )?;
    if authority.holder().principal_id.as_str() != row.principal_id
        || authority.holder().station_id.as_str() != row.station_id
    {
        return Err(corrupt("full Account differs from its original source"));
    }
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    for (approval, key) in authority.methods() {
        let present = sql_query("SELECT EXISTS(SELECT 1 FROM event_approval_private_audit WHERE approval_context=$1 AND approver_did=$2 AND nonce=$3 AND event_id=$4 AND event_digest=$5 AND realm_id=$6 AND accepted_commit_id=$7 AND evidence=$8 AND accepted_basis->>'public_key'=$9) AS present")
            .bind::<Text,_>(arkret_canonical::canonical_json_string(&approval.input.approval_context).map_err(corrupt)?)
            .bind::<Text,_>(approval.input.approver_did.as_str()).bind::<Text,_>(&approval.input.nonce)
            .bind::<Text,_>(event.event_id.as_str()).bind::<Text,_>(arkret_canonical::canonical_sha256(&event).map_err(corrupt)?)
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(commit.commit_id.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(approval).map_err(corrupt)?)
            .bind::<Text,_>(arkret_canonical::ed25519_pubkey_to_did_key_multibase(key))
            .get_result::<Present>(&mut *conn).await.map_err(crate::persistence_query_error)?;
        if !present.present {
            return Err(corrupt("original approval consumption is missing"));
        }
    }
    Ok(Some((request, source, result, fact)))
}

pub(crate) async fn exact_original_in_connection(
    conn: &mut AsyncPgConnection,
    incoming: &PeerAuthorityForwardEventRequestBody,
    source: &DidCoreId,
) -> PersistenceResult<Option<AuthoritySubmitResponseBody>> {
    incoming.validate().map_err(refused)?;
    if !incoming.is_organization_pcr_genesis_candidate()
        || incoming
            .event_submission
            .event
            .actor_id
            .as_account_id()
            .is_none_or(|holder| &holder.station_id != source)
    {
        return Err(refused(
            "original lookup lacks authenticated hosting source",
        ));
    }
    let Some((request, original_source, result, _)) =
        original_in_connection(conn, &incoming.event_submission.event.realm_id).await?
    else {
        return Ok(None);
    };
    if request.event_submission != incoming.event_submission || &original_source != source {
        return Err(PersistenceError::Conflict(
            "duplicate_conflict: Organization original differs".into(),
        ));
    }
    Ok(Some(result))
}

/// Accepted-governance consumers require this closure, not merely a structural
/// purpose/executor selector or editable principal-resolution projection.
pub(crate) async fn verify_accepted_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let Some((request, _, result, _)) = original_in_connection(conn, &event.realm_id).await? else {
        return Err(refused("accepted native source is missing"));
    };
    if request.event_submission.event != *event
        || !matches!(result, AuthoritySubmitResponseBody::Accepted { commit:original,.. } if original==*commit)
    {
        return Err(corrupt("accepted governance differs from its source"));
    }
    Ok(())
}

/// The public and private-handoff readers project the same immutable native source.
/// This never reads current DID/account projections or writes a second fact cache.
pub(crate) async fn fact_for_commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<
    Option<arkret_models_collaboration::authority_commit::OrganizationGenesisSignerFact>,
> {
    let Some((request, _, result, fact)) = original_in_connection(conn, &event.realm_id).await?
    else {
        return Ok(None);
    };
    if request.event_submission.event != *event
        || !matches!(&result, AuthoritySubmitResponseBody::Accepted { commit:original,.. } if original==commit)
    {
        return Err(corrupt(
            "requested Genesis differs from its one original source",
        ));
    }
    Ok(Some(fact))
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    write: &OrganizationPcrGenesisAdmissionWrite,
) -> Result<AuthoritySubmitResponseBody, PgTransactionError> {
    let transaction = &write.transaction;
    let event = &transaction.event;
    let commit = &transaction.commit;
    if event != &write.request.event_submission.event
        || commit.committed_at != write.queued_at
        || transaction.expected_authority.generation != 0
        || transaction.expected_authority.realm_id != event.realm_id
        || transaction.expected_authority.last_handoff_ref.is_some()
        || transaction.expected_authority.authority_ref
            != RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone())
    {
        return Err(refused("transaction differs from the exact one-create unit").into());
    }
    let holder = event
        .actor_id
        .as_account_id()
        .ok_or_else(|| refused("full Account missing"))?;
    // Serialize this exact Account's first binding. Existing immutable Human,
    // Agent and Organization originals can never be upgraded or overwritten.
    let key = format!(
        "native-account-inception:{}",
        arkret_canonical::canonical_json_string(holder).map_err(corrupt)?
    );
    sql_query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind::<Text, _>(&key)
        .execute(&mut *conn)
        .await?;
    if let Some((original, source, result, _)) =
        original_in_connection(conn, &event.realm_id).await?
    {
        if original.event_submission != write.request.event_submission
            || source != write.source_service_id
        {
            return Err(PersistenceError::Conflict(
                "duplicate_conflict: Organization genesis original differs".into(),
            )
            .into());
        }
        return Ok(result);
    }
    require_creatable_account_owner(conn, holder).await?;
    let (authority, fact) = verify_original(
        &write.request,
        &write.source_service_id,
        &write.organization_log_entries,
        &write.organization_witness_records,
        write.producer_service_resolution.as_ref(),
        commit,
    )?;
    let expected_fact = arkret_models_collaboration::authority_commit::HistoricalProducerSignerFact::OrganizationGenesis(fact);
    if transaction.producer_signer_fact.as_ref() != Some(&expected_fact) {
        return Err(refused("candidate fact differs from its sole original native source").into());
    }
    lock_current_histories(conn, write).await?;
    if authority.holder() != holder
        || transaction.expected_authority.service_id
            != arkret_wire::detached_signature_service_id(&commit.signature).map_err(refused)?
    {
        return Err(refused("accepting authority or full Account differs").into());
    }
    #[derive(QueryableByName)]
    struct Present {
        #[diesel(sql_type=Bool)]
        present: bool,
    }
    let bound=sql_query("SELECT EXISTS(SELECT 1 FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM pcr_genesis_units WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM organization_pcr_genesis_sources WHERE principal_id=$1 AND station_id=$2) OR EXISTS(SELECT 1 FROM canonical_events WHERE id=$3) AS present")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).get_result::<Present>(&mut *conn).await?;
    if bound.present {
        return Err(refused("an immutable Account or Event inception already exists").into());
    }
    let inserted=sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref,last_handoff_ref) VALUES($1,0,$2,$3,NULL) ON CONFLICT DO NOTHING")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(transaction.expected_authority.service_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&transaction.expected_authority.authority_ref).map_err(corrupt)?)
        .execute(&mut *conn).await?;
    if inserted != 1 {
        return Err(refused("Realm already exists").into());
    }
    crate::authority_commit::queue_event_in_connection(conn, event, write.queued_at).await?;
    match crate::authority_commit::commit_verified_organization_pcr_genesis_in_connection(
        conn,
        transaction,
    )
    .await?
    {
        AuthorityCommitWriteOutcome::Committed => {}
        _ => return Err(refused("native create did not commit once").into()),
    }
    crate::capability_grant_current_states::commit_realm_authority_root_current_state_in_connection(conn,event,commit).await?;
    crate::realm_bootstrap_current_states::commit_ordinary_bootstrap_singleton_current_state_in_connection(conn,event,commit).await?;
    let genesis = event.as_realm_create().map_err(refused)?.object;
    let initial = genesis
        .initial_resolution
        .ok_or_else(|| refused("initial resolution missing"))?;
    let resolution = arkret_models_identity::PrincipalResolutionProjection {
        did: initial.did,
        method_history_head: initial.method_history_head,
        version_id: initial.version_id,
        resolution_event_ref: event.event_id.to_string(),
        updated_at: event.created_at,
    };
    let inserted=sql_query("WITH inserted AS (INSERT INTO principal_resolutions(principal_id,station_id,pcr_realm_id,genesis_event_id,current_event_id,projection,updated_at) VALUES($1,$2,$3,$4,$4,$5,$6) ON CONFLICT DO NOTHING RETURNING principal_id,station_id), original AS (INSERT INTO principal_resolution_events(principal_id,station_id,event_id,previous_event_id,method_history_head,event_json,created_at) SELECT principal_id,station_id,$4,NULL,$7,$8,$6 FROM inserted) SELECT EXISTS(SELECT 1 FROM inserted) AS present")
        .bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str()).bind::<Text,_>(event.realm_id.as_str())
        .bind::<Text,_>(event.event_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&resolution).map_err(corrupt)?)
        .bind::<Timestamptz,_>(resolution.updated_at).bind::<Text,_>(&resolution.method_history_head)
        .bind::<Jsonb,_>(serde_json::to_value(event).map_err(corrupt)?).get_result::<Present>(&mut *conn).await?;
    if !inserted.present {
        return Err(refused("full Account already has another PCR").into());
    }
    crate::principal_resolution_unit::initialize_in_connection(
        conn,
        holder,
        event,
        commit,
        &resolution,
    )
    .await?;
    crate::accounts::create_native_holder_account_in_connection(conn, holder, commit.committed_at)
        .await?;
    let qualified=authority.methods().iter().map(|(signature,key)|crate::approval_admission::QualifiedApproval {
        method:coland_storage::ApprovalHistoricalMethod {signature:signature.clone(),public_key:*key,native_control:None,
            control_history:Some(json!({"log_entries":write.organization_log_entries,"witness_records":write.organization_witness_records}))},
        qualification_basis:json!({"organization_pcr_genesis":true,"account_id":holder,"delegated_service":authority.delegated_service()}),
    }).collect::<Vec<_>>();
    crate::approval_admission::consume_and_audit(conn,event,commit,&qualified,&json!({"unit_kind":"organization_pcr_genesis","event_id":event.event_id,"commit_id":commit.commit_id})).await?;
    let result = AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    sql_query("INSERT INTO organization_pcr_genesis_sources(realm_id,principal_id,station_id,source_service_id,event_pk,accepted_commit_id,peer_request_json,organization_log_entries,organization_witness_records,producer_service_resolution,result_json) SELECT $1,$2,$3,$4,e.pk,$5,$6,$7,$8,$9,$10 FROM canonical_events e WHERE e.id=$11 AND e.envelope=$12")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(holder.principal_id.as_str()).bind::<Text,_>(holder.station_id.as_str())
        .bind::<Text,_>(write.source_service_id.as_str()).bind::<Text,_>(commit.commit_id.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(&write.request).map_err(corrupt)?)
        .bind::<Jsonb,_>(serde_json::to_value(&write.organization_log_entries).map_err(corrupt)?)
        .bind::<Jsonb,_>(serde_json::to_value(&write.organization_witness_records).map_err(corrupt)?)
        .bind::<Nullable<Jsonb>,_>(write.producer_service_resolution.as_ref().map(serde_json::to_value).transpose().map_err(corrupt)?)
        .bind::<Jsonb,_>(serde_json::to_value(&result).map_err(corrupt)?)
        .bind::<Binary,_>(event.event_id.token_bytes().to_vec()).bind::<Jsonb,_>(serde_json::to_value(event).map_err(corrupt)?)
        .execute(&mut *conn).await?;
    verify_accepted_in_connection(conn, event, commit).await?;
    Ok(result)
}
