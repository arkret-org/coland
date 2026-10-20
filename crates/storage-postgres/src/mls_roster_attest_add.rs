//! Governance installation of a recipient Station's historical MLS Add proof.
//! The authenticated peer and both historical signatures are verified by the
//! serving layer. This transaction independently binds that proof to accepted
//! governance facts; the short-lived recipient claim ledger is never read.

use arkret_models_collaboration::mls_roster_authority::{MlsAttestAddOutcome, MlsAttestAddStatus};
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{DidCoreId, EventKind, MlsGroupCurrent, MlsWelcomeDelivery};
use coland_storage::{ConflictCode, VerifiedMlsAddAuthorityAttestation};
use diesel::sql_types::{BigInt, Binary, Integer, Jsonb, Text};

use crate::{
    AsyncConnection, AsyncPgConnection, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, PgTransactionError, QueryableByName, RunQueryDsl, pg_conn, sql_query,
};

#[derive(QueryableByName)]
struct TenureRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

#[derive(QueryableByName)]
struct AcceptedRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct WelcomeRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    scope_key: String,
    #[diesel(sql_type = Text)]
    commit_event_ref: String,
    #[diesel(sql_type = Text)]
    recipient_station_id: String,
    #[diesel(sql_type = Text)]
    claim_id: String,
    #[diesel(sql_type = Text)]
    delivery_digest: String,
    #[diesel(sql_type = Binary)]
    delivery_canonical_json: Vec<u8>,
}

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct ProposalRow {
    #[diesel(sql_type = BigInt)]
    consumed_proposal_ordinal: i64,
    #[diesel(sql_type = BigInt)]
    commit_stream_position: i64,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = Integer)]
    proposal_type: i32,
    #[diesel(sql_type = Binary)]
    proposal_wire: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    target_after_actor_id: serde_json::Value,
    #[diesel(sql_type = Text)]
    target_after_signature_key: String,
}

#[derive(QueryableByName)]
struct InstalledRow {
    #[diesel(sql_type = Text)]
    attestation_digest: String,
    #[diesel(sql_type = Jsonb)]
    request_json: serde_json::Value,
    #[diesel(sql_type = Binary)]
    attestor_resolution_canonical_json: Vec<u8>,
    #[diesel(sql_type = Binary)]
    claim_issuer_resolution_canonical_json: Vec<u8>,
    #[diesel(sql_type = BigInt)]
    consumed_proposal_ordinal: i64,
}

fn refused(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::DuplicateConflict))
}

fn unavailable(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{}: {detail}", ConflictCode::FailedPrecondition))
}

pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    verified: &VerifiedMlsAddAuthorityAttestation,
    issuer: &DidCoreId,
) -> PersistenceResult<MlsAttestAddOutcome> {
    let request = &verified.request;
    request
        .validate_claim_binding()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let attestation = &request.attestation;
    if verified.source_station_id != attestation.attestor_station_id {
        return Err(refused("authenticated source differs from Add attestor"));
    }
    if verified.attestor_resolution.service_id != attestation.attestor_station_id
        || verified.attestor_resolution.service_kind != "station"
        || arkret::verify_mls_attest_add_request(
            request,
            &verified.claim_issuer_resolution,
            &verified.attestor_resolution,
        )
        .is_err()
    {
        return Err(refused(
            "Add proof lacks verified historical Station resolution",
        ));
    }
    let claim_resolution_bytes =
        arkret_canonical::canonical_json_bytes(&verified.claim_issuer_resolution)
            .map_err(PersistenceError::database)?;
    let resolution_bytes = arkret_canonical::canonical_json_bytes(&verified.attestor_resolution)
        .map_err(PersistenceError::database)?;
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&attestation.effective_scope)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let tenure = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1 FOR SHARE")
        .bind::<Text, _>(attestation.realm_id.as_str())
        .get_result::<TenureRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| unavailable("MLS Realm authority is unavailable"))?;
    if tenure.service_id != issuer.as_str() {
        return Err(unavailable("this Station does not govern the MLS Realm"));
    }

    let token = crate::ids::parse_event_id(attestation.commit_event_ref.as_str())
        .ok_or_else(|| refused("Add Commit Event ref is not canonical"))?;
    let accepted = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed' FOR SHARE OF e,c",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<AcceptedRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("accepted Add Commit is unavailable"))?;
    let event: arkret_wire::Event = serde_json::from_value(accepted.envelope).map_err(|error| {
        PersistenceError::Internal(format!("stored Add Event invalid: {error}"))
    })?;
    let commit: arkret_wire::RealmCommit =
        serde_json::from_value(accepted.commit_json).map_err(|error| {
            PersistenceError::Internal(format!("stored Add Commit invalid: {error}"))
        })?;
    let payload: MlsCommitPayload = serde_json::to_value(&event.payload)
        .map_err(PersistenceError::database)
        .and_then(|value| {
            serde_json::from_value(value).map_err(|error| {
                PersistenceError::Internal(format!("stored MLS payload invalid: {error}"))
            })
        })?;
    if event.kind != EventKind::MlsCommit
        || event.realm_id != attestation.realm_id
        || event.scope_ref != attestation.effective_scope
        || event.event_id != attestation.commit_event_ref
        || commit.event_ref != event.event_id
        || commit.stream_position != attestation.commit_stream_position
        || payload.next_epoch() != attestation.epoch
        || attestation.mls_group_id
            != event
                .scope_ref
                .canonical_mls_group_id()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?
    {
        return Err(refused("Add proof differs from accepted MLS Commit"));
    }

    if !crate::realm_actor_mls_route::matches_accepted_add(
        &attestation.actor_id,
        &attestation.attestor_station_id,
        &commit,
    ) {
        return Err(refused(
            "Add attestor differs from accepted recipient authority",
        ));
    }

    let welcome = sql_query(
        "SELECT realm_id,scope_key,commit_event_ref,recipient_station_id,claim_id, \
         delivery_digest,delivery_canonical_json FROM mls_welcome_provenance \
         WHERE welcome_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(attestation.welcome_id.as_str())
    .get_result::<WelcomeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("frozen Welcome is unavailable"))?;
    let delivery: MlsWelcomeDelivery = serde_json::from_slice(&welcome.delivery_canonical_json)
        .map_err(|error| PersistenceError::Internal(format!("stored Welcome invalid: {error}")))?;
    let canonical_delivery =
        arkret_canonical::canonical_json_bytes(&delivery).map_err(PersistenceError::database)?;
    let delivery_digest =
        arkret_canonical::canonical_sha256(&delivery).map_err(PersistenceError::database)?;
    if canonical_delivery != welcome.delivery_canonical_json
        || delivery_digest != welcome.delivery_digest
        || welcome.realm_id != attestation.realm_id.as_str()
        || welcome.scope_key != key
        || welcome.commit_event_ref != event.event_id.as_str()
        || welcome.recipient_station_id != verified.source_station_id.as_str()
        || welcome.claim_id != attestation.claim_id.as_str()
        || delivery.welcome_id != attestation.welcome_id
        || delivery.recipient_actor_id != attestation.actor_id
        || delivery.recipient_endpoint != attestation.endpoint
        || delivery.keypackage_claim_ref != attestation.claim_id
        || delivery.commit_event_ref != event.event_id
    {
        return Err(refused("Add proof differs from frozen Welcome"));
    }

    let group = sql_query(
        "SELECT mls_group_id,value FROM mls_group_current_results WHERE scope_key=$1 FOR SHARE",
    )
    .bind::<Text, _>(&key)
    .get_result::<GroupRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| unavailable("accepted MLS group provenance is unavailable"))?;
    let group_value: MlsGroupCurrent = serde_json::from_value(group.value).map_err(|error| {
        PersistenceError::Internal(format!("stored MLS group invalid: {error}"))
    })?;
    if group.mls_group_id != attestation.mls_group_id.as_str()
        || group_value.genesis_event_ref != attestation.genesis_event_ref
        || group_value.effective_scope != attestation.effective_scope
    {
        return Err(refused("Add proof differs from immutable MLS Genesis"));
    }

    let proposals = sql_query(
        "SELECT consumed_proposal_ordinal,commit_stream_position,epoch,proposal_type, \
         proposal_wire,target_after_actor_id,target_after_signature_key \
         FROM mls_consumed_proposal_provenance \
         WHERE scope_key=$1 AND commit_event_ref=$2 AND proposal_type=1 \
         ORDER BY consumed_proposal_ordinal FOR SHARE",
    )
    .bind::<Text, _>(&key)
    .bind::<Text, _>(event.event_id.as_str())
    .load::<ProposalRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let selected_claim = request
        .claim_outcome
        .claims
        .iter()
        .find(|claim| claim.claim_id == attestation.claim_id.as_str())
        .ok_or_else(|| refused("original claim is absent"))?;
    let claim_key_package =
        arkret_canonical::base64url::base64url_decode(selected_claim.keypackage.as_bytes())
            .map_err(|_| refused("claim KeyPackage is not base64url"))?;
    if arkret_canonical::sha256_digest(&claim_key_package) != selected_claim.keypackage_ref {
        return Err(refused(
            "claim KeyPackage bytes differ from its content ref",
        ));
    }
    let mut matching_ordinal = None;
    for proposal in proposals {
        if proposal.proposal_type != 1
            || proposal.commit_stream_position
                != i64::try_from(commit.stream_position).map_err(PersistenceError::database)?
            || proposal.epoch
                != i64::try_from(attestation.epoch).map_err(PersistenceError::database)?
        {
            return Err(refused("frozen Add Proposal has a different accepted cut"));
        }
        let parsed = arkret_mls::verify_add_proposal_leaf(&proposal.proposal_wire)
            .map_err(|error| refused(&format!("frozen Add Proposal is invalid: {error}")))?;
        let stored_actor: arkret_wire::ActorId =
            serde_json::from_value(proposal.target_after_actor_id).map_err(|error| {
                PersistenceError::Internal(format!("stored Add actor invalid: {error}"))
            })?;
        if parsed.actor_id != stored_actor
            || parsed.leaf_signature_key.as_str() != proposal.target_after_signature_key
        {
            return Err(refused("frozen Add Proposal differs from verified target"));
        }
        if parsed.actor_id == attestation.actor_id
            && parsed.leaf_signature_key == attestation.leaf_signature_key_b64u
            && parsed.key_package_bytes == claim_key_package
            && matching_ordinal
                .replace(proposal.consumed_proposal_ordinal)
                .is_some()
        {
            return Err(refused("Add proof matches multiple consumed Proposals"));
        }
    }
    let ordinal =
        matching_ordinal.ok_or_else(|| refused("Add proof has no matching consumed Proposal"))?;
    let digest = arkret_canonical::canonical_sha256(request).map_err(PersistenceError::database)?;
    let request_json = serde_json::to_value(request).map_err(PersistenceError::database)?;
    let existing = sql_query(
        "SELECT attestation_digest,request_json,attestor_resolution_canonical_json,claim_issuer_resolution_canonical_json,consumed_proposal_ordinal \
         FROM mls_add_authority_attestations WHERE welcome_id=$1 FOR UPDATE",
    )
    .bind::<Text, _>(attestation.welcome_id.as_str())
    .get_result::<InstalledRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(existing) = existing {
        let stored_resolution = serde_json::from_slice::<
            arkret_models_identity::AuthenticatedServiceResolution,
        >(&existing.attestor_resolution_canonical_json)
        .map_err(|_| refused("installed Add historical resolution is damaged"))?;
        if arkret_canonical::canonical_json_bytes(&stored_resolution)
            .ok()
            .as_deref()
            != Some(existing.attestor_resolution_canonical_json.as_slice())
        {
            return Err(refused(
                "installed Add historical resolution is not canonical",
            ));
        }
        let stored_claim_resolution: arkret_models_identity::AuthenticatedServiceResolution =
            serde_json::from_slice(&existing.claim_issuer_resolution_canonical_json)
                .map_err(|_| refused("installed claim issuer resolution is damaged"))?;
        if arkret_canonical::canonical_json_bytes(&stored_claim_resolution)
            .ok()
            .as_deref()
            != Some(existing.claim_issuer_resolution_canonical_json.as_slice())
        {
            return Err(refused(
                "installed claim issuer resolution is not canonical",
            ));
        }
        arkret::verify_mls_attest_add_request(
            request,
            &stored_claim_resolution,
            &stored_resolution,
        )
        .map_err(|error| {
            refused(&format!(
                "installed Add historical signatures invalid: {error}"
            ))
        })?;
        if existing.attestation_digest != digest
            || existing.request_json != request_json
            || existing.attestor_resolution_canonical_json != resolution_bytes
            || existing.claim_issuer_resolution_canonical_json != claim_resolution_bytes
            || existing.consumed_proposal_ordinal != ordinal
        {
            return Err(refused("replayed Add proof differs from installed history"));
        }
        return Ok(MlsAttestAddOutcome {
            status: MlsAttestAddStatus::Duplicate,
            attestation_digest: arkret_wire::Hash::new(digest)
                .map_err(|error| PersistenceError::Internal(error.to_string()))?,
        });
    }
    let inserted = sql_query(
        "INSERT INTO mls_add_authority_attestations \
         (attestor_station_id,realm_id,scope_key,mls_group_id,genesis_event_ref,commit_event_ref, \
          commit_stream_position,epoch,welcome_id,claim_id,consumed_proposal_ordinal, \
          attestation_digest,request_json,attestor_resolution_canonical_json,claim_issuer_resolution_canonical_json,installed_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(attestation.attestor_station_id.as_str())
    .bind::<Text, _>(attestation.realm_id.as_str())
    .bind::<Text, _>(&key)
    .bind::<Text, _>(attestation.mls_group_id.as_str())
    .bind::<Text, _>(attestation.genesis_event_ref.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<BigInt, _>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
    .bind::<BigInt, _>(i64::try_from(attestation.epoch).map_err(PersistenceError::database)?)
    .bind::<Text, _>(attestation.welcome_id.as_str())
    .bind::<Text, _>(attestation.claim_id.as_str())
    .bind::<BigInt, _>(ordinal)
    .bind::<Text, _>(&digest)
    .bind::<Jsonb, _>(&request_json)
    .bind::<Binary, _>(&resolution_bytes)
    .bind::<Binary, _>(&claim_resolution_bytes)
    .bind::<diesel::sql_types::Timestamptz, _>(attestation.attested_at)
    .execute(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(refused(
            "Add proof conflicts with an installed historical fact",
        ));
    }
    Ok(MlsAttestAddOutcome {
        status: MlsAttestAddStatus::Installed,
        attestation_digest: arkret_wire::Hash::new(digest)
            .map_err(|error| PersistenceError::Internal(error.to_string()))?,
    })
}

pub(crate) async fn install(
    pool: &PgPool,
    verified: &VerifiedMlsAddAuthorityAttestation,
    issuer: &DidCoreId,
) -> PersistenceResult<MlsAttestAddOutcome> {
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        install_in_connection(conn, verified, issuer)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
