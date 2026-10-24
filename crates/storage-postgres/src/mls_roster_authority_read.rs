//! Complete MLS historical roster at one member-authorized PostgreSQL cut.
//! Never expose a partial result: missing/corrupt Add provenance is uniformly
//! unavailable to an otherwise authorized caller.

use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_roster_authority::{
    MlsAttestAddRequestBody, MlsRosterAuthorityReadRequestBody, MlsRosterRecord,
};
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{
    ActorId, Base64UrlString, CommitStreamRef, DidCoreId, EventId, EventKind, MlsGroupValue,
    MlsWelcomeDelivery,
};
use coland_storage::{
    MlsMemberGroupStateMaterialRead, MlsRosterAuthorityFacts, MlsRosterAuthorityRead,
};
use diesel::sql_types::{BigInt, Binary, Integer, Jsonb, Text};

use crate::{
    AsyncConnection, AsyncPgConnection, OptionalExtension, PersistenceError, PersistenceResult,
    PgPool, PgTransactionError, QueryableByName, RunQueryDsl, pg_conn, sql_query,
};

#[derive(QueryableByName)]
struct GroupRow {
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Jsonb)]
    value: serde_json::Value,
}

#[derive(QueryableByName)]
struct ProvenanceRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    mls_group_id: String,
    #[diesel(sql_type = Text)]
    genesis_event_ref: String,
}

#[derive(QueryableByName)]
struct AuthorityRow {
    #[diesel(sql_type = Text)]
    service_id: String,
}

pub(crate) async fn member_selector(
    pool: &PgPool,
    request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
) -> PersistenceResult<coland_storage::MlsMemberRosterSelectorRead> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        member_selector_in_connection(conn, request, issuer)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}

pub(crate) async fn member_selector_in_connection(
    conn: &mut AsyncPgConnection,
    request: &arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
) -> PersistenceResult<coland_storage::MlsMemberRosterSelectorRead> {
    use coland_storage::MlsMemberRosterSelectorRead as Selected;

    use crate::mls_group_state_material_read::MemberMlsTargetSelector;
    if request
        .caller_actor_id
        .as_realm_actor_id()
        .is_some_and(|actor| actor.realm_id != request.realm_id)
        || request
            .caller_actor_id
            .fixed_route_service_id()
            .is_some_and(|station| station != issuer)
    {
        return Ok(Selected::NotFound);
    }
    let selector = MemberMlsTargetSelector {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        group_state_event_id: None,
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
    };
    match crate::mls_group_state_material_read::read_in_connection(conn, &selector, issuer, None)
        .await?
    {
        MlsMemberGroupStateMaterialRead::NotFound => return Ok(Selected::NotFound),
        MlsMemberGroupStateMaterialRead::RevisionUnavailable => {
            return Ok(Selected::RevisionUnavailable);
        }
        MlsMemberGroupStateMaterialRead::Authorized { .. } => {}
    }
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&request.effective_scope)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let current =
        sql_query("SELECT mls_group_id,value FROM mls_group_current_states WHERE scope_key=$1")
            .bind::<Text, _>(&key)
            .get_result::<GroupRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
    let mut genesis = None;
    if let Some(row) = current {
        let Ok(group) = serde_json::from_value::<MlsGroupValue>(row.value) else {
            return Ok(Selected::RevisionUnavailable);
        };
        if row.mls_group_id != request.mls_group_id.as_str()
            || group.effective_scope != request.effective_scope
        {
            return Ok(Selected::RevisionUnavailable);
        }
        genesis = Some(group.genesis_event_ref);
    }
    let frozen = sql_query("SELECT realm_id,mls_group_id,genesis_event_ref FROM mls_replica_genesis_provenance WHERE scope_key=$1")
        .bind::<Text, _>(&key).get_result::<ProvenanceRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(row) = frozen {
        let Ok(reference) = EventId::new(row.genesis_event_ref) else {
            return Ok(Selected::RevisionUnavailable);
        };
        if row.realm_id != request.realm_id.as_str()
            || row.mls_group_id != request.mls_group_id.as_str()
            || genesis.as_ref().is_some_and(|value| value != &reference)
        {
            return Ok(Selected::RevisionUnavailable);
        }
        genesis = Some(reference);
    }
    let Some(genesis) = genesis else {
        return Ok(Selected::RevisionUnavailable);
    };
    let peer = request.with_accepted_genesis(genesis);
    if peer.validate().is_err() {
        return Ok(Selected::RevisionUnavailable);
    }
    let Some(authority) = sql_query("SELECT service_id FROM realm_authorities WHERE realm_id=$1")
        .bind::<Text, _>(request.realm_id.as_str())
        .get_result::<AuthorityRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
    else {
        return Ok(Selected::RevisionUnavailable);
    };
    let Ok(governance_station_id) = DidCoreId::new(authority.service_id) else {
        return Ok(Selected::RevisionUnavailable);
    };
    Ok(Selected::Authorized {
        request: Box::new(peer),
        governance_station_id,
    })
}

#[derive(QueryableByName)]
struct AcceptedRow {
    #[diesel(sql_type = Jsonb)]
    envelope: serde_json::Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: serde_json::Value,
}

#[derive(QueryableByName)]
struct AddRow {
    #[diesel(sql_type = Text)]
    commit_event_ref: String,
    #[diesel(sql_type = BigInt)]
    commit_stream_position: i64,
    #[diesel(sql_type = BigInt)]
    epoch: i64,
    #[diesel(sql_type = BigInt)]
    consumed_proposal_ordinal: i64,
    #[diesel(sql_type = Integer)]
    proposal_type: i32,
    #[diesel(sql_type = Binary)]
    proposal_wire: Vec<u8>,
    #[diesel(sql_type = Jsonb)]
    sender_actor_id: serde_json::Value,
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
}

#[derive(QueryableByName)]
struct WelcomeRow {
    #[diesel(sql_type = Text)]
    delivery_digest: String,
    #[diesel(sql_type = Binary)]
    delivery_canonical_json: Vec<u8>,
}

fn unavailable() -> MlsRosterAuthorityRead {
    MlsRosterAuthorityRead::RevisionUnavailable
}

async fn accepted(
    conn: &mut AsyncPgConnection,
    reference: &EventId,
) -> PersistenceResult<Option<(arkret_wire::Event, arkret_wire::RealmCommit)>> {
    let Some(token) = crate::ids::parse_event_id(reference.as_str()) else {
        return Ok(None);
    };
    let row = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .get_result::<AcceptedRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    row.map(|row| {
        let event = serde_json::from_value(row.envelope).map_err(|error| {
            PersistenceError::Internal(format!("stored MLS roster Event invalid: {error}"))
        })?;
        let commit = serde_json::from_value(row.commit_json).map_err(|error| {
            PersistenceError::Internal(format!("stored MLS roster Commit invalid: {error}"))
        })?;
        Ok((event, commit))
    })
    .transpose()
}

async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    request: &MlsRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
    source_peer: Option<&DidCoreId>,
) -> PersistenceResult<MlsRosterAuthorityRead> {
    use crate::mls_group_state_material_read::{MemberMlsTargetSelector, read_in_connection};

    let selector = MemberMlsTargetSelector {
        realm_id: request.realm_id.clone(),
        effective_scope: request.effective_scope.clone(),
        mls_group_id: request.mls_group_id.clone(),
        group_state_event_id: Some(request.genesis_event_ref.clone()),
        caller_actor_id: request.caller_actor_id.clone(),
        target_commit_event_ref: request.target_commit_event_ref.clone(),
        target_epoch: request.target_epoch,
    };
    let genesis = match read_in_connection(conn, &selector, issuer, source_peer).await? {
        MlsMemberGroupStateMaterialRead::NotFound => return Ok(MlsRosterAuthorityRead::NotFound),
        MlsMemberGroupStateMaterialRead::RevisionUnavailable => return Ok(unavailable()),
        MlsMemberGroupStateMaterialRead::Authorized { genesis: None } => {
            return Ok(MlsRosterAuthorityRead::Authorized { facts: None });
        }
        MlsMemberGroupStateMaterialRead::Authorized {
            genesis: Some(full),
        } => full,
    };
    let payload: MlsGenesisPayload = serde_json::to_value(&genesis.event.payload)
        .ok()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(|| PersistenceError::Internal("stored roster Genesis invalid".to_owned()))?;
    payload.validate().map_err(|error| {
        PersistenceError::Internal(format!("stored roster Genesis invalid: {error}"))
    })?;
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&request.effective_scope)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let Some(group) =
        sql_query("SELECT mls_group_id,value FROM mls_group_current_states WHERE scope_key=$1")
            .bind::<Text, _>(&key)
            .get_result::<GroupRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
    else {
        return Ok(unavailable());
    };
    let current: MlsGroupValue = serde_json::from_value(group.value).map_err(|error| {
        PersistenceError::Internal(format!("stored MLS group current invalid: {error}"))
    })?;
    if group.mls_group_id != request.mls_group_id.as_str()
        || current.genesis_event_ref != request.genesis_event_ref
        || current.effective_scope != request.effective_scope
        || current.epoch < request.target_epoch
    {
        return Ok(unavailable());
    }
    let Some((target_event, target_commit)) =
        accepted(conn, &request.target_commit_event_ref).await?
    else {
        return Ok(unavailable());
    };
    let Some((head_event, head_commit)) =
        accepted(conn, &current.current_mls_commit_event_ref).await?
    else {
        return Ok(unavailable());
    };
    let expected_stream = match &request.effective_scope {
        arkret_wire::ScopeRef::Realm { realm_id } => CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } => CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        },
        arkret_wire::ScopeRef::Sidecar {
            realm_id,
            sidecar_id,
        } => CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        _ => return Ok(MlsRosterAuthorityRead::NotFound),
    };
    if target_commit.stream_ref != expected_stream
        || head_commit.stream_ref != expected_stream
        || target_commit.event_ref != target_event.event_id
        || head_commit.event_ref != head_event.event_id
        || target_event.event_id != request.target_commit_event_ref
        || head_event.event_id != current.current_mls_commit_event_ref
        || target_event.realm_id != request.realm_id
        || head_event.realm_id != request.realm_id
        || target_event.scope_ref != request.effective_scope
        || head_event.scope_ref != request.effective_scope
        || head_commit.stream_position < target_commit.stream_position
        || (request.target_epoch == 0 && head_event.event_id != request.genesis_event_ref)
    {
        return Ok(unavailable());
    }
    let (head_epoch, head_group) = match head_event.kind {
        EventKind::MlsGenesis => (
            0,
            payload.mls_group_id().map_err(|error| {
                PersistenceError::Internal(format!("stored roster Genesis group invalid: {error}"))
            })?,
        ),
        EventKind::MlsCommit => {
            let Ok(value) = serde_json::to_value(&head_event.payload) else {
                return Ok(unavailable());
            };
            let Ok(payload) = serde_json::from_value::<MlsCommitPayload>(value) else {
                return Ok(unavailable());
            };
            let group = payload.mls_group_id().map_err(|error| {
                PersistenceError::Internal(format!("stored roster head group invalid: {error}"))
            })?;
            (payload.next_epoch(), group)
        }
        _ => return Ok(unavailable()),
    };
    if head_epoch != current.epoch || head_group != request.mls_group_id {
        return Ok(unavailable());
    }
    let mut records = vec![MlsRosterRecord::Genesis {
        genesis_event_ref: request.genesis_event_ref.clone(),
        actor_id: genesis.event.actor_id.clone(),
        leaf_signature_key_base64url: payload.creator_leaf_authority.leaf_signature_key_base64url,
        endpoint: payload.creator_leaf_authority.endpoint,
        authorization_event_ref: payload.creator_leaf_authority.authorization_event_ref,
    }];
    let mut historical_add_proofs = Vec::new();
    let additions = sql_query(
        "SELECT commit_event_ref,commit_stream_position,epoch,consumed_proposal_ordinal, \
         proposal_type,proposal_wire,sender_actor_id,target_after_actor_id,target_after_signature_key \
         FROM mls_consumed_proposal_provenance \
         WHERE scope_key=$1 AND proposal_type=1 AND commit_stream_position<=$2 \
         ORDER BY commit_stream_position,consumed_proposal_ordinal",
    )
    .bind::<Text, _>(&key)
    .bind::<BigInt, _>(i64::try_from(target_commit.stream_position).map_err(PersistenceError::database)?)
    .load::<AddRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let mut previous = None;
    for row in additions {
        let position = (row.commit_stream_position, row.consumed_proposal_ordinal);
        if previous.is_some_and(|prior| prior >= position) || row.proposal_type != 1 {
            return Ok(unavailable());
        }
        previous = Some(position);
        let Ok(commit_ref) = EventId::new(row.commit_event_ref.clone()) else {
            return Ok(unavailable());
        };
        let Some((event, commit)) = accepted(conn, &commit_ref).await? else {
            return Ok(unavailable());
        };
        let Ok(payload_value) = serde_json::to_value(&event.payload) else {
            return Ok(unavailable());
        };
        let Ok(commit_payload) = serde_json::from_value::<MlsCommitPayload>(payload_value) else {
            return Ok(unavailable());
        };
        if event.kind != EventKind::MlsCommit
            || event.realm_id != request.realm_id
            || event.scope_ref != request.effective_scope
            || event.event_id != commit_ref
            || commit.event_ref != commit_ref
            || commit.stream_ref != expected_stream
            || i64::try_from(commit.stream_position).ok() != Some(row.commit_stream_position)
            || i64::try_from(commit_payload.next_epoch()).ok() != Some(row.epoch)
        {
            return Ok(unavailable());
        }
        let Ok(parsed) = arkret_mls::verify_add_proposal_leaf(&row.proposal_wire) else {
            return Ok(unavailable());
        };
        let Ok(target_actor) = serde_json::from_value::<ActorId>(row.target_after_actor_id) else {
            return Ok(unavailable());
        };
        let Ok(sender_actor) = serde_json::from_value::<ActorId>(row.sender_actor_id) else {
            return Ok(unavailable());
        };
        if parsed.actor_id != target_actor
            || parsed.leaf_signature_key.as_str() != row.target_after_signature_key
            || sender_actor != event.actor_id
        {
            return Ok(unavailable());
        }
        let Some(installed) = sql_query(
            "SELECT attestation_digest,request_json,attestor_resolution_canonical_json,claim_issuer_resolution_canonical_json FROM mls_add_authority_attestations \
             WHERE scope_key=$1 AND commit_event_ref=$2 AND consumed_proposal_ordinal=$3",
        )
        .bind::<Text, _>(&key)
        .bind::<Text, _>(commit_ref.as_str())
        .bind::<BigInt, _>(row.consumed_proposal_ordinal)
        .get_result::<InstalledRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        else {
            return Ok(unavailable());
        };
        let Ok(proof) = serde_json::from_value::<MlsAttestAddRequestBody>(installed.request_json)
        else {
            return Ok(unavailable());
        };
        if proof.validate_claim_binding().is_err()
            || arkret_canonical::canonical_sha256(&proof).ok().as_deref()
                != Some(installed.attestation_digest.as_str())
        {
            return Ok(unavailable());
        }
        let attestation = proof.attestation.clone();
        let Ok(attestor_resolution) = serde_json::from_slice::<
            arkret_models_identity::AuthenticatedServiceResolution,
        >(&installed.attestor_resolution_canonical_json) else {
            return Ok(unavailable());
        };
        if arkret_canonical::canonical_json_bytes(&attestor_resolution)
            .ok()
            .as_deref()
            != Some(installed.attestor_resolution_canonical_json.as_slice())
            || attestor_resolution.service_id != attestation.attestor_station_id
            || attestor_resolution.service_kind != "station"
        {
            return Ok(unavailable());
        }
        let Ok(claim_issuer_resolution) =
            serde_json::from_slice::<arkret_models_identity::AuthenticatedServiceResolution>(
                &installed.claim_issuer_resolution_canonical_json,
            )
        else {
            return Ok(unavailable());
        };
        if arkret_canonical::canonical_json_bytes(&claim_issuer_resolution)
            .ok()
            .as_deref()
            != Some(installed.claim_issuer_resolution_canonical_json.as_slice())
            || arkret::verify_mls_attest_add_request(
                &proof,
                &claim_issuer_resolution,
                &attestor_resolution,
            )
            .is_err()
        {
            return Ok(unavailable());
        }
        if attestation.realm_id != request.realm_id
            || attestation.effective_scope != request.effective_scope
            || attestation.mls_group_id != request.mls_group_id
            || attestation.genesis_event_ref != request.genesis_event_ref
            || attestation.commit_event_ref != commit_ref
            || i64::try_from(attestation.commit_stream_position).ok()
                != Some(row.commit_stream_position)
            || i64::try_from(attestation.epoch).ok() != Some(row.epoch)
            || attestation.actor_id != target_actor
            || attestation.leaf_signature_key_base64url != parsed.leaf_signature_key
        {
            return Ok(unavailable());
        }
        let Some(claim) = proof
            .claim_outcome
            .claims
            .iter()
            .find(|claim| claim.claim_id == attestation.claim_id.as_str())
        else {
            return Ok(unavailable());
        };
        let Ok(claim_bytes) =
            arkret_canonical::base64url::base64url_decode(claim.keypackage.as_bytes())
        else {
            return Ok(unavailable());
        };
        if claim_bytes != parsed.key_package_bytes
            || arkret_canonical::sha256_digest(&claim_bytes) != claim.keypackage_ref
        {
            return Ok(unavailable());
        }
        let Some(welcome) = sql_query(
            "SELECT delivery_digest,delivery_canonical_json FROM mls_welcome_provenance \
             WHERE welcome_id=$1 AND scope_key=$2 AND commit_event_ref=$3",
        )
        .bind::<Text, _>(attestation.welcome_id.as_str())
        .bind::<Text, _>(&key)
        .bind::<Text, _>(commit_ref.as_str())
        .get_result::<WelcomeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        else {
            return Ok(unavailable());
        };
        let Ok(delivery) =
            serde_json::from_slice::<MlsWelcomeDelivery>(&welcome.delivery_canonical_json)
        else {
            return Ok(unavailable());
        };
        if arkret_canonical::canonical_json_bytes(&delivery).ok()
            != Some(welcome.delivery_canonical_json)
            || arkret_canonical::canonical_sha256(&delivery)
                .ok()
                .as_deref()
                != Some(welcome.delivery_digest.as_str())
            || delivery.welcome_id != attestation.welcome_id
            || delivery.recipient_actor_id != attestation.actor_id
            || delivery.recipient_endpoint != attestation.endpoint
            || delivery.keypackage_claim_ref != attestation.claim_id
            || delivery.commit_event_ref != commit_ref
            || !crate::realm_actor_mls_route::accepted_add_matches(
                conn,
                &delivery.recipient_actor_id,
                &attestation.attestor_station_id,
                &commit_ref,
            )
            .await?
        {
            return Ok(unavailable());
        }
        let Ok(proposal_wire_base64url) =
            Base64UrlString::new(arkret_canonical::base64url_encode(&row.proposal_wire))
        else {
            return Ok(unavailable());
        };
        records.push(MlsRosterRecord::Add {
            commit_event_ref: commit_ref,
            consumed_proposal_ordinal: u64::try_from(row.consumed_proposal_ordinal)
                .map_err(PersistenceError::database)?,
            sender_actor_id: sender_actor,
            proposal_wire_base64url,
            claim_issuer_resolution: attestation
                .actor_id
                .as_realm_actor_id()
                .map(|_| claim_issuer_resolution),
            attestation,
            attestor_resolution,
        });
        historical_add_proofs.push(proof);
    }
    Ok(MlsRosterAuthorityRead::Authorized {
        facts: Some(MlsRosterAuthorityFacts {
            group_info_ref: payload.group_info_ref,
            ratchet_tree_ref: payload.ratchet_tree_ref,
            authority_head_commit_event_ref: head_event.event_id,
            records,
            historical_add_proofs,
        }),
    })
}

pub(crate) async fn read(
    pool: &PgPool,
    request: &MlsRosterAuthorityReadRequestBody,
    issuer: &DidCoreId,
    source_peer: Option<&DidCoreId>,
) -> PersistenceResult<MlsRosterAuthorityRead> {
    request
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mut conn = pg_conn(pool).await?;
    conn.transaction::<_, PgTransactionError, _>(async move |conn| {
        sql_query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *conn)
            .await?;
        read_in_connection(conn, request, issuer, source_peer)
            .await
            .map_err(PgTransactionError::from)
    })
    .await
    .map_err(PgTransactionError::into_persistence)
}
