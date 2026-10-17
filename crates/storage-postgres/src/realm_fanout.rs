//! Realm committed-replication fanout planned in the accepting transaction
//! (`federation.md` §4.1.1).
//!
//! After an Event's RealmCommit and its typed current results are written,
//! the same transaction reads the accepted joined members of the Realm,
//! projects each complete ActorId to its routing service, drops this Station
//! and groups the rest by service. Every distinct remote Station gets one
//! durable `committed_replication` intent that carries the exact source
//! submission and source RealmCommit -- and, for an `ak.mls.commit`, the
//! Welcomes of the recipients that Station hosts -- with the frozen
//! `(realm_id, member_id, membership_event_ref)` bases that authorized it kept
//! in the sender's outbox metadata. The Event's acceptance, the complete
//! target set and every intent therefore commit or roll back together.
//!
//! A remote Station enters the target set only when one of its members may
//! hold the Event's complete canonical bytes: a plaintext Message body is
//! replicated only to a Station the Realm lists as a private plaintext
//! service for message content, and a moderation report, readable only by
//! moderators, only to a Station hosting a member who holds a moderation
//! capability at this cut.
//!
//! A `leave` or `ban` that ends a member's joined state removes that member
//! from the accepted joined set, so the member's own Station would never
//! learn it. Such an Event is additionally owed to the departing member's
//! Station, frozen with the Event itself as the membership basis, and stays
//! owed only while that Event is still the member's effective membership
//! (`federation.md` §4.1.1).

use std::collections::BTreeMap;

use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerAuthoritySubmitRequest,
    PeerCommittedReplicationRequest,
};
use coland_storage::{
    FederationOutboxRecord, PersistenceError, PersistenceResult, RealmFanoutAuthorityWitness,
    RealmFanoutBinding, RealmFanoutOutboxInput, ids,
};
use diesel::sql_types::{BigInt, Binary, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

use crate::PgTransactionError;

/// Peer ingress every Realm fanout intent is delivered to.
pub(crate) const PEER_EVENTS_ENDPOINT: &str = "/_arkret/peer/events";

#[derive(diesel::QueryableByName)]
struct JoinedMemberRow {
    #[diesel(sql_type = Text)]
    member_id: String,
    #[diesel(sql_type = Text)]
    membership_event_id: String,
}

#[derive(diesel::QueryableByName)]
struct CurrentValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct GenesisEnvelopeRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
}

#[derive(diesel::QueryableByName)]
struct FrozenRemoteWelcomeRow {
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

pub(crate) async fn freeze_welcomes_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    welcomes: &[&arkret_wire::MlsWelcomeDelivery],
) -> Result<(), PgTransactionError> {
    if welcomes.is_empty() {
        return Ok(());
    }
    if event.kind != arkret_wire::EventKind::MlsCommit {
        return Err(PersistenceError::SchemaViolation(
            "Welcomes accompany only an MLS Commit".into(),
        )
        .into());
    }
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&event.scope_ref)
            .map_err(PersistenceError::database)?,
    )
    .map_err(internal)?;
    for welcome in welcomes {
        welcome.validate_shape().map_err(internal)?;
        if welcome.realm_id != event.realm_id
            || welcome.effective_scope != event.scope_ref
            || welcome.commit_event_ref != event.event_id
        {
            return Err(PersistenceError::SchemaViolation(
                "Welcome differs from its accepted Commit".into(),
            )
            .into());
        }
        let bytes =
            arkret_canonical::canonical_json_bytes(welcome).map_err(PersistenceError::database)?;
        let digest =
            arkret_canonical::canonical_sha256(welcome).map_err(PersistenceError::database)?;
        let station = welcome.recipient_actor_id.route_service_id();
        sql_query(
            "INSERT INTO mls_welcome_provenance \
             (welcome_id,realm_id,scope_key,commit_event_ref,recipient_station_id,claim_id, \
              delivery_digest,delivery_canonical_json,accepted_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING",
        )
        .bind::<Text, _>(welcome.welcome_id.as_str())
        .bind::<Text, _>(event.realm_id.as_str())
        .bind::<Text, _>(&key)
        .bind::<Text, _>(event.event_id.as_str())
        .bind::<Text, _>(station.as_str())
        .bind::<Text, _>(welcome.keypackage_claim_ref.as_str())
        .bind::<Text, _>(&digest)
        .bind::<Binary, _>(&bytes)
        .bind::<Timestamptz, _>(commit.committed_at)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
        let frozen = sql_query(
            "SELECT realm_id,scope_key,commit_event_ref,recipient_station_id,claim_id, \
             delivery_digest,delivery_canonical_json FROM mls_welcome_provenance \
             WHERE welcome_id=$1 FOR SHARE",
        )
        .bind::<Text, _>(welcome.welcome_id.as_str())
        .get_result::<FrozenRemoteWelcomeRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if !frozen.is_some_and(|row| {
            row.realm_id == event.realm_id.as_str()
                && row.scope_key == key
                && row.commit_event_ref == event.event_id.as_str()
                && row.recipient_station_id == station.as_str()
                && row.claim_id == welcome.keypackage_claim_ref.as_str()
                && row.delivery_digest == digest
                && row.delivery_canonical_json == bytes
        }) {
            return Err(PersistenceError::Conflict(format!(
                "{}: Welcome replay differs from the frozen signed delivery",
                coland_storage::ConflictCode::DuplicateConflict
            ))
            .into());
        }
    }
    Ok(())
}

/// Read the immutable Genesis from the just-installed accepted group and
/// cross-check the original committed Genesis Event before freezing it into
/// every authenticated peer intent. A later Commit base is never a selector.
async fn accepted_mls_genesis_for_fanout(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
) -> Result<Option<arkret_wire::EventId>, PgTransactionError> {
    if event.kind != arkret_wire::EventKind::MlsCommit {
        return Ok(None);
    }
    let key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&event.scope_ref)
            .map_err(PersistenceError::database)?,
    )
    .map_err(internal)?;
    let row = sql_query("SELECT value FROM mls_group_current_results WHERE scope_key=$1 FOR SHARE")
        .bind::<Text, _>(&key)
        .get_result::<CurrentValueRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?
        .ok_or_else(|| {
            PersistenceError::SchemaViolation("MLS fanout has no accepted group current".into())
        })?;
    let group: arkret_wire::MlsGroupCurrent =
        serde_json::from_value(row.value).map_err(PersistenceError::database)?;
    if group.effective_scope != event.scope_ref
        || group.current_mls_commit_event_ref != event.event_id
    {
        return Err(PersistenceError::SchemaViolation(
            "MLS fanout group current differs from the accepted Commit".into(),
        )
        .into());
    }
    let token = ids::parse_event_id(group.genesis_event_ref.as_str()).ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS Genesis id is not canonical".into())
    })?;
    let genesis = sql_query(
        "SELECT envelope FROM canonical_events WHERE id=$1 AND realm_id=$2 \
         AND kind='ak.mls.genesis' AND state='committed' FOR SHARE",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<GenesisEnvelopeRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| {
        PersistenceError::SchemaViolation("MLS fanout has no exact accepted Genesis".into())
    })?;
    let genesis: arkret_wire::Event =
        serde_json::from_value(genesis.envelope).map_err(PersistenceError::database)?;
    let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(Value::Object(genesis.payload.clone().into_iter().collect()))
            .map_err(PersistenceError::database)?;
    if genesis.event_id != group.genesis_event_ref
        || genesis.realm_id != event.realm_id
        || genesis.scope_ref != event.scope_ref
        || payload.mls_group_id().map_err(internal)?
            != event.scope_ref.canonical_mls_group_id().map_err(internal)?
    {
        return Err(PersistenceError::SchemaViolation(
            "MLS fanout Genesis provenance differs from its accepted group".into(),
        )
        .into());
    }
    Ok(Some(group.genesis_event_ref))
}

#[derive(diesel::QueryableByName)]
struct MembershipEventRow {
    #[diesel(sql_type = Text)]
    event_id: String,
}

#[derive(diesel::QueryableByName)]
struct PriorMembershipRow {
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    membership: Option<String>,
}

#[derive(diesel::QueryableByName)]
struct EventPkRow {
    #[diesel(sql_type = BigInt)]
    pk: i64,
}

fn internal(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Internal(detail.to_string())
}

/// The idempotency key of the one intent a RealmCommit owes a peer Station.
#[must_use]
pub(crate) fn fanout_idempotency_key(commit_id: &arkret_wire::RealmCommitId) -> String {
    format!("realm-fanout:{commit_id}")
}

/// Whether the Event carries a plaintext Message body: a create or a revise
/// without an encrypted carrier.
pub(crate) fn plaintext_message(event: &arkret_wire::Event) -> bool {
    matches!(
        event.kind,
        arkret_wire::EventKind::MessageCreate | arkret_wire::EventKind::MessageRevise
    ) && !event.payload.contains_key("encrypted_content")
}

/// The Stations a `realm_plaintext_visible_services` current value names as
/// private plaintext services for message content.
pub(crate) fn plaintext_message_service_ids(value: &Value) -> Vec<String> {
    value
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| {
            service.get("visibility").and_then(Value::as_str) == Some("private_plaintext")
                && service
                    .get("data_classes")
                    .and_then(Value::as_array)
                    .is_some_and(|classes| classes.iter().any(|class| class == "message_content"))
        })
        .filter_map(|service| service.get("service_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

/// The Stations the Realm names as private plaintext services for message
/// content at this cut.
async fn plaintext_message_services(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
) -> PersistenceResult<Vec<String>> {
    let Some(row) = sql_query(
        "SELECT b.value FROM realm_bootstrap_current_results b \
         JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.result_family='realm_plaintext_visible_services' \
           AND c.realm_id=b.realm_id AND c.stream_position=b.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=b.realm_id",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<CurrentValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    else {
        return Ok(Vec::new());
    };
    Ok(plaintext_message_service_ids(&row.value))
}

/// The departing member's Station owed a membership Event that ended the
/// member's joined state, with the Event itself as the frozen basis. `None`
/// when the Event is no such transition, the member is hosted here, the
/// member was not joined before it, or the Event is no longer the member's
/// effective membership.
async fn departing_member_target(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
) -> PersistenceResult<Option<(arkret_wire::DidCoreId, RealmFanoutAuthorityWitness)>> {
    if event.kind != arkret_wire::EventKind::MemberState {
        return Ok(None);
    }
    let Ok(payload) = serde_json::to_value(&event.payload).and_then(
        serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::MembershipPayload,
        >,
    ) else {
        return Ok(None);
    };
    use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
    if !matches!(
        payload.membership,
        MembershipPayloadState::Leave | MembershipPayloadState::Ban
    ) {
        return Ok(None);
    }
    let member = payload.member_id;
    let station = member.route_service_id().clone();
    if &station == authority_station {
        return Ok(None);
    }
    let member_key = member.to_string();
    let current = sql_query(
        "SELECT e.envelope->>'event_id' AS event_id \
         FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE m.realm_id=$1 AND m.member_id=$2 \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(&member_key)
    .get_result::<MembershipEventRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if current.is_none_or(|row| row.event_id != event.event_id.as_str()) {
        return Ok(None);
    }
    let event_token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".into()))?;
    let prior = sql_query(
        "SELECT pe.kind, pe.envelope->'payload'->>'membership' AS membership \
         FROM canonical_events e \
         JOIN realm_commits c ON c.event_pk=e.pk \
         JOIN realm_commits pc ON pc.stream_key=c.stream_key \
           AND pc.stream_position < c.stream_position \
         JOIN canonical_events pe ON pe.pk=pc.event_pk \
         WHERE e.id=$1 AND pe.state='committed' AND ( \
           (pe.kind='ak.member.state' AND pe.envelope->'payload'->'member_id'=$2::jsonb) \
           OR (pe.kind='ak.invite.accept' AND pe.envelope->'actor_id'=$2::jsonb)) \
         ORDER BY pc.stream_position DESC LIMIT 1",
    )
    .bind::<Binary, _>(event_token.to_vec())
    .bind::<Text, _>(&member_key)
    .get_result::<PriorMembershipRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let joined_before = prior.is_some_and(|row| {
        row.kind == arkret_wire::EventKind::InviteAccept.as_str()
            || row.membership.as_deref() == Some("join")
    });
    if !joined_before {
        return Ok(None);
    }
    Ok(Some((
        station,
        RealmFanoutAuthorityWitness {
            member_id: member,
            circle_membership_event_ref: None,
            membership_event_ref: event.event_id.to_string(),
        },
    )))
}

/// Propose exact current membership witnesses. Complete-byte disclosure is
/// intersected below on each witness, never on the Station as a whole.
async fn remote_targets(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<BTreeMap<arkret_wire::DidCoreId, Vec<RealmFanoutAuthorityWitness>>> {
    let proposed = membership_targets(conn, event, authority_station, at).await?;
    if proposed.is_empty() {
        return Ok(proposed);
    }
    #[derive(diesel::QueryableByName)]
    struct AcceptedRow {
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    let token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| internal("fanout Event id is not canonical"))?;
    let accepted = sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e \
        JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=e.realm_id \
        WHERE e.id=$1 AND e.realm_id=$2 AND e.state='committed'",
    )
    .bind::<Binary, _>(token.to_vec())
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<AcceptedRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let row = arkret_wire::CommittedEventFullView {
        event: serde_json::from_value(accepted.envelope).map_err(internal)?,
        commit: serde_json::from_value(accepted.commit_json).map_err(internal)?,
    };
    if row.event != *event || row.commit.event_ref != event.event_id {
        return Err(internal("fanout differs from its exact accepted Event"));
    }
    if !crate::committed_disclosure::withheld_commit_ids_in_connection(
        conn,
        &[row.commit.commit_id.to_string()],
    )
    .await?
    .is_empty()
    {
        return Ok(BTreeMap::new());
    }
    let mut targets = BTreeMap::new();
    for (station, witnesses) in proposed {
        let mut qualified = Vec::new();
        for witness in witnesses {
            // The explicit terminating membership exception proves the old
            // interval in membership_targets. Its post-leave floor is absent;
            // byte withdrawal still applies above to the termination itself.
            let departing = witness.membership_event_ref == event.event_id.as_str()
                && event.kind == arkret_wire::EventKind::MemberState
                && matches!(
                    event.payload.get("membership").and_then(Value::as_str),
                    Some("leave" | "ban")
                )
                || witness.circle_membership_event_ref.as_ref() == Some(&event.event_id)
                    && event.kind == arkret_wire::EventKind::CircleMemberState
                    && matches!(
                        event.payload.get("membership").and_then(Value::as_str),
                        Some("leave" | "ban")
                    );
            if !departing {
                if matches!(
                    row.commit.stream_ref,
                    arkret_wire::CommitStreamRef::Realm { .. }
                ) {
                    let Some(floor) = crate::account_stream_scan::caller_realm_floor_in_connection(
                        conn,
                        &event.realm_id,
                        &witness.member_id,
                    )
                    .await?
                    else {
                        continue;
                    };
                    if row.commit.stream_position < floor.oldest_position {
                        continue;
                    }
                }
                match crate::committed_disclosure::full_event_for_member_in_connection(
                    conn,
                    &row,
                    &witness.member_id,
                    at,
                )
                .await
                {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(PersistenceError::Conflict(detail))
                        if detail.starts_with("capability_denied:") =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            qualified.push(witness);
        }
        if !qualified.is_empty() {
            targets.insert(station, qualified);
        }
    }
    Ok(targets)
}

async fn membership_targets(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
    commit_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<BTreeMap<arkret_wire::DidCoreId, Vec<RealmFanoutAuthorityWitness>>> {
    // A joined-member witness cannot authorize private controller nonce or
    // PolicyRef source bytes. This carrier has no withheld Event branch.
    // RealmAction configuration and ordinary shared PolicySet remain shared.
    if crate::committed_disclosure::author_private_source(event) {
        return Ok(BTreeMap::new());
    }
    let sidecar = match &event.scope_ref {
        arkret_wire::ScopeRef::Sidecar { sidecar_id, .. } => Some(sidecar_id.clone()),
        _ if event.kind == arkret_wire::EventKind::SidecarCreate => {
            Some(arkret_wire::SidecarId::from_event_id(&event.event_id))
        }
        _ => None,
    };
    if let Some(sidecar) = sidecar {
        let recipients =
            crate::sidecar_access::recipients_in_connection(conn, &event.realm_id, &sidecar)
                .await?;
        let mut targets: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for recipient in recipients {
            if &recipient.station_id == authority_station {
                continue;
            }
            let actor = arkret_wire::ActorId::account(recipient.clone());
            let Some(join) = sql_query("SELECT m.member_id,e.envelope->>'event_id' AS membership_event_id \
                FROM member_state_current_results m JOIN realm_commits c ON c.realm_id=m.realm_id AND c.commit_id=m.current_commit_id \
                AND c.stream_position=m.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' \
                WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join'")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(actor.to_string())
                .get_result::<JoinedMemberRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? else { continue; };
            targets
                .entry(recipient.station_id)
                .or_default()
                .push(RealmFanoutAuthorityWitness {
                    member_id: actor,
                    membership_event_ref: join.membership_event_id,
                    circle_membership_event_ref: None,
                });
        }
        return Ok(targets);
    }
    // A Circle is empty at create. Its Realm-stream authorization shell is
    // visible, but the signed object contains private directory fields. The
    // committed-replication carrier below contains a complete Event and has
    // no withheld branch, so no remote Realm member may receive these bytes.
    // A peer can fetch the Commit-only chain node through the registered
    // committed-event scan; Circle-specific availability remains closed.
    if event.kind == arkret_wire::EventKind::CircleCreate {
        return Ok(BTreeMap::new());
    }
    let moderation_private = matches!(
        event.kind,
        arkret_wire::EventKind::SelfModerationReport
            | arkret_wire::EventKind::ModerationFrankingProof
    );
    let effective_scope = if event.kind == arkret_wire::EventKind::ModerationFrankingProof {
        let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(internal)?)
                .map_err(internal)?;
        crate::moderation_franking_proof_current_results::franking_target_scope_in_connection(
            conn,
            &event.realm_id,
            &proof.event_id,
        )
        .await?
    } else {
        event.scope_ref.clone()
    };
    let rows = sql_query(
        "SELECT m.member_id, e.envelope->>'event_id' AS membership_event_id \
         FROM member_state_current_results m \
         JOIN realm_commits c ON c.commit_id=m.current_commit_id \
         JOIN canonical_events e ON e.pk=c.event_pk \
         WHERE m.realm_id=$1 AND m.membership='join' \
           AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
           AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id \
           AND e.state='committed' \
         ORDER BY m.member_id",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .load::<JoinedMemberRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    let plaintext_services = if plaintext_message(event) {
        Some(plaintext_message_services(conn, &event.realm_id).await?)
    } else {
        None
    };
    let mut targets: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in rows {
        let member: arkret_wire::ActorId = serde_json::from_str(&row.member_id)
            .map_err(|error| internal(format!("joined member identity is malformed: {error}")))?;
        let station = member.route_service_id().clone();
        if &station == authority_station {
            continue;
        }
        if plaintext_services
            .as_ref()
            .is_some_and(|services| !services.iter().any(|service| service == station.as_str()))
        {
            continue;
        }
        let circle_membership_event_ref = if !moderation_private {
            if let arkret_wire::ScopeRef::Circle {
                realm_id,
                circle_id,
            } = &effective_scope
            {
                let Some(basis) = sql_query("SELECT e.envelope->>'event_id' AS event_id FROM circle_member_state_current_results m JOIN circle_current_results circle ON circle.circle_id=m.circle_id AND circle.realm_id=m.realm_id JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position AND c.stream_ref=m.source_stream_ref JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) AND circle.value->>'state'='active' AND e.state='committed'")
                .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).bind::<Text, _>(member.to_string())
                .get_result::<MembershipEventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? else { continue; };
                Some(arkret_wire::EventId::new(basis.event_id).map_err(internal)?)
            } else {
                None
            }
        } else {
            None
        };
        if moderation_private
            && !crate::moderation_report_current_results::scope_moderator(
                conn,
                &event.realm_id,
                &effective_scope,
                &member,
                &[
                    arkret_wire::CapabilityActionId::POLICY_MANAGE,
                    arkret_wire::CapabilityActionId::MODERATION_DECISION,
                ],
                commit_at,
            )
            .await?
        {
            continue;
        }
        arkret_wire::EventId::new(row.membership_event_id.clone())
            .map_err(|error| internal(format!("membership Event id is malformed: {error}")))?;
        targets
            .entry(station)
            .or_default()
            .push(RealmFanoutAuthorityWitness {
                member_id: member,
                circle_membership_event_ref,
                membership_event_ref: row.membership_event_id,
            });
    }
    if let Some((station, witness)) =
        departing_member_target(conn, event, authority_station).await?
    {
        targets.entry(station).or_default().push(witness);
    }
    if let Some((station, witness)) =
        departing_circle_member_target(conn, event, authority_station).await?
    {
        targets.entry(station).or_default().push(witness);
    }
    Ok(targets)
}

async fn departing_circle_member_target(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    authority_station: &arkret_wire::DidCoreId,
) -> PersistenceResult<Option<(arkret_wire::DidCoreId, RealmFanoutAuthorityWitness)>> {
    if event.kind != arkret_wire::EventKind::CircleMemberState
        || !matches!(
            event.payload.get("membership").and_then(Value::as_str),
            Some("leave" | "ban")
        )
    {
        return Ok(None);
    }
    let arkret_wire::ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &event.scope_ref
    else {
        return Ok(None);
    };
    let member: arkret_wire::ActorId = serde_json::from_value(
        event
            .payload
            .get("member_id")
            .cloned()
            .ok_or_else(|| internal("Circle departure has no member"))?,
    )
    .map_err(internal)?;
    if member.route_service_id() == authority_station {
        return Ok(None);
    }
    let Some(parent) = sql_query("SELECT e.envelope->>'event_id' AS event_id FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join' AND e.state='committed' AND c.stream_ref->>'kind'='realm'")
        .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(member.to_string()).get_result::<MembershipEventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)? else { return Ok(None); };
    let current = sql_query("SELECT e.envelope->>'event_id' AS event_id FROM circle_member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position AND c.stream_ref=m.source_stream_ref JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership IN ('leave','ban') AND e.state='committed'")
        .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).bind::<Text, _>(member.to_string()).get_result::<MembershipEventRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if current.as_ref().map(|row| row.event_id.as_str()) != Some(event.event_id.as_str()) {
        return Ok(None);
    }
    let previous = sql_query("SELECT e.kind, e.envelope->'payload'->>'membership' AS membership FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.realm_id=$1 AND c.stream_ref=$2 AND e.kind='ak.circle.member.state' AND e.envelope->'payload'->'member_id'=$3 AND c.stream_position < (SELECT current_stream_position FROM circle_member_state_current_results WHERE realm_id=$1 AND circle_id=$4 AND member_id=$5) ORDER BY c.stream_position DESC LIMIT 1")
        .bind::<Text, _>(realm_id.as_str()).bind::<Jsonb, _>(serde_json::to_value(arkret_wire::CommitStreamRef::Circle { realm_id:realm_id.clone(),circle_id:circle_id.clone() }).map_err(internal)?).bind::<Jsonb, _>(serde_json::to_value(&member).map_err(internal)?).bind::<Text, _>(circle_id.as_str()).bind::<Text, _>(member.to_string()).get_result::<PriorMembershipRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if previous.and_then(|row| row.membership).as_deref() != Some("join") {
        return Ok(None);
    }
    Ok(Some((
        member.route_service_id().clone(),
        RealmFanoutAuthorityWitness {
            member_id: member,
            membership_event_ref: parent.event_id,
            circle_membership_event_ref: Some(event.event_id.clone()),
        },
    )))
}

/// Whether a frozen fanout intent to `peer` is still owed at the current
/// accepted cut (`federation.md` §4.1.1): at least one frozen
/// `(member_id, membership_event_ref)` basis must, as a whole, still be a
/// current joined member routed to `peer` for which the Event's scope and
/// plaintext policy still allow the complete canonical bytes.
pub(crate) async fn fanout_still_owed_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    local_station: &arkret_wire::DidCoreId,
    peer: &arkret_wire::DidCoreId,
    witnesses: &[RealmFanoutAuthorityWitness],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let targets = remote_targets(conn, event, local_station, at).await?;
    Ok(targets
        .get(peer)
        .is_some_and(|current| witnesses.iter().any(|witness| current.contains(witness))))
}

/// Plan and durably enqueue the Realm fanout of one just-committed Event.
///
/// Must run after the Event's typed current results were written, so the
/// joined set is the one the Event itself produced. `welcomes` are the
/// verified Welcomes of an `ak.mls.commit` whose recipients other Stations
/// host, in submission order: each rides the intent to its recipient's
/// routing service (encryption-and-audit.md §2.2 "跨站 recipient"), and a
/// service outside the target set refuses the whole Commit with a bare
/// `failed_precondition`. Returns the number of intents this call inserted.
pub(crate) async fn plan_realm_fanout_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    authority_station: &arkret_wire::DidCoreId,
    source: Option<&arkret_wire::EventAdmissionSubmission>,
    welcomes: &[&arkret_wire::MlsWelcomeDelivery],
    created_at: i64,
) -> Result<usize, PgTransactionError> {
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    if commit.stream_ref != realm_stream {
        let supported_circle = matches!(&event.scope_ref, arkret_wire::ScopeRef::Circle { .. })
            && matches!(
                event.kind,
                arkret_wire::EventKind::CircleMemberState
                    | arkret_wire::EventKind::CapabilityGrant
                    | arkret_wire::EventKind::CapabilityRevoke
                    | arkret_wire::EventKind::PolicySet
                    | arkret_wire::EventKind::StrandWatchSet
                    | arkret_wire::EventKind::AuditAccessed
                    | arkret_wire::EventKind::MlsGenesis
                    | arkret_wire::EventKind::MlsCommit
                    | arkret_wire::EventKind::StrandCreate
                    | arkret_wire::EventKind::MessageCreate
                    | arkret_wire::EventKind::MessageRevise
                    | arkret_wire::EventKind::MessageRedact
                    | arkret_wire::EventKind::SelfModerationReport
                    | arkret_wire::EventKind::ModerationDecision
                    | arkret_wire::EventKind::ModerationDecisionLift
                    | arkret_wire::EventKind::RelationCreate
                    | arkret_wire::EventKind::RelationUpdate
                    | arkret_wire::EventKind::RelationTombstone
                    | arkret_wire::EventKind::PinAdd
                    | arkret_wire::EventKind::PinRemove
                    | arkret_wire::EventKind::PinReorder
            );
        let supported_sidecar = matches!(&event.scope_ref, arkret_wire::ScopeRef::Sidecar { .. });
        if !supported_circle && !supported_sidecar {
            if source.is_some() {
                return Err(PersistenceError::Conflict(
                    "Circle and Sidecar fanout target planning is unavailable".to_owned(),
                )
                .into());
            }
            return Ok(0);
        }
    }
    let targets = remote_targets(conn, event, authority_station, commit.committed_at).await?;
    let mut replicated_welcomes: BTreeMap<_, Vec<arkret_wire::MlsWelcomeDelivery>> =
        BTreeMap::new();
    for welcome in welcomes {
        let service = welcome.recipient_actor_id.route_service_id();
        if !targets.contains_key(service) {
            return Err(PersistenceError::Conflict(format!(
                "{}: the remote Welcome recipient's Station is not a replication target",
                coland_storage::ConflictCode::FailedPrecondition
            ))
            .into());
        }
        replicated_welcomes
            .entry(service.clone())
            .or_default()
            .push((*welcome).clone());
    }
    if targets.is_empty() {
        return Ok(0);
    }
    crate::organization_moderation_gate::require_organization_moderation_authority_in_connection(
        conn,
        &event.realm_id,
        if matches!(
            commit.stream_ref,
            arkret_wire::CommitStreamRef::Realm { .. }
        ) {
            Some(commit.stream_position)
        } else {
            None
        },
        commit.committed_at,
    )
    .await?;
    let source = source.ok_or_else(|| {
        PersistenceError::Conflict(
            "Realm Event with remote joined members has no fanout source submission".to_owned(),
        )
    })?;
    if source.event != *event {
        return Err(PersistenceError::SchemaViolation(
            "Realm fanout source submission does not carry the committed Event".to_owned(),
        )
        .into());
    }
    let event_token = ids::parse_event_id(event.event_id.as_str())
        .ok_or_else(|| PersistenceError::SchemaViolation("Event id is not canonical".into()))?;
    let event_pk = sql_query("SELECT pk FROM canonical_events WHERE id=$1")
        .bind::<Binary, _>(event_token.to_vec())
        .get_result::<EventPkRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .pk;
    let idempotency_key = fanout_idempotency_key(&commit.commit_id);
    let genesis_event_ref = accepted_mls_genesis_for_fanout(conn, event).await?;
    freeze_welcomes_in_connection(conn, event, commit, welcomes).await?;
    let producer_signer_fact =
        crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
            conn, event, commit,
        )
        .await?;
    let mut inserted = 0;
    for (station, authority_witnesses) in targets {
        let request =
            PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
                branch: CommittedReplicationBranch::CommittedReplication,
                replications: vec![CommittedEventSubmission::from_source_submission(
                    source,
                    commit.clone(),
                    producer_signer_fact.clone(),
                    genesis_event_ref.clone(),
                    replicated_welcomes.remove(&station),
                )],
            });
        request
            .validate()
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
        let payload_json = String::from_utf8(
            arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?,
        )
        .map_err(internal)?;
        let id = format!("{idempotency_key}:{station}");
        let peer_url = crate::service_route::cached_station_base_in_connection(
            conn,
            &station,
            commit.committed_at,
        )
        .await?;
        let record = FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
            id: id.clone(),
            peer_id: station,
            peer_url,
            endpoint: PEER_EVENTS_ENDPOINT.to_owned(),
            idempotency_key: idempotency_key.clone(),
            payload_json,
            binding: RealmFanoutBinding {
                realm_id: event.realm_id.to_string(),
                source_event_ids: vec![event.event_id.to_string()],
                authority_witnesses,
            },
            created_at,
        });
        if crate::federation::enqueue_federation_outbox_in_connection(conn, &record).await? {
            inserted += 1;
            sql_query(
                "INSERT INTO event_federation_outbox (event_pk, outbox_id) VALUES ($1, $2) \
                 ON CONFLICT DO NOTHING",
            )
            .bind::<BigInt, _>(event_pk)
            .bind::<Text, _>(&id)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
    }
    Ok(inserted)
}

/// One source-committed business/audit unit; never two ordinary fanout items.
pub(crate) async fn plan_audit_pair_in_connection(
    conn: &mut AsyncPgConnection,
    unit: &arkret_models_collaboration::authority_commit::AuditPairedEventUnitSubmission,
    commits: &[arkret_wire::RealmCommit; 2],
    authority_station: &arkret_wire::DidCoreId,
) -> Result<usize, PgTransactionError> {
    use arkret_models_collaboration::authority_commit::{
        AuditPairedEventFederationSubmission, PeerRegisteredAtomicUnit,
        PeerRegisteredAtomicUnitRequest, RegisteredAtomicUnitBranch,
    };
    let mut business_targets = remote_targets(
        conn,
        &unit.events[0].event,
        authority_station,
        commits[1].committed_at,
    )
    .await?;
    let audit_targets = remote_targets(
        conn,
        &unit.events[1].event,
        authority_station,
        commits[1].committed_at,
    )
    .await?;
    let mut sources = Vec::with_capacity(2);
    for (slot, commit) in unit.events.iter().zip(commits) {
        let fact = crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
            conn,
            &slot.event,
            commit,
        )
        .await?;
        sources.push(CommittedEventSubmission::from_source_submission(
            slot,
            commit.clone(),
            fact,
            None,
            None,
        ));
    }
    let committed_events: [CommittedEventSubmission; 2] = sources
        .try_into()
        .map_err(|_| internal("audit pair requires two source slots"))?;
    let request =
        PeerAuthoritySubmitRequest::RegisteredAtomicUnit(PeerRegisteredAtomicUnitRequest {
            branch: RegisteredAtomicUnitBranch::RegisteredAtomicUnit,
            unit: PeerRegisteredAtomicUnit::AuditPairedEvent(
                AuditPairedEventFederationSubmission {
                    unit_kind: unit.unit_kind,
                    committed_events,
                },
            ),
        });
    request.validate().map_err(PersistenceError::database)?;
    let payload_json = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&request).map_err(PersistenceError::database)?,
    )
    .map_err(internal)?;
    let idempotency_key = fanout_idempotency_key(&commits[1].commit_id);
    let mut inserted = 0;
    for (station, witnesses) in business_targets.iter_mut() {
        let Some(audit_witnesses) = audit_targets.get(station) else {
            continue;
        };
        for witness in audit_witnesses {
            if !witnesses.contains(witness) {
                witnesses.push(witness.clone());
            }
        }
        let id = format!("{idempotency_key}:{station}");
        let peer_url = crate::service_route::cached_station_base_in_connection(
            conn,
            station,
            commits[1].committed_at,
        )
        .await?;
        let record = FederationOutboxRecord::realm_fanout(RealmFanoutOutboxInput {
            id: id.clone(),
            peer_id: station.clone(),
            peer_url,
            endpoint: PEER_EVENTS_ENDPOINT.to_owned(),
            idempotency_key: idempotency_key.clone(),
            payload_json: payload_json.clone(),
            binding: RealmFanoutBinding {
                realm_id: unit.events[0].event.realm_id.to_string(),
                source_event_ids: unit
                    .events
                    .iter()
                    .map(|slot| slot.event.event_id.to_string())
                    .collect(),
                authority_witnesses: witnesses.clone(),
            },
            created_at: commits[1].committed_at.timestamp(),
        });
        if crate::federation::enqueue_federation_outbox_in_connection(conn, &record).await? {
            inserted += 1;
            for slot in &unit.events {
                sql_query("INSERT INTO event_federation_outbox(event_pk,outbox_id) SELECT pk,$2 FROM canonical_events WHERE envelope->>'event_id'=$1 ON CONFLICT DO NOTHING")
                    .bind::<Text,_>(slot.event.event_id.as_str()).bind::<Text,_>(&id).execute(&mut *conn).await?;
            }
        }
    }
    Ok(inserted)
}
