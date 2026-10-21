//! Whole-value Agent mode CAS and shared producer gates at the accepting cut.
use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::agent_interaction::{
    AgentInteractionCurrentValue, AgentInteractionMode, AgentInteractionSetPayload,
};
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CurrentRevision, Event, EventKind, RealmCommit, RealmId,
    ScopeRef,
};
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(QueryableByName)]
pub(crate) struct ModeRow {
    #[diesel(sql_type = Text)]
    pub(crate) current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    pub(crate) current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    pub(crate) value: Value,
}
#[derive(QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}
#[derive(QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    present: bool,
}
fn denied(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("capability_denied: {detail}"))
}
fn precondition(detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("failed_precondition: {detail}"))
}
fn invalid(error: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(error.to_string())
}

/// Current exact ownership and the joined generation that admitted this Agent.
pub(crate) async fn controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AccountId>> {
    read_controller_in_connection(conn, realm, agent, at, true).await
}

/// The enclosing repeatable-read transaction fixes this visibility cut.
pub(crate) async fn controller_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<Option<AccountId>> {
    read_controller_in_connection(conn, realm, agent, at, false).await
}

#[derive(QueryableByName)]
struct OwnedCurrentSourceRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    envelope: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Text>)]
    scope_set_digest: Option<String>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    accountability_scope: Option<Value>,
    #[diesel(sql_type = diesel::sql_types::Nullable<Jsonb>)]
    commit_json: Option<Value>,
}

fn owned_current_source(
    row: &OwnedCurrentSourceRow,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<(Event, RealmCommit)> {
    let event: Event = serde_json::from_value(
        row.envelope
            .clone()
            .ok_or_else(|| denied("owned current has no accepted source Event"))?,
    )
    .map_err(invalid)?;
    let commit: RealmCommit = serde_json::from_value(
        row.commit_json
            .clone()
            .ok_or_else(|| denied("owned current has no accepting Commit"))?,
    )
    .map_err(invalid)?;
    let realm: RealmId = row.realm_id.parse().map_err(invalid)?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let position = u64::try_from(row.current_stream_position).map_err(invalid)?;
    if event.realm_id != realm
        || commit.realm_id != realm
        || commit.commit_id.as_str() != row.current_commit_id
        || commit.stream_position != position
        || commit.stream_ref != stream
        || commit.event_ref != event.event_id
        || commit.committed_at > at
        || (event.scope_ref != ScopeRef::Realm { realm_id: realm }
            && !(event.kind == EventKind::RealmCreate && event.scope_ref == ScopeRef::RealmGenesis))
    {
        return Err(denied("owned current source coordinates differ"));
    }
    event
        .verify_event_id_matches_content_with_digest_suite(
            event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    commit.verify_commit_id_matches_content().map_err(invalid)?;
    arkret_schema::validate_event_for_submit(&event).map_err(invalid)?;
    Ok((event, commit))
}

/// Require the original native self-admission witness, not a newly resolved
/// device or a principal projection, and verify its original Event signature.
async fn require_owned_controller_source(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    controller: &AccountId,
    controller_pcr: &RealmId,
    kind: &str,
    provision_ref: Option<&arkret_wire::CommittedEventRef>,
) -> PersistenceResult<()> {
    use arkret_models_identity::signer_key_operations::{
        HistoricalSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    };
    #[derive(QueryableByName)]
    struct NativeSourceRow {
        #[diesel(sql_type = Jsonb)]
        outcome: Value,
        #[diesel(sql_type = Jsonb)]
        provenance: Value,
    }
    let row = sql_query("SELECT outcome,self_admission_provenance AS provenance FROM agent_producer_signer_keys WHERE commit_id=$1 AND self_admission_kind=$2 AND self_admission_account=$3 AND self_admission_provenance IS NOT NULL")
        .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(kind)
        .bind::<Jsonb,_>(json!(controller)).get_result::<NativeSourceRow>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("owned current native acceptance witness is unavailable"))?;
    let accepted_pcr: RealmId =
        serde_json::from_value(row.provenance["accepted_pcr_realm_id"].clone()).map_err(invalid)?;
    if accepted_pcr != *controller_pcr || event.actual_signer().as_account_id() != Some(controller)
    {
        return Err(denied("owned current original controller source differs"));
    }
    if let Some(provision_ref) = provision_ref {
        let expected_controller: AccountId =
            serde_json::from_value(row.provenance["controller_account"].clone())
                .map_err(invalid)?;
        let expected_ref: arkret_wire::CommittedEventRef =
            serde_json::from_value(row.provenance["provision_ref"].clone()).map_err(invalid)?;
        if expected_controller != *controller
            || expected_ref != *provision_ref
            || row.provenance["controller_delegation_ref"].as_str()
                != event.authorization_ref.as_deref()
        {
            return Err(denied("owned current original provision witness differs"));
        }
    } else if event.realm_id != *controller_pcr || event.executed_by.is_some() {
        return Err(denied(
            "owned current is not the controller's original PCR write",
        ));
    }
    let outcome: SignerKeyQueryOutcome = serde_json::from_value(row.outcome).map_err(invalid)?;
    outcome.validate(&event.realm_id).map_err(invalid)?;
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())
        .map_err(invalid)?
        .ok_or_else(|| denied("owned current controller device proof is unavailable"))?;
    let expected = SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice {
            actor: event.actual_signer().clone(),
            device_id: producer.device_id.clone(),
            verification_method: event
                .producer_proof
                .as_ref()
                .ok_or_else(|| denied("owned current proof missing"))?
                .verification_method
                .clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        },
    };
    if outcome.selector() != &expected
        || !matches!(outcome, SignerKeyQueryOutcome::HistoricalResolved { .. })
    {
        return Err(denied("owned current historical device witness differs"));
    }
    let key = outcome
        .key()
        .ok_or_else(|| denied("owned current historical key unavailable"))?;
    if key.authorization_ref.stream_ref.realm_id() != controller_pcr {
        return Err(denied(
            "owned current device authorization belongs to another PCR",
        ));
    }
    let bytes =
        arkret_canonical::base64url_decode(key.public_key_b64u.as_str()).map_err(invalid)?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| denied("owned current device key length differs"))?;
    #[derive(QueryableByName)]
    struct AuthorizationSource {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let original=sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE c.realm_id=$1 AND c.commit_id=$2 AND c.stream_position=$3 AND c.stream_ref=$4")
        .bind::<Text,_>(controller_pcr.as_str()).bind::<Text,_>(key.authorization_ref.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(key.authorization_ref.stream_position).map_err(invalid)?)
        .bind::<Jsonb,_>(json!(key.authorization_ref.stream_ref)).get_result::<AuthorizationSource>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("owned current original device authorization is unavailable"))?;
    let authorization_event: Event = serde_json::from_value(original.envelope).map_err(invalid)?;
    let authorization_commit: RealmCommit =
        serde_json::from_value(original.commit_json).map_err(invalid)?;
    let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(json!(authorization_event.payload)).map_err(invalid)?;
    if authorization_event.kind != EventKind::DeviceAuthorize
        || authorization_event.actor_id.as_account_id() != Some(controller)
        || authorization_event.event_id != key.authorization_ref.event_id
        || authorization_commit.event_ref != authorization_event.event_id
        || authorization_commit.commit_id != key.authorization_ref.commit_id
        || authorization_commit.realm_id != *controller_pcr
        || authorization_event.realm_id != *controller_pcr
        || authorization_commit.stream_ref != key.authorization_ref.stream_ref
        || authorization_commit.stream_position != key.authorization_ref.stream_position
        || outcome.accepted_at() != Some(authorization_commit.committed_at)
        || authorization_commit.committed_at > commit.committed_at
        || authorization.device_id != producer.device_id
    {
        return Err(denied(
            "owned current historical authorization coordinates differ",
        ));
    }
    if [
        event.created_at,
        event.producer_proof.as_ref().unwrap().created_at,
        commit.committed_at,
    ]
    .into_iter()
    .any(|at| {
        at < authorization.not_before
            || authorization
                .expires_at
                .flatten()
                .is_some_and(|expiry| at >= expiry)
    }) {
        return Err(denied(
            "owned current original device authorization window differs",
        ));
    }
    authorization_event
        .verify_event_id_matches_content_with_digest_suite(
            controller_pcr.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    authorization_commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    authorization.validate_wire_constraints().map_err(invalid)?;
    let revision = sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE c.realm_id=$1 AND c.commit_id=$2 AND c.stream_position=$3 AND c.stream_ref=$4")
        .bind::<Text,_>(controller_pcr.as_str()).bind::<Text,_>(key.revision.commit_id.as_str())
        .bind::<BigInt,_>(i64::try_from(key.revision.stream_position).map_err(invalid)?)
        .bind::<Jsonb,_>(json!(key.authorization_ref.stream_ref)).get_result::<AuthorizationSource>(&mut *conn)
        .await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| denied("owned current original PCR revision is unavailable"))?;
    let revision_event: Event = serde_json::from_value(revision.envelope).map_err(invalid)?;
    let revision_commit: RealmCommit =
        serde_json::from_value(revision.commit_json).map_err(invalid)?;
    if revision_event.realm_id != *controller_pcr
        || revision_commit.realm_id != *controller_pcr
        || revision_commit.event_ref != revision_event.event_id
        || revision_commit.commit_id != key.revision.commit_id
        || revision_commit.stream_ref != key.authorization_ref.stream_ref
        || revision_commit.stream_position != key.revision.stream_position
        || revision_commit.stream_position < authorization_commit.stream_position
        || revision_commit.governance_generation != key.governance_generation
        || revision_commit.committed_at > commit.committed_at
    {
        return Err(denied(
            "owned current original PCR revision does not cover authorization",
        ));
    }
    revision_event
        .verify_event_id_matches_content_with_digest_suite(
            controller_pcr.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    revision_commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    let multibase = authorization
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| denied("owned current device key is not a closed did:key"))?;
    if arkret_canonical::decode_ed25519_multibase(multibase)
        .map_err(invalid)?
        .as_slice()
        != raw.as_slice()
    {
        return Err(denied(
            "owned current retained signer key differs from original authorization",
        ));
    }
    let envelope = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(invalid)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        event.producer_proof.as_ref().unwrap(),
        &envelope,
        &event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: raw.to_vec(),
        },
        event.realm_id.digest_suite_code().digest_suite(),
    )
    .map_err(invalid)?;
    Ok(())
}

async fn read_controller_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Option<AccountId>> {
    let joined = sql_query(format!("SELECT m.realm_id,m.current_commit_id,m.current_stream_position,m.value,e.envelope,c.commit_json,NULL::text AS scope_set_digest,NULL::jsonb AS accountability_scope FROM member_state_current_results m LEFT JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join'{}",if lock { " FOR SHARE OF m" } else { "" }))
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(ActorId::account(agent.clone()).to_string())
        .get_result::<OwnedCurrentSourceRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(joined) = joined else {
        return Ok(None);
    };
    let (agent_join, agent_join_commit) = owned_current_source(&joined, at)?;
    if agent_join.kind != EventKind::MemberState || joined.value != json!({"membership":"join"}) {
        return Err(denied(
            "owned Agent join current differs from its accepted writer",
        ));
    }
    let membership: arkret_models_collaboration::governance::membership_invite::MembershipPayload =
        serde_json::from_value(json!(agent_join.payload)).map_err(invalid)?;
    if membership.member_id != ActorId::account(agent.clone())
        || json!(membership.membership) != json!("join")
    {
        return Err(denied("owned Agent join source names another member"));
    }
    let Some(binding) = membership.agent_controller_binding else {
        return Ok(None);
    };
    binding.validate().map_err(invalid)?;
    let controller = binding.controller_account_id;
    if controller.station_id != agent.station_id || binding.controller_terminal_event_ref.is_some()
    {
        return Ok(None);
    }
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        &agent_join,
        &agent_join_commit,
    )
    .await?
    .is_none()
    {
        return Err(denied(
            "owned Agent join original producer source is unavailable",
        ));
    }
    let current=sql_query(format!("SELECT m.realm_id,m.current_commit_id,m.current_stream_position,m.value,e.envelope,c.commit_json,NULL::text AS scope_set_digest,NULL::jsonb AS accountability_scope FROM member_state_current_results m LEFT JOIN realm_commits c ON c.commit_id=m.current_commit_id AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE m.realm_id=$1 AND m.member_id=$2 AND m.membership='join'{}",if lock { " FOR SHARE OF m" } else { "" }))
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(ActorId::account(controller.clone()).to_string())
        .get_result::<OwnedCurrentSourceRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(current) = current else {
        return Ok(None);
    };
    let (controller_join, controller_join_commit) = owned_current_source(&current, at)?;
    if controller_join.event_id != binding.controller_membership_generation_ref
        || current.value != json!({"membership":"join"})
    {
        return Ok(None);
    }
    match controller_join.kind {
        EventKind::MemberState => {
            let body:arkret_models_collaboration::governance::membership_invite::MembershipPayload=serde_json::from_value(json!(controller_join.payload)).map_err(invalid)?;
            if body.member_id != ActorId::account(controller.clone())
                || json!(body.membership) != json!("join")
            {
                return Err(denied("owned controller join source names another member"));
            }
        }
        EventKind::InviteAccept
            if controller_join.actor_id.as_account_id() == Some(&controller) =>
        {
            let body: arkret_models_collaboration::governance::membership_invite::InviteAcceptPayload =
                    serde_json::from_value(json!(controller_join.payload)).map_err(invalid)?;
            body.validate_actor(&controller_join.actor_id)
                .map_err(invalid)?;
        }
        _ => {
            return Err(denied(
                "owned controller current has no registered join writer",
            ));
        }
    }
    if crate::agent_producer_signer_keys::producer_source_for_commit_in_connection(
        conn,
        &controller_join,
        &controller_join_commit,
    )
    .await?
    .is_none()
    {
        return Err(denied(
            "owned controller join original producer source is unavailable",
        ));
    }
    Ok(
        owned_provenance_in_connection(conn, agent, &controller, at, lock)
            .await?
            .map(|_| controller),
    )
}

/// The existing accepted ownership reader, usable before an Agent's first join.
/// This returns only verified original provision/status/accountability evidence;
/// it does not create membership or approve a management action.
pub(crate) async fn owned_provenance_in_connection(
    conn: &mut AsyncPgConnection,
    agent: &AccountId,
    controller: &AccountId,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Option<Value>> {
    let controller = controller.clone();
    let provisions = sql_query(format!("SELECT p.realm_id,p.current_commit_id,p.current_stream_position,p.value,e.envelope,c.commit_json,NULL::text AS scope_set_digest,NULL::jsonb AS accountability_scope FROM agent_provisioning_current_results p JOIN pcr_genesis_units g ON g.realm_id=p.realm_id AND g.principal_id=$2 AND g.station_id=$3 LEFT JOIN realm_commits c ON c.commit_id=p.current_commit_id AND c.realm_id=p.realm_id AND c.stream_position=p.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE p.agent_id=$1{}", if lock { " FOR SHARE OF p" } else { "" }))
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller.station_id.as_str())
        .load::<OwnedCurrentSourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let [row] = provisions.as_slice() else {
        return Ok(None);
    };
    let (provision_event, provision_commit) = owned_current_source(row, at)?;
    let payload =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &provision_event,
        )
        .map_err(invalid)?;
    payload
        .validate_envelope(&provision_event)
        .map_err(invalid)?;
    if provision_event.actor_id.as_account_id() != Some(&controller)
        || payload
            .agent_account_id(&provision_event)
            .map_err(invalid)?
            != *agent
        || serde_json::to_value(payload.provisioning_value()).map_err(invalid)? != row.value
    {
        return Err(denied(
            "owned provisioning current differs from its accepted source",
        ));
    }
    let provision_pin =
        json!({"current":row.value,"event":provision_event,"commit":provision_commit});
    let controller_pcr = &provision_event.realm_id;
    require_owned_controller_source(
        conn,
        &provision_event,
        &provision_commit,
        &controller,
        controller_pcr,
        "own_pcr",
        None,
    )
    .await?;
    let provision = payload.provisioning_value();
    let provision_ref = arkret_wire::CommittedEventRef {
        event_id: provision_event.event_id,
        commit_id: provision_commit.commit_id,
        stream_ref: provision_commit.stream_ref,
        stream_position: provision_commit.stream_position,
    };
    if lock {
        crate::agent_current_results::lock_agent_producer_current(
            conn,
            &provision.principal_control_realm_id,
            &agent.principal_id,
        )
        .await?;
    }
    let status = sql_query(format!("SELECT s.realm_id,s.current_commit_id,s.current_stream_position,s.value,e.envelope,c.commit_json,NULL::text AS scope_set_digest,NULL::jsonb AS accountability_scope FROM agent_status_current_results s LEFT JOIN realm_commits c ON c.commit_id=s.current_commit_id AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE s.realm_id=$1 AND s.agent_id=$2 AND s.actor_id=$3 AND s.current_key=$4 AND NOT EXISTS(SELECT 1 FROM realm_commits newer JOIN canonical_events ne ON ne.pk=newer.event_pk AND ne.state='committed' WHERE newer.realm_id=s.realm_id AND newer.stream_ref=c.stream_ref AND newer.stream_position>s.current_stream_position AND ne.envelope->'actor_id'=s.actor_id AND ne.kind IN ('ak.self.agent.pause','ak.self.agent.resume','ak.self.agent.deactivate')){}",if lock { " FOR SHARE OF s" } else { "" }))
        .bind::<Text,_>(provision.principal_control_realm_id.as_str()).bind::<Text,_>(agent.principal_id.as_str())
        .bind::<Jsonb,_>(json!(ActorId::account(agent.clone())))
        .bind::<Text,_>(arkret_wire::derive_agent_status_current_key(&ActorId::account(agent.clone())).map_err(invalid)?)
        .get_result::<OwnedCurrentSourceRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    let Some(status) = status else {
        return Ok(None);
    };
    let (status_event, status_commit) = owned_current_source(&status, at)?;
    if status_event.actor_id.as_account_id() != Some(agent)
        || status_event
            .executed_by
            .as_ref()
            .and_then(ActorId::as_account_id)
            != Some(&controller)
        || status_event.authorization_ref.as_deref()
            != Some(provision.controller_authorization_ref.as_str())
    {
        return Err(denied("owned status source controller differs"));
    }
    let status_pin = json!({"current":status.value,"event":status_event,"commit":status_commit});
    let expected_status = match status_event.kind {
        EventKind::RealmCreate => {
            let body: arkret_models_collaboration::events_payloads::RealmCreatePayload =
                serde_json::from_value(json!(status_event.payload)).map_err(invalid)?;
            body.object.validate().map_err(invalid)?;
            if body.object.purpose
                != arkret_models_collaboration::events_payloads::realm::RealmPurpose::AgentControl
                || status_commit.stream_position != 0
                || status_event.realm_id != RealmId::from_event_id(&status_event.event_id)
            {
                return Err(denied(
                    "owned status source is not the Agent's accepted genesis",
                ));
            }
            "active"
        }
        EventKind::SelfAgentResume => {
            let body: arkret_models_collaboration::events_payloads::agent::AgentResumePayload =
                serde_json::from_value(json!(status_event.payload)).map_err(invalid)?;
            if body.transition != "resume" || body.previous_status != "paused" {
                return Err(denied("owned status resume source differs"));
            }
            "active"
        }
        EventKind::SelfAgentPause => "paused",
        EventKind::SelfAgentDeactivate => "deactivated",
        _ => return Err(denied("owned status has an unregistered source writer")),
    };
    if status.value != json!(expected_status) {
        return Err(denied(
            "owned status whole value differs from its accepted source",
        ));
    }
    require_owned_controller_source(
        conn,
        &status_event,
        &status_commit,
        &controller,
        controller_pcr,
        if status_event.kind == EventKind::RealmCreate {
            "agent_pcr_genesis"
        } else {
            "agent_pcr_controller"
        },
        Some(&provision_ref),
    )
    .await?;
    if expected_status != "active" {
        return Ok(None);
    }
    let rows = sql_query(format!("SELECT a.realm_id,a.current_commit_id,a.current_stream_position,a.value,e.envelope,c.commit_json,a.scope_set_digest,a.accountability_scope FROM identity_accountability_current_results a LEFT JOIN realm_commits c ON c.commit_id=a.current_commit_id AND c.realm_id=a.realm_id AND c.stream_position=a.current_stream_position LEFT JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE a.subject_id=$1 AND a.issuer_id=$2 AND a.realm_id=$3 ORDER BY a.realm_id,a.scope_set_digest{}", if lock { " FOR SHARE OF a" } else { "" }))
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(controller_pcr.as_str())
        .load::<OwnedCurrentSourceRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let mut accountable = false;
    let mut accountability_pins = Vec::new();
    for row in rows {
        let (source, commit) = owned_current_source(&row, at)?;
        if source.actor_id.as_account_id() != Some(&controller) {
            return Err(denied(
                "owned accountability source has another full controller",
            ));
        }
        let projected = match source.kind {
            EventKind::AgentProvision => {
                let body=arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(&source).map_err(invalid)?;
                body.validate_envelope(&source).map_err(invalid)?;
                arkret_models_collaboration::governance::accountability::AccountabilityProjection::from_provision(&body,source.created_at).map_err(invalid)?
            }
            EventKind::IdentityAccountabilityGrant => {
                let body:arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload=serde_json::from_value(json!(source.payload)).map_err(invalid)?;
                arkret_models_collaboration::governance::accountability::AccountabilityProjection::from_grant(&body).map_err(invalid)?
            }
            _ => {
                return Err(denied(
                    "owned accountability has an unregistered source writer",
                ));
            }
        };
        if row.scope_set_digest.as_deref()
            != Some(
                projected
                    .accountability_scope
                    .digest()
                    .map_err(invalid)?
                    .as_str(),
            )
            || row.accountability_scope.as_ref() != Some(&json!(projected.accountability_scope))
        {
            return Err(denied("owned accountability normalized scope key differs"));
        }
        if projected.issuer_id != controller.principal_id
            || projected.subject_id != agent.principal_id
            || serde_json::to_value(&projected).map_err(invalid)? != row.value
        {
            return Err(denied(
                "owned accountability whole value differs from its accepted source",
            ));
        }
        require_owned_controller_source(
            conn,
            &source,
            &commit,
            &controller,
            controller_pcr,
            "own_pcr",
            None,
        )
        .await?;
        #[derive(QueryableByName)]
        struct LaterAccountability {
            #[diesel(sql_type=Jsonb)]
            envelope: Value,
        }
        let later=sql_query("SELECT e.envelope FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk AND e.state='committed' WHERE c.realm_id=$1 AND c.stream_ref=$2 AND c.stream_position>$3 AND e.kind='ak.identity.accountability_grant' AND e.envelope->'payload'->>'issuer_id'=$4 AND e.envelope->'payload'->>'subject_id'=$5")
            .bind::<Text,_>(controller_pcr.as_str()).bind::<Jsonb,_>(json!(commit.stream_ref))
            .bind::<BigInt,_>(i64::try_from(commit.stream_position).map_err(invalid)?)
            .bind::<Text,_>(controller.principal_id.as_str()).bind::<Text,_>(agent.principal_id.as_str())
            .load::<LaterAccountability>(&mut *conn).await.map_err(PersistenceError::database)?;
        for later in later {
            let event: Event = serde_json::from_value(later.envelope).map_err(invalid)?;
            let body:arkret_models_collaboration::governance::accountability::AccountabilityGrantPayload=serde_json::from_value(json!(event.payload)).map_err(invalid)?;
            let newer=arkret_models_collaboration::governance::accountability::AccountabilityProjection::from_grant(&body).map_err(invalid)?;
            if newer.accountability_scope == projected.accountability_scope {
                return Err(denied(
                    "owned accountability current misses a later accepted writer",
                ));
            }
        }
        accountability_pins.push(json!({"value":projected,"event":source,"commit":commit,"scope_set_digest":row.scope_set_digest}));
        accountable |= projected.verifies_at(at)
            && projected
                .accountability_scope
                .scopes()
                .contains(&arkret_wire::AccountabilityScopeKind::AgentOperator);
    }
    if !accountable {
        return Ok(None);
    }
    let mut ownership = json!({"controller":controller,"agent":agent,"provision":provision_pin,"status":status_pin,"accountability":accountability_pins});
    let bootstrap =
        owned_bootstrap_in_connection(conn, agent, &controller, &ownership, at, lock).await?;
    ownership["bootstrap"] = bootstrap;
    Ok(Some(ownership))
}

/// Active status and complete DID binding are independent prerequisites. This
/// local Station path holds the original document row across the review unit;
/// absent local native history cannot be replaced by an Agent service row.
pub(crate) async fn owned_bootstrap_in_connection(
    conn: &mut AsyncPgConnection,
    agent: &AccountId,
    controller: &AccountId,
    ownership: &Value,
    at: chrono::DateTime<chrono::Utc>,
    lock: bool,
) -> PersistenceResult<Value> {
    let provision_event: Event =
        serde_json::from_value(ownership["provision"]["event"].clone()).map_err(invalid)?;
    let provision_commit: RealmCommit =
        serde_json::from_value(ownership["provision"]["commit"].clone()).map_err(invalid)?;
    let provision =
        arkret_models_collaboration::events_payloads::agent::AgentProvisionPayload::try_from(
            &provision_event,
        )
        .map_err(invalid)?;
    #[derive(QueryableByName)]
    struct GenesisRow {
        #[diesel(sql_type=Jsonb)]
        envelope: Value,
        #[diesel(sql_type=Jsonb)]
        commit_json: Value,
    }
    let genesis = sql_query(format!("SELECT e.envelope,c.commit_json FROM principal_resolutions r JOIN canonical_events e ON e.envelope->>'event_id'=r.genesis_event_id AND e.realm_id=r.pcr_realm_id AND e.state='committed' JOIN realm_commits c ON c.event_pk=e.pk AND c.realm_id=r.pcr_realm_id WHERE r.principal_id=$1 AND r.station_id=$2 AND r.pcr_realm_id=$3{}", if lock { " FOR SHARE OF r" } else { "" }))
        .bind::<Text,_>(agent.principal_id.as_str()).bind::<Text,_>(agent.station_id.as_str())
        .bind::<Text,_>(provision.principal_control_realm_id.as_str())
        .get_result::<GenesisRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| precondition("Agent accepted PCR genesis is unavailable"))?;
    let genesis_event: Event = serde_json::from_value(genesis.envelope).map_err(invalid)?;
    let genesis_commit: RealmCommit =
        serde_json::from_value(genesis.commit_json).map_err(invalid)?;
    let create = genesis_event.as_realm_create().map_err(invalid)?.object;
    let initial = create
        .initial_resolution
        .as_ref()
        .ok_or_else(|| precondition("Agent accepted genesis inception is unavailable"))?;
    if genesis_event.kind != EventKind::RealmCreate
        || genesis_event.actor_id.as_account_id() != Some(agent)
        || genesis_event
            .executed_by
            .as_ref()
            .and_then(ActorId::as_account_id)
            != Some(controller)
        || genesis_event.authorization_ref.as_deref()
            != Some(provision.controller_authorization_ref.as_str())
        || genesis_event.realm_id != provision.principal_control_realm_id
        || genesis_event.scope_ref != ScopeRef::RealmGenesis
        || genesis_commit.event_ref != genesis_event.event_id
        || genesis_commit.realm_id != genesis_event.realm_id
        || genesis_commit.stream_position != 0
        || genesis_commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: genesis_event.realm_id.clone(),
            })
        || genesis_commit.previous_commit_ref.is_some()
        || genesis_commit.committed_at > at
        || provision_commit.committed_at > genesis_commit.committed_at
        || create.purpose
            != arkret_models_collaboration::events_payloads::realm::RealmPurpose::AgentControl
        || create.governance_station_id != agent.station_id
        || arkret_wire::project_did_to_core_id(&initial.did).map_err(invalid)? != agent.principal_id
    {
        return Err(denied(
            "Agent bootstrap differs from its accepted full Account and controller",
        ));
    }
    genesis_event
        .verify_event_id_matches_content_with_digest_suite(
            genesis_event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(invalid)?;
    genesis_commit
        .verify_commit_id_matches_content()
        .map_err(invalid)?;
    let provision_ref = arkret_wire::CommittedEventRef {
        event_id: provision_event.event_id.clone(),
        commit_id: provision_commit.commit_id.clone(),
        stream_ref: provision_commit.stream_ref.clone(),
        stream_position: provision_commit.stream_position,
    };
    require_owned_controller_source(
        conn,
        &genesis_event,
        &genesis_commit,
        controller,
        &provision_event.realm_id,
        "agent_pcr_genesis",
        Some(&provision_ref),
    )
    .await?;
    #[derive(QueryableByName)]
    struct DocumentRow {
        #[diesel(sql_type=Text)]
        did: String,
        #[diesel(sql_type=Jsonb)]
        did_document: Value,
        #[diesel(sql_type=diesel::sql_types::Nullable<Text>)]
        key_log_head: Option<String>,
        #[diesel(sql_type=BigInt)]
        seq: i64,
    }
    #[derive(QueryableByName)]
    struct LogRow {
        #[diesel(sql_type=Text)]
        id: String,
        #[diesel(sql_type=BigInt)]
        seq: i64,
        #[diesel(sql_type=Jsonb)]
        operation: Value,
    }
    // The normal WebVH writer locks this same document before appending a log.
    // Keep that lock until the review/commit transaction completes, so a new
    // head cannot race immutable pins with the current qualification check.
    let document = sql_query(format!("SELECT id AS did,did_document,key_log_head,seq FROM webvh_documents WHERE id=$1 OR (id LIKE 'did:webvh:%' AND split_part(id,':',3)=split_part($1,':',3)) ORDER BY seq DESC LIMIT 1{}", if lock { " FOR SHARE" } else { "" }))
        .bind::<Text,_>(initial.did.as_str()).get_result::<DocumentRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("revision_unavailable: Agent complete native DID binding is unavailable".into()))?;
    let logs = sql_query("SELECT id,seq,operation FROM webvh_log_events WHERE did=$1 OR (did LIKE 'did:webvh:%' AND split_part(did,':',3)=split_part($1,':',3)) ORDER BY seq,id")
        .bind::<Text,_>(initial.did.as_str()).load::<LogRow>(&mut *conn).await.map_err(PersistenceError::database)?;
    let head = logs
        .last()
        .ok_or_else(|| precondition("Agent complete native DID history is unavailable"))?;
    if logs.iter().enumerate().any(|(i, row)| {
        row.seq != i as i64 + 1
            || arkret_canonical::canonical_sha256(&row.operation)
                .ok()
                .as_deref()
                != Some(row.id.as_str())
    }) || document.seq != head.seq
        || document.key_log_head.as_deref() != Some(head.id.as_str())
        || document.did_document != head.operation["state"]
    {
        return Err(denied(
            "Agent native document and accepted log head are inconsistent",
        ));
    }
    let current_did = arkret_wire::Did::new(document.did).map_err(invalid)?;
    let entries = logs
        .iter()
        .map(|row| row.operation.clone())
        .collect::<Vec<_>>();
    let history =
        arkret_identity::verify_did_webvh_v1_chain(&current_did, &entries).map_err(invalid)?;
    if history
        .entries
        .last()
        .is_some_and(|head| head.version_time > at)
    {
        return Err(precondition(
            "Agent current native head is not effective at the review cut",
        ));
    }
    validate_owned_bootstrap_history(
        &history,
        initial,
        controller,
        &provision.principal_control_realm_id,
        &provision.controller_authorization_ref,
        &provision.requested_scope_digest,
        genesis_commit.committed_at,
        at,
    )?;
    Ok(
        json!({"genesis_event":genesis_event,"genesis_commit":genesis_commit,"initial_resolution":initial,"binding":entries[1],"current_did":current_did,"current_head":head.id,"current_document":document.did_document}),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bootstrap verification binds independent controller, inception, authorization, scope and time evidence."
)]
fn validate_owned_bootstrap_history(
    history: &arkret_identity::VerifiedDidWebvhLog,
    initial: &arkret_models_identity::ResolutionCommitment,
    controller: &AccountId,
    pcr: &RealmId,
    authorization: &arkret_wire::DidUrl,
    requested_scope_digest: &arkret_wire::Hash,
    genesis_accepted_at: chrono::DateTime<chrono::Utc>,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let inception = history
        .entries
        .as_slice()
        .first()
        .ok_or_else(|| precondition("Agent native inception is unavailable"))?;
    if history.entries.len() != history.raw_entries.len()
        || history.entries.len() < 2
        || inception.version_id != initial.version_id
        || !inception.version_id.starts_with("1-")
        || arkret_canonical::canonical_sha256(&history.raw_entries[0]).map_err(invalid)?
            != initial.method_history_head
        || inception.version_time > genesis_accepted_at
        || arkret_wire::project_did_to_core_id(&initial.did).map_err(invalid)?
            != arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new(
                    history.entries.last().unwrap().state["id"]
                        .as_str()
                        .ok_or_else(|| invalid("Agent native state omits DID"))?
                        .to_owned(),
                )
                .map_err(invalid)?,
            )
            .map_err(invalid)?
    {
        return Err(precondition(
            "Agent accepted PCR inception does not match complete native history",
        ));
    }
    let validate_document = |document: &Value, bound: bool| -> PersistenceResult<()> {
        let did = arkret_wire::Did::new(
            document["id"]
                .as_str()
                .ok_or_else(|| invalid("Agent native document has no DID"))?
                .to_owned(),
        )
        .map_err(invalid)?;
        arkret_signatures::webvh::validate_agent_did_document_profile(did.as_str(), document, &[])
            .map_err(invalid)?;
        let services = document
            .get("service")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Agent native services are missing"))?;
        if services.len() != if bound { 3 } else { 2 }
            || services[1]["id"] != json!(format!("{}#managed-controller", did.as_str()))
            || services[1]
                .pointer("/serviceEndpoint/controller_did")
                .and_then(Value::as_str)
                != Some(controller.principal_id.as_str())
        {
            return Err(denied(
                "Agent native controller delegation differs from the full accepted controller",
            ));
        }
        if bound {
            let binding = &services[2];
            if binding["id"] != json!(format!("{}#arkret-principal-control-realm", did.as_str()))
                || binding["type"] != "ArkretPrincipalControlRealm"
                || binding
                    .pointer("/serviceEndpoint/realm_id")
                    .and_then(Value::as_str)
                    != Some(pcr.as_str())
                || binding
                    .pointer("/serviceEndpoint/controller_did")
                    .and_then(Value::as_str)
                    != Some(controller.principal_id.as_str())
                || binding
                    .pointer("/serviceEndpoint/authorization_ref")
                    .and_then(Value::as_str)
                    != Some(authorization.as_str())
                || binding
                    .pointer("/serviceEndpoint/requested_scope_digest")
                    .and_then(Value::as_str)
                    != Some(requested_scope_digest.as_str())
                || binding
                    .pointer("/serviceEndpoint/requested_scope")
                    .is_some()
            {
                return Err(denied(
                    "Agent native binding changed its create-locked authorization tuple",
                ));
            }
        }
        Ok(())
    };
    validate_document(&inception.state, false)?;
    let binding = &history.entries[1];
    if !binding.version_id.starts_with("2-")
        || binding.version_time < genesis_accepted_at
        || binding.version_time > at
    {
        return Err(precondition(
            "Agent complete DID binding was not accepted at the review cut",
        ));
    }
    for entry in history
        .entries
        .iter()
        .filter(|entry| entry.version_time <= at)
    {
        if entry.parameters.get("deactivated").and_then(Value::as_bool) == Some(true) {
            return Err(denied("Agent native DID is deactivated at the review cut"));
        }
    }
    for entry in history
        .entries
        .iter()
        .skip(1)
        .filter(|entry| entry.version_time <= at)
    {
        validate_document(&entry.state, true)?;
    }
    Ok(())
}

pub(crate) async fn read_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
) -> PersistenceResult<Option<ModeRow>> {
    let key = arkret_wire::derive_agent_interaction_current_key(agent).map_err(invalid)?;
    // A projection cannot establish an already-public transition by itself.
    // Bind the whole value to the last accepted mode Event for this account.
    sql_query("SELECT r.current_commit_id,r.current_stream_position,r.value FROM agent_interaction_current_results r JOIN realm_commits c ON c.realm_id=r.realm_id AND c.commit_id=r.current_commit_id AND c.stream_position=r.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk AND e.realm_id=c.realm_id AND e.state='committed' AND e.kind='ak.agent.interaction.set' WHERE r.realm_id=$1 AND r.current_key=$2 AND r.agent_account_id=$3 AND c.stream_ref=jsonb_build_object('kind','realm','realm_id',$1) AND e.scope_ref=c.stream_ref AND e.envelope->'payload'->'agent_account_id'=$3 AND r.value=jsonb_build_object('controller_account_id',e.envelope->'payload'->'controller_account_id','interaction_mode',e.envelope->'payload'->'interaction_mode') AND NOT EXISTS(SELECT 1 FROM realm_commits newer JOIN canonical_events ne ON ne.pk=newer.event_pk AND ne.realm_id=newer.realm_id AND ne.state='committed' AND ne.kind='ak.agent.interaction.set' WHERE newer.realm_id=$1 AND newer.stream_ref=c.stream_ref AND newer.stream_position>c.stream_position AND ne.envelope->'payload'->'agent_account_id'=$3)")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(key).bind::<Jsonb,_>(json!(agent)).get_result(&mut *conn).await.optional().map_err(PersistenceError::database)
}

pub(crate) async fn known_never_written(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    head_position: u64,
) -> PersistenceResult<bool> {
    // A prefix with an unheld genesis or a gap cannot prove absence.
    let complete = sql_query("SELECT (COUNT(DISTINCT stream_position)=$2+1 AND MIN(stream_position)=0 AND MAX(stream_position)=$2) AS present FROM realm_commits WHERE realm_id=$1 AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1)")
        .bind::<Text,_>(realm.as_str()).bind::<BigInt,_>(i64::try_from(head_position).map_err(invalid)?)
        .get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if !complete {
        return Ok(false);
    }
    Ok(!sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events WHERE realm_id=$1 AND kind='ak.agent.interaction.set' AND state='committed' AND envelope->'payload'->'agent_account_id'=$2) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(json!(agent)).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present)
}

pub(crate) async fn admit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    review: Option<&crate::agent_management_review::ReviewAdmission>,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentInteractionSet {
        return Ok(());
    }
    let payload: AgentInteractionSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
    if event.actor_id.as_account_id() != Some(&payload.controller_account_id)
        || event.executed_by.is_some()
        || event.applet_id.is_some()
        || event.producer_proof.is_none()
        || event.scope_ref
            != (ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(denied(
            "Agent mode requires the exact controller device author",
        ));
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    if controller_in_connection(
        conn,
        &event.realm_id,
        &payload.agent_account_id,
        commit.committed_at,
    )
    .await?
    .as_ref()
        != Some(&payload.controller_account_id)
    {
        return Err(denied(
            "Agent ownership or member generation is not current",
        ));
    }
    let prior = read_in_connection(conn, &event.realm_id, &payload.agent_account_id).await?;
    if prior.is_none()
        && !known_never_written(
            conn,
            &event.realm_id,
            &payload.agent_account_id,
            commit
                .stream_position
                .checked_sub(1)
                .ok_or_else(|| precondition("Agent mode needs an established Realm prefix"))?,
        )
        .await?
    {
        return Err(PersistenceError::Conflict(
            "revision_unavailable: Agent mode absence is not confirmed".into(),
        ));
    }
    let current = prior
        .as_ref()
        .map(|row| -> PersistenceResult<CurrentRevision> {
            Ok(CurrentRevision {
                commit_id: row.current_commit_id.parse().map_err(invalid)?,
                stream_position: u64::try_from(row.current_stream_position).map_err(invalid)?,
            })
        })
        .transpose()?;
    if current != payload.expected_revision {
        return Err(precondition(
            "Agent mode expected_revision differs from current",
        ));
    }
    if payload.interaction_mode == AgentInteractionMode::Public {
        let already_public = prior
            .as_ref()
            .map(|row| serde_json::from_value::<AgentInteractionCurrentValue>(row.value.clone()))
            .transpose()
            .map_err(invalid)?
            .is_some_and(|value| {
                value.controller_account_id == payload.controller_account_id
                    && value.interaction_mode == AgentInteractionMode::Public
            });
        if !already_public {
            crate::agent_management_admission::require_publish_in_connection(
                conn,
                &event.realm_id,
                &payload.controller_account_id,
                &payload.agent_account_id,
                commit.committed_at,
                event,
                review,
            )
            .await?;
        }
    }
    Ok(())
}

/// Install only a committed value; shared by authority writes and verified replicas.
pub(crate) async fn install_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    revision: &CurrentRevision,
    value: &AgentInteractionCurrentValue,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let key = arkret_wire::derive_agent_interaction_current_key(agent).map_err(invalid)?;
    sql_query("INSERT INTO agent_interaction_current_results (realm_id,current_key,agent_account_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,current_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(key).bind::<Jsonb,_>(json!(agent)).bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(invalid)?).bind::<Jsonb,_>(json!(value)).bind::<Timestamptz,_>(at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    Ok(())
}
pub(crate) async fn project_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::AgentInteractionSet {
        return Ok(());
    }
    let payload: AgentInteractionSetPayload =
        serde_json::from_value(json!(&event.payload)).map_err(invalid)?;
    install_in_connection(
        conn,
        &event.realm_id,
        &payload.agent_account_id,
        &CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        &AgentInteractionCurrentValue {
            controller_account_id: payload.controller_account_id,
            interaction_mode: payload.interaction_mode,
        },
        commit.committed_at,
    )
    .await
}

/// Public collaboration output is classified from the signed Event, never
/// from a selector that may have fallen back from a private Sidecar to Realm.
pub(crate) fn requires_shared_public_mode(event: &Event) -> bool {
    if !matches!(
        event.scope_ref,
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
    ) {
        return false;
    }
    if matches!(event.kind, EventKind::MlsGenesis | EventKind::MlsCommit)
        || (matches!(
            event.kind,
            EventKind::StrandWatchSet | EventKind::ReadCursorAdvance
        ) && event.executed_by.is_none())
    {
        return false;
    }
    if event.kind == EventKind::MemberState
        && event.executed_by.is_none()
        && serde_json::to_value(&event.payload)
            .ok()
            .and_then(|p| p.get("member_id").cloned())
            == Some(json!(event.actor_id))
    {
        return false;
    }
    true
}

/// The caller already holds the exact current ownership and Realm cut.
pub(crate) async fn require_current_public_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    controller: &AccountId,
    agent: &AccountId,
) -> PersistenceResult<()> {
    let Some(row) = Box::pin(read_in_connection(conn, realm, agent)).await? else {
        return Err(denied("shared Agent authority is unavailable"));
    };
    let value: AgentInteractionCurrentValue = serde_json::from_value(row.value).map_err(invalid)?;
    if value.controller_account_id != *controller
        || value.interaction_mode != AgentInteractionMode::Public
    {
        return Err(denied("shared Agent authority is unavailable"));
    }
    Ok(())
}

/// Public mode is necessary on ordinary shared writes, including delegated writers.
pub(crate) async fn require_shared_producer_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if !requires_shared_public_mode(event) {
        return Ok(());
    }
    crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id).await?;
    // PCR governance is independent of collaboration mode.
    let governance = sql_query("SELECT EXISTS(SELECT 1 FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_genesis' AND value->>'purpose' IN ('principal_control','agent_control')) AS present")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<PresentRow>(&mut *conn).await.map_err(PersistenceError::database)?.present;
    if governance {
        return Ok(());
    }
    for actor in std::iter::once(&event.actor_id).chain(event.executed_by.iter()) {
        let Some(agent) = actor.as_account_id() else {
            continue;
        };
        let is_agent =
            sql_query("SELECT (EXISTS(SELECT 1 FROM agent_principals WHERE id=$1) OR EXISTS(SELECT 1 FROM member_state_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id JOIN canonical_events e ON e.pk=c.event_pk WHERE m.realm_id=$2 AND m.member_id=$3 AND e.envelope->'payload' ? 'agent_controller_binding')) AS present")
                .bind::<Text, _>(agent.principal_id.as_str())
                .bind::<Text, _>(event.realm_id.as_str())
                .bind::<Text, _>(actor.to_string())
                .get_result::<PresentRow>(&mut *conn)
                .await
                .map_err(PersistenceError::database)?
                .present;
        if !is_agent {
            continue;
        }
        // An independent owner Direct remains private and does not read group mode.
        let direct = sql_query("SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1 FOR SHARE")
            .bind::<Text,_>(event.realm_id.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
        if let Some(direct) = direct {
            let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue = serde_json::from_value(direct.value).map_err(invalid)?;
            value.binding.validate_shape().map_err(invalid)?;
            if value.binding.unordered_participant_ids.iter().any(|a| a.as_account_id() == Some(agent)) && value.binding.authorization_basis.kind == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController { continue; }
        }
        let Some(controller) =
            controller_in_connection(conn, &event.realm_id, agent, commit.committed_at).await?
        else {
            return Err(denied("shared Agent authority is unavailable"));
        };
        require_current_public_in_connection(conn, &event.realm_id, &controller, agent).await?;
    }
    Ok(())
}

/// Read the agreed owner Direct binding without consulting group mode.
pub(crate) async fn owner_direct_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &RealmId,
    agent: &AccountId,
    controller: &AccountId,
) -> PersistenceResult<bool> {
    let row = sql_query(
        "SELECT value FROM direct_conversation_binding_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<ValueRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue = serde_json::from_value(row.value).map_err(invalid)?;
    value.binding.validate_shape().map_err(invalid)?;
    Ok({
        value.binding.authorization_basis.kind == arkret_models_collaboration::objects::direct_conversation::DirectConversationAuthorizationKind::AgentController
        && value.binding.unordered_participant_ids.len() == 2
        && value.binding.unordered_participant_ids.contains(&ActorId::account(agent.clone()))
        && value.binding.unordered_participant_ids.contains(&ActorId::account(controller.clone()))
    })
}

#[cfg(test)]
mod owned_review_bootstrap_tests {
    use super::*;
    fn material(
        binding_digest: &arkret_wire::Hash,
    ) -> (
        arkret_identity::VerifiedDidWebvhLog,
        arkret_models_identity::ResolutionCommitment,
        AccountId,
        RealmId,
        arkret_wire::DidUrl,
        chrono::DateTime<chrono::Utc>,
    ) {
        let at = "2026-10-01T00:00:00.000Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap();
        let controller: AccountId = serde_json::from_value(json!({
            "principal_id":"ak:did_core:webvh:z6mkfixturecontroller",
            "station_id":"ak:did_core:webvh:z6mkfixturestation"
        }))
        .unwrap();
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[102; 32])
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &"https://review-agent.example/".parse().unwrap(),
                local_id: "review-agent",
                controller_principal_id: &controller.principal_id,
                version_time: at,
                root_seed: &[101; 32],
                next_root_public_key_multibase: &next,
            },
        )
        .unwrap();
        let pcr = RealmId::new("ak:realm:AT47eNekH0_aKZyIMsXq_s1FAWdYXC71_CUxQ5O478t-".to_owned())
            .unwrap();
        let initial = arkret_models_identity::ResolutionCommitment {
            did: arkret_wire::Did::new(inception.did.clone()).unwrap(),
            version_id: inception.version_id.clone(),
            method_history_head: arkret_canonical::canonical_sha256(&inception.log_entry).unwrap(),
        };
        let authorization =
            arkret_wire::DidUrl::new(format!("{}#managed-controller", inception.did)).unwrap();
        let next = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[103; 32])
                .verifying_key()
                .as_bytes(),
        );
        let update = arkret_signatures::webvh::prepare_agent_binding_update(
            &arkret_signatures::webvh::AgentBindingUpdateInput {
                did: &inception.did,
                local_id: &inception.local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: at + chrono::TimeDelta::seconds(1),
                current_root_seed: &[102; 32],
                next_root_public_key_multibase: &next,
                controller_principal_id: &controller.principal_id,
                principal_control_realm_id: &pcr,
                requested_scope_digest: binding_digest,
            },
        )
        .unwrap();
        let history = arkret_identity::verify_did_webvh_v1_chain(
            &initial.did,
            &[inception.log_entry, update.log_entry],
        )
        .unwrap();
        (history, initial, controller, pcr, authorization, at)
    }
    #[test]
    fn management_review_requires_binding_independently_of_active_genesis() {
        let digest = arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let (history, initial, controller, pcr, authorization, at) = material(&digest);
        assert!(
            validate_owned_bootstrap_history(
                &history,
                &initial,
                &controller,
                &pcr,
                &authorization,
                &digest,
                at,
                at + chrono::TimeDelta::seconds(1)
            )
            .is_ok()
        );
        let mut inception_only = history.clone();
        inception_only.entries.truncate(1);
        inception_only.raw_entries.truncate(1);
        assert!(
            validate_owned_bootstrap_history(
                &inception_only,
                &initial,
                &controller,
                &pcr,
                &authorization,
                &digest,
                at,
                at + chrono::TimeDelta::seconds(1)
            )
            .is_err()
        );
        assert!(
            validate_owned_bootstrap_history(
                &history,
                &initial,
                &controller,
                &pcr,
                &authorization,
                &digest,
                at,
                at
            )
            .is_err()
        );
    }
    #[test]
    fn management_review_rejects_validly_signed_other_scope_binding() {
        let signed = arkret_wire::Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let expected = arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let (history, initial, controller, pcr, authorization, at) = material(&signed);
        assert!(
            validate_owned_bootstrap_history(
                &history,
                &initial,
                &controller,
                &pcr,
                &authorization,
                &expected,
                at,
                at + chrono::TimeDelta::seconds(1)
            )
            .is_err()
        );
    }
    #[test]
    fn management_review_pins_original_inception_and_pcr() {
        let digest = arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let (history, mut initial, controller, pcr, authorization, at) = material(&digest);
        initial.method_history_head = format!("sha256:{}", "0".repeat(64));
        assert!(
            validate_owned_bootstrap_history(
                &history,
                &initial,
                &controller,
                &pcr,
                &authorization,
                &digest,
                at,
                at + chrono::TimeDelta::seconds(1)
            )
            .is_err()
        );
    }
}
