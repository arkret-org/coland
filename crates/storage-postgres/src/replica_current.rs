//! Typed current a member Station keeps for a Realm stream it holds as a
//! replica of a Realm another Station governs (`federation.md` §4.1.1,
//! member Station bootstrap).
//!
//! The governing Station's verified bootstrap snapshot is installed once,
//! anchored at its head; every later replica then advances the same result
//! families with the registered result each committed Event derives. A
//! member Station never admits: the governing Station's RealmCommit is the
//! accepted judgement, so these writers carry no capability, CAS or
//! lifecycle gate, only the projection of the committed Event.
//!
//! The member Station keeps the families its recipient re-verification and
//! local reads consume: the Realm singletons (history access, plaintext
//! services, profile), the policy bundle, `member_state`, `strand`, the three
//! Space families, the default Strand pointer, `message_revision`,
//! `object_redaction` and `message_reactions`. The
//! authority root, capability grants, Invite registers and MLS group state
//! are governing admission inputs whose rows hold Station-private material a
//! snapshot row does not carry (the authority Event ref, the accepting
//! Event id, the public RFC 9420 tracker); a member Station keeps none of
//! them and never reads them.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

/// Every table a member Station projects a replica Realm into.
const MEMBER_STATION_FAMILIES: &[&str] = &[
    "space_parent_current_results",
    "space_child_scope_policy_current_results",
    "space_current_results",
    "realm_bootstrap_current_results",
    "scope_read_receipt_policy_current_results",
    "realm_policy_bundle_current_results",
    "realm_link_current_results",
    "member_state_current_results",
    "strand_current_results",
    "strand_position_current_results",
    "strand_watch_current_results",
    "agent_interaction_current_results",
    "direct_conversation_binding_current_results",
    "rsvp_current_results",
    "realm_set_default_strand_current_results",
    "message_revision_current_results",
    "object_redaction_current_results",
    "message_reactions_current_results",
    "sidecar_exchange_controls_current_results",
    "pin_current_results",
    "schema_definition_current_results",
    "circle_member_state_current_results",
    "circle_current_results",
    "call_state_current_results",
    "call_component_current_results",
    "realm_media_service_current_results",
    "moderation_report_current_results",
    "moderation_state_current_results",
    "moderation_franking_proof_current_results",
];

fn position(value: u64) -> PersistenceResult<i64> {
    i64::try_from(value).map_err(|_| {
        PersistenceError::SchemaViolation("stream position exceeds PostgreSQL BIGINT".to_owned())
    })
}

fn malformed(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::SchemaViolation(format!("bootstrap snapshot row is malformed: {detail}"))
}

struct Revision<'a> {
    commit_id: &'a str,
    stream_position: i64,
    updated_at: chrono::DateTime<chrono::Utc>,
}

async fn upsert_singleton(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    family: &str,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position<EXCLUDED.current_stream_position \
           OR (realm_bootstrap_current_results.current_stream_position=EXCLUDED.current_stream_position \
             AND realm_bootstrap_current_results.current_commit_id=EXCLUDED.current_commit_id \
             AND realm_bootstrap_current_results.value=EXCLUDED.value)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    require_one_current_write(changed)
}

fn require_one_current_write(changed: usize) -> PersistenceResult<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(PersistenceError::Conflict(
            "failed_precondition: replica current belongs to another Realm, a later revision or a different value at this revision".to_owned(),
        ))
    }
}

#[derive(diesel::QueryableByName)]
struct ExistingCircleCurrent {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    create_event_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ExistingCircleMemberCurrent {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ExistingFrankingProofCurrent {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    source_stream_ref: Value,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct ExistingTerminalCurrent {
    #[diesel(sql_type = Text)]
    current_commit_id: String,
    #[diesel(sql_type = BigInt)]
    current_stream_position: i64,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// Snapshot replacement removes rows from the old disclosed source before
/// inserting the new subset. Check retained selectors while their old rows
/// are still locked, so that replacement cannot hide a revision fork.
async fn guard_snapshot_revisions(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    entries: &[arkret_wire::TypedCurrentRow],
) -> PersistenceResult<()> {
    use arkret_wire::CurrentSelector as S;
    let terminal = diesel::sql_query(
        "SELECT current_commit_id,current_stream_position,value \
         FROM realm_bootstrap_current_results \
         WHERE realm_id=$1 AND result_family='realm_tombstone' FOR UPDATE",
    )
    .bind::<Text, _>(realm_id.as_str())
    .get_result::<ExistingTerminalCurrent>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?;
    if let Some(terminal) = terminal {
        let retained = entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentRow::Value {
                selector: S::RealmTombstone, source_stream_ref, revision, value,
            } if source_stream_ref == &arkret_wire::CommitStreamRef::Realm {realm_id: realm_id.clone()}
                && revision.commit_id.as_str() == terminal.current_commit_id
                && position(revision.stream_position).ok() == Some(terminal.current_stream_position)
                && value == &terminal.value
        ));
        if !retained {
            return Err(PersistenceError::Conflict(
                "failed_precondition: snapshot cannot remove or rewrite the terminal fence"
                    .to_owned(),
            ));
        }
    }
    for entry in entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        let source = serde_json::to_value(source_stream_ref).map_err(malformed)?;
        let incoming_position = position(revision.stream_position)?;
        match selector {
            S::Policy { policy_id } => {
                crate::policy_current_results::validate_disclosed_shared_policy(
                    realm_id,
                    policy_id,
                    source_stream_ref,
                    value,
                )?;
                let old = diesel::sql_query("SELECT current_commit_id,current_stream_position,source_stream_ref,value FROM replica_authorization_rows WHERE realm_id=$1 AND selector=$2 FOR UPDATE")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(selector).map_err(malformed)?)
                    .get_result::<ExistingFrankingProofCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if old.is_some_and(|old| {
                    old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                }) {
                    return Err(malformed(
                        "shared Policy snapshot revision, source or value conflicts",
                    ));
                }
            }
            S::AgentInteraction { agent_account_id } => {
                let key = arkret_wire::derive_agent_interaction_current_key(agent_account_id)
                    .map_err(malformed)?;
                let old = diesel::sql_query("SELECT current_commit_id,current_stream_position,value FROM agent_interaction_current_results WHERE realm_id=$1 AND current_key=$2")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(key)
                    .get_result::<crate::agent_interaction_current_results::ModeRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if old.is_some_and(|old| {
                    old.current_stream_position > incoming_position
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                }) {
                    return Err(PersistenceError::Conflict(
                        "failed_precondition: Agent interaction snapshot is stale or conflicting"
                            .into(),
                    ));
                }
            }
            S::DirectConversationBinding { .. } => {
                crate::direct_conversation_admission::guard_binding_snapshot_in_connection(
                    conn, realm_id, entry,
                )
                .await?;
            }
            S::CallFocus { call_id }
            | S::CallRoster { call_id }
            | S::CallModeration { call_id } => {
                let old=diesel::sql_query("SELECT current_commit_id,current_stream_position,source_stream_ref,value FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector=$3 FOR UPDATE")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(call_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(selector).map_err(malformed)?)
                    .get_result::<ExistingFrankingProofCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(old) = old {
                    let retained = match selector {
                        S::CallFocus { .. } => true,
                        _ => old
                            .value
                            .get("assertions")
                            .and_then(Value::as_array)
                            .is_some_and(|a| {
                                value
                                    .get("assertions")
                                    .and_then(Value::as_array)
                                    .is_some_and(|new| a.iter().all(|item| new.contains(item)))
                            }),
                    };
                    if old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || !retained
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                    {
                        return Err(malformed(
                            "Call snapshot regresses its source, revision or retained assertions",
                        ));
                    }
                }
            }
            S::AgentSidecarExchangeControls {
                sidecar_id,
                source_context_ref,
            } => {
                use arkret_models_collaboration::agent_sidecar::AgentSidecarExchangeControlsCurrentValue;
                let incoming: AgentSidecarExchangeControlsCurrentValue =
                    serde_json::from_value(value.clone()).map_err(malformed)?;
                incoming
                    .validate_for_context(sidecar_id, source_context_ref)
                    .map_err(malformed)?;
                let subject =
                    arkret_canonical::canonical_sha256(source_context_ref).map_err(malformed)?;
                let old = diesel::sql_query("SELECT current_commit_id,current_stream_position,source_stream_ref,value FROM sidecar_exchange_controls_current_results WHERE realm_id=$1 AND sidecar_id=$2 AND context_ref_digest=$3 FOR UPDATE")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(sidecar_id.as_str()).bind::<Text,_>(&subject)
                    .get_result::<ExistingFrankingProofCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(old) = old {
                    let retained: AgentSidecarExchangeControlsCurrentValue =
                        serde_json::from_value(old.value.clone()).map_err(malformed)?;
                    if old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || retained
                            .assertions()
                            .iter()
                            .any(|assertion| !incoming.assertions().contains(assertion))
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                    {
                        return Err(PersistenceError::Conflict("failed_precondition: Sidecar controls snapshot changes its source, revision or retained assertions".into()));
                    }
                }
            }
            S::Pin { pin_scope } => {
                use arkret_models_collaboration::objects::productivity::PinCurrentValue;
                let incoming: PinCurrentValue =
                    serde_json::from_value(value.clone()).map_err(malformed)?;
                incoming.validate_for_scope(pin_scope).map_err(malformed)?;
                let subject =
                    arkret_canonical::canonical_json_string(pin_scope).map_err(malformed)?;
                let old = diesel::sql_query("SELECT current_commit_id,current_stream_position,source_stream_ref,value FROM pin_current_results WHERE realm_id=$1 AND pin_scope_key=$2 FOR UPDATE")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(&subject)
                    .get_result::<ExistingFrankingProofCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(old) = old {
                    let retained: PinCurrentValue =
                        serde_json::from_value(old.value.clone()).map_err(malformed)?;
                    if old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || retained
                            .assertions()
                            .iter()
                            .any(|assertion| !incoming.assertions().contains(assertion))
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                    {
                        return Err(PersistenceError::Conflict("failed_precondition: Pin snapshot changes its source, revision or retained assertions".into()));
                    }
                }
            }
            S::Circle { circle_id } => {
                if *source_stream_ref
                    != (arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                    || value.get("id").and_then(Value::as_str) != Some(circle_id.as_str())
                    || value.get("realm_id").and_then(Value::as_str) != Some(realm_id.as_str())
                {
                    return Err(malformed("Circle selector, source and value differ"));
                }
                let existing = diesel::sql_query("SELECT realm_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,value FROM circle_current_results WHERE circle_id=$1 FOR UPDATE")
                    .bind::<Text,_>(circle_id.as_str())
                    .get_result::<ExistingCircleCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(old) = existing {
                    let create_id = circle_id.as_str().replacen("ak:circle:", "ak:event:", 1);
                    if old.realm_id != realm_id.as_str()
                        || old.create_event_id != create_id
                        || old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value))
                    {
                        return Err(PersistenceError::Conflict("failed_precondition: Circle snapshot current revision or value differs".to_owned()));
                    }
                }
            }
            S::CircleMemberState {
                circle_id,
                member_actor_id,
            } => {
                if *source_stream_ref
                    != (arkret_wire::CommitStreamRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
                {
                    return Err(malformed("Circle member selector and source differ"));
                }
                let existing = diesel::sql_query("SELECT realm_id,current_commit_id,current_stream_position,source_stream_ref,value FROM circle_member_state_current_results WHERE circle_id=$1 AND member_id=$2 FOR UPDATE")
                    .bind::<Text,_>(circle_id.as_str())
                    .bind::<Text,_>(member_actor_id.to_string())
                    .get_result::<ExistingCircleMemberCurrent>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
                if let Some(old) = existing
                    && (old.realm_id != realm_id.as_str()
                        || old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value)))
                {
                    return Err(PersistenceError::Conflict("failed_precondition: Circle member snapshot current revision or value differs".to_owned()));
                }
            }
            S::ModerationFrankingProof { event_id } => {
                if *source_stream_ref
                    != (arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                    || value.get("event_id").and_then(Value::as_str) != Some(event_id.as_str())
                {
                    return Err(malformed(
                        "franking proof selector, source and value differ",
                    ));
                }
                let old = diesel::sql_query("SELECT current_commit_id,current_stream_position,source_stream_ref,value FROM moderation_franking_proof_current_results WHERE realm_id=$1 AND target_event_id=$2 FOR UPDATE")
                    .bind::<Text, _>(realm_id.as_str())
                    .bind::<Text, _>(event_id.as_str())
                    .get_result::<ExistingFrankingProofCurrent>(&mut *conn)
                    .await
                    .optional()
                    .map_err(PersistenceError::database)?;
                if let Some(old) = old
                    && (old.source_stream_ref != source
                        || old.current_stream_position > incoming_position
                        || (old.current_stream_position == incoming_position
                            && (old.current_commit_id != revision.commit_id.as_str()
                                || old.value != *value)))
                {
                    return Err(PersistenceError::Conflict("failed_precondition: franking proof snapshot current revision or value differs".to_owned()));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A verified snapshot/replica carries authority; this projection never
/// reevaluates the governing Station's current capabilities.
async fn upsert_call_genesis(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    call: &arkret_wire::CallId,
    source: &arkret_wire::CommitStreamRef,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    use arkret_models_collaboration::events_payloads::call::{
        CallCreatePayload, CallStateCurrentValue,
    };
    let current: CallStateCurrentValue =
        serde_json::from_value(value.clone()).map_err(malformed)?;
    current.validate().map_err(malformed)?;
    if source.realm_id() != realm
        || !matches!(
            source,
            arkret_wire::CommitStreamRef::Realm { .. }
                | arkret_wire::CommitStreamRef::Circle { .. }
        )
    {
        return Err(malformed(
            "Call replica currently requires a genesis value in its exact Realm",
        ));
    }
    let create = arkret_wire::EventId::new(call.as_str().replacen("ak:call:", "ak:event:", 1))
        .map_err(malformed)?;
    #[derive(diesel::QueryableByName)]
    struct AcceptedRow {
        #[diesel(sql_type = Jsonb)]
        envelope: Value,
        #[diesel(sql_type = Jsonb)]
        commit_json: Value,
    }
    // Bootstrap may legitimately precede retained create history. If the
    // covering accepted Event is available, it must prove every coordinate.
    let accepted = diesel::sql_query("SELECT e.envelope,c.commit_json FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE c.commit_id=$1 AND e.state='committed'")
        .bind::<Text,_>(revision.commit_id).get_result::<AcceptedRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if let Some(record) = accepted {
        let event: arkret_wire::Event =
            serde_json::from_value(record.envelope).map_err(malformed)?;
        let commit: arkret_wire::RealmCommit =
            serde_json::from_value(record.commit_json).map_err(malformed)?;
        let expected = match event.kind {
            arkret_wire::EventKind::CallCreate => {
                let payload: CallCreatePayload =
                    serde_json::from_value(serde_json::json!(&event.payload)).map_err(malformed)?;
                payload.validate().map_err(malformed)?;
                if event.event_id != create {
                    return Err(malformed("Call genesis identity differs"));
                }
                serde_json::to_value(CallStateCurrentValue {
                    from: None,
                    to: payload.initial_state,
                    failure_reason_code: None,
                })
                .map_err(malformed)?
            }
            arkret_wire::EventKind::CallState => {
                let payload: arkret_models_collaboration::events_payloads::call::CallStatePayload =
                    serde_json::from_value(serde_json::json!(&event.payload)).map_err(malformed)?;
                if payload.call_id != *call {
                    return Err(malformed("Call transition identity differs"));
                }
                serde_json::to_value(
                    payload
                        .state_transition
                        .ok_or_else(|| malformed("Call lifecycle transition absent"))?,
                )
                .map_err(malformed)?
            }
            _ => return Err(malformed("Call lifecycle source kind differs")),
        };
        if event.realm_id != *realm
            || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
                .map_err(malformed)?
                != *source
            || commit.event_ref != event.event_id
            || commit.realm_id != *realm
            || commit.stream_ref != *source
            || commit.commit_id.as_str() != revision.commit_id
            || position(commit.stream_position)? != revision.stream_position
            || *value != expected
        {
            return Err(malformed(
                "Call current differs from accepted lifecycle Event and Commit",
            ));
        }
    }
    let changed = diesel::sql_query("INSERT INTO call_state_current_results (realm_id,call_id,create_event_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,call_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE call_state_current_results.create_event_id=EXCLUDED.create_event_id AND call_state_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (call_state_current_results.current_stream_position<EXCLUDED.current_stream_position OR (call_state_current_results.current_stream_position=EXCLUDED.current_stream_position AND call_state_current_results.current_commit_id=EXCLUDED.current_commit_id AND call_state_current_results.value=EXCLUDED.value))")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).bind::<Text,_>(create.as_str())
        .bind::<Jsonb,_>(serde_json::to_value(source).map_err(malformed)?).bind::<Text,_>(revision.commit_id)
        .bind::<BigInt,_>(revision.stream_position).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(revision.updated_at)
        .execute(conn).await.map_err(PersistenceError::database)?;
    require_one_current_write(changed)
}

/// Upsert one row of a family keyed by `(realm_id)` or `(realm_id, key)`.
async fn upsert_keyed(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    table: &'static str,
    key: Option<(&'static str, &str)>,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let sql = match key {
        Some((column, _)) => format!(
            "INSERT INTO {table} \
             (realm_id,{column},current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$6,$2,$3,$4,$5) ON CONFLICT({conflict}) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
             WHERE {table}.realm_id=EXCLUDED.realm_id \
               AND ({table}.current_stream_position<EXCLUDED.current_stream_position \
                 OR ({table}.current_stream_position=EXCLUDED.current_stream_position \
                   AND {table}.current_commit_id=EXCLUDED.current_commit_id \
                   AND {table}.value=EXCLUDED.value))",
            conflict = match table {
                "strand_current_results" => "strand_id",
                "space_current_results"
                | "space_parent_current_results"
                | "space_child_scope_policy_current_results" => "space_id",
                "message_revision_current_results" => "message_id",
                "moderation_report_current_results" => "realm_id,report_event_id",
                _ => "realm_id,target_ref",
            },
        ),
        None => format!(
            "INSERT INTO {table} \
             (realm_id,current_commit_id,current_stream_position,value,updated_at) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(realm_id) DO UPDATE SET \
             current_commit_id=EXCLUDED.current_commit_id, \
             current_stream_position=EXCLUDED.current_stream_position, \
             value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
             WHERE {table}.current_stream_position<EXCLUDED.current_stream_position \
               OR ({table}.current_stream_position=EXCLUDED.current_stream_position \
                 AND {table}.current_commit_id=EXCLUDED.current_commit_id \
                 AND {table}.value=EXCLUDED.value)"
        ),
    };
    let query = diesel::sql_query(sql)
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Text, _>(revision.commit_id)
        .bind::<BigInt, _>(revision.stream_position)
        .bind::<Jsonb, _>(value)
        .bind::<Timestamptz, _>(revision.updated_at);
    let changed = match key {
        Some((_, key)) => query.bind::<Text, _>(key).execute(conn).await,
        None => query.execute(conn).await,
    }
    .map_err(PersistenceError::database)?;
    require_one_current_write(changed)
}

async fn upsert_franking_proof(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    target: &arkret_wire::EventId,
    source: &arkret_wire::CommitStreamRef,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    if *source
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        })
        || value.get("event_id").and_then(Value::as_str) != Some(target.as_str())
    {
        return Err(malformed(
            "franking proof selector, source and value differ",
        ));
    }
    let changed = diesel::sql_query(
        "INSERT INTO moderation_franking_proof_current_results \
         (realm_id,target_event_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,target_event_id) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE moderation_franking_proof_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
           AND (moderation_franking_proof_current_results.current_stream_position<EXCLUDED.current_stream_position \
             OR (moderation_franking_proof_current_results.current_stream_position=EXCLUDED.current_stream_position \
               AND moderation_franking_proof_current_results.current_commit_id=EXCLUDED.current_commit_id \
               AND moderation_franking_proof_current_results.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(target.as_str())
    .bind::<Jsonb, _>(serde_json::to_value(source).map_err(malformed)?)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    require_one_current_write(changed)
}

async fn upsert_member_state(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    member: &arkret_wire::ActorId,
    revision: &Revision<'_>,
    value: &Value,
) -> PersistenceResult<()> {
    let membership = value
        .get("membership")
        .and_then(Value::as_str)
        .filter(|membership| matches!(*membership, "join" | "knock" | "leave" | "ban"))
        .ok_or_else(|| malformed("member_state has no closed membership"))?;
    let changed = diesel::sql_query(
        "INSERT INTO member_state_current_results \
         (realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,member_id) DO UPDATE SET \
         membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE member_state_current_results.current_stream_position<EXCLUDED.current_stream_position \
           OR (member_state_current_results.current_stream_position=EXCLUDED.current_stream_position \
             AND member_state_current_results.current_commit_id=EXCLUDED.current_commit_id \
             AND member_state_current_results.value=EXCLUDED.value)",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(member.to_string())
    .bind::<Text, _>(membership)
    .bind::<Text, _>(revision.commit_id)
    .bind::<BigInt, _>(revision.stream_position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(revision.updated_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    require_one_current_write(changed)
}

/// Replace the member Station's typed current of `realm_id` with a verified
/// bootstrap snapshot's rows. Every row must come from the Realm stream at or
/// below `head`; a family this module does not keep is left out, and a
/// selector outside the bootstrap disclosure subset refuses the install.
#[cfg(test)]
pub(crate) async fn install_snapshot_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    head: &arkret_wire::CommitStreamHead,
    entries: &[arkret_wire::TypedCurrentRow],
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    install_snapshot_at_heads_in_connection(
        conn,
        realm_id,
        head,
        std::slice::from_ref(head),
        entries,
        installed_at,
    )
    .await
}

pub(crate) async fn install_snapshot_at_heads_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    head: &arkret_wire::CommitStreamHead,
    visible_heads: &[arkret_wire::CommitStreamHead],
    entries: &[arkret_wire::TypedCurrentRow],
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    arkret_models_collaboration::exact_current_results::validate_calendar_current_pairs(
        realm_id, entries,
    )
    .map_err(malformed)?;
    let mut selectors = std::collections::BTreeSet::new();
    for entry in entries {
        let arkret_wire::TypedCurrentRow::Value { selector, .. } = entry;
        let key = arkret_canonical::canonical_json_bytes(selector).map_err(malformed)?;
        if !selectors.insert(key) {
            return Err(malformed("a snapshot repeats a current selector"));
        }
    }
    if head.stream_ref.realm_id() != realm_id || !visible_heads.contains(head) {
        return Err(malformed(
            "snapshot target head is not in its verified visible heads",
        ));
    }
    let replaces_realm = visible_heads.iter().any(|head| {
        head.stream_ref
            == (arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
    });
    if replaces_realm {
        #[derive(diesel::QueryableByName)]
        struct Present {
            #[diesel(sql_type = diesel::sql_types::Bool)]
            present: bool,
        }
        let omitted = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM replica_authorization_rows r WHERE r.realm_id=$1 AND r.selector->>'kind'='policy' AND r.value->>'schema'='ak.schema.policy.v1' AND r.value->>'policy_kind' IN ('access','moderation','agent') AND EXISTS(SELECT 1 FROM jsonb_array_elements($3) h WHERE h->'stream_ref'=r.source_stream_ref) AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements($2) incoming WHERE incoming->'selector'=r.selector)) AS present")
            .bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(entries).map_err(malformed)?)
            .bind::<Jsonb,_>(serde_json::to_value(visible_heads).map_err(malformed)?)
            .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
        if omitted {
            return Err(malformed("snapshot cannot erase an accepted shared Policy"));
        }
    }
    if replaces_realm
        && crate::direct_conversation_admission::binding_current_in_connection(conn, realm_id)
            .await?
            .is_some()
        && !entries.iter().any(|entry| {
            matches!(
                entry,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::DirectConversationBinding { .. },
                    ..
                }
            )
        })
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: snapshot cannot remove an accepted binding".into(),
        ));
    }
    crate::replica_authorization::guard_current_rows(conn, realm_id, entries).await?;
    guard_snapshot_revisions(conn, realm_id, entries).await?;
    for source_head in visible_heads {
        if source_head.stream_ref.realm_id() != realm_id {
            return Err(malformed("a visible head crosses Realm"));
        }
        crate::replica_authorization::install_verified_head(conn, source_head, installed_at)
            .await?;
        let source =
            serde_json::to_value(&source_head.stream_ref).map_err(PersistenceError::database)?;
        for table in MEMBER_STATION_FAMILIES {
            diesel::sql_query(format!("DELETE FROM {table} WHERE realm_id=$1 AND current_commit_id IN (SELECT current_commit_id FROM replica_authorization_rows WHERE realm_id=$1 AND source_stream_ref=$2)"))
                .bind::<Text, _>(realm_id.as_str()).bind::<Jsonb, _>(&source).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
        diesel::sql_query(
            "DELETE FROM replica_authorization_rows WHERE realm_id=$1 AND source_stream_ref=$2",
        )
        .bind::<Text, _>(realm_id.as_str())
        .bind::<Jsonb, _>(&source)
        .execute(&mut *conn)
        .await
        .map_err(PersistenceError::database)?;
    }
    for entry in entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        let source_head = visible_heads
            .iter()
            .find(|candidate| &candidate.stream_ref == source_stream_ref)
            .ok_or_else(|| malformed("row source stream is not disclosed"))?;
        if source_stream_ref.realm_id() != realm_id
            || revision.stream_position > source_head.stream_position
            || (revision.stream_position == source_head.stream_position
                && revision.commit_id != source_head.commit_id)
        {
            return Err(malformed("row exceeds its exact snapshot source head"));
        }
        crate::replica_authorization::save_row(conn, realm_id, entry, installed_at).await?;
        let commit_id = revision.commit_id.to_string();
        let row = Revision {
            commit_id: &commit_id,
            stream_position: position(revision.stream_position)?,
            updated_at: installed_at,
        };
        use arkret_wire::CurrentSelector as S;
        if let S::Policy { policy_id } = selector {
            crate::policy_current_results::validate_disclosed_shared_policy(
                realm_id,
                policy_id,
                source_stream_ref,
                value,
            )?;
        }
        let singleton = match selector {
            S::RealmGenesis => Some("realm_genesis"),
            S::RealmProfile => Some("realm_profile"),
            S::RealmPreviewPolicy => {
                if source_stream_ref
                    != &(arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                {
                    return Err(malformed(
                        "preview policy requires the exact Realm source stream",
                    ));
                }
                let _: arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValue = serde_json::from_value(value.clone()).map_err(malformed)?;
                Some("realm_preview_policy")
            }
            S::ScopeReadReceiptPolicy { scope_ref } => {
                crate::scope_read_receipt_policy_current_results::install(
                    conn,
                    realm_id,
                    scope_ref,
                    source_stream_ref,
                    revision,
                    value,
                    installed_at,
                )
                .await?;
                continue;
            }
            S::RealmJoinRule => Some("realm_join_rule"),
            S::RealmHistoryAccess => Some("realm_history_access"),
            S::RealmDiscovery => Some("realm_discovery"),
            S::RealmAlias => Some("realm_alias"),
            S::RealmPlaintextVisibleServices => Some("realm_plaintext_visible_services"),
            S::RealmTombstone => Some("realm_tombstone"),
            S::RealmArchive => Some("realm_archive"),
            S::RealmFreeze => Some("realm_freeze"),
            _ => None,
        };
        if let Some(family) = singleton {
            upsert_singleton(conn, realm_id, family, &row, value).await?;
            continue;
        }
        match selector {
            S::ActorProfile {actor_profile_id} => {
                crate::applet_scope_profiles::validate_disclosed(actor_profile_id,source_stream_ref,value)?;
            }
            S::AgentInteraction { agent_account_id } => {
                if *source_stream_ref
                    != (arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                {
                    return Err(PersistenceError::SchemaViolation(
                        "Agent interaction snapshot is not Realm scoped".into(),
                    ));
                }
                let current: arkret_models_collaboration::agent_interaction::AgentInteractionCurrentValue = serde_json::from_value(value.clone()).map_err(malformed)?;
                crate::agent_interaction_current_results::install_in_connection(
                    conn,
                    realm_id,
                    agent_account_id,
                    revision,
                    &current,
                    installed_at,
                )
                .await?;
            }
            S::DirectConversationBinding { .. } => {
                crate::direct_conversation_admission::install_binding_snapshot_in_connection(
                    conn,
                    realm_id,
                    entry,
                    installed_at,
                )
                .await?;
            }
            S::AgentSidecarExchangeControls { .. } => {
                crate::sidecar_exchange_controls::install_in_connection(
                    conn,
                    realm_id,
                    entry,
                    installed_at,
                )
                .await?;
            }
            S::Sidecar { .. } | S::SidecarContext { .. } => {
                crate::sidecar_replica_current::install_in_connection(
                    conn,
                    realm_id,
                    entry,
                    installed_at,
                )
                .await?;
            }
            S::CallState { call_id } => {
                upsert_call_genesis(conn, realm_id, call_id, source_stream_ref, &row, value)
                    .await?;
            }
            S::CallFocus{call_id} | S::CallRoster{call_id} | S::CallModeration{call_id} => {
                match selector {
                    S::CallRoster{..}=>serde_json::from_value::<arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue>(value.clone()).map_err(malformed)?.validate_sources(source_stream_ref,revision).map_err(malformed)?,
                    S::CallModeration{..}=>serde_json::from_value::<arkret_models_collaboration::events_payloads::call::CallModerationCurrentValue>(value.clone()).map_err(malformed)?.validate_sources(source_stream_ref,revision).map_err(malformed)?,
                    _=>{let _:arkret_models_collaboration::events_payloads::call::CallFocus=serde_json::from_value(value.clone()).map_err(malformed)?;},
                }
                let changed=diesel::sql_query("INSERT INTO call_component_current_results(realm_id,call_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(realm_id,call_id,selector) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE call_component_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (call_component_current_results.current_stream_position<EXCLUDED.current_stream_position OR (call_component_current_results.current_stream_position=EXCLUDED.current_stream_position AND call_component_current_results.current_commit_id=EXCLUDED.current_commit_id AND call_component_current_results.value=EXCLUDED.value))")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(call_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(selector).map_err(malformed)?)
                    .bind::<Jsonb,_>(serde_json::to_value(source_stream_ref).map_err(malformed)?).bind::<Text,_>(row.commit_id).bind::<BigInt,_>(row.stream_position).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(row.updated_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::RealmMediaService => {
                let _:arkret_models_collaboration::events_payloads::RealmMediaServiceValue=serde_json::from_value(value.clone()).map_err(malformed)?;
                let changed=diesel::sql_query("INSERT INTO realm_media_service_current_results(realm_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE realm_media_service_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (realm_media_service_current_results.current_stream_position<EXCLUDED.current_stream_position OR (realm_media_service_current_results.current_stream_position=EXCLUDED.current_stream_position AND realm_media_service_current_results.current_commit_id=EXCLUDED.current_commit_id AND realm_media_service_current_results.value=EXCLUDED.value))")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(source_stream_ref).map_err(malformed)?).bind::<Text,_>(row.commit_id).bind::<BigInt,_>(row.stream_position).bind::<Jsonb,_>(value).bind::<Timestamptz,_>(row.updated_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::Circle { circle_id } => {
                let create_id = arkret_wire::EventId::new(circle_id.as_str().replacen(
                    "ak:circle:",
                    "ak:event:",
                    1,
                ))
                .map_err(malformed)?;
                let name = value
                    .pointer("/display/short_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("Circle display name is absent"))?
                    .to_ascii_lowercase();
                let changed = diesel::sql_query("INSERT INTO circle_current_results (realm_id,circle_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,short_name_folded,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(circle_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref,short_name_folded=EXCLUDED.short_name_folded,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE circle_current_results.realm_id=EXCLUDED.realm_id AND circle_current_results.create_event_id=EXCLUDED.create_event_id AND circle_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (circle_current_results.current_stream_position<EXCLUDED.current_stream_position OR (circle_current_results.current_stream_position=EXCLUDED.current_stream_position AND circle_current_results.current_commit_id=EXCLUDED.current_commit_id AND circle_current_results.value=EXCLUDED.value AND circle_current_results.short_name_folded=EXCLUDED.short_name_folded))")
                    .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).bind::<Text, _>(create_id.as_str()).bind::<Text, _>(row.commit_id).bind::<BigInt, _>(row.stream_position).bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(malformed)?).bind::<Text, _>(name).bind::<Jsonb, _>(value).bind::<Timestamptz, _>(installed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::CircleMemberState {
                circle_id,
                member_actor_id,
            } => {
                let current: arkret_wire::CircleMemberStateCurrent =
                    serde_json::from_value(value.clone()).map_err(malformed)?;
                let membership = serde_json::to_value(current.membership).map_err(malformed)?;
                let membership = membership
                    .as_str()
                    .ok_or_else(|| malformed("Circle membership is not a name"))?;
                let changed = diesel::sql_query("INSERT INTO circle_member_state_current_results (realm_id,circle_id,member_id,membership,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(circle_id,member_id) DO UPDATE SET membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE circle_member_state_current_results.realm_id=EXCLUDED.realm_id AND circle_member_state_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (circle_member_state_current_results.current_stream_position<EXCLUDED.current_stream_position OR (circle_member_state_current_results.current_stream_position=EXCLUDED.current_stream_position AND circle_member_state_current_results.current_commit_id=EXCLUDED.current_commit_id AND circle_member_state_current_results.membership=EXCLUDED.membership AND circle_member_state_current_results.value=EXCLUDED.value))")
                    .bind::<Text, _>(realm_id.as_str()).bind::<Text, _>(circle_id.as_str()).bind::<Text, _>(member_actor_id.to_string()).bind::<Text, _>(membership).bind::<Text, _>(row.commit_id).bind::<BigInt, _>(row.stream_position).bind::<Jsonb, _>(serde_json::to_value(source_stream_ref).map_err(malformed)?).bind::<Jsonb, _>(value).bind::<Timestamptz, _>(installed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::ModerationState { target_ref } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "moderation_state_current_results",
                    Some(("target_ref", target_ref.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::ModerationReport { event_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "moderation_report_current_results",
                    Some(("report_event_id", event_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::ModerationFrankingProof { event_id } => {
                upsert_franking_proof(conn, realm_id, event_id, source_stream_ref, &row, value)
                    .await?;
            }
            S::RealmPolicyBundle => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_policy_bundle_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::Pin { pin_scope } => {
                let set: arkret_models_collaboration::objects::productivity::PinCurrentValue =
                    serde_json::from_value(value.clone()).map_err(malformed)?;
                set.validate_for_scope(pin_scope).map_err(malformed)?;
                let subject =
                    arkret_canonical::canonical_json_string(pin_scope).map_err(malformed)?;
                let changed = diesel::sql_query("INSERT INTO pin_current_results (realm_id,pin_scope_key,pin_scope,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$8,$4,$5,$6,$7) ON CONFLICT(realm_id,pin_scope_key) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE pin_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND EXCLUDED.value->'assertions' @> pin_current_results.value->'assertions' AND (pin_current_results.current_stream_position<EXCLUDED.current_stream_position OR (pin_current_results.current_stream_position=EXCLUDED.current_stream_position AND pin_current_results.current_commit_id=EXCLUDED.current_commit_id AND pin_current_results.value=EXCLUDED.value))")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(&subject)
                    .bind::<Jsonb,_>(serde_json::to_value(pin_scope).map_err(malformed)?)
                    .bind::<Text,_>(row.commit_id).bind::<BigInt,_>(row.stream_position)
                    .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(installed_at)
                    .bind::<Jsonb,_>(serde_json::to_value(source_stream_ref).map_err(malformed)?)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::SchemaDefinition { schema_id } => {
                let payload = serde_json::json!({"value":value});
                arkret_schema::validate_schema_definition_payload(&payload).map_err(malformed)?;
                if value.get("$id").and_then(serde_json::Value::as_str) != Some(schema_id.as_str())
                {
                    return Err(malformed("schema definition subject differs from its $id"));
                }
                let changed = diesel::sql_query("INSERT INTO schema_definition_current_results (realm_id,schema_id,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id,schema_id) DO UPDATE SET updated_at=schema_definition_current_results.updated_at WHERE schema_definition_current_results.value=EXCLUDED.value AND schema_definition_current_results.current_commit_id=EXCLUDED.current_commit_id AND schema_definition_current_results.current_stream_position=EXCLUDED.current_stream_position")
                    .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(schema_id)
                    .bind::<Text,_>(row.commit_id).bind::<BigInt,_>(row.stream_position)
                    .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(installed_at)
                    .execute(&mut *conn).await.map_err(PersistenceError::database)?;
                require_one_current_write(changed)?;
            }
            S::MemberState { actor_id } => {
                upsert_member_state(conn, realm_id, actor_id, &row, value).await?;
            }
            S::Strand { strand_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "strand_current_results",
                    Some(("strand_id", strand_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::CalendarScheduleSource { .. } => {}
            S::Rsvp {
                event_ref,
                occurrence,
                responder_actor_id,
            } => {
                crate::rsvp_current_results::install_verified_rsvp_in_connection(
                    conn,
                    realm_id,
                    event_ref,
                    occurrence,
                    responder_actor_id,
                    source_stream_ref,
                    revision,
                    value,
                    installed_at,
                )
                .await?;
            }
            S::StrandWatch {
                strand_id,
                watcher_actor_id,
            } => {
                crate::strand_watch_current_results::install_in_connection(
                    conn,
                    realm_id,
                    strand_id,
                    watcher_actor_id,
                    revision,
                    value,
                    installed_at,
                )
                .await?;
            }
            S::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                let current = serde_json::from_value::<
                    Option<arkret_models_collaboration::objects::strand::StrandPositionCurrent>,
                >(value.clone())
                .map_err(PersistenceError::database)?;
                crate::strand_position_current_results::install_in_connection(
                    conn,
                    realm_id,
                    board_space_id,
                    strand_id,
                    revision,
                    &current,
                    installed_at,
                )
                .await?;
            }
            S::Space { space_id }
            | S::SpaceParent { space_id }
            | S::SpaceChildScopePolicy { space_id } => {
                let table = match selector {
                    S::Space { .. } => "space_current_results",
                    S::SpaceParent { .. } => "space_parent_current_results",
                    S::SpaceChildScopePolicy { .. } => "space_child_scope_policy_current_results",
                    _ => unreachable!(),
                };
                upsert_keyed(
                    conn,
                    realm_id,
                    table,
                    Some(("space_id", space_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::RealmSetDefaultStrand => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "realm_set_default_strand_current_results",
                    None,
                    &row,
                    value,
                )
                .await?;
            }
            S::MessageRevision { message_id } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "message_revision_current_results",
                    Some(("message_id", message_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::ObjectRedaction { target_ref } => {
                upsert_keyed(
                    conn,
                    realm_id,
                    "object_redaction_current_results",
                    Some(("target_ref", target_ref.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            S::MessageReactions { target_ref } => {
                let set: arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue =
                    serde_json::from_value(value.clone()).map_err(malformed)?;
                set.validate_for_target(target_ref).map_err(malformed)?;
                arkret_wire::MessageId::new(target_ref.as_str()).map_err(malformed)?;
                upsert_keyed(
                    conn,
                    realm_id,
                    "message_reactions_current_results",
                    Some(("target_ref", target_ref.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
            // Governing admission inputs a member Station never keeps.
            S::RealmAuthorityRoot
            // The snapshot has no accepting EventId; keep the exact signed
            // Policy row only in replica_authorization_rows, not a fake current.
            | S::Policy { .. }
            | S::CapabilityGrant { .. }
            | S::InviteLifecycle { .. }
            | S::InviteLiveTarget { .. }
            | S::InviteDirectedInvitee { .. }
            | S::MlsGroup { .. } => {}
            _ => {
                return Err(malformed(
                    "a row family is outside the member bootstrap disclosure subset",
                ));
            }
        }
    }
    for entry in entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        if let arkret_wire::CurrentSelector::CalendarScheduleSource { strand_id } = selector {
            let paired = entries.iter().find_map(|entry| {
                let arkret_wire::TypedCurrentRow::Value { selector, source_stream_ref: stream, revision: basis, value } = entry;
                matches!(selector, arkret_wire::CurrentSelector::Strand { strand_id: id } if id == strand_id)
                    .then_some((stream, basis, value))
            }).ok_or_else(|| malformed("Calendar source has no paired Strand"))?;
            if paired.0 != source_stream_ref || paired.1 != revision {
                return Err(malformed("Calendar and Strand cuts differ"));
            }
            let source: arkret_wire::CalendarScheduleSourceValue =
                serde_json::from_value(value.clone()).map_err(malformed)?;
            source
                .validate_for_current(realm_id, source_stream_ref, revision)
                .map_err(malformed)?;
            let strand: arkret_models_collaboration::objects::strand::Strand =
                serde_json::from_value(paired.2.clone()).map_err(malformed)?;
            match (&strand.encrypted_metadata, &source.metadata_context) {
                (Some(envelope), Some(context))
                    if envelope.payload_digest().map_err(malformed)? == context.payload_digest => {}
                (None, None) => {}
                _ => {
                    return Err(malformed(
                        "Calendar metadata context differs from current ciphertext",
                    ));
                }
            }
            let changed = diesel::sql_query("UPDATE strand_current_results SET calendar_schedule_source_value=$3 WHERE realm_id=$1 AND strand_id=$2 AND current_commit_id=$4 AND current_stream_position=$5")
                .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(strand_id.as_str()).bind::<Jsonb,_>(value)
                .bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(i64::try_from(revision.stream_position).map_err(malformed)?)
                .execute(&mut *conn).await.map_err(PersistenceError::database)?;
            require_one_current_write(changed)?;
        }
    }
    Ok(())
}

/// Advance the member Station's typed current with one committed replica
/// that directly follows its anchored held head.
pub(crate) async fn advance_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let commit_id = commit.commit_id.to_string();
    let row = Revision {
        commit_id: &commit_id,
        stream_position: position(commit.stream_position)?,
        updated_at: commit.committed_at,
    };
    let payload = || serde_json::to_value(&event.payload).map_err(PersistenceError::database);
    if matches!(
        event.kind,
        arkret_wire::EventKind::CapabilityGrant
            | arkret_wire::EventKind::CapabilityRevoke
            | arkret_wire::EventKind::CapabilityRelinquish
            | arkret_wire::EventKind::RealmPolicyBundle
            | arkret_wire::EventKind::RealmOwnerTransfer
            | arkret_wire::EventKind::RealmAuthorityReset
            | arkret_wire::EventKind::MlsGenesis
            | arkret_wire::EventKind::MlsCommit
    ) {
        diesel::sql_query("DELETE FROM replica_authorization_cuts WHERE realm_id=$1")
            .bind::<Text, _>(event.realm_id.as_str())
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        diesel::sql_query("DELETE FROM replica_authorization_rows WHERE realm_id=$1 AND selector->>'kind' IN ('realm_authority_root','realm_policy_bundle')").bind::<Text, _>(event.realm_id.as_str()).execute(&mut *conn).await.map_err(PersistenceError::database)?;
    }

    match event.kind {
        arkret_wire::EventKind::DirectConversationBound => {
            crate::direct_conversation_admission::commit_binding_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
            let value = crate::direct_conversation_admission::binding_current_in_connection(
                conn,
                &event.realm_id,
            )
            .await?
            .ok_or_else(|| malformed("accepted binding has no projected current"))?;
            let pair_key = value.endorsements[0].value.pair_key.clone();
            crate::replica_authorization::save_row(
                conn,
                &event.realm_id,
                &arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::DirectConversationBinding { pair_key },
                    source_stream_ref: commit.stream_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: commit.commit_id.clone(),
                        stream_position: commit.stream_position,
                    },
                    value: serde_json::to_value(value).map_err(malformed)?,
                },
                commit.committed_at,
            )
            .await?;
        }
        arkret_wire::EventKind::ProfileCreate | arkret_wire::EventKind::ProfileUpdate => {
            crate::applet_scope_profiles::project_replica(conn, event, commit).await?;
        }
        arkret_wire::EventKind::RealmTombstone
        | arkret_wire::EventKind::RealmArchive
        | arkret_wire::EventKind::RealmRestore
        | arkret_wire::EventKind::RealmFreeze
        | arkret_wire::EventKind::RealmUnfreeze => {
            crate::realm_lifecycle_current_results::commit_in_connection(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::CallState => {
            let body: arkret_models_collaboration::events_payloads::call::CallStatePayload =
                serde_json::from_value(payload()?).map_err(malformed)?;
            body.validate().map_err(malformed)?;
            if event.realm_id != commit.realm_id
                || event.event_id != commit.event_ref
                || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
                    .map_err(malformed)?
                    != commit.stream_ref
            {
                return Err(malformed("Call state replica source differs"));
            }
            if let Some(transition) = &body.state_transition {
                upsert_call_genesis(
                    conn,
                    &event.realm_id,
                    &body.call_id,
                    &commit.stream_ref,
                    &row,
                    &serde_json::to_value(transition).map_err(malformed)?,
                )
                .await?;
            }
            crate::call_state_current_results::write_axes(conn, event, commit, &body).await?;
        }
        arkret_wire::EventKind::RealmMediaService => {
            let body: arkret_models_collaboration::events_payloads::RealmMediaServicePayload =
                serde_json::from_value(payload()?).map_err(malformed)?;
            body.value.validate().map_err(malformed)?;
            diesel::sql_query("INSERT INTO realm_media_service_current_results(realm_id,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(realm_id) DO UPDATE SET current_commit_id=EXCLUDED.current_commit_id,current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at WHERE realm_media_service_current_results.source_stream_ref=EXCLUDED.source_stream_ref AND (realm_media_service_current_results.current_stream_position<EXCLUDED.current_stream_position OR (realm_media_service_current_results.current_stream_position=EXCLUDED.current_stream_position AND realm_media_service_current_results.current_commit_id=EXCLUDED.current_commit_id AND realm_media_service_current_results.value=EXCLUDED.value))")
            .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).map_err(malformed)?).bind::<Text,_>(commit.commit_id.as_str()).bind::<BigInt,_>(position(commit.stream_position)?).bind::<Jsonb,_>(serde_json::to_value(body.value).map_err(malformed)?).bind::<Timestamptz,_>(commit.committed_at).execute(&mut *conn).await.map_err(PersistenceError::database)?;
        }
        arkret_wire::EventKind::CallCreate => {
            use arkret_models_collaboration::events_payloads::call::{
                CallCreatePayload, CallStateCurrentValue,
            };
            if event.realm_id != commit.realm_id
                || event.event_id != commit.event_ref
                || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
                    .map_err(malformed)?
                    != commit.stream_ref
            {
                return Err(malformed("Call replica Event and covering Commit differ"));
            }
            let body: CallCreatePayload = serde_json::from_value(payload()?).map_err(malformed)?;
            body.validate().map_err(malformed)?;
            let value = serde_json::to_value(CallStateCurrentValue {
                from: None,
                to: body.initial_state,
                failure_reason_code: None,
            })
            .map_err(malformed)?;
            let call_id = arkret_wire::CallId::from_event_id(&event.event_id);
            upsert_call_genesis(
                conn,
                &event.realm_id,
                &call_id,
                &commit.stream_ref,
                &row,
                &value,
            )
            .await?;
            let entry = arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::CallState { call_id },
                source_stream_ref: commit.stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
                value,
            };
            crate::replica_authorization::save_row(
                conn,
                &event.realm_id,
                &entry,
                commit.committed_at,
            )
            .await?;
        }
        arkret_wire::EventKind::CircleCreate | arkret_wire::EventKind::CircleMemberState => {
            crate::circle_current_results::commit_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::AgentSidecarExchangeControl => {
            crate::sidecar_exchange_controls::commit_in_connection(conn, event, commit, false)
                .await?;
        }
        arkret_wire::EventKind::SidecarCreate | arkret_wire::EventKind::SidecarContextAttach => {
            // The source authority accepted the immutable Event; project its
            // result without rerunning the source Station's admission policy.
            crate::sidecar_current_results::commit_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::PolicySet => {
            use arkret_models_collaboration::governance::operation_wire::{
                PolicySetStatePayload, PolicySetValue,
            };
            let body: PolicySetStatePayload =
                serde_json::from_value(payload()?).map_err(malformed)?;
            body.validate().map_err(malformed)?;
            let selector = arkret_wire::CurrentSelector::Policy {
                policy_id: body.policy_id.clone(),
            };
            let value = serde_json::to_value(&body.value).map_err(malformed)?;
            let shared = matches!(&body.value, PolicySetValue::Governance(p) if matches!(p.policy_kind, arkret_wire::PolicyKind::Access | arkret_wire::PolicyKind::Moderation | arkret_wire::PolicyKind::Agent));
            let agent = matches!(&body.value, PolicySetValue::Governance(p) if p.policy_kind == arkret_wire::PolicyKind::Agent);
            #[derive(diesel::QueryableByName)]
            struct Present {
                #[diesel(sql_type = diesel::sql_types::Bool)]
                present: bool,
            }
            let previous_agent = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM replica_authorization_rows WHERE realm_id=$1 AND selector=$2 AND value->>'schema'='ak.schema.policy.v1' AND value->>'policy_kind'='agent') AS present")
                .bind::<Text,_>(event.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&selector).map_err(malformed)?)
                .get_result::<Present>(&mut *conn).await.map_err(PersistenceError::database)?.present;
            if previous_agent && !agent {
                return Err(malformed(
                    "replica Agent Policy cannot change family or kind",
                ));
            }
            let entry = arkret_wire::TypedCurrentRow::Value {
                selector,
                source_stream_ref: commit.stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
                value,
            };
            if shared {
                if event.realm_id != commit.realm_id
                    || event.event_id != commit.event_ref
                    || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
                        .map_err(malformed)?
                        != commit.stream_ref
                {
                    return Err(malformed("Policy replica Event and covering Commit differ"));
                }
                let arkret_wire::TypedCurrentRow::Value { value, .. } = &entry;
                crate::policy_current_results::validate_disclosed_shared_policy(
                    &event.realm_id,
                    &body.policy_id,
                    &commit.stream_ref,
                    value,
                )?;
                guard_snapshot_revisions(conn, &event.realm_id, std::slice::from_ref(&entry))
                    .await?;
            }
            crate::policy_current_results::commit_replica_in_connection(conn, event, commit)
                .await?;
            if shared {
                crate::replica_authorization::save_row(
                    conn,
                    &event.realm_id,
                    &entry,
                    commit.committed_at,
                )
                .await?;
            }
        }
        arkret_wire::EventKind::PolicyAction => {
            crate::policy_current_results::commit_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::SelfModerationReport => {
            upsert_keyed(
                conn,
                &event.realm_id,
                "moderation_report_current_results",
                Some(("report_event_id", event.event_id.as_str())),
                &row,
                &payload()?,
            )
            .await?;
        }
        arkret_wire::EventKind::ModerationFrankingProof => {
            let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                serde_json::from_value(payload()?).map_err(malformed)?;
            upsert_franking_proof(
                conn,
                &event.realm_id,
                &proof.event_id,
                &commit.stream_ref,
                &row,
                &payload()?,
            )
            .await?;
        }
        arkret_wire::EventKind::ModerationDecision
        | arkret_wire::EventKind::ModerationDecisionLift => {
            let body = payload()?;
            let target = body
                .get("target_ref")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed("moderation assertion has no target"))?
                .to_owned();
            #[derive(diesel::QueryableByName)]
            struct StateRow {
                #[diesel(sql_type=Jsonb)]
                value: Value,
            }
            let current = diesel::sql_query("SELECT value FROM moderation_state_current_results WHERE realm_id=$1 AND target_ref=$2 FOR UPDATE").bind::<Text, _>(event.realm_id.as_str()).bind::<Text, _>(&target).get_result::<StateRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
            let mut assertions = current
                .map(|row| {
                    row.value
                        .get("assertions")
                        .and_then(Value::as_array)
                        .cloned()
                        .ok_or_else(|| malformed("moderation assertions are malformed"))
                })
                .transpose()?
                .unwrap_or_default();
            assertions.push(serde_json::json!({"tag_id": crate::moderation_state_current_results::assertion_tag(&event.event_id), "value":body}));
            assertions.sort_by(|left, right| {
                left.get("tag_id")
                    .and_then(Value::as_str)
                    .cmp(&right.get("tag_id").and_then(Value::as_str))
            });
            upsert_keyed(
                conn,
                &event.realm_id,
                "moderation_state_current_results",
                Some(("target_ref", &target)),
                &row,
                &serde_json::json!({"assertions":assertions}),
            )
            .await?;
        }
        arkret_wire::EventKind::RealmJoinRule => {
            crate::realm_bootstrap_current_results::commit_realm_join_rule_current_result_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::RealmHistoryAccess => {
            crate::realm_bootstrap_current_results::commit_realm_history_access_current_result_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::ScopeReadReceiptPolicy => {
            crate::realm_bootstrap_current_results::commit_read_receipt_policy_current_result_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::RealmPlaintextVisibleServices => {
            crate::realm_bootstrap_current_results::commit_plaintext_services_current_result_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::RealmPreviewPolicy => {
            crate::realm_bootstrap_current_results::commit_preview_policy_current_result_in_connection(conn, event, commit).await?;
        }
        arkret_wire::EventKind::RealmProfile => {
            crate::realm_bootstrap_current_results::commit_realm_profile_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        arkret_wire::EventKind::SchemaDefine => {
            crate::unit_of_work::commit_schema_definition_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::MemberState
        | arkret_wire::EventKind::InviteAccept
        | arkret_wire::EventKind::RealmPolicyBundle
        | arkret_wire::EventKind::RealmLink => {
            crate::unit_of_work::commit_parent_membership_current_results(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::StrandCreate => {
            let (strand_id, value) =
                crate::strand_current_results::strand_create_current_value(event)?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "strand_current_results",
                Some(("strand_id", strand_id.as_str())),
                &row,
                &value,
            )
            .await?;
            crate::strand_current_results::refresh_calendar_source_in_connection(
                conn,
                event,
                commit,
                strand_id.as_str(),
            )
            .await?;
        }
        arkret_wire::EventKind::AgentInteractionSet => {
            crate::agent_interaction_current_results::project_in_connection(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::StrandWatchSet => {
            let payload: arkret_models_collaboration::events_payloads::strand::StrandWatchSetPayload = serde_json::from_value(serde_json::json!(&event.payload)).map_err(PersistenceError::database)?;
            crate::strand_watch_current_results::install_in_connection(
                conn,
                &event.realm_id,
                &payload.strand_id,
                &payload.watcher_actor_id,
                &arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
                &crate::strand_watch_current_results::event_value(event)?,
                commit.committed_at,
            )
            .await?;
        }
        arkret_wire::EventKind::StrandUpdate => {
            // Only the already verified, immediately following RealmCommit
            // reaches this fold. Use the same typed update as the authority;
            // skipping it would leave subsequent CAS guards on a stale value.
            crate::strand_current_results::commit_strand_update_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        arkret_wire::EventKind::StrandTracksUpdate => {
            crate::strand_current_results::commit_strand_tracks_update_current_result_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        arkret_wire::EventKind::RsvpSet => {
            crate::rsvp_current_results::project_verified_rsvp_in_connection(conn, event, commit)
                .await?;
        }
        arkret_wire::EventKind::StrandArchive
        | arkret_wire::EventKind::StrandRestore
        | arkret_wire::EventKind::StrandStageSet => {
            crate::strand_current_results::commit_strand_transition_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::StrandMove | arkret_wire::EventKind::StrandReorder => {
            crate::strand_position_current_results::project_verified_event_in_connection(
                conn, event, commit,
            )
            .await?;
        }
        arkret_wire::EventKind::SpaceArchive
        | arkret_wire::EventKind::SpaceRestore
        | arkret_wire::EventKind::SpaceTombstone => {
            crate::space_current_results::commit_space_transition_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::SpaceUpdate => {
            crate::space_current_results::commit_space_update_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::SpaceParent => {
            let payload: arkret_models_collaboration::events_payloads::space::SpaceParentPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "space_parent_current_results",
                Some(("space_id", payload.space_id.as_str())),
                &row,
                &serde_json::json!({ "parent_space_id": payload.parent_space_id }),
            )
            .await?;
        }
        arkret_wire::EventKind::RelationCreate
        | arkret_wire::EventKind::RelationUpdate
        | arkret_wire::EventKind::RelationTombstone => {
            crate::unit_of_work::commit_relation_current_result_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::ReactionAdd | arkret_wire::EventKind::ReactionRemove => {
            crate::message_reactions_current_results::commit_reaction_current_result_in_connection(
                conn, event, commit, false, None,
            )
            .await?;
        }
        arkret_wire::EventKind::PinAdd
        | arkret_wire::EventKind::PinRemove
        | arkret_wire::EventKind::PinReorder => {
            crate::pin_current_results::commit_pin_in_connection(conn, event, commit, false, None)
                .await?;
        }
        arkret_wire::EventKind::SpaceCreate => {
            let values = crate::space_current_results::space_create_current_values(event)?;
            for (table, value) in [
                ("space_current_results", &values.space),
                ("space_parent_current_results", &values.parent),
                (
                    "space_child_scope_policy_current_results",
                    &values.child_scope_policy,
                ),
            ] {
                upsert_keyed(
                    conn,
                    &event.realm_id,
                    table,
                    Some(("space_id", values.space_id.as_str())),
                    &row,
                    value,
                )
                .await?;
            }
        }
        arkret_wire::EventKind::RealmSetDefaultStrand => {
            let payload: arkret_models_collaboration::events_payloads::strand::RealmSetDefaultStrandPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "realm_set_default_strand_current_results",
                None,
                &row,
                &serde_json::json!({ "default_strand_id": payload.strand_id }),
            )
            .await?;
        }
        arkret_wire::EventKind::MessageCreate => {
            let message_id = arkret_wire::MessageId::from_event_id(&event.event_id);
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", message_id.as_str())),
                &row,
                &payload()?,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRevise => {
            let payload = payload()?;
            let message_id = payload
                .get("message_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PersistenceError::SchemaViolation("Message revise names no Message".to_owned())
                })?
                .to_owned();
            upsert_keyed(
                conn,
                &event.realm_id,
                "message_revision_current_results",
                Some(("message_id", &message_id)),
                &row,
                &payload,
            )
            .await?;
        }
        arkret_wire::EventKind::MessageRedact => {
            let payload: arkret_models_collaboration::events_payloads::message::MessageRedactPayload =
                serde_json::from_value(payload()?)
                    .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            let message_id = payload.message_id.clone();
            let value = crate::object_redaction_current_results::message_redaction_current_value(
                event, payload,
            )?;
            upsert_keyed(
                conn,
                &event.realm_id,
                "object_redaction_current_results",
                Some(("target_ref", message_id.as_str())),
                &row,
                &serde_json::to_value(&value).map_err(PersistenceError::database)?,
            )
            .await?;
        }
        _ => {}
    }
    crate::replica_authorization::advance_verified_head(conn, commit).await?;
    Ok(())
}

#[cfg(test)]
#[path = "replica_current/circle_revision_tests.rs"]
mod circle_revision_tests;

#[cfg(test)]
#[path = "replica_current/current_integrity_tests.rs"]
mod current_integrity_tests;

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn agent_policy_snapshot_and_tail_keep_exact_current_without_fabricating_admission() {
        shared_policy_snapshot_and_tail("agent").await;
    }

    #[tokio::test]
    async fn product_policies_snapshot_and_tail_keep_exact_current_and_refuse_erasure() {
        for kind in ["access", "moderation"] {
            shared_policy_snapshot_and_tail(kind).await;
        }
    }

    async fn shared_policy_snapshot_and_tail(kind: &str) {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x61; 32],
        ));
        let id =
            arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000001").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:policy-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:policy-station.example").unwrap(),
        ));
        let rules = if kind == "agent" {
            json!([{"rule_id":"ban","kind":"agent","effect":"deny",
                "agent_target":{"kind":"all"},"agent_operations":["execute"]}])
        } else {
            json!([{"rule_id":"ban","kind":"action","effect":"deny",
                "actions":["ak.typing.broadcast"]}])
        };
        let value = json!({"schema":"ak.schema.policy.v1","id":id,"realm_id":realm,
            "policy_kind":kind,"rules":rules,
            "default_effect":"allow","created_by":actor,"created_at":at});
        let head = arkret_wire::CommitStreamHead {
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entry = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Policy {
                policy_id: id.clone(),
            },
            source_stream_ref: head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: value.clone(),
        };
        for _ in 0..2 {
            install_snapshot_in_connection(
                &mut conn,
                &realm,
                &head,
                std::slice::from_ref(&entry),
                at,
            )
            .await
            .unwrap();
        }
        let read = "SELECT jsonb_build_object('rows',(SELECT jsonb_agg(to_jsonb(r)) FROM replica_authorization_rows r WHERE realm_id=$1),'heads',(SELECT jsonb_agg(to_jsonb(h)) FROM replica_authorization_cuts h WHERE realm_id=$1),'private_count',(SELECT COUNT(*) FROM policy_current_results WHERE realm_id=$1)) AS value";
        let original: ValueRow = diesel::sql_query(read)
            .bind::<Text, _>(realm.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(original.value["rows"][0]["value"], value);
        assert_eq!(original.value["private_count"], 0);
        let mut invalid = vec![];
        for field in ["id", "realm_id", "policy_kind", "schema"] {
            let mut changed = entry.clone();
            let arkret_wire::TypedCurrentRow::Value {
                value, revision, ..
            } = &mut changed;
            revision.stream_position = 8;
            revision.commit_id = arkret_wire::RealmCommitId::from_digest([8; 32]);
            value[field] = match field {
                "id" => json!("ak:policy:0198ff00-0000-7000-8000-000000000002"),
                "realm_id" => json!(null),
                "policy_kind" => json!(if kind == "agent" {
                    "access"
                } else {
                    "retention"
                }),
                _ => json!("ak.schema.recovery_policy.v1"),
            };
            invalid.push(changed);
        }
        let mut fork = entry.clone();
        let arkret_wire::TypedCurrentRow::Value {
            value: fork_value, ..
        } = &mut fork;
        fork_value["default_effect"] = json!("deny");
        invalid.push(fork);
        let mut stale = entry.clone();
        let arkret_wire::TypedCurrentRow::Value { revision, .. } = &mut stale;
        revision.stream_position = 6;
        revision.commit_id = arkret_wire::RealmCommitId::from_digest([6; 32]);
        invalid.push(stale);
        let mut foreign = entry.clone();
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut foreign;
        *source_stream_ref = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x62; 32],
            )),
        };
        invalid.push(foreign);
        let next_head = arkret_wire::CommitStreamHead {
            stream_position: 8,
            commit_id: arkret_wire::RealmCommitId::from_digest([8; 32]),
            ..head.clone()
        };
        for rows in invalid
            .into_iter()
            .map(|row| vec![row])
            .chain(std::iter::once(vec![]))
        {
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            assert!(
                install_snapshot_in_connection(&mut conn, &realm, &next_head, &rows, at)
                    .await
                    .is_err()
            );
            diesel::sql_query("ROLLBACK")
                .execute(&mut conn)
                .await
                .unwrap();
            let after: ValueRow = diesel::sql_query(read)
                .bind::<Text, _>(realm.as_str())
                .get_result(&mut conn)
                .await
                .unwrap();
            assert_eq!(after.value, original.value);
        }
        // Imported projection fixture starts after source Event/Commit verification.
        // It does not exercise production signing or Agent management admission.
        let mut next_value = value.clone();
        next_value["rules"][0]["effect"] = json!("allow");
        let mut body = json!({"policy_id":id,"value":next_value});
        if kind == "agent" {
            body["expected_revision"] = json!({"commit_id":head.commit_id,"stream_position":7});
        }
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.policy.set",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor,
            body,
            at,
        )
        .unwrap();
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: next_head.commit_id.clone(),
            realm_id: realm.clone(),
            stream_ref: head.stream_ref.clone(),
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:policy-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "aa".repeat(32)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        };
        advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        let after: ValueRow = diesel::sql_query(read)
            .bind::<Text, _>(realm.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(after.value["rows"][0]["value"], next_value);
        assert_eq!(
            after.value["rows"][0]["current_commit_id"],
            json!(commit.commit_id)
        );
        assert_eq!(after.value["private_count"], 1);
        if kind != "agent" {
            // A complete Realm cut cannot erase a visible Policy, but a Circle
            // omitted from visible heads proves no authority over that stream.
            let current = arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Policy {
                    policy_id: id.clone(),
                },
                source_stream_ref: commit.stream_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: 8,
                },
                value: next_value.clone(),
            };
            let circle_source = arkret_wire::CommitStreamRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_wire::CircleId::from_event_id(
                    &arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0x62; 32],
                    ),
                ),
            };
            let circle_head = arkret_wire::CommitStreamHead {
                stream_ref: circle_source.clone(),
                stream_position: 3,
                commit_id: arkret_wire::RealmCommitId::from_digest([3; 32]),
            };
            let circle_id =
                arkret_wire::PolicyId::new("ak:policy:0198ff00-0000-7000-8000-000000000002")
                    .unwrap();
            let mut circle_value = next_value;
            circle_value["id"] = json!(circle_id);
            let circle = arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Policy {
                    policy_id: circle_id,
                },
                source_stream_ref: circle_source,
                revision: arkret_wire::CurrentRevision {
                    commit_id: circle_head.commit_id.clone(),
                    stream_position: 3,
                },
                value: circle_value,
            };
            install_snapshot_at_heads_in_connection(
                &mut conn,
                &realm,
                &next_head,
                &[next_head.clone(), circle_head],
                &[current.clone(), circle],
                at,
            )
            .await
            .unwrap();
            install_snapshot_in_connection(&mut conn, &realm, &next_head, &[current], at)
                .await
                .unwrap();
            return;
        }
        // The historical reducer never re-applies the producer's old CAS.
        let mut rebound = next_value;
        rebound["policy_kind"] = json!("access");
        rebound["rules"] = json!([{"rule_id":"allow","kind":"action","effect":"allow","actions":["ak.message.create"]}]);
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.policy.set",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            event.actor_id.clone(),
            json!({"policy_id":id,"value":rebound}),
            at,
        )
        .unwrap();
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
            stream_position: 9,
            previous_commit_ref: Some(commit.commit_id.clone()),
            event_ref: event.event_id.clone(),
            ..commit
        };
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        assert!(
            advance_in_connection(&mut conn, &event, &commit)
                .await
                .is_err()
        );
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        let unchanged: ValueRow = diesel::sql_query(read)
            .bind::<Text, _>(realm.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
        assert_eq!(unchanged.value, after.value);
    }

    #[tokio::test]
    async fn binding_snapshot_and_successor_fold_keep_native_current_and_reject_forks() {
        use arkret_models_collaboration::events_payloads::direct_conversation::{
            DirectConversationBindingCurrentValue, DirectConversationBindingEndorsementEntry,
            DirectConversationBoundPayload,
        };
        use arkret_models_collaboration::exact_current_results::CanonicalEventDot;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let id = |byte| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
        };
        let realm = arkret_wire::RealmId::from_event_id(&id(1));
        let actor = |name: &str| {
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:binding-station.example").unwrap(),
            ))
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let payload: DirectConversationBoundPayload = serde_json::from_value(json!({
            "pair_key":format!("sha256:{}", "1".repeat(64)),
            "unordered_participant_ids":[actor("alice"),actor("bob")],
            "realm_id":realm,"main_strand_id":arkret_wire::StrandId::from_event_id(&id(2)),
            "founding_unit_digest":format!("sha256:{}", "2".repeat(64)),
            "authorization_basis":{"kind":"accepted_contact","event_refs":[id(3),id(6)]},
            "initial_exact_pair_group_state_ref":id(4),"created_at":at,
        }))
        .unwrap();
        let initial = DirectConversationBindingCurrentValue {
            endorsements: vec![DirectConversationBindingEndorsementEntry {
                tag_id: CanonicalEventDot::new(id(5), 0).unwrap(),
                value: payload.clone(),
            }],
        };
        let source = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: source.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entry = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::DirectConversationBinding {
                pair_key: payload.pair_key.clone(),
            },
            source_stream_ref: source.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: serde_json::to_value(&initial).unwrap(),
        };
        install_snapshot_in_connection(&mut conn, &realm, &head, std::slice::from_ref(&entry), at)
            .await
            .unwrap();
        install_snapshot_in_connection(&mut conn, &realm, &head, std::slice::from_ref(&entry), at)
            .await
            .unwrap();
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.direct_conversation.bound",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor("bob"),
            serde_json::to_value(&payload).unwrap(),
            at,
        )
        .unwrap();
        // Projection input is downstream of source Commit verification, as in
        // the other replica fold tests. This is not a live signer fixture.
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([8; 32]),
            realm_id: realm.clone(),
            stream_ref: source.clone(),
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(id(1)),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:binding-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        };
        advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        drop(conn);
        let mut conn = pool.get().await.unwrap();
        let current =
            crate::direct_conversation_admission::binding_current_in_connection(&mut conn, &realm)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(current.endorsements.len(), 2);
        assert!(current.endorsed_by(&event.event_id));
        assert_eq!(
            current.binding_digest().unwrap(),
            initial.binding_digest().unwrap()
        );
        let complete = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::DirectConversationBinding {
                pair_key: payload.pair_key.clone(),
            },
            source_stream_ref: source.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: commit.commit_id.clone(),
                stream_position: 8,
            },
            value: serde_json::to_value(current).unwrap(),
        };
        for mutation in 0..5 {
            let mut bad = complete.clone();
            let arkret_wire::TypedCurrentRow::Value {
                revision,
                value,
                selector,
                source_stream_ref,
            } = &mut bad;
            match mutation {
                0 => revision.stream_position = 7,
                1 => revision.commit_id = arkret_wire::RealmCommitId::from_digest([9; 32]),
                2 => {
                    revision.stream_position = 9;
                    *value = serde_json::to_value(&initial).unwrap();
                }
                3 => {
                    *selector = arkret_wire::CurrentSelector::DirectConversationBinding {
                        pair_key: arkret_wire::Hash::new(format!("sha256:{}", "4".repeat(64)))
                            .unwrap(),
                    }
                }
                _ => {
                    *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
                        realm_id: arkret_wire::RealmId::from_event_id(&id(9)),
                    }
                }
            }
            assert!(
                guard_snapshot_revisions(&mut conn, &realm, &[bad])
                    .await
                    .is_err()
            );
        }
        let newer = arkret_wire::CommitStreamHead {
            stream_ref: source,
            stream_position: 8,
            commit_id: commit.commit_id,
        };
        assert!(
            install_snapshot_in_connection(&mut conn, &realm, &newer, &[], at)
                .await
                .is_err()
        );
        install_snapshot_in_connection(&mut conn, &realm, &newer, &[complete], at)
            .await
            .unwrap();
        assert_eq!(
            crate::direct_conversation_admission::binding_current_in_connection(&mut conn, &realm)
                .await
                .unwrap()
                .unwrap()
                .endorsements
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn pin_snapshot_guard_keeps_assertions_and_exact_stream_before_replacement() {
        use arkret_models_collaboration::exact_current_results::CanonicalEventDot;
        use arkret_models_collaboration::objects::productivity::{
            PinAddPayload, PinAssertionEntry, PinAssertionPayload, PinCurrentValue,
        };
        use arkret_wire::{
            CommitStreamRef, CurrentRevision, CurrentSelector, EventId, PinScope, RealmCommitId,
            RealmId, TypedCurrentRow,
        };
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x21; 32]);
        let realm = RealmId::from_event_id(&event);
        let home = PinScope::Realm { id: realm.clone() };
        let source = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let commit = RealmCommitId::from_digest([0x42; 32]);
        let set = PinCurrentValue::new(vec![PinAssertionEntry {
            tag_id: CanonicalEventDot::new(event.clone(), 0).unwrap(),
            value: PinAssertionPayload::Add(PinAddPayload {
                pin_scope: home.clone(),
                target_ref: arkret_wire::MessageId::from_event_id(&event).to_string(),
                rank: "a0".into(),
                note: None,
            }),
        }])
        .unwrap();
        let value = serde_json::to_value(set).unwrap();
        diesel::sql_query("INSERT INTO pin_current_results (realm_id,pin_scope_key,pin_scope,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,7,$6,now())")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(arkret_canonical::canonical_json_string(&home).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&home).unwrap()).bind::<Jsonb,_>(serde_json::to_value(&source).unwrap())
            .bind::<Text,_>(commit.as_str()).bind::<Jsonb,_>(&value).execute(&mut *conn).await.unwrap();
        let entry = TypedCurrentRow::Value {
            selector: CurrentSelector::Pin { pin_scope: home },
            source_stream_ref: source,
            revision: CurrentRevision {
                commit_id: commit,
                stream_position: 7,
            },
            value,
        };
        guard_snapshot_revisions(&mut conn, &realm, std::slice::from_ref(&entry))
            .await
            .unwrap();
        for mutation in 0..4 {
            let mut changed = entry.clone();
            let TypedCurrentRow::Value {
                source_stream_ref,
                revision,
                value,
                ..
            } = &mut changed;
            match mutation {
                0 => {
                    revision.stream_position = 8;
                    value["assertions"] = serde_json::json!([]);
                }
                1 => {
                    revision.stream_position = 8;
                    *source_stream_ref = CommitStreamRef::Realm {
                        realm_id: RealmId::from_event_id(&EventId::from_digest(
                            arkret_canonical::DigestSuite::Sha256,
                            [0x43; 32],
                        )),
                    };
                }
                2 => revision.stream_position = 6,
                _ => revision.commit_id = RealmCommitId::from_digest([0x44; 32]),
            }
            assert!(matches!(
                guard_snapshot_revisions(&mut conn, &realm, &[changed]).await,
                Err(PersistenceError::Conflict(_))
            ));
        }
        guard_snapshot_revisions(&mut conn, &realm, &[entry])
            .await
            .unwrap();
    }

    #[derive(Clone)]
    enum FixtureWriter {
        Singleton(&'static str),
        Keyed(&'static str, Option<(&'static str, String)>),
        Member(arkret_wire::ActorId),
    }

    impl FixtureWriter {
        async fn write(
            &self,
            conn: &mut AsyncPgConnection,
            realm: &arkret_wire::RealmId,
            revision: &Revision<'_>,
            value: &Value,
        ) -> PersistenceResult<()> {
            match self {
                Self::Singleton(family) => {
                    upsert_singleton(conn, realm, family, revision, value).await
                }
                Self::Keyed(table, key) => {
                    upsert_keyed(
                        conn,
                        realm,
                        table,
                        key.as_ref().map(|(column, key)| (*column, key.as_str())),
                        revision,
                        value,
                    )
                    .await
                }
                Self::Member(actor) => {
                    upsert_member_state(conn, realm, actor, revision, value).await
                }
            }
        }
    }

    #[tokio::test]
    async fn replica_current_writers_keep_revision_value_and_realm_identity() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        let id = |byte| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
        };
        let realm = arkret_wire::RealmId::from_event_id(&id(1));
        let foreign = arkret_wire::RealmId::from_event_id(&id(2));
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:member.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let original = Revision {
            commit_id: "original",
            stream_position: 7,
            updated_at: at,
        };
        let next = Revision {
            commit_id: "next",
            stream_position: 8,
            updated_at: at,
        };
        let stale = Revision {
            commit_id: "stale",
            stream_position: 6,
            updated_at: at,
        };
        let fork = Revision {
            commit_id: "fork",
            stream_position: 7,
            updated_at: at,
        };
        let mut cases = [
            "realm_genesis",
            "realm_profile",
            "realm_join_rule",
            "realm_history_access",
            "realm_preview_policy",
            "realm_discovery",
            "realm_alias",
            "realm_plaintext_visible_services",
        ]
        .into_iter()
        .map(|family| {
            (
                FixtureWriter::Singleton(family),
                json!({"original":true}),
                json!({"changed":true}),
            )
        })
        .collect::<Vec<_>>();
        let keyed =
            |table, column, key: &str| FixtureWriter::Keyed(table, Some((column, key.to_owned())));
        cases.extend([
            (
                FixtureWriter::Keyed("realm_policy_bundle_current_results", None),
                json!({"original":true}),
                json!({"changed":true}),
            ),
            (
                FixtureWriter::Keyed("realm_set_default_strand_current_results", None),
                json!({"default_strand_id":"strand"}),
                json!({"default_strand_id":"next-strand"}),
            ),
            (
                keyed("strand_current_results", "strand_id", "strand"),
                json!({"id":"strand","realm_id":realm,"title":"original"}),
                json!({"id":"strand","realm_id":realm,"title":"changed"}),
            ),
            (
                keyed("space_current_results", "space_id", "space"),
                json!({"id":"space","realm_id":realm,"title":"original"}),
                json!({"id":"space","realm_id":realm,"title":"changed"}),
            ),
            (
                keyed("space_parent_current_results", "space_id", "space"),
                json!({"parent_space_id":null}),
                json!({"parent_space_id":"parent"}),
            ),
            (
                keyed(
                    "space_child_scope_policy_current_results",
                    "space_id",
                    "space",
                ),
                Value::Null,
                json!({"changed":true}),
            ),
            (
                keyed("message_revision_current_results", "message_id", "message"),
                json!({"strand_id":"strand","track_name":"discussion","text":"original"}),
                json!({"strand_id":"strand","track_name":"discussion","text":"changed"}),
            ),
            (
                keyed("object_redaction_current_results", "target_ref", "target"),
                json!({"assertions":[{"tag":"original"}]}),
                json!({"assertions":[{"tag":"changed"}]}),
            ),
            (
                FixtureWriter::Member(actor),
                json!({"membership":"join","original":true}),
                json!({"membership":"join","changed":true}),
            ),
        ]);
        for (writer, value, changed) in cases {
            writer
                .write(&mut conn, &realm, &original, &value)
                .await
                .unwrap();
            writer
                .write(&mut conn, &realm, &original, &value)
                .await
                .unwrap();
            for (revision, candidate) in [(&stale, &value), (&fork, &value), (&original, &changed)]
            {
                assert!(matches!(
                    writer.write(&mut conn, &realm, revision, candidate).await,
                    Err(PersistenceError::Conflict(_))
                ));
            }
            if matches!(
                &writer,
                FixtureWriter::Keyed(
                    "strand_current_results"
                        | "space_current_results"
                        | "space_parent_current_results"
                        | "space_child_scope_policy_current_results"
                        | "message_revision_current_results",
                    Some(_)
                )
            ) {
                // Try a newer receipt from a different Realm, which used to
                // overwrite shared object identities at the global PK.
                let mut foreign_value = changed.clone();
                if let Some(value) = foreign_value.as_object_mut()
                    && value.contains_key("realm_id")
                {
                    value.insert("realm_id".to_owned(), json!(foreign));
                }
                assert!(matches!(
                    writer
                        .write(&mut conn, &foreign, &next, &foreign_value)
                        .await,
                    Err(PersistenceError::Conflict(_))
                ));
            }
            writer
                .write(&mut conn, &realm, &next, &changed)
                .await
                .unwrap();
            writer
                .write(&mut conn, &realm, &next, &changed)
                .await
                .unwrap();
            assert!(
                writer
                    .write(&mut conn, &realm, &original, &value)
                    .await
                    .is_err()
            );
        }
    }
    use diesel::sql_types::Text;
    use diesel_async::RunQueryDsl;
    use serde_json::json;

    use super::*;
    use crate::test_database::TestDatabase;

    #[tokio::test]
    async fn franking_replica_current_rejects_stale_and_forked_revisions() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        let id = |byte| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
        };
        let realm = arkret_wire::RealmId::from_event_id(&id(1));
        let target = id(2);
        let source = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let original = Revision {
            commit_id: "proof-original",
            stream_position: 7,
            updated_at: at,
        };
        let value = json!({"event_id":target,"proof":"original"});
        upsert_franking_proof(&mut conn, &realm, &target, &source, &original, &value)
            .await
            .unwrap();
        upsert_franking_proof(&mut conn, &realm, &target, &source, &original, &value)
            .await
            .unwrap();
        for (commit_id, stream_position, candidate) in [
            ("stale", 6, value.clone()),
            ("fork", 7, value.clone()),
            (
                "proof-original",
                7,
                json!({"event_id":target,"proof":"fork"}),
            ),
        ] {
            let revision = Revision {
                commit_id,
                stream_position,
                updated_at: at,
            };
            assert!(matches!(
                upsert_franking_proof(&mut conn, &realm, &target, &source, &revision, &candidate)
                    .await,
                Err(PersistenceError::Conflict(_))
            ));
        }
        let entry = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::ModerationFrankingProof {
                event_id: target.clone(),
            },
            source_stream_ref: source.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
                stream_position: 7,
            },
            value: value.clone(),
        };
        assert!(matches!(
            guard_snapshot_revisions(&mut conn, &realm, &[entry]).await,
            Err(PersistenceError::Conflict(_))
        ));
        let next = Revision {
            commit_id: "proof-next",
            stream_position: 8,
            updated_at: at,
        };
        let updated = json!({"event_id":target,"proof":"next"});
        upsert_franking_proof(&mut conn, &realm, &target, &source, &next, &updated)
            .await
            .unwrap();
        let row = diesel::sql_query("SELECT value FROM moderation_franking_proof_current_results WHERE realm_id=$1 AND target_event_id=$2")
            .bind::<Text, _>(realm.as_str())
            .bind::<Text, _>(target.as_str())
            .get_result::<ValueRow>(&mut conn)
            .await
            .unwrap();
        assert_eq!(row.value, updated);
    }

    #[derive(diesel::QueryableByName)]
    struct ValueRow {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }

    #[tokio::test]
    async fn terminal_snapshot_is_sticky_and_blocks_fresh_child_effects() {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 9,
            commit_id: arkret_wire::RealmCommitId::from_digest([42; 32]),
        };
        let value = json!({"reason":"migration", "successor_realm_id":
            "ak:realm:ASR8x2N1qyfyy6I-eob3l-FNhx4FPBTyMJrIfifkksgW"});
        let entry = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::RealmTombstone,
            source_stream_ref: stream,
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 9,
            },
            value: value.clone(),
        };
        let at = chrono::Utc::now();
        for _ in 0..2 {
            install_snapshot_in_connection(
                &mut conn,
                &realm,
                &head,
                std::slice::from_ref(&entry),
                at,
            )
            .await
            .unwrap();
        }
        let error = install_snapshot_in_connection(&mut conn, &realm, &head, &[], at)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.space.update",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor,
            json!({}),
            at,
        )
        .unwrap();
        let error = crate::realm_lifecycle_current_results::require_replica_live_in_connection(
            &mut conn, &event,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("failed_precondition"), "{error}");
        let retained = diesel::sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_tombstone'")
            .bind::<Text, _>(realm.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap();
        assert_eq!(retained.value, value);
    }

    #[tokio::test]
    async fn call_genesis_snapshot_replica_keeps_exact_source_and_rejects_cross_scope_reuse() {
        let database = TestDatabase::lease().await;
        let realm =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let call = arkret_wire::CallId::new("ak:call:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
            .unwrap();
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let value = serde_json::json!({"from":null,"to":"ringing"});
        let entries = [arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CallState {
                call_id: call.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: value.clone(),
        }];
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let at = chrono::Utc::now();
        // The caller verifies the signed bootstrap before this durable sink.
        // Retained genesis history can be absent at the disclosure floor.
        for _ in 0..2 {
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            install_snapshot_in_connection(&mut conn, &realm, &head, &entries, at)
                .await
                .unwrap();
            diesel::sql_query("COMMIT")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let stored=diesel::sql_query("SELECT jsonb_build_object('source',source_stream_ref,'value',value,'create',create_event_id) AS value FROM call_state_current_results WHERE realm_id=$1 AND call_id=$2")
            .bind::<Text,_>(realm.as_str()).bind::<Text,_>(call.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap().value;
        assert_eq!(stored["source"], serde_json::json!(&stream));
        assert_eq!(stored["value"], value);
        assert_eq!(
            stored["create"],
            call.as_str().replacen("ak:call:", "ak:event:", 1)
        );
        let other = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::new(
                "ak:circle:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7",
            )
            .unwrap(),
        };
        let commit_id = head.commit_id.to_string();
        let revision = Revision {
            commit_id: &commit_id,
            stream_position: 7,
            updated_at: at,
        };
        assert!(
            upsert_call_genesis(&mut conn, &realm, &call, &other, &revision, &value)
                .await
                .is_err()
        );
        assert!(
            upsert_call_genesis(
                &mut conn,
                &realm,
                &call,
                &stream,
                &revision,
                &serde_json::json!({"from":null,"to":"active"})
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn space_families_snapshot_install_keeps_registered_values() {
        let database = TestDatabase::lease().await;
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let space_id =
            arkret_wire::SpaceId::new("ak:space:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let commit_id = arkret_wire::RealmCommitId::from_digest([7u8; 32]);
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: commit_id.clone(),
        };
        let revision = arkret_wire::CurrentRevision {
            commit_id,
            stream_position: 7,
        };
        let metadata = json!({
            "id":space_id,
            "realm_id":realm_id,
            "schema":"ak.schema.space.v1",
            "kind":"board",
            "title":"Replica board",
            "state":"active"
        });
        let parent = json!({"parent_space_id":null});
        let policy = Value::Null;
        let entry = |selector, value| arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref: stream.clone(),
            revision: revision.clone(),
            value,
        };
        // Deliberately put the sibling families before Space metadata. The
        // deferred FK must be satisfied by the complete snapshot transaction.
        let entries = vec![
            entry(
                arkret_wire::CurrentSelector::SpaceParent {
                    space_id: space_id.clone(),
                },
                parent.clone(),
            ),
            entry(
                arkret_wire::CurrentSelector::SpaceChildScopePolicy {
                    space_id: space_id.clone(),
                },
                policy.clone(),
            ),
            entry(
                arkret_wire::CurrentSelector::Space {
                    space_id: space_id.clone(),
                },
                metadata.clone(),
            ),
        ];
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        for _ in 0..2 {
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            install_snapshot_in_connection(
                &mut conn,
                &realm_id,
                &head,
                &entries,
                chrono::Utc::now(),
            )
            .await
            .unwrap();
            diesel::sql_query("COMMIT")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        for (table, expected) in [
            ("space_current_results", metadata),
            ("space_parent_current_results", parent),
            ("space_child_scope_policy_current_results", policy),
        ] {
            let row: ValueRow = diesel::sql_query(format!(
                "SELECT value FROM {table} WHERE realm_id=$1 AND space_id=$2"
            ))
            .bind::<Text, _>(realm_id.as_str())
            .bind::<Text, _>(space_id.as_str())
            .get_result(&mut conn)
            .await
            .unwrap();
            assert_eq!(row.value, expected);
        }

        let at =
            chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
        let author = arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap();
        let station =
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(author, station));
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.space.create",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor.clone(),
            json!({"object":{
                "schema":"ak.schema.space.v1",
                "realm_id":realm_id,
                "parent_space_id":space_id,
                "kind":"list",
                "title":"Replicated list",
                "created_by":actor,
                "created_at":arkret_canonical::format_timestamp_canonical(at)
            }}),
            at,
        )
        .unwrap();
        let digest = arkret_wire::Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .unwrap(),
        )
        .unwrap();
        event.producer_proof = Some(arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                .unwrap(),
            event_digest: digest.clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(at),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
        });
        let next_id = arkret_wire::SpaceId::from_event_id(&event.event_id);
        let next_commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([8u8; 32]),
            realm_id: realm_id.clone(),
            stream_ref: stream,
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:replica-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl".to_owned()).unwrap(),
            },
        };
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        advance_in_connection(&mut conn, &event, &next_commit)
            .await
            .unwrap();
        diesel::sql_query("COMMIT")
            .execute(&mut conn)
            .await
            .unwrap();
        let next_parent: ValueRow =
            diesel::sql_query("SELECT value FROM space_parent_current_results WHERE space_id=$1")
                .bind::<Text, _>(next_id.as_str())
                .get_result(&mut conn)
                .await
                .unwrap();
        assert_eq!(next_parent.value, json!({"parent_space_id":space_id}));
        let next_policy: ValueRow = diesel::sql_query(
            "SELECT value FROM space_child_scope_policy_current_results WHERE space_id=$1",
        )
        .bind::<Text, _>(next_id.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(next_policy.value, Value::Null);
    }

    #[tokio::test]
    async fn strand_update_replica_advances_current_and_preserves_stale_cas_rejection() {
        use arkret_models_collaboration::objects::strand::Strand;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let strand_id =
            arkret_wire::StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap(),
        ));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut strand = Strand::new(strand_id.clone(), realm_id.clone(), "Before", actor.clone());
        strand.created_at = at;
        let before = serde_json::to_value(strand).unwrap();
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entries = [arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: before.clone(),
        }];
        install_snapshot_in_connection(&mut conn, &realm_id, &head, &entries, at)
            .await
            .unwrap();
        let expected = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&before).unwrap(),
        );
        for (position, title, accepted) in [(8, "After", true), (9, "Stale", false)] {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::StrandUpdate.as_str(),
                arkret_wire::ScopeRef::Realm { realm_id: realm_id.clone() }, actor.clone(),
                json!({"target_ref":strand_id,"expected_state_digest":expected,"patch":{"metadata.title":{"$op":"set","value":title}}}), at,
            ).unwrap();
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            // This fold is tested after the replica verifier boundary. The
            // SDK structural proof fixture is not accepted as a live signer.
            event.producer_proof = Some(arkret_wire::ProducerEventProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                    .unwrap(),
                event_digest: digest.clone(),
                created_at: at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
            });
            let commit = arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                stream_position: position,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
                    [(position - 1) as u8; 32],
                )),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                committed_at: at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:replica-station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
                },
            };
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            let result = advance_in_connection(&mut conn, &event, &commit).await;
            assert_eq!(result.is_ok(), accepted, "{result:?}");
            diesel::sql_query(if accepted { "COMMIT" } else { "ROLLBACK" })
                .execute(&mut conn)
                .await
                .unwrap();
            let row: ValueRow =
                diesel::sql_query("SELECT value FROM strand_current_results WHERE strand_id=$1")
                    .bind::<Text, _>(strand_id.as_str())
                    .get_result(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(row.value["metadata"]["title"], "After");
        }
    }

    #[tokio::test]
    async fn strand_tracks_update_replica_moves_primary_and_rejects_invalid_track_sets() {
        use arkret_models_collaboration::objects::strand::Strand;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm_id =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let active_id =
            arkret_wire::StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let archived_id =
            arkret_wire::StrandId::new("ak:strand:AQ0TR0sBDqKm829Sb5QBpmH0XLw6VOIDfnYcIBxXFQMg")
                .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap(),
        ));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entries = [
            (&active_id, arkret_wire::ObjectState::Active),
            (&archived_id, arkret_wire::ObjectState::Archived),
        ]
        .map(|(strand_id, state)| {
            let mut strand =
                Strand::new(strand_id.clone(), realm_id.clone(), "Tracks", actor.clone());
            strand.created_at = at;
            strand.state = Some(state);
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::Strand {
                    strand_id: strand_id.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: head.commit_id.clone(),
                    stream_position: 7,
                },
                value: serde_json::to_value(strand).unwrap(),
            }
        });
        install_snapshot_in_connection(&mut conn, &realm_id, &head, &entries, at)
            .await
            .unwrap();
        let cases = [
            // The primary moves to a newly enabled discussion track atomically.
            (
                8,
                &active_id,
                json!({
                    "tracks.discussion.enabled": {"$op":"set","value":true},
                    "tracks.discussion.is_primary": {"$op":"set","value":true},
                    "tracks.synthesis.is_primary": {"$op":"set","value":false}
                }),
                None,
            ),
            // Disabling the current primary leaves no primary track.
            (
                9,
                &active_id,
                json!({"tracks.discussion.enabled": {"$op":"set","value":false}}),
                Some("track_disabled"),
            ),
            // Every track key must be a registered track name.
            (
                9,
                &active_id,
                json!({"tracks.review.enabled": {"$op":"set","value":true}}),
                Some("unregistered Strand track name"),
            ),
            // The tracks writer owns only the tracks map.
            (
                9,
                &active_id,
                json!({"metadata.title": {"$op":"set","value":"Other"}}),
                Some("patch path is forbidden"),
            ),
            // A track mutation is an update of a non-active Strand.
            (
                9,
                &archived_id,
                json!({"tracks.discussion.enabled": {"$op":"set","value":true}}),
                Some("strand_not_active"),
            ),
        ];
        for (position, strand_id, patch, refusal) in cases {
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::StrandTracksUpdate.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor.clone(),
                json!({"target_ref": strand_id, "patch": patch}),
                at,
            )
            .unwrap();
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            // This fold is tested after the replica verifier boundary. The
            // SDK structural proof fixture is not accepted as a live signer.
            event.producer_proof = Some(arkret_wire::ProducerEventProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                    .unwrap(),
                event_digest: digest.clone(),
                created_at: at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
            });
            let commit = arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                stream_position: position,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
                    [(position - 1) as u8; 32],
                )),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                committed_at: at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:replica-station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
                },
            };
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            let result = advance_in_connection(&mut conn, &event, &commit).await;
            match refusal {
                None => assert!(result.is_ok(), "{result:?}"),
                Some(expected) => {
                    let error = result.expect_err("invalid tracks update must be refused");
                    assert!(error.to_string().contains(expected), "{error}");
                }
            }
            diesel::sql_query(if refusal.is_none() {
                "COMMIT"
            } else {
                "ROLLBACK"
            })
            .execute(&mut conn)
            .await
            .unwrap();
        }
        let row: ValueRow =
            diesel::sql_query("SELECT value FROM strand_current_results WHERE strand_id=$1")
                .bind::<Text, _>(active_id.as_str())
                .get_result(&mut conn)
                .await
                .unwrap();
        assert_eq!(row.value["tracks"]["discussion"]["enabled"], true);
        assert_eq!(row.value["tracks"]["discussion"]["is_primary"], true);
        assert_eq!(row.value["tracks"]["synthesis"]["is_primary"], false);
        assert_eq!(row.value["metadata"]["title"], "Tracks");
        assert_eq!(
            row.value["updated_by"],
            serde_json::to_value(&actor).unwrap()
        );
    }

    #[tokio::test]
    async fn strand_transition_replica_follows_snapshot_baseline_without_local_covering_commits() {
        use arkret_models_collaboration::objects::strand::Strand;
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm =
            arkret_wire::RealmId::new("ak:realm:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let strand_id =
            arkret_wire::StrandId::new("ak:strand:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7")
                .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap(),
        ));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut strand = Strand::new(
            strand_id.clone(),
            realm.clone(),
            "Snapshot Strand",
            actor.clone(),
        );
        strand.created_at = at;
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entries = [arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Strand {
                strand_id: strand_id.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: head.commit_id.clone(),
                stream_position: 7,
            },
            value: serde_json::to_value(strand).unwrap(),
        }];
        // The signed snapshot and each following Event/Commit were verified
        // before this adapter boundary. Structural signatures here are not
        // claimed as live acceptance or a snapshot signature verification test.
        install_snapshot_in_connection(&mut conn, &realm, &head, &entries, at)
            .await
            .unwrap();
        let history: ValueRow =
            diesel::sql_query("SELECT to_jsonb(count(*)) AS value FROM realm_commits")
                .get_result(&mut conn)
                .await
                .unwrap();
        assert_eq!(
            history.value,
            json!(0),
            "snapshot installation does not invent local covering Commit nodes"
        );
        let mut first = None;
        for (position, kind, payload, expected_state, expected_stage) in [
            (
                8,
                arkret_wire::EventKind::StrandStageSet,
                json!({"strand_id":strand_id,"stage":"planned"}),
                "active",
                "planned",
            ),
            (
                9,
                arkret_wire::EventKind::StrandArchive,
                json!({"target_ref":strand_id}),
                "archived",
                "planned",
            ),
            (
                10,
                arkret_wire::EventKind::StrandRestore,
                json!({"target_ref":strand_id}),
                "active",
                "planned",
            ),
            (
                11,
                arkret_wire::EventKind::StrandStageSet,
                json!({"strand_id":strand_id,"stage":"done","expected_stage":"planned"}),
                "active",
                "done",
            ),
        ] {
            let event_at = at + chrono::Duration::seconds(position);
            let mut event = arkret_wire::test_support::raw_event_for_actor_at(
                kind.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                payload,
                event_at,
            )
            .unwrap();
            let digest = arkret_wire::Hash::new(
                event
                    .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap();
            event.producer_proof = Some(arkret_wire::ProducerEventProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: arkret_wire::DidUrl::new("did:web:replica-author.example#key")
                    .unwrap(),
                event_digest: digest.clone(),
                created_at: event_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
            });
            let commit_at = event_at + chrono::Duration::milliseconds(500);
            let commit = arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                stream_position: position as u64,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
                    [(position - 1) as u8; 32],
                )),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                committed_at: commit_at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:replica-station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: commit_at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
                },
            };
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            let result = advance_in_connection(&mut conn, &event, &commit).await;
            diesel::sql_query(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .execute(&mut conn)
                .await
                .unwrap();
            result.unwrap();
            let row: ValueRow =
                diesel::sql_query("SELECT value FROM strand_current_results WHERE strand_id=$1")
                    .bind::<Text, _>(strand_id.as_str())
                    .get_result(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(row.value["state"], expected_state);
            assert_eq!(row.value["stage"], expected_stage);
            if kind == arkret_wire::EventKind::StrandStageSet {
                assert_eq!(
                    row.value["stage_changed_at"],
                    arkret_canonical::format_timestamp_canonical(event_at)
                );
            } else {
                assert_eq!(
                    row.value["state_changed_at"],
                    arkret_canonical::format_timestamp_canonical(commit_at)
                );
            }
            let revision:ValueRow = diesel::sql_query("SELECT jsonb_build_object('commit',current_commit_id,'position',current_stream_position) AS value FROM strand_current_results WHERE strand_id=$1").bind::<Text,_>(strand_id.as_str()).get_result(&mut conn).await.unwrap();
            assert_eq!(
                revision.value,
                json!({"commit":commit.commit_id,"position":position})
            );
            if position == 8 {
                first = Some((event, commit));
            }
        }
        let before:ValueRow = diesel::sql_query("SELECT jsonb_build_object('value',value,'commit',current_commit_id,'position',current_stream_position) AS value FROM strand_current_results WHERE strand_id=$1").bind::<Text,_>(strand_id.as_str()).get_result(&mut conn).await.unwrap();
        let (event, commit) = first.unwrap();
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        let error = advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap_err();
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(error.to_string().contains("does not precede transition"));
        let after:ValueRow = diesel::sql_query("SELECT jsonb_build_object('value',value,'commit',current_commit_id,'position',current_stream_position) AS value FROM strand_current_results WHERE strand_id=$1").bind::<Text,_>(strand_id.as_str()).get_result(&mut conn).await.unwrap();
        assert_eq!(
            before.value, after.value,
            "a late older transition cannot undo the verified current"
        );
    }

    #[tokio::test]
    async fn position_snapshot_keeps_both_identity_components_null_and_transactional_rejection() {
        use arkret_models_collaboration::objects::strand::StrandPositionCurrent;
        use arkret_wire::{CurrentRevision, CurrentSelector, SpaceId, StrandId, TypedCurrentRow};
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let id = |byte| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
        };
        let realm = arkret_wire::RealmId::from_event_id(&id(1));
        let strand = StrandId::from_event_id(&id(2));
        let board_a = SpaceId::from_event_id(&id(3));
        let board_b = SpaceId::from_event_id(&id(4));
        let list = SpaceId::from_event_id(&id(5));
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let revision = CurrentRevision {
            commit_id: head.commit_id.clone(),
            stream_position: 7,
        };
        let placed = Some(StrandPositionCurrent {
            list_space_id: list.clone(),
            rank: "a0".to_owned(),
        });
        // The caller has verified the snapshot; this test exercises the
        // durable sink and its transaction boundary, not a signed disclosure.
        let entries = [
            TypedCurrentRow::Value {
                selector: CurrentSelector::StrandPosition {
                    board_space_id: board_a.clone(),
                    strand_id: strand.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: serde_json::to_value(&placed).unwrap(),
            },
            TypedCurrentRow::Value {
                selector: CurrentSelector::StrandPosition {
                    board_space_id: board_b.clone(),
                    strand_id: strand.clone(),
                },
                source_stream_ref: stream.clone(),
                revision: revision.clone(),
                value: Value::Null,
            },
        ];
        install_snapshot_in_connection(&mut conn, &realm, &head, &entries, at)
            .await
            .unwrap();
        install_snapshot_in_connection(&mut conn, &realm, &head, &entries, at)
            .await
            .unwrap();
        // Duplicate selectors must fail before clearing any installed rows,
        // even when they carry an identical value at an identical revision.
        let duplicate = [entries[0].clone(), entries[0].clone()];
        assert!(
            install_snapshot_in_connection(&mut conn, &realm, &head, &duplicate, at)
                .await
                .is_err()
        );
        for (board, expected) in [
            (&board_a, serde_json::to_value(&placed).unwrap()),
            (&board_b, Value::Null),
        ] {
            let actual: ValueRow = diesel::sql_query(
                "SELECT value FROM strand_position_current_results WHERE board_space_id=$1 AND strand_id=$2",
            ).bind::<Text,_>(board.as_str()).bind::<Text,_>(strand.as_str())
                .get_result(&mut conn).await.unwrap();
            assert_eq!(actual.value, expected);
        }
        // A replay must agree on both receipt and value at the same position.
        for (candidate_revision, candidate_value) in [
            (
                CurrentRevision {
                    commit_id: arkret_wire::RealmCommitId::from_digest([99; 32]),
                    stream_position: 7,
                },
                placed.clone(),
            ),
            (
                revision.clone(),
                Some(StrandPositionCurrent {
                    list_space_id: list.clone(),
                    rank: "b0".to_owned(),
                }),
            ),
        ] {
            assert!(
                crate::strand_position_current_results::install_in_connection(
                    &mut conn,
                    &realm,
                    &board_a,
                    &strand,
                    &candidate_revision,
                    &candidate_value,
                    at,
                )
                .await
                .is_err()
            );
        }
        let foreign_realm = arkret_wire::RealmId::from_event_id(&id(6));
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        assert!(
            crate::strand_position_current_results::install_in_connection(
                &mut conn,
                &foreign_realm,
                &board_a,
                &strand,
                &revision,
                &None,
                at,
            )
            .await
            .is_err()
        );
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        let mut malformed = entries.to_vec();
        let TypedCurrentRow::Value { value, .. } = &mut malformed[1];
        *value = json!({"rank":"partial"});
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        assert!(
            install_snapshot_in_connection(&mut conn, &realm, &head, &malformed, at)
                .await
                .is_err()
        );
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        let actual: ValueRow = diesel::sql_query(
            "SELECT value FROM strand_position_current_results WHERE board_space_id=$1 AND strand_id=$2",
        ).bind::<Text,_>(board_a.as_str()).bind::<Text,_>(strand.as_str())
            .get_result(&mut conn).await.unwrap();
        assert_eq!(actual.value, serde_json::to_value(placed).unwrap());
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:replica-station.example").unwrap(),
        ));
        // Admission has already occurred at the authority. Even a stale
        // optional preimage must not be re-adjudicated during replica folding.
        for (position, board, kind, rank) in [
            (8, &board_a, arkret_wire::EventKind::StrandMove, "b0"),
            (9, &board_b, arkret_wire::EventKind::StrandMove, "c0"),
            (10, &board_a, arkret_wire::EventKind::StrandReorder, "d0"),
        ] {
            let mut payload = json!({"board_space_id":board,"strand_id":strand,"rank":rank});
            payload[if kind == arkret_wire::EventKind::StrandMove {
                "target_space_id"
            } else {
                "space_id"
            }] = json!(list);
            if position != 9 {
                payload["expected_position"] = json!({"list_space_id":list,"rank":"stale"});
            }
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                kind.as_str(),
                arkret_wire::ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                actor.clone(),
                payload,
                at,
            )
            .unwrap();
            let commit = arkret_wire::RealmCommit {
                producer_signer_fact_digest: None,
                commit_id: arkret_wire::RealmCommitId::from_digest([position as u8; 32]),
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                stream_position: position,
                previous_commit_ref: Some(arkret_wire::RealmCommitId::from_digest(
                    [(position - 1) as u8; 32],
                )),
                event_ref: event.event_id.clone(),
                governance_generation: 0,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    event.event_id.clone(),
                ),
                committed_at: at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: arkret_wire::DidUrl::new(
                        "did:web:replica-station.example#authority",
                    )
                    .unwrap(),
                    signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                        .unwrap(),
                    created_at: at,
                    sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
                },
            };
            advance_in_connection(&mut conn, &event, &commit)
                .await
                .unwrap();
            advance_in_connection(&mut conn, &event, &commit)
                .await
                .unwrap();
        }
        for (board, rank) in [(&board_a, "d0"), (&board_b, "c0")] {
            let actual: ValueRow = diesel::sql_query(
                "SELECT value FROM strand_position_current_results WHERE board_space_id=$1 AND strand_id=$2",
            ).bind::<Text,_>(board.as_str()).bind::<Text,_>(strand.as_str())
                .get_result(&mut conn).await.unwrap();
            assert_eq!(actual.value, json!({"list_space_id":list,"rank":rank}));
        }
    }

    #[tokio::test]
    async fn rsvp_snapshot_install_and_replica_advance_keep_one_winner() {
        let database = TestDatabase::lease().await;
        let mut conn = database.pool().get().await.unwrap();
        let id = |byte| {
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32])
        };
        let realm = arkret_wire::RealmId::from_event_id(&id(81));
        let strand = arkret_wire::StrandId::from_event_id(&id(82));
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:rsvp-replica.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:rsvp-host.example").unwrap(),
        ));
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: arkret_wire::RealmCommitId::from_digest([7; 32]),
        };
        let entry = |ciphertext| {
            json!({
                "schedule_basis_refs": [id(83)],
                "encrypted_response": {
                    "version": "1.0",
                    "content_type": "application/vnd.arkret.calendar-rsvp-response+json",
                    "encryption_context": {
                        "epoch": 7,
                        "group_state_ref": id(84)
                    },
                    "ciphertext": ciphertext
                }
            })
        };
        let selector = arkret_wire::CurrentSelector::Rsvp {
            event_ref: strand.clone(),
            occurrence: None,
            responder_actor_id: actor.clone(),
        };
        install_snapshot_in_connection(
            &mut conn,
            &realm,
            &head,
            &[arkret_wire::TypedCurrentRow::Value {
                selector: selector.clone(),
                source_stream_ref: stream.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: head.commit_id.clone(),
                    stream_position: 7,
                },
                value: entry("first"),
            }],
            at,
        )
        .await
        .unwrap();
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            arkret_wire::EventKind::RsvpSet.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor.clone(),
            json!({"event_ref":strand,"occurrence":null,"entry":entry("second")}),
            at,
        )
        .unwrap();
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([8; 32]),
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:rsvp-host.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        };
        advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        #[derive(diesel::QueryableByName)]
        struct CurrentRow {
            #[diesel(sql_type = Jsonb)]
            value: Value,
        }
        let current: CurrentRow = diesel::sql_query(
            "SELECT jsonb_build_object('count',COUNT(*),'entry',MAX(value::text)) AS value \
             FROM rsvp_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(current.value["count"], 1);
        let accepted: Value =
            serde_json::from_str(current.value["entry"].as_str().unwrap()).unwrap();
        assert_eq!(accepted, entry("second"));
        crate::rsvp_current_results::project_verified_rsvp_in_connection(
            &mut conn, &event, &commit,
        )
        .await
        .unwrap();
        let stale = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([6; 32]),
            stream_position: 6,
            previous_commit_ref: None,
            ..commit
        };
        assert!(
            crate::rsvp_current_results::project_verified_rsvp_in_connection(
                &mut conn, &event, &stale
            )
            .await
            .is_err()
        );
        let unchanged: CurrentRow = diesel::sql_query(
            "SELECT jsonb_build_object('count',COUNT(*),'entry',MAX(value::text)) AS value \
             FROM rsvp_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(unchanged.value, current.value);
    }
    #[tokio::test]
    async fn receipt_policy_snapshot_and_tail_preserve_exact_values_and_reject_invalid_scope() {
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x78; 32],
        ));
        let stream = arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let commit_id = arkret_wire::RealmCommitId::from_digest([7; 32]);
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 7,
            commit_id: commit_id.clone(),
        };
        let policy = json!({"disclosure":"required","visibility":"private"});
        let entry = arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::ScopeReadReceiptPolicy {
                scope_ref: stream.scope_ref(),
            },
            source_stream_ref: stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id,
                stream_position: 7,
            },
            value: policy.clone(),
        };
        for _ in 0..2 {
            install_snapshot_in_connection(
                &mut conn,
                &realm,
                &head,
                std::slice::from_ref(&entry),
                at,
            )
            .await
            .unwrap();
        }
        let actual: ValueRow = diesel::sql_query(
            "SELECT value FROM scope_read_receipt_policy_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(actual.value, policy);
        for invalid in [
            json!({}),
            json!({"disclosure":"sometimes"}),
            json!({"disclosure":"optional","visibility":null}),
            json!({"disclosure":"optional","extra":true}),
        ] {
            let mut malformed_entry = entry.clone();
            let arkret_wire::TypedCurrentRow::Value {
                value, revision, ..
            } = &mut malformed_entry;
            *value = invalid;
            revision.commit_id = arkret_wire::RealmCommitId::from_digest([8; 32]);
            revision.stream_position = 8;
            let malformed_head = arkret_wire::CommitStreamHead {
                commit_id: revision.commit_id.clone(),
                stream_position: 8,
                ..head.clone()
            };
            diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
            let refused = install_snapshot_in_connection(
                &mut conn,
                &realm,
                &malformed_head,
                &[malformed_entry],
                at,
            )
            .await
            .unwrap_err();
            assert!(matches!(refused, PersistenceError::SchemaViolation(_)));
            diesel::sql_query("ROLLBACK")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        let mut foreign = entry.clone();
        let arkret_wire::TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut foreign;
        *source_stream_ref = arkret_wire::CommitStreamRef::Circle {
            realm_id: realm.clone(),
            circle_id: arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x79; 32],
            )),
        };
        let foreign_head = arkret_wire::CommitStreamHead {
            stream_ref: source_stream_ref.clone(),
            ..head.clone()
        };
        diesel::sql_query("BEGIN").execute(&mut conn).await.unwrap();
        assert!(
            install_snapshot_in_connection(&mut conn, &realm, &foreign_head, &[foreign], at)
                .await
                .is_err()
        );
        diesel::sql_query("ROLLBACK")
            .execute(&mut conn)
            .await
            .unwrap();
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:receipt-replica-author.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:receipt-replica-station.example").unwrap(),
        ));
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.scope.read_receipt_policy",
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor,
            json!({"disclosure":"disabled"}),
            at,
        )
        .unwrap();
        let mut proof = arkret_wire::ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_wire::DidUrl::new(
                "did:web:receipt-replica-author.example#ak:device:01904100-0000-7000-8000-000000000086",
            ).unwrap(),
            event_digest: event.event_id.event_digest(),
            created_at: at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        };
        proof.jws = arkret_signatures::jws::sign_jws_ed25519(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &ed25519_dalek::SigningKey::from_bytes(&[0x79; 32]),
        )
        .unwrap();
        event.producer_proof = Some(proof);
        let commit = arkret_wire::RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: arkret_wire::RealmCommitId::from_digest([8; 32]),
            realm_id: realm.clone(),
            stream_ref: stream,
            stream_position: 8,
            previous_commit_ref: Some(head.commit_id),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                event.event_id.clone(),
            ),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:receipt-replica-station.example#authority",
                )
                .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "3".repeat(64)))
                    .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        };
        advance_in_connection(&mut conn, &event, &commit)
            .await
            .unwrap();
        let actual: ValueRow = diesel::sql_query(
            "SELECT value FROM scope_read_receipt_policy_current_results WHERE realm_id=$1",
        )
        .bind::<Text, _>(realm.as_str())
        .get_result(&mut conn)
        .await
        .unwrap();
        assert_eq!(actual.value, json!({"disclosure":"disabled"}));
    }
}
