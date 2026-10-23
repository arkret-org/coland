//! Durable singleton current results established by an ordinary Realm bootstrap.

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};

use crate::{PersistenceError, PersistenceResult};

#[cfg(test)]
#[path = "../tests/support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

fn typed_payload<T>(
    event: &arkret_wire::Event,
    decode: fn(&arkret_wire::Event) -> arkret_wire::Result<T>,
) -> PersistenceResult<T> {
    decode(event).map_err(|error| {
        PersistenceError::SchemaViolation(format!(
            "ordinary Realm bootstrap payload is invalid: {error}"
        ))
    })
}

fn result_value<T: serde::Serialize>(value: &T) -> PersistenceResult<serde_json::Value> {
    serde_json::to_value(value).map_err(PersistenceError::database)
}

/// Materialize the singleton families declared by the registered ordinary
/// bootstrap Event kinds. The authority root, policy bundle and creator
/// member state have dedicated durable tables and are written by their own
/// materializers in the same transaction.
///
/// `realm-and-space.md` §2.5 create projection rows 5 and 7: a Direct
/// Conversation or control-Realm genesis also runs `realm_history_access`
/// `null -> since_join` in the same write, since those profiles have no
/// history-access bootstrap facet.
pub(crate) async fn commit_ordinary_bootstrap_singleton_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    let rows = match event.kind {
        arkret_wire::EventKind::RealmCreate => {
            let genesis = typed_payload(event, EventPayloadExt::as_realm_create)?.object;
            let mut rows = vec![("realm_genesis", result_value(&genesis)?)];
            if matches!(
                genesis.purpose,
                RealmPurpose::DirectConversation
                    | RealmPurpose::PrincipalControl
                    | RealmPurpose::AgentControl
            ) {
                rows.push((
                    "realm_history_access",
                    result_value(&arkret_wire::HistoryAccess::SinceJoin)?,
                ));
            }
            rows
        }
        arkret_wire::EventKind::RealmProfile => vec![(
            "realm_profile",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_profile)?)?,
        )],
        arkret_wire::EventKind::RealmJoinRule => vec![(
            "realm_join_rule",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_join_rule)?.value)?,
        )],
        arkret_wire::EventKind::RealmHistoryAccess => {
            let payload = typed_payload(event, EventPayloadExt::as_realm_history_access)?;
            if payload.from.is_some() {
                return Err(PersistenceError::Conflict(
                    "ordinary Realm bootstrap history must transition from null".to_owned(),
                ));
            }
            vec![("realm_history_access", result_value(&payload.to)?)]
        }
        arkret_wire::EventKind::RealmDiscovery => vec![(
            "realm_discovery",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_discovery)?.value)?,
        )],
        arkret_wire::EventKind::RealmAlias => vec![(
            "realm_alias",
            result_value(&typed_payload(event, EventPayloadExt::as_realm_alias)?)?,
        )],
        arkret_wire::EventKind::RealmPlaintextVisibleServices => vec![(
            "realm_plaintext_visible_services",
            result_value(&typed_payload(
                event,
                EventPayloadExt::as_realm_plaintext_visible_services,
            )?)?,
        )],
        _ => return Ok(()),
    };
    for (family, value) in rows {
        insert_singleton(conn, event, commit, family, &value).await?;
    }
    Ok(())
}

/// Join-rule changes use the same serialized Realm governance cut as the
/// capability decision and advance only with their exact covering Commit.
pub(crate) async fn commit_realm_join_rule_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmJoinRule {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    commit_realm_join_rule_current_result_in_connection(conn, event, commit).await
}

/// Apply an already verified JoinRule Commit, preserving its source revision.
/// Restricted entrance modes must retain an automatic gate in the current
/// committed policy bundle (join-policy.md §2).
pub(crate) async fn commit_realm_join_rule_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmJoinRule {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "join rule requires its exact Realm Event and covering Commit".to_owned(),
        ));
    }
    let rule = typed_payload(event, EventPayloadExt::as_realm_join_rule)?;
    let value = result_value(&rule.value)?;
    if value
        .as_str()
        .is_some_and(coland_storage::join_rule_requires_an_automatic_gate)
    {
        #[derive(diesel::QueryableByName)]
        struct PolicyRow {
            #[diesel(sql_type = Jsonb)]
            value: serde_json::Value,
        }
        let policy = diesel::sql_query(
            "SELECT value FROM realm_policy_bundle_current_results WHERE realm_id=$1 FOR SHARE",
        )
        .bind::<Text, _>(event.realm_id.as_str())
        .get_result::<PolicyRow>(&mut *conn)
        .await
        .optional()
        .map_err(PersistenceError::database)?;
        if !coland_storage::join_policy_declares_an_automatic_gate(
            policy.as_ref().and_then(|row| row.value.get("join_policy")),
        ) {
            return Err(PersistenceError::Conflict(
                "join_rule_policy_mismatch: restricted join rule requires an automatic gate"
                    .to_owned(),
            ));
        }
    }
    advance_singleton(conn, event, commit, "realm_join_rule", &value).await
}

/// Advance the complete profile value with its covering RealmCommit. Omitted
/// optional fields disappear; no previous value is merged into the new value.
pub(crate) async fn commit_realm_profile_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmProfile {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    commit_realm_profile_current_result_in_connection(conn, event, commit).await
}

/// Apply an already verified profile Commit to the typed current value.
pub(crate) async fn commit_realm_profile_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmProfile {
        return Ok(());
    }
    let profile = typed_payload(event, EventPayloadExt::as_realm_profile)?;
    let value = profile.to_value().map_err(|error| {
        PersistenceError::SchemaViolation(format!("invalid Realm profile: {error}"))
    })?;
    advance_singleton(conn, event, commit, "realm_profile", &value).await
}

/// A later declaration replaces the complete plaintext-service value under
/// the ordinary same-cut capability/lifecycle rules, never a bootstrap bypass.
pub(crate) async fn commit_plaintext_services_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmPlaintextVisibleServices {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    commit_plaintext_services_current_result_in_connection(conn, event, commit).await
}

/// Replication consumes the accepted declaration without repeating admission.
pub(crate) async fn commit_plaintext_services_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmPlaintextVisibleServices {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: plaintext services require their exact Realm Event and Commit"
                .into(),
        ));
    }
    let policy = typed_payload(event, EventPayloadExt::as_realm_plaintext_visible_services)?;
    advance_singleton(
        conn,
        event,
        commit,
        "realm_plaintext_visible_services",
        &result_value(&policy)?,
    )
    .await
}

/// History policy is a scope-local security ratchet with an exact current
/// predecessor. The accepted Event and its new provenance advance atomically.
pub(crate) async fn commit_realm_history_access_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmHistoryAccess {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    commit_realm_history_access_current_result_in_connection(conn, event, commit).await
}

pub(crate) async fn commit_realm_history_access_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmHistoryAccess {
        return Ok(());
    }
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "history policy requires its exact Realm Event and covering Commit".to_owned(),
        ));
    }
    let payload = typed_payload(event, EventPayloadExt::as_realm_history_access)?;
    payload
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    #[derive(diesel::QueryableByName)]
    struct Current {
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }
    let current = diesel::sql_query("SELECT value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_history_access' FOR UPDATE")
        .bind::<Text,_>(event.realm_id.as_str())
        .get_result::<Current>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| PersistenceError::Conflict("failed_precondition: history policy current is missing".to_owned()))?;
    let current: arkret_wire::HistoryAccess = serde_json::from_value(current.value)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if payload.from != Some(current) {
        return Err(PersistenceError::Conflict(
            "failed_precondition: history policy predecessor differs from current".to_owned(),
        ));
    }
    advance_singleton(
        conn,
        event,
        commit,
        "realm_history_access",
        &result_value(&payload.to)?,
    )
    .await
}

pub(crate) async fn commit_preview_policy_authority_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmPreviewPolicy {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    commit_preview_policy_current_result_in_connection(conn, event, commit).await
}

/// Retain payload.value only; the optional reason remains Event audit data.
pub(crate) async fn commit_preview_policy_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RealmPreviewPolicy {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref
        != (arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        })
        || commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::SchemaViolation(
            "preview policy requires its exact Realm Event and covering Commit".to_owned(),
        ));
    }
    let policy = event
        .typed_payload::<arkret_wire::event_spec::RealmPreviewPolicy>()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    advance_singleton(
        conn,
        event,
        commit,
        "realm_preview_policy",
        &result_value(&policy.value)?,
    )
    .await
}

async fn advance_singleton(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    family: &str,
    value: &serde_json::Value,
) -> PersistenceResult<()> {
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("Realm singleton position exceeds BIGINT".to_owned())
    })?;
    let changed = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) \
         ON CONFLICT(realm_id,result_family) DO UPDATE SET \
         current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position, \
         value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE realm_bootstrap_current_results.current_stream_position < EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(format!(
            "Realm singleton {family} cannot advance from this Commit"
        )));
    }
    Ok(())
}

async fn insert_singleton(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    family: &str,
    value: &serde_json::Value,
) -> PersistenceResult<()> {
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation(
            "ordinary Realm bootstrap stream position exceeds PostgreSQL BIGINT".to_owned(),
        )
    })?;
    let inserted = diesel::sql_query(
        "INSERT INTO realm_bootstrap_current_results \
         (realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(family)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(PersistenceError::Conflict(format!(
            "ordinary Realm bootstrap current result {family} already exists"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use coland_storage::{AuthorityCommitStore, EventCommitUnitOfWork, EventStore};

    use super::*;

    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Text)]
        current_commit_id: String,
        #[diesel(sql_type = Jsonb)]
        value: serde_json::Value,
    }

    #[tokio::test]
    async fn join_rule_current_is_atomic_authorized_and_requires_automatic_gate() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
        let mut previous = discussion.head.authority_commit;
        let founder = discussion.unit.transactions[0]
            .event
            .actor_id
            .signing_principal_id();
        let uow = crate::PgEventCommitUnitOfWork::new(pool.clone());
        for value in ["public", "invite"] {
            let request = ordinary_realm::next_request(
                &previous,
                arkret_wire::EventKind::RealmJoinRule,
                founder,
                serde_json::json!({"value":value}),
                chrono::Utc::now(),
            );
            uow.commit_event(request.clone()).await.unwrap();
            uow.commit_event(request.clone()).await.unwrap();
            let material = crate::PgAuthorityCommitStore { pool: pool.clone() }
                .realm_state_snapshot_material(&request.authority_commit.event.realm_id)
                .await
                .unwrap()
                .unwrap();
            let row = material
                .current_state_entries
                .iter()
                .find(|entry| {
                    matches!(
                        entry,
                        arkret_wire::TypedCurrentRow::Value {
                            selector: arkret_wire::CurrentSelector::RealmJoinRule,
                            ..
                        }
                    )
                })
                .expect("confirmed join rule current");
            let arkret_wire::TypedCurrentRow::Value {
                revision,
                value: actual,
                source_stream_ref,
                ..
            } = row;
            assert_eq!(actual, &serde_json::json!(value));
            assert_eq!(
                revision.commit_id,
                request.authority_commit.commit.commit_id
            );
            assert_eq!(
                revision.stream_position,
                request.authority_commit.commit.stream_position
            );
            assert_eq!(
                source_stream_ref,
                &request.authority_commit.commit.stream_ref
            );
            previous = request.authority_commit;
        }
        let outsider = Box::pin(ordinary_realm::human_profile::admit(
            &pool,
            &ordinary_realm::station(),
            "join-rule-outsider",
        ))
        .await;
        let denied = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmJoinRule,
            &outsider.principal_id,
            serde_json::json!({"value":"public"}),
            chrono::Utc::now(),
        );
        let denied = Box::pin(ordinary_realm::source_request(&pool, denied)).await;
        let restricted = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmJoinRule,
            founder,
            serde_json::json!({"value":"knock_restricted"}),
            chrono::Utc::now(),
        );
        for (candidate, expected) in [
            (denied, coland_storage::ConflictCode::CapabilityDenied),
            (
                restricted,
                coland_storage::ConflictCode::JoinRulePolicyMismatch,
            ),
        ] {
            let error = uow.commit_event(candidate.clone()).await.unwrap_err();
            assert_eq!(error.conflict_code(), Some(expected), "{error:?}");
            assert!(
                crate::PgEventStore { pool: pool.clone() }
                    .get(candidate.authority_commit.event.event_id.as_str())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                crate::PgAuthorityCommitStore { pool: pool.clone() }
                    .committed_event_by_commit_id(&candidate.authority_commit.commit.commit_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let mut conn = pool.get().await.unwrap();
        let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_join_rule'")
            .bind::<Text,_>(previous.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(
            current.current_commit_id,
            previous.commit.commit_id.as_str()
        );
        assert_eq!(current.value, serde_json::json!("invite"));
        drop(conn);
        let policy = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmPolicyBundle,
            founder,
            serde_json::json!({"policy_revision":2,"federation_policy":"closed", "join_policy":{
                "gates":[{"gate_id":"claim","kind":"claim_required","auto_resolve":true,
                    "required_claims":["employee"],"trusted_issuer_ids":[ordinary_realm::station()]}],"combinator":"all"
            }}),
            chrono::Utc::now(),
        );
        uow.commit_event(policy.clone()).await.unwrap();
        previous = policy.authority_commit;
        let knock = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmJoinRule,
            founder,
            serde_json::json!({"value":"knock_restricted"}),
            chrono::Utc::now(),
        );
        uow.commit_event(knock.clone()).await.unwrap();
        previous = knock.authority_commit;
        let erase = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmPolicyBundle,
            founder,
            serde_json::json!({"policy_revision":3,"federation_policy":"closed"}),
            chrono::Utc::now(),
        );
        let error = uow.commit_event(erase.clone()).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::JoinRulePolicyMismatch)
        );
        assert!(
            crate::PgEventStore { pool: pool.clone() }
                .get(erase.authority_commit.event.event_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            crate::PgAuthorityCommitStore { pool: pool.clone() }
                .committed_event_by_commit_id(&erase.authority_commit.commit.commit_id)
                .await
                .unwrap()
                .is_none()
        );
        let mut conn = pool.get().await.unwrap();
        let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_join_rule'")
            .bind::<Text,_>(previous.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(
            current.current_commit_id,
            previous.commit.commit_id.as_str()
        );
        assert_eq!(current.value, serde_json::json!("knock_restricted"));
    }

    #[tokio::test]
    async fn join_rule_replica_tail_preserves_covering_source_and_rejects_mismatched_commit() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
        let previous = discussion.head.authority_commit;
        let founder = discussion.unit.transactions[0]
            .event
            .actor_id
            .signing_principal_id();
        let request = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmJoinRule,
            founder,
            serde_json::json!({"value":"public"}),
            chrono::Utc::now(),
        );
        // This projection input is downstream of source Commit verification;
        // it exercises the replica fold, not a live signer or HTTP admission.
        let source = &request.authority_commit;
        let mut conn = pool.get().await.unwrap();
        let mut wrong_commit = source.commit.clone();
        wrong_commit.event_ref = previous.event.event_id;
        assert!(
            crate::replica_current::advance_in_connection(&mut conn, &source.event, &wrong_commit)
                .await
                .is_err()
        );
        crate::replica_current::advance_in_connection(&mut conn, &source.event, &source.commit)
            .await
            .unwrap();
        let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_join_rule'")
            .bind::<Text,_>(source.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(current.current_commit_id, source.commit.commit_id.as_str());
        assert_eq!(current.value, serde_json::json!("public"));
    }

    #[tokio::test]
    async fn preview_policy_current_is_atomic_authorized_and_excludes_audit_reason() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
        let mut previous = discussion.head.authority_commit;
        let founder = discussion.unit.transactions[0]
            .event
            .actor_id
            .signing_principal_id();
        let uow = crate::PgEventCommitUnitOfWork::new(pool.clone());
        let mut first = None;
        for value in [
            serde_json::json!({"mode":"directory_card","audiences":["invited"],"fields":["title"]}),
            serde_json::json!({"mode":"none","audiences":["anonymous"],"fields":["title"]}),
        ] {
            let request = ordinary_realm::next_request(
                &previous,
                arkret_wire::EventKind::RealmPreviewPolicy,
                founder,
                serde_json::json!({"value":value,"reason":"not part of current"}),
                chrono::Utc::now(),
            );
            uow.commit_event(request.clone()).await.unwrap();
            if first.is_none() {
                first = Some(request.clone());
            }
            let material = crate::PgAuthorityCommitStore { pool: pool.clone() }
                .realm_state_snapshot_material(&request.authority_commit.event.realm_id)
                .await
                .unwrap()
                .unwrap();
            let row = material
                .current_state_entries
                .iter()
                .find(|entry| {
                    matches!(
                        entry,
                        arkret_wire::TypedCurrentRow::Value {
                            selector: arkret_wire::CurrentSelector::RealmPreviewPolicy,
                            ..
                        }
                    )
                })
                .expect("confirmed preview current in material");
            let arkret_wire::TypedCurrentRow::Value {
                revision,
                value: actual,
                source_stream_ref,
                ..
            } = row;
            assert_eq!(actual, &value);
            assert_eq!(
                revision.commit_id,
                request.authority_commit.commit.commit_id
            );
            assert_eq!(
                revision.stream_position,
                request.authority_commit.commit.stream_position
            );
            assert_eq!(
                source_stream_ref,
                &request.authority_commit.commit.stream_ref
            );
            previous = request.authority_commit;
        }
        uow.commit_event(first.unwrap()).await.unwrap();
        let outsider = Box::pin(ordinary_realm::human_profile::admit(
            &pool,
            &ordinary_realm::station(),
            "preview-outsider",
        ))
        .await;
        let denied = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmPreviewPolicy,
            &outsider.principal_id,
            serde_json::json!({"value":{"mode":"directory_card","audiences":["anonymous"],"fields":["title"]}}),
            chrono::Utc::now(),
        );
        let denied = Box::pin(ordinary_realm::source_request(&pool, denied)).await;
        let denied_error = uow.commit_event(denied.clone()).await.unwrap_err();
        assert_eq!(
            denied_error.conflict_code(),
            Some(coland_storage::ConflictCode::CapabilityDenied),
            "accepted human without Realm authorization: {denied_error:?}"
        );
        assert!(
            crate::PgEventStore { pool: pool.clone() }
                .get(denied.authority_commit.event.event_id.as_str())
                .await
                .unwrap()
                .is_none()
        );

        let candidate = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::RealmPreviewPolicy,
            founder,
            serde_json::json!({"value":{"mode":"directory_card","audiences":["invited"],"fields":["join_rule"]}}),
            chrono::Utc::now(),
        );
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query("CREATE FUNCTION preview_policy_current_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result_family='realm_preview_policy' THEN RAISE EXCEPTION 'preview policy current fault'; END IF; RETURN NEW; END $$").execute(&mut *conn).await.unwrap();
        diesel::sql_query("CREATE TRIGGER preview_policy_current_fault BEFORE INSERT OR UPDATE ON realm_bootstrap_current_results FOR EACH ROW EXECUTE FUNCTION preview_policy_current_fault()").execute(&mut *conn).await.unwrap();
        drop(conn);
        let failed = uow.commit_event(candidate.clone()).await;
        let mut conn = pool.get().await.unwrap();
        diesel::sql_query(
            "DROP TRIGGER preview_policy_current_fault ON realm_bootstrap_current_results",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        diesel::sql_query("DROP FUNCTION preview_policy_current_fault()")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            failed.is_err(),
            "the injected current write must actually fail"
        );
        let current = diesel::sql_query("SELECT current_commit_id,value FROM realm_bootstrap_current_results WHERE realm_id=$1 AND result_family='realm_preview_policy'").bind::<Text,_>(candidate.authority_commit.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(
            current.current_commit_id,
            previous.commit.commit_id.as_str()
        );
        assert_eq!(
            current.value,
            serde_json::json!({"mode":"none","audiences":["anonymous"],"fields":["title"]})
        );
        drop(conn);
        assert!(
            crate::PgEventStore { pool: pool.clone() }
                .get(candidate.authority_commit.event.event_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            crate::PgAuthorityCommitStore { pool }
                .committed_event_by_commit_id(&candidate.authority_commit.commit.commit_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn read_receipt_policy_commits_exact_current_and_rejects_unauthorized_writes() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let discussion =
            ordinary_realm::open_human_discussion(&pool, &uuid::Uuid::now_v7().to_string()).await;
        let mut previous = discussion.head.authority_commit;
        let uow = crate::PgEventCommitUnitOfWork::new(pool.clone());
        let founder = discussion.unit.transactions[0]
            .event
            .actor_id
            .signing_principal_id();
        for payload in [
            serde_json::json!({"disclosure":"disabled","visibility":"private"}),
            serde_json::json!({"disclosure":"required"}),
        ] {
            let request = ordinary_realm::next_request(
                &previous,
                arkret_wire::EventKind::ScopeReadReceiptPolicy,
                founder,
                payload.clone(),
                chrono::Utc::now(),
            );
            uow.commit_event(request.clone()).await.unwrap();
            let mut conn = pool.get().await.unwrap();
            let current = diesel::sql_query("SELECT current_commit_id,value FROM scope_read_receipt_policy_current_results WHERE realm_id=$1 AND scope_ref->>'kind'='realm'")
                .bind::<Text, _>(request.authority_commit.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
            assert_eq!(
                current.current_commit_id,
                request.authority_commit.commit.commit_id.as_str()
            );
            assert_eq!(
                current.value, payload,
                "a successor replaces the entire policy value"
            );
            previous = request.authority_commit;
        }
        let outsider = arkret_wire::DidCoreId::new("ak:did_core:web:outsider.example").unwrap();
        let denied = ordinary_realm::next_request(
            &previous,
            arkret_wire::EventKind::ScopeReadReceiptPolicy,
            &outsider,
            serde_json::json!({"disclosure":"disabled"}),
            chrono::Utc::now(),
        );
        assert!(uow.commit_event(denied.clone()).await.is_err());
        let mut conn = pool.get().await.unwrap();
        let current = diesel::sql_query("SELECT current_commit_id,value FROM scope_read_receipt_policy_current_results WHERE realm_id=$1 AND scope_ref->>'kind'='realm'")
            .bind::<Text, _>(previous.event.realm_id.as_str()).get_result::<Row>(&mut *conn).await.unwrap();
        assert_eq!(
            current.current_commit_id,
            previous.commit.commit_id.as_str()
        );
        assert_eq!(current.value, serde_json::json!({"disclosure":"required"}));
        let stored = crate::PgEventStore { pool }
            .get(&denied.authority_commit.event.event_id.to_string())
            .await
            .unwrap();
        assert!(
            stored.is_none(),
            "an unauthorized policy must leave no canonical Event"
        );
    }
}
