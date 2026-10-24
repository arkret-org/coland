//! Independent Realm/Circle receipt policy currents and atomic admission.

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::CurrentScopeReadReceiptPolicy;
use arkret_wire::{CurrentRevision, CurrentSelector, Event, EventKind, RealmCommit, ScopeRef};
use chrono::{DateTime, Utc};
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::AsyncPgConnection;
use horme::RunQueryDsl;

use crate::{PersistenceError, PersistenceResult};

pub(crate) async fn commit_read_receipt_policy_authority_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    if event.kind != EventKind::ScopeReadReceiptPolicy {
        return Ok(());
    }
    crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
        conn, event, commit, prepared,
    )
    .await?;
    if matches!(&event.scope_ref, ScopeRef::Circle { .. }) {
        crate::circle_current_states::require_active_author_in_connection(conn, event, commit)
            .await?;
    }
    commit_read_receipt_policy_current_state_in_connection(conn, event, commit).await
}

/// Apply an already verified accepted Event without rejudging past authority.
pub(crate) async fn commit_read_receipt_policy_current_state_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != EventKind::ScopeReadReceiptPolicy {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if event.scope_ref.realm_id_opt() != Some(&event.realm_id)
        || commit.stream_ref.scope_ref() != event.scope_ref
        || commit.realm_id != event.realm_id
        || commit.event_ref != event.event_id
    {
        return Err(PersistenceError::Conflict(
            "failed_precondition: receipt policy requires its exact scope Event and covering Commit".into(),
        ));
    }
    let value = event
        .as_scope_read_receipt_policy()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let current = CurrentScopeReadReceiptPolicy {
        selector: CurrentSelector::ScopeReadReceiptPolicy {
            scope_ref: event.scope_ref.clone(),
        },
        source_stream_ref: commit.stream_ref.clone(),
        revision: CurrentRevision {
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        },
        value,
    };
    upsert_verified_current_in_connection(conn, &current, commit.committed_at).await
}

/// Snapshot callers must authenticate the cut and visibility before this write.
pub(crate) async fn upsert_verified_current_in_connection(
    conn: &mut AsyncPgConnection,
    current: &CurrentScopeReadReceiptPolicy,
    updated_at: DateTime<Utc>,
) -> PersistenceResult<()> {
    current
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    arkret_canonical::canonical_json_bytes(current)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let CurrentSelector::ScopeReadReceiptPolicy { scope_ref } = &current.selector else {
        return Err(PersistenceError::SchemaViolation(
            "receipt policy selector required".into(),
        ));
    };
    let realm = scope_ref
        .realm_id_opt()
        .ok_or_else(|| PersistenceError::SchemaViolation("receipt scope has no Realm".into()))?;
    let scope = serde_json::to_value(scope_ref).map_err(PersistenceError::database)?;
    let source =
        serde_json::to_value(&current.source_stream_ref).map_err(PersistenceError::database)?;
    let value = serde_json::to_value(&current.value).map_err(PersistenceError::database)?;
    let position =
        i64::try_from(current.revision.stream_position).map_err(PersistenceError::database)?;
    let affected = diesel::sql_query(
        "INSERT INTO scope_read_receipt_policy_current_states \
         (realm_id,scope_ref,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (realm_id,scope_ref) DO UPDATE SET \
         source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id, \
         current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
         WHERE scope_read_receipt_policy_current_states.source_stream_ref=EXCLUDED.source_stream_ref \
           AND (scope_read_receipt_policy_current_states.current_stream_position<EXCLUDED.current_stream_position \
             OR (scope_read_receipt_policy_current_states.current_stream_position=EXCLUDED.current_stream_position \
               AND scope_read_receipt_policy_current_states.current_commit_id=EXCLUDED.current_commit_id \
               AND scope_read_receipt_policy_current_states.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(realm.as_str()).bind::<Jsonb, _>(scope).bind::<Jsonb, _>(source)
    .bind::<Text, _>(current.revision.commit_id.as_str()).bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(value).bind::<Timestamptz, _>(updated_at)
    .execute(conn).await.map_err(PersistenceError::database)?;
    if affected != 1 {
        return Err(PersistenceError::Conflict(
            "failed_precondition: receipt policy revision regressed or forked".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn install(
        conn: &mut AsyncPgConnection,
        realm: &arkret_wire::RealmId,
        scope: &ScopeRef,
        stream: &arkret_wire::CommitStreamRef,
        revision: &CurrentRevision,
        value: &serde_json::Value,
        at: DateTime<Utc>,
    ) -> PersistenceResult<()> {
        if scope.realm_id_opt() != Some(realm) {
            return Err(PersistenceError::SchemaViolation(
                "test current belongs to another Realm".into(),
            ));
        }
        let current = CurrentScopeReadReceiptPolicy {
            selector: CurrentSelector::ScopeReadReceiptPolicy {
                scope_ref: scope.clone(),
            },
            source_stream_ref: stream.clone(),
            revision: revision.clone(),
            value: serde_json::from_value(value.clone())
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
        };
        upsert_verified_current_in_connection(conn, &current, at).await
    }

    #[tokio::test]
    async fn independent_scope_values_reject_cross_stream_and_same_position_forks() {
        let database = crate::test_database::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [81; 32],
        ));
        let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [82; 32],
        ));
        let scopes = [
            arkret_wire::ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            arkret_wire::ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: circle,
            },
        ];
        let at = chrono::Utc::now();
        for (i, scope) in scopes.iter().enumerate() {
            let stream = arkret_wire::CommitStreamRef::from_scope(scope, None).unwrap();
            let revision = arkret_wire::CurrentRevision {
                commit_id: arkret_wire::RealmCommitId::from_digest([i as u8 + 1; 32]),
                stream_position: 1,
            };
            let value = serde_json::json!({"disclosure":if i==0 {"required"} else {"disabled"}});
            install(&mut conn, &realm, scope, &stream, &revision, &value, at)
                .await
                .unwrap();
            install(&mut conn, &realm, scope, &stream, &revision, &value, at)
                .await
                .unwrap();
            assert!(
                install(
                    &mut conn,
                    &realm,
                    scope,
                    &stream,
                    &revision,
                    &serde_json::json!({"visibility":"private"}),
                    at
                )
                .await
                .is_err()
            );
            let overflow = arkret_wire::CurrentRevision {
                commit_id: revision.commit_id.clone(),
                stream_position: 9_007_199_254_740_992,
            };
            assert!(matches!(
                install(&mut conn, &realm, scope, &stream, &overflow, &value, at).await,
                Err(PersistenceError::SchemaViolation(_))
            ));
            let other = arkret_wire::CommitStreamRef::from_scope(&scopes[1 - i], None).unwrap();
            assert!(matches!(
                install(&mut conn, &realm, scope, &other, &revision, &value, at).await,
                Err(PersistenceError::SchemaViolation(_))
            ));
            for invalid in [
                serde_json::json!({}),
                serde_json::json!({"disclosure":null}),
                serde_json::json!({"scope_overrides_allowed":false}),
            ] {
                assert!(matches!(
                    install(&mut conn, &realm, scope, &stream, &revision, &invalid, at).await,
                    Err(PersistenceError::SchemaViolation(_))
                ));
            }
        }
        #[derive(diesel::QueryableByName)]
        struct Row {
            #[diesel(sql_type=Jsonb)]
            value: serde_json::Value,
        }
        for (i, scope) in scopes.iter().enumerate() {
            let row:Row=diesel::sql_query("SELECT value FROM scope_read_receipt_policy_current_states WHERE realm_id=$1 AND scope_ref=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(scope).unwrap()).get_result(&mut conn).await.unwrap();
            assert_eq!(
                row.value,
                serde_json::json!({"disclosure":if i==0 {"required"} else {"disabled"}})
            );
        }
    }
}
