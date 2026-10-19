//! One exact-scope read-receipt policy current, without Realm inheritance.
use diesel::sql_types::{BigInt, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{PersistenceError, PersistenceResult};

pub(crate) async fn install(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    stream: &arkret_wire::CommitStreamRef,
    revision: &arkret_wire::CurrentRevision,
    value: &serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    let current = arkret_models_collaboration::events_payloads::ScopeReadReceiptPolicyCurrent {
        selector: arkret_wire::CurrentSelector::ScopeReadReceiptPolicy {
            scope_ref: scope.clone(),
        },
        source_stream_ref: stream.clone(),
        revision: revision.clone(),
        value: serde_json::from_value(value.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?,
    };
    current
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    arkret_canonical::canonical_json_bytes(&current)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if stream.realm_id() != realm_id {
        return Err(PersistenceError::Conflict(
            "read-receipt policy Realm differs".into(),
        ));
    }
    let scope = serde_json::to_value(scope).map_err(PersistenceError::database)?;
    let source = serde_json::to_value(stream).map_err(PersistenceError::database)?;
    let position = i64::try_from(revision.stream_position)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let changed = diesel::sql_query("INSERT INTO scope_read_receipt_policy_current_results \
        (realm_id,scope_ref,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) \
        VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,scope_ref) DO UPDATE SET \
        source_stream_ref=EXCLUDED.source_stream_ref,current_commit_id=EXCLUDED.current_commit_id, \
        current_stream_position=EXCLUDED.current_stream_position,value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
        WHERE scope_read_receipt_policy_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
        AND (scope_read_receipt_policy_current_results.current_stream_position<EXCLUDED.current_stream_position \
        OR (scope_read_receipt_policy_current_results.current_stream_position=EXCLUDED.current_stream_position \
        AND scope_read_receipt_policy_current_results.current_commit_id=EXCLUDED.current_commit_id \
        AND scope_read_receipt_policy_current_results.value=EXCLUDED.value))")
        .bind::<Text,_>(realm_id.as_str()).bind::<Jsonb,_>(scope).bind::<Jsonb,_>(source)
        .bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(position)
        .bind::<Jsonb,_>(value).bind::<Timestamptz,_>(at).execute(conn).await.map_err(PersistenceError::database)?;
    if changed != 1 {
        return Err(PersistenceError::Conflict(
            "read-receipt current rollback or same-position fork".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            let row:Row=diesel::sql_query("SELECT value FROM scope_read_receipt_policy_current_results WHERE realm_id=$1 AND scope_ref=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Jsonb,_>(serde_json::to_value(scope).unwrap()).get_result(&mut conn).await.unwrap();
            assert_eq!(
                row.value,
                serde_json::json!({"disclosure":if i==0 {"required"} else {"disabled"}})
            );
        }
    }
}
