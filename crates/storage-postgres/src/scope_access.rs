//! Shared Realm/Circle scope membership and target authorization helpers.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text};
use diesel_async::AsyncPgConnection;
use horme::{OptionalExtension as _, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

#[derive(diesel::QueryableByName)]
struct StrandScopeRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

/// The single anti-oracle answer for an absent, invisible or scope-mismatched
/// target used by committed moderation and redaction admission.
fn target_not_found() -> PersistenceError {
    PersistenceError::NotFound("scope target not found".to_owned())
}

async fn present(
    conn: &mut AsyncPgConnection,
    query: &'static str,
    realm_id: &str,
    subject: &str,
    before_position: i64,
) -> PersistenceResult<bool> {
    Ok(diesel::sql_query(query)
        .bind::<Text, _>(realm_id)
        .bind::<Text, _>(subject)
        .bind::<BigInt, _>(before_position)
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present)
}

/// Prove `target_ref` names an accepted Realm-scope object of this Realm
/// strictly before the governing Commit on the same Realm stream.
pub(crate) async fn ensure_realm_scope_target(
    conn: &mut AsyncPgConnection,
    realm_id: &str,
    target_ref: &str,
    before_position: i64,
) -> PersistenceResult<()> {
    if target_ref == realm_id {
        return Ok(());
    }
    let kind = target_ref
        .strip_prefix("ak:")
        .and_then(|rest| rest.split_once(':'))
        .map_or("", |(kind, _)| kind);
    let found = match kind {
        "event" => {
            present(
                conn,
                "SELECT EXISTS (SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
                 WHERE c.realm_id=$1 AND c.commit_json->>'event_ref'=$2 AND c.stream_position<$3 \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=c.realm_id \
                   AND e.state='committed' AND e.envelope->'scope_ref'->>'kind'='realm') AS present",
                realm_id,
                target_ref,
                before_position,
            )
            .await?
        }
        "message" => {
            present(
                conn,
                "SELECT EXISTS (SELECT 1 FROM message_revision_current_states m \
                 JOIN realm_commits c ON c.commit_id=m.current_commit_id \
                 WHERE m.realm_id=$1 AND m.message_id=$2 AND c.stream_position<$3 \
                   AND c.realm_id=m.realm_id AND c.stream_position=m.current_stream_position \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=m.realm_id) AS present",
                realm_id,
                target_ref,
                before_position,
            )
            .await?
        }
        "strand" => {
            let strand = diesel::sql_query(
                "SELECT s.value FROM strand_current_states s \
                 JOIN realm_commits c ON c.commit_id=s.current_commit_id \
                 WHERE s.realm_id=$1 AND s.strand_id=$2 AND c.stream_position<$3 \
                   AND c.realm_id=s.realm_id AND c.stream_position=s.current_stream_position \
                   AND c.stream_ref->>'kind'='realm' AND c.stream_ref->>'realm_id'=s.realm_id \
                 FOR SHARE OF s",
            )
            .bind::<Text, _>(realm_id)
            .bind::<Text, _>(target_ref)
            .bind::<BigInt, _>(before_position)
            .get_result::<StrandScopeRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            strand.is_some_and(|row| {
                row.value
                    .get("scope_circle_id")
                    .is_none_or(Value::is_null)
            })
        }
        // Other object families have no same-cut typed current here yet.
        _ => false,
    };
    if found {
        Ok(())
    } else {
        Err(target_not_found())
    }
}

pub(crate) fn scoped_event_stream(
    event: &arkret_wire::Event,
) -> PersistenceResult<arkret_wire::CommitStreamRef> {
    match &event.scope_ref {
        arkret_wire::ScopeRef::Realm { realm_id } if realm_id == &event.realm_id => {
            Ok(arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            })
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == &event.realm_id => Ok(arkret_wire::CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        }),
        _ => Err(target_not_found()),
    }
}

pub(crate) async fn ensure_scope_member(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<()> {
    if scope_member_in_connection(conn, realm, scope, actor).await? {
        Ok(())
    } else {
        Err(target_not_found())
    }
}

/// Membership is an internal authorization fact. The consuming operation owns
/// its refusal category; database and other storage failures propagate intact.
pub(crate) async fn scope_member_in_connection(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<bool> {
    scope_member_at_cut(conn, realm, scope, actor, true).await
}

/// Current readers retain one snapshot instead of taking writer locks.
pub(crate) async fn ensure_scope_member_snapshot(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<()> {
    if scope_member_at_cut(conn, realm, scope, actor, false).await? {
        Ok(())
    } else {
        Err(target_not_found())
    }
}

async fn scope_member_at_cut(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
    lock_parent: bool,
) -> PersistenceResult<bool> {
    if scope.realm_id_opt() != Some(realm) {
        return Ok(false);
    }
    if let arkret_wire::ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    {
        if realm_id != realm {
            return Ok(false);
        }
        return crate::sidecar_access::participant_in_connection(conn, realm, sidecar_id, actor)
            .await;
    }
    let membership = if lock_parent {
        crate::member_state_admission::locked_membership(conn, realm, actor).await?
    } else {
        crate::member_state_admission::snapshot_membership(conn, realm, actor).await?
    };
    if membership != "join" {
        return Ok(false);
    }
    if let arkret_wire::ScopeRef::Circle { circle_id, .. } = scope {
        if !crate::circle_current_states::effective_member_in_connection(
            conn, realm, circle_id, actor,
        )
        .await?
        {
            return Ok(false);
        }
        let joined = diesel::sql_query(
            "SELECT EXISTS (SELECT 1 FROM circle_member_state_current_states m \
            JOIN circle_current_states c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
            WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' \
            AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value) \
            AND c.value->>'state'='active') AS present",
        )
        .bind::<Text, _>(realm.as_str())
        .bind::<Text, _>(circle_id.as_str())
        .bind::<Text, _>(actor.to_string())
        .get_result::<PresentRow>(&mut *conn)
        .await
        .map_err(PersistenceError::database)?
        .present;
        if !joined {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn ensure_scope_target(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    target: &str,
    before: i64,
) -> PersistenceResult<()> {
    let arkret_wire::ScopeRef::Circle { circle_id, .. } = scope else {
        return ensure_realm_scope_target(conn, realm.as_str(), target, before).await;
    };
    let found = diesel::sql_query("SELECT EXISTS (
        SELECT 1 FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2 AND circle_id=$3
        UNION ALL SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
         WHERE c.realm_id=$1 AND c.stream_ref->>'circle_id'=$2 AND c.stream_ref->>'kind'='circle'
          AND c.stream_position<$4 AND e.state='committed' AND c.commit_json->>'event_ref'=$3
        UNION ALL SELECT 1 FROM message_revision_current_states m JOIN realm_commits c ON c.commit_id=m.current_commit_id
         WHERE m.realm_id=$1 AND m.message_id=$3 AND c.stream_ref->>'circle_id'=$2
          AND c.stream_ref->>'kind'='circle' AND c.stream_position<$4
        UNION ALL SELECT 1 FROM strand_current_states s JOIN realm_commits c ON c.commit_id=s.current_commit_id
         WHERE s.realm_id=$1 AND s.strand_id=$3 AND s.value->>'scope_circle_id'=$2
          AND c.stream_ref->>'kind'='circle' AND c.stream_ref->>'circle_id'=$2 AND c.stream_position<$4
        ) AS present")
        .bind::<Text,_>(realm.as_str()).bind::<Text,_>(circle_id.as_str()).bind::<Text,_>(target)
        .bind::<BigInt,_>(before).get_result::<PresentRow>(&mut *conn).await
        .map_err(PersistenceError::database)?.present;
    if found {
        Ok(())
    } else {
        Err(target_not_found())
    }
}
