//! The `moderation_report` typed current writer at the accepting RealmCommit cut.
//!
//! `governance/content-moderation.md` §3.3 makes the accepted
//! `ak.self.moderation.report` Event itself the canonical fact: the subject is
//! the Event's own id and the value is the complete signed payload. The
//! reporter-authored self report is accepted on its exact Realm or Circle stream.
//! Membership and target visibility are read at the accepting authority cut;
//! MIMI facade reports remain outside this self-ingress.

use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
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

fn conflict(detail: &'static str) -> PersistenceError {
    PersistenceError::Conflict(detail.to_owned())
}

/// The single anti-oracle answer for an absent, invisible or scope-mismatched
/// target (`ak.self.moderation.command.report.v1` operation mapping).
fn target_not_found() -> PersistenceError {
    PersistenceError::NotFound("moderation target not found".to_owned())
}

fn position(commit: &arkret_wire::RealmCommit) -> PersistenceResult<i64> {
    i64::try_from(commit.stream_position).map_err(|_| conflict("invalid report stream position"))
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

/// Prove the signed `target_ref` names an accepted Realm-scope object of this
/// Realm strictly before the report's own Commit on the same Realm stream.
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
                "SELECT EXISTS (SELECT 1 FROM message_revision_current_results m \
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
                "SELECT s.value FROM strand_current_results s \
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

pub(crate) async fn commit_moderation_report_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::SelfModerationReport {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let stream = moderation_stream(event)?;
    if commit.stream_ref != stream || commit.event_ref != event.event_id {
        return Err(conflict(
            "moderation report source stream differs from signed scope",
        ));
    }
    if event.executed_by.is_some() || event.authorization_ref.is_some() || event.applet_id.is_some()
    {
        return Err(conflict(
            "self moderation report must be directly authored by its reporter",
        ));
    }
    let payload = serde_json::to_value(&event.payload).map_err(PersistenceError::database)?;
    let typed: arkret_models_collaboration::events_payloads::moderation::ModerationReportPayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let mimi = typed.provenance == Some(arkret_models_collaboration::events_payloads::moderation::ModerationReportProvenance::MimiFacade);
    if !mimi {
        typed
            .validate_self_endpoint(event.actor_id.signing_principal_id())
            .map_err(|error| PersistenceError::Conflict(error.to_owned()))?;
    }
    if typed.realm_id != event.realm_id {
        return Err(target_not_found());
    }
    let effective_scope =
        typed
            .effective_scope
            .clone()
            .unwrap_or_else(|| arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            });
    if effective_scope != event.scope_ref {
        return Err(target_not_found());
    }
    let before = position(commit)?;
    // The exact full reporter Account and its current membership were checked
    // by the required MimiFacade producer guard before this writer is called.
    if !mimi {
        ensure_scope_member(conn, &event.realm_id, &event.scope_ref, &event.actor_id).await?;
    }
    ensure_scope_target(
        conn,
        &event.realm_id,
        &event.scope_ref,
        typed.target_ref.as_str(),
        before,
    )
    .await?;
    let inserted = diesel::sql_query(
        "INSERT INTO moderation_report_current_results \
         (realm_id,report_event_id,current_commit_id,current_stream_position,value,updated_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(event.event_id.as_str())
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(before)
    .bind::<Jsonb, _>(&payload)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if inserted != 1 {
        return Err(conflict(
            "duplicate_conflict: moderation report current result already exists",
        ));
    }
    Ok(())
}

pub(crate) fn moderation_stream(
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
    if crate::member_state_admission::locked_membership(conn, realm, actor).await? != "join" {
        return Ok(false);
    }
    if let arkret_wire::ScopeRef::Circle { circle_id, .. } = scope {
        let joined = diesel::sql_query(
            "SELECT EXISTS (SELECT 1 FROM circle_member_state_current_results m \
            JOIN circle_current_results c ON c.circle_id=m.circle_id AND c.realm_id=m.realm_id \
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
        SELECT 1 FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 AND circle_id=$3
        UNION ALL SELECT 1 FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
         WHERE c.realm_id=$1 AND c.stream_ref->>'circle_id'=$2 AND c.stream_ref->>'kind'='circle'
          AND c.stream_position<$4 AND e.state='committed' AND c.commit_json->>'event_ref'=$3
        UNION ALL SELECT 1 FROM message_revision_current_results m JOIN realm_commits c ON c.commit_id=m.current_commit_id
         WHERE m.realm_id=$1 AND m.message_id=$3 AND c.stream_ref->>'circle_id'=$2
          AND c.stream_ref->>'kind'='circle' AND c.stream_position<$4
        UNION ALL SELECT 1 FROM strand_current_results s JOIN realm_commits c ON c.commit_id=s.current_commit_id
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

pub(crate) async fn scope_moderator(
    conn: &mut AsyncPgConnection,
    realm: &arkret_wire::RealmId,
    scope: &arkret_wire::ScopeRef,
    actor: &arkret_wire::ActorId,
    actions: &[&str],
    at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<bool> {
    let cut =
        crate::realm_authorization_cut::RealmAuthorizationCut::read(conn, realm, actor).await?;
    let target = match scope {
        arkret_wire::ScopeRef::Realm { realm_id } if realm_id == realm => {
            if cut.actor_is_root_controller() {
                return Ok(true);
            }
            arkret_wire::WireResourceSelector::realm(realm.clone())
        }
        arkret_wire::ScopeRef::Circle {
            realm_id,
            circle_id,
        } if realm_id == realm => {
            arkret_wire::WireResourceSelector::circle(realm.clone(), circle_id.clone())
        }
        _ => return Ok(false),
    };
    let facts = coland_storage::OperationFacts::default();
    Ok(!cut
        .evaluate(actions, &target, &facts, at)
        .unreserved()
        .is_empty())
}
