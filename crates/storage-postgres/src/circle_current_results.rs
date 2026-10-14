//! Same-cut authority admission and durable current for the first ordinary
//! Circle create and self-membership edges. Unsupported Circle branches remain
//! closed; no projection table is an authorization source.

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_collaboration::events_payloads::circle::{
    CircleCreatePayload, CircleMemberStatePayload,
};
use arkret_models_collaboration::governance::circle::{
    Circle, CircleJoinRule, CircleMembership, CircleState,
};
use arkret_wire::{
    CircleId, CircleMemberStateCurrent, CommitStreamRef, Event, EventKind, MembershipState,
    RealmCommit, SchemaId, ScopeRef, WirePresence,
};
use coland_storage::{ConflictCode, PersistenceError, PersistenceResult};
use diesel::sql_types::{BigInt, Bool, Jsonb, Text, Timestamptz};
use diesel::{OptionalExtension as _, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct CircleRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct MemberRow {
    #[diesel(sql_type = Text)]
    membership: String,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

/// A Circle-scoped content writer must use the signed Circle stream and the
/// durable active Circle/member currents at its accepting cut. The Realm
/// authority lock held by capability authorization serializes governance
/// changes; the covering Commit joins exclude unproved projection rows.
pub(crate) async fn require_active_author_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &event.scope_ref
    else {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "Circle source scope is absent",
        ));
    };
    if realm_id != &event.realm_id
        || commit.event_ref != event.event_id
        || commit.stream_ref
            != (CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: circle_id.clone(),
            })
        || crate::member_state_admission::locked_membership(conn, realm_id, &event.actor_id).await?
            != "join"
    {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "Circle source or Realm membership differs",
        ));
    }
    let active = sql_query(
        "SELECT EXISTS (SELECT 1 FROM circle_current_results circle \
         JOIN realm_commits cc ON cc.commit_id=circle.current_commit_id \
         WHERE circle.realm_id=$1 AND circle.circle_id=$2 AND circle.value->>'state'='active' \
           AND cc.realm_id=circle.realm_id AND cc.stream_position=circle.current_stream_position \
           AND cc.stream_ref=circle.source_stream_ref \
           AND cc.stream_ref->>'kind'='realm' AND cc.stream_ref->>'realm_id'=circle.realm_id) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !active.present {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "circle_not_active",
        ));
    }
    let present = sql_query(
        "SELECT EXISTS (SELECT 1 FROM circle_current_results circle \
         JOIN realm_commits cc ON cc.commit_id=circle.current_commit_id \
         JOIN circle_member_state_current_results member ON member.circle_id=circle.circle_id AND member.realm_id=circle.realm_id \
         JOIN realm_commits mc ON mc.commit_id=member.current_commit_id \
         WHERE circle.realm_id=$1 AND circle.circle_id=$2 AND circle.value->>'state'='active' \
           AND cc.realm_id=circle.realm_id AND cc.stream_position=circle.current_stream_position \
           AND cc.stream_ref=circle.source_stream_ref \
           AND cc.stream_ref->>'kind'='realm' AND cc.stream_ref->>'realm_id'=circle.realm_id \
           AND member.member_id=$3 AND member.membership='join' \
           AND mc.realm_id=member.realm_id AND mc.stream_position=member.current_stream_position \
           AND mc.stream_ref=member.source_stream_ref \
           AND mc.stream_ref->>'kind'='circle' AND mc.stream_ref->>'realm_id'=member.realm_id \
           AND mc.stream_ref->>'circle_id'=member.circle_id AND mc.stream_position<$4 \
           AND circle_member_parent_join_current(member.realm_id,member.member_id,member.value)) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(event.actor_id.to_string())
    .bind::<BigInt, _>(i64::try_from(commit.stream_position).map_err(PersistenceError::database)?)
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if !present.present {
        return Err(conflict(
            ConflictCode::FailedPrecondition,
            "Circle is inactive or actor is not a confirmed member",
        ));
    }
    Ok(())
}

/// Effective Circle membership of one complete ActorId at this cut
/// (`circle.md` section 9.1): the canonical Circle join whose bound parent
/// revision is still the parent Realm `member_state` current.
pub(crate) async fn effective_member_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    circle_id: &CircleId,
    actor: &arkret_wire::ActorId,
) -> PersistenceResult<bool> {
    Ok(sql_query(
        "SELECT EXISTS (SELECT 1 FROM circle_member_state_current_results m \
         WHERE m.realm_id=$1 AND m.circle_id=$2 AND m.member_id=$3 AND m.membership='join' \
           AND circle_member_parent_join_current(m.realm_id,m.member_id,m.value)) AS present",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(circle_id.as_str())
    .bind::<Text, _>(actor.to_string())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present)
}

fn conflict(code: ConflictCode, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

fn schema(detail: &str) -> PersistenceError {
    PersistenceError::SchemaViolation(detail.to_owned())
}

fn member_state_payload(event: &Event) -> PersistenceResult<CircleMemberStatePayload> {
    event
        .as_circle_member_state()
        .map_err(|error| schema(&format!("Circle membership payload is invalid: {error}")))
}

fn circle_id(event: &Event) -> CircleId {
    CircleId::from_event_id(&event.event_id)
}

fn folded_short_name(name: &str) -> PersistenceResult<String> {
    let bytes = name.as_bytes();
    if !(1..=24).contains(&bytes.len())
        || !bytes[0].is_ascii_uppercase()
        || !bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-'))
    {
        return Err(schema(
            "Circle short_name is outside its closed ASCII profile",
        ));
    }
    Ok(name.to_ascii_lowercase())
}

pub(crate) async fn admit_with_audit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
    _authority_station: &arkret_wire::DidCoreId,
    audit_unit: Option<&coland_storage::RegisteredAuditCommit>,
    prepared: Option<&coland_storage::EventApprovalCommit>,
) -> PersistenceResult<()> {
    let paired = audit_unit.is_some_and(|unit| unit.pair_for(event));
    match &event.kind {
        EventKind::CircleCreate => {
            if event.scope_ref
                != (ScopeRef::Realm {
                    realm_id: event.realm_id.clone(),
                })
                || commit.stream_ref
                    != (CommitStreamRef::Realm {
                        realm_id: event.realm_id.clone(),
                    })
            {
                return Err(schema("Circle create must be on the Realm stream"));
            }
            let payload = event
                .as_circle_create()
                .map_err(|_| schema("Circle create payload is invalid"))?;
            let object = payload.object;
            if object.schema != SchemaId::CIRCLE_V1
                || object.id.is_some()
                || object.mls_group_id.is_some()
                || object.realm_id != event.realm_id
                || object.created_by != event.actor_id
                || object.created_at != event.created_at
                || object.state != CircleState::Active
                || object.state_changed_at.is_some()
                || object.updated_by.is_some()
                || object.updated_at.is_some()
            {
                return Err(schema("Circle create object differs from its signed Event"));
            }
            if object.profile_ref.is_some() {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "Circle profile needs its own admission cut",
                ));
            }
            crate::agent_participation_admission::require_child_tightens(
                conn,
                event.realm_id.as_str(),
                None,
                &serde_json::to_value(&object).map_err(PersistenceError::database)?,
            )
            .await?;
            let short_name = folded_short_name(&object.display.short_name)?;
            crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                conn, event, commit, prepared,
            )
            .await?;
            let used_name = sql_query(
                "SELECT value FROM circle_current_results WHERE realm_id=$1 AND short_name_folded=$2 FOR SHARE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(short_name)
            .get_result::<CircleRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            if used_name.is_some() {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_short_name_taken",
                ));
            }
            Ok(())
        }
        EventKind::CircleMemberState => {
            let ScopeRef::Circle {
                realm_id,
                circle_id,
            } = &event.scope_ref
            else {
                return Err(schema("Circle membership needs a Circle stream"));
            };
            let payload = member_state_payload(event)?;
            if realm_id != &event.realm_id
                || commit.stream_ref
                    != (CommitStreamRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
                || payload.circle_id != *circle_id
            {
                return Err(schema("Circle membership scope and payload differ"));
            }
            let member = payload.member_id.clone();
            if member != event.actor_id && !paired {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "cross-actor Circle membership needs its audit and manager cut",
                ));
            }
            let next = payload.membership.as_str();
            crate::realm_authorization_cut::lock_realm_authorization_cut(conn, &event.realm_id)
                .await?;
            // circle.md section 9.1: the parent current must be join, and a
            // Circle join must name exactly its revision on the Realm stream.
            let parent =
                crate::member_state_admission::locked_membership_revision(conn, realm_id, &member)
                    .await?;
            let parent_admits = match &parent {
                Some((MembershipState::Join, revision)) => {
                    payload.membership != CircleMembership::Join
                        || payload.parent_membership_revision.as_ref() == Some(revision)
                }
                _ => false,
            };
            if !parent_admits {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_member_must_be_realm_member",
                ));
            }
            if !paired {
                crate::realm_authorization_cut::authorize_capability_gated_event_with_approvals(
                    conn, event, commit, prepared,
                )
                .await?;
            }
            let circle = sql_query(
                "SELECT value FROM circle_current_results WHERE realm_id=$1 AND circle_id=$2 FOR SHARE",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .get_result::<CircleRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .ok_or_else(|| PersistenceError::NotFound("Circle is not available".to_owned()))?;
            let circle: Circle = serde_json::from_value(circle.value)
                .map_err(|error| schema(&format!("stored Circle is invalid: {error}")))?;
            if circle.state != CircleState::Active {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "circle_not_active",
                ));
            }
            if !paired && next == "join" && circle.join_rule != CircleJoinRule::Public {
                return Err(conflict(
                    ConflictCode::UnsupportedFeature,
                    "Circle self-entry requires a public Circle",
                ));
            }
            if next == "knock" && circle.join_rule != CircleJoinRule::Knock {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "Circle knock requires its knock join rule",
                ));
            }
            let current = sql_query(
                "SELECT membership FROM circle_member_state_current_results \
                 WHERE circle_id=$1 AND member_id=$2 FOR UPDATE",
            )
            .bind::<Text, _>(circle_id.as_str())
            .bind::<Text, _>(member.to_string())
            .get_result::<MemberRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?;
            let previous = current.as_ref().map(|row| row.membership.as_str());
            let expected_matches = match &payload.expected_membership {
                WirePresence::Missing => true,
                WirePresence::Null => previous.is_none(),
                WirePresence::Value(expected) => previous == Some(expected.as_str()),
            };
            if !expected_matches {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "Circle membership CAS differs",
                ));
            }
            if !matches!(
                (previous, next),
                (None | Some("leave"), "join" | "knock") | (Some("join" | "knock"), "leave")
            ) {
                return Err(conflict(
                    ConflictCode::InvalidMembershipTransition,
                    "Circle self-membership edge is invalid",
                ));
            }
            if next == "join" {
                let cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
                    conn, realm_id, &member,
                )
                .await?;
                if let Some(controller) = cut
                    .owned_controller_in_connection(conn, commit.committed_at)
                    .await?
                {
                    crate::agent_management_admission::require_circle_join_in_connection(
                        conn,
                        realm_id,
                        circle_id,
                        controller
                            .as_account_id()
                            .ok_or_else(|| schema("Agent controller is not an Account"))?,
                        member
                            .as_account_id()
                            .ok_or_else(|| schema("Agent member is not an Account"))?,
                        commit.committed_at,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) async fn commit_in_connection(
    conn: &mut AsyncPgConnection,
    event: &Event,
    commit: &RealmCommit,
) -> PersistenceResult<()> {
    let position = i64::try_from(commit.stream_position)
        .map_err(|_| schema("Circle stream position exceeds storage"))?;
    match &event.kind {
        EventKind::CircleCreate => {
            let mut payload: CircleCreatePayload = serde_json::from_value(json!(&event.payload))
                .map_err(|_| schema("Circle create payload is invalid"))?;
            let id = circle_id(event);
            let short_name = folded_short_name(&payload.object.display.short_name)?;
            payload.object.id = Some(id.clone());
            let value = serde_json::to_value(payload.object).map_err(PersistenceError::database)?;
            sql_query(
                "INSERT INTO circle_current_results \
                 (realm_id,circle_id,create_event_id,current_commit_id,current_stream_position,source_stream_ref,short_name_folded,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(id.as_str())
            .bind::<Text, _>(event.event_id.as_str())
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
            .bind::<Text, _>(short_name)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
        }
        EventKind::CircleMemberState => {
            let ScopeRef::Circle { circle_id, .. } = &event.scope_ref else {
                return Err(schema("Circle membership scope invalid"));
            };
            let payload = member_state_payload(event)?;
            let member = payload.member_id.clone();
            let membership = payload.membership.as_str();
            // The signed parent revision is copied verbatim, never derived.
            let current = CircleMemberStateCurrent {
                membership: serde_json::from_value(json!(membership))
                    .map_err(|_| schema("membership invalid"))?,
                parent_membership_revision: payload.parent_membership_revision.clone(),
                effective_at: payload.effective_at.unwrap_or(event.created_at),
            };
            current
                .validate()
                .map_err(|error| schema(&error.to_string()))?;
            let value = serde_json::to_value(&current).map_err(PersistenceError::database)?;
            let changed = sql_query(
                "INSERT INTO circle_member_state_current_results \
                 (realm_id,circle_id,member_id,membership,current_commit_id,current_stream_position,source_stream_ref,value,updated_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) \
                 ON CONFLICT(circle_id,member_id) DO UPDATE SET \
                 membership=EXCLUDED.membership,current_commit_id=EXCLUDED.current_commit_id, \
                 current_stream_position=EXCLUDED.current_stream_position,source_stream_ref=EXCLUDED.source_stream_ref, \
                 value=EXCLUDED.value,updated_at=EXCLUDED.updated_at \
                 WHERE circle_member_state_current_results.realm_id=EXCLUDED.realm_id \
                   AND circle_member_state_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
                   AND (circle_member_state_current_results.current_stream_position<EXCLUDED.current_stream_position \
                     OR (circle_member_state_current_results.current_stream_position=EXCLUDED.current_stream_position \
                       AND circle_member_state_current_results.current_commit_id=EXCLUDED.current_commit_id \
                       AND circle_member_state_current_results.membership=EXCLUDED.membership \
                       AND circle_member_state_current_results.value=EXCLUDED.value))",
            )
            .bind::<Text, _>(event.realm_id.as_str())
            .bind::<Text, _>(circle_id.as_str())
            .bind::<Text, _>(member.to_string())
            .bind::<Text, _>(membership)
            .bind::<Text, _>(commit.commit_id.as_str())
            .bind::<BigInt, _>(position)
            .bind::<Jsonb, _>(serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?)
            .bind::<Jsonb, _>(value)
            .bind::<Timestamptz, _>(commit.committed_at)
            .execute(&mut *conn)
            .await
            .map_err(PersistenceError::database)?;
            if changed != 1 {
                return Err(conflict(
                    ConflictCode::FailedPrecondition,
                    "Circle membership current revision or value differs",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod typed_membership_tests {
    use super::*;

    fn event(kind: EventKind, payload: Value) -> Event {
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm { realm_id: realm },
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:circle-member.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:web:circle-station.example").unwrap(),
            )),
            payload,
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn membership_projection_checks_kind_and_closed_payload_before_admission() {
        let circle = CircleId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [2; 32],
        ));
        let actor = event(EventKind::CircleMemberState, json!({})).actor_id;
        let payload = json!({"circle_id": circle, "member_id": actor, "membership": "leave"});
        let accepted =
            member_state_payload(&event(EventKind::CircleMemberState, payload.clone())).unwrap();
        assert_eq!(accepted.circle_id, circle);
        assert_eq!(accepted.membership, CircleMembership::Leave);
        assert!(member_state_payload(&event(EventKind::MemberState, payload.clone())).is_err());
        let mut extra = payload;
        extra["unexpected"] = json!(true);
        assert!(member_state_payload(&event(EventKind::CircleMemberState, extra)).is_err());
        assert!(
            member_state_payload(&event(
                EventKind::CircleMemberState,
                json!({"circle_id": circle, "membership": "leave"})
            ))
            .is_err()
        );
    }
}
