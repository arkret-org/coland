//! Accepted `ak.rsvp.set` writes the complete entry to one typed current row.
//! Target admission reads only signed envelopes and public Strand axes; it
//! never decides whether a basis is the current plaintext schedule winner.

use arkret_event_draft::EventPayloadExt as _;
use coland_storage::{PersistenceError, PersistenceResult};
use diesel::OptionalExtension as _;
use diesel::sql_types::{BigInt, Binary, Bool, Jsonb, Text, Timestamptz};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use serde_json::Value;

#[derive(diesel::QueryableByName)]
struct StrandRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

#[derive(diesel::QueryableByName)]
struct BasisRow {
    #[diesel(sql_type = Text)]
    realm_id: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    stream_ref: Value,
    #[diesel(sql_type = BigInt)]
    stream_position: i64,
}

#[derive(diesel::QueryableByName)]
struct PresentRow {
    #[diesel(sql_type = Bool)]
    present: bool,
}

fn refused(code: &str, detail: &str) -> PersistenceError {
    PersistenceError::Conflict(format!("{code}: {detail}"))
}

/// The Realm authority row lock is already held by the enclosing UOW. A
/// failed check aborts its Event, Commit, quota reservation and this result.
pub(crate) async fn commit_rsvp_current_result_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RsvpSet {
        return Ok(());
    }
    arkret_schema::validate_event_for_submit(event)
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if commit.stream_ref
        != (arkret_wire::CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        })
    {
        return Err(refused(
            "failed_precondition",
            "RSVP requires the target Realm commit stream",
        ));
    }
    let payload: arkret_models_collaboration::objects::productivity::RsvpSetPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    payload
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    if let Some(occurrence) = payload.occurrence.as_deref() {
        arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(
            occurrence,
        )
        .map_err(|error| refused("rsvp_occurrence_not_canonical", &error.to_string()))?;
    }

    // The ordinary capability evaluator now addresses RSVP at the exact
    // Strand resource. Its quota reservation is part of this same UOW.
    crate::realm_authorization_cut::authorize_capability_gated_event_in_connection(
        conn,
        event,
        commit.committed_at,
    )
    .await?;

    let target = diesel::sql_query(
        "SELECT realm_id,value FROM strand_current_results WHERE strand_id=$1 FOR SHARE",
    )
    .bind::<Text, _>(payload.event_ref.as_str())
    .get_result::<StrandRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| refused("not_found", "RSVP target is unavailable"))?;
    if target.realm_id != event.realm_id.as_str()
        || target.value.get("state").and_then(Value::as_str) != Some("active")
        || !target
            .value
            .get("schema_refs")
            .and_then(Value::as_array)
            .is_some_and(|refs| {
                refs.iter()
                    .any(|reference| reference == "ak.schema.calendar_event.v1")
            })
    {
        return Err(refused("not_found", "RSVP target is unavailable"));
    }
    let expected_scope = match target.value.get("scope_circle_id") {
        None | Some(Value::Null) => arkret_wire::ScopeRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        Some(Value::String(id)) => arkret_wire::ScopeRef::Circle {
            realm_id: event.realm_id.clone(),
            circle_id: arkret_wire::CircleId::new(id.clone()).map_err(|error| {
                PersistenceError::Internal(format!("stored Strand scope is invalid: {error}"))
            })?,
        },
        Some(_) => {
            return Err(PersistenceError::Internal(
                "stored Strand scope has an invalid type".to_owned(),
            ));
        }
    };
    if event.scope_ref != expected_scope {
        return Err(refused("not_found", "RSVP target is unavailable"));
    }

    let basis_id = &payload.entry.schedule_basis_refs[0];
    let basis = diesel::sql_query(
        "SELECT e.realm_id,e.kind,e.envelope,c.stream_ref,c.stream_position \
         FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.id=$1 AND e.state='committed'",
    )
    .bind::<Binary, _>(
        crate::ids::event_token_part_or_schema_violation(basis_id.as_str(), "event")?.to_vec(),
    )
    .get_result::<BasisRow>(&mut *conn)
    .await
    .optional()
    .map_err(PersistenceError::database)?
    .ok_or_else(|| refused("dependency_missing", "RSVP basis Event is not committed"))?;
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("RSVP stream position exceeds BIGINT".to_owned())
    })?;
    if basis.realm_id != event.realm_id.as_str()
        || basis.stream_position >= position
        || basis.stream_ref
            != serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?
        || !basis_names_target(&basis, basis_id, &payload.event_ref)?
    {
        return Err(refused(
            "failed_precondition",
            "RSVP basis does not name an earlier schedule target Event",
        ));
    }

    let scope_key = String::from_utf8(
        arkret_canonical::canonical_json_bytes(&expected_scope)
            .map_err(PersistenceError::database)?,
    )
    .map_err(PersistenceError::database)?;
    let activated = diesel::sql_query(
        "SELECT EXISTS(SELECT 1 FROM mls_group_current_results WHERE scope_key=$1 AND realm_id=$2) AS present",
    )
    .bind::<Text, _>(&scope_key)
    .bind::<Text, _>(event.realm_id.as_str())
    .get_result::<PresentRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?
    .present;
    if payload.entry.response.is_some() {
        if activated {
            return Err(refused(
                "mls_activation_required",
                "plaintext RSVP is forbidden in an activated scope",
            ));
        }
        // The current Station's ServiceDescribe does not declare
        // rsvp_response. The Realm declaration alone cannot authorize it.
        return Err(refused(
            "unsupported_feature",
            "plaintext RSVP lacks the required service declaration",
        ));
    }

    let occurrence =
        serde_json::to_value(&payload.occurrence).map_err(PersistenceError::database)?;
    let actor = serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
    // The registered set value is the signed payload.entry itself, not a
    // reserialized view of the typed validator.
    let value = event
        .payload
        .get("entry")
        .cloned()
        .ok_or_else(|| PersistenceError::SchemaViolation("RSVP entry is missing".to_owned()))?;
    let stream_ref =
        serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    let written = diesel::sql_query(
        "INSERT INTO rsvp_current_results \
         (realm_id,event_ref,occurrence,responder_actor_id,current_commit_id,\
          current_stream_position,source_stream_ref,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,event_ref,occurrence,responder_actor_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           source_stream_ref=EXCLUDED.source_stream_ref, value=EXCLUDED.value, \
           updated_at=EXCLUDED.updated_at \
         WHERE rsvp_current_results.current_stream_position < EXCLUDED.current_stream_position",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.event_ref.as_str())
    .bind::<Jsonb, _>(&occurrence)
    .bind::<Jsonb, _>(&actor)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&stream_ref)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(refused(
            "failed_precondition",
            "RSVP current is already at or beyond this stream position",
        ));
    }
    Ok(())
}

/// A member Station folds only an already verified, consecutive source
/// RealmCommit. The governing Station has decided capability, schedule basis
/// and lifecycle admission; the replica retains the signed entry and order.
pub(crate) async fn project_verified_rsvp_in_connection(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
) -> PersistenceResult<()> {
    if event.kind != arkret_wire::EventKind::RsvpSet
        || event.realm_id != commit.realm_id
        || event.event_id != commit.event_ref
        || arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)
            .map_err(PersistenceError::database)?
            != commit.stream_ref
    {
        return Err(PersistenceError::SchemaViolation(
            "RSVP replica Event and covering Commit differ".to_owned(),
        ));
    }
    let payload: arkret_models_collaboration::objects::productivity::RsvpSetPayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(PersistenceError::database)?,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    payload
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let position = i64::try_from(commit.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("RSVP stream position exceeds BIGINT".to_owned())
    })?;
    let occurrence =
        serde_json::to_value(&payload.occurrence).map_err(PersistenceError::database)?;
    let actor = serde_json::to_value(&event.actor_id).map_err(PersistenceError::database)?;
    let source = serde_json::to_value(&commit.stream_ref).map_err(PersistenceError::database)?;
    let value = event
        .payload
        .get("entry")
        .cloned()
        .ok_or_else(|| PersistenceError::SchemaViolation("RSVP entry is missing".to_owned()))?;
    let written = diesel::sql_query(
        "INSERT INTO rsvp_current_results \
         (realm_id,event_ref,occurrence,responder_actor_id,current_commit_id, \
          current_stream_position,source_stream_ref,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,event_ref,occurrence,responder_actor_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           source_stream_ref=EXCLUDED.source_stream_ref,value=EXCLUDED.value, \
           updated_at=EXCLUDED.updated_at \
         WHERE rsvp_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
           AND (rsvp_current_results.current_stream_position<EXCLUDED.current_stream_position \
             OR (rsvp_current_results.current_stream_position=EXCLUDED.current_stream_position \
               AND rsvp_current_results.current_commit_id=EXCLUDED.current_commit_id \
               AND rsvp_current_results.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(payload.event_ref.as_str())
    .bind::<Jsonb, _>(&occurrence)
    .bind::<Jsonb, _>(&actor)
    .bind::<Text, _>(commit.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&source)
    .bind::<Jsonb, _>(&value)
    .bind::<Timestamptz, _>(commit.committed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "RSVP replica conflicts with the retained source revision".to_owned(),
        ));
    }
    Ok(())
}

/// Install one signed Snapshot row at its verified source revision. The row
/// may precede locally retained history, so it cannot depend on a basis Event
/// or a local capability grant.
#[expect(
    clippy::too_many_arguments,
    reason = "Atomic RSVP installation binds the Event, current revision and verified provenance."
)]
pub(crate) async fn install_verified_rsvp_in_connection(
    conn: &mut AsyncPgConnection,
    realm_id: &arkret_wire::RealmId,
    event_ref: &arkret_wire::StrandId,
    occurrence: &Option<String>,
    responder_actor_id: &arkret_wire::ActorId,
    source_stream_ref: &arkret_wire::CommitStreamRef,
    revision: &arkret_wire::CurrentRevision,
    value: &Value,
    installed_at: chrono::DateTime<chrono::Utc>,
) -> PersistenceResult<()> {
    if source_stream_ref.realm_id() != realm_id {
        return Err(PersistenceError::SchemaViolation(
            "RSVP snapshot row belongs to another Realm".to_owned(),
        ));
    }
    if let Some(occurrence) = occurrence {
        arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(
            occurrence,
        )
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    }
    let entry: arkret_models_collaboration::objects::productivity::RsvpEntry =
        serde_json::from_value(value.clone())
            .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    entry
        .validate()
        .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
    let occurrence = serde_json::to_value(occurrence).map_err(PersistenceError::database)?;
    let actor = serde_json::to_value(responder_actor_id).map_err(PersistenceError::database)?;
    let source = serde_json::to_value(source_stream_ref).map_err(PersistenceError::database)?;
    let position = i64::try_from(revision.stream_position).map_err(|_| {
        PersistenceError::SchemaViolation("RSVP stream position exceeds BIGINT".to_owned())
    })?;
    let written = diesel::sql_query(
        "INSERT INTO rsvp_current_results \
         (realm_id,event_ref,occurrence,responder_actor_id,current_commit_id, \
          current_stream_position,source_stream_ref,value,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) \
         ON CONFLICT (realm_id,event_ref,occurrence,responder_actor_id) DO UPDATE SET \
           current_commit_id=EXCLUDED.current_commit_id, \
           current_stream_position=EXCLUDED.current_stream_position, \
           source_stream_ref=EXCLUDED.source_stream_ref,value=EXCLUDED.value, \
           updated_at=EXCLUDED.updated_at \
         WHERE rsvp_current_results.source_stream_ref=EXCLUDED.source_stream_ref \
           AND (rsvp_current_results.current_stream_position<EXCLUDED.current_stream_position \
             OR (rsvp_current_results.current_stream_position=EXCLUDED.current_stream_position \
               AND rsvp_current_results.current_commit_id=EXCLUDED.current_commit_id \
               AND rsvp_current_results.value=EXCLUDED.value))",
    )
    .bind::<Text, _>(realm_id.as_str())
    .bind::<Text, _>(event_ref.as_str())
    .bind::<Jsonb, _>(&occurrence)
    .bind::<Jsonb, _>(&actor)
    .bind::<Text, _>(revision.commit_id.as_str())
    .bind::<BigInt, _>(position)
    .bind::<Jsonb, _>(&source)
    .bind::<Jsonb, _>(value)
    .bind::<Timestamptz, _>(installed_at)
    .execute(conn)
    .await
    .map_err(PersistenceError::database)?;
    if written != 1 {
        return Err(PersistenceError::Conflict(
            "RSVP snapshot conflicts with the retained source revision".to_owned(),
        ));
    }
    Ok(())
}

fn basis_names_target(
    basis: &BasisRow,
    basis_id: &arkret_wire::EventId,
    target: &arkret_wire::StrandId,
) -> PersistenceResult<bool> {
    let event: arkret_wire::Event =
        serde_json::from_value(basis.envelope.clone()).map_err(|error| {
            PersistenceError::SchemaViolation(format!("RSVP basis Event invalid: {error}"))
        })?;
    if event.event_id != *basis_id
        || event.kind.as_str() != basis.kind
        || event.realm_id.as_str() != basis.realm_id
    {
        return Err(PersistenceError::SchemaViolation(
            "RSVP basis row differs from its Event".to_owned(),
        ));
    }
    match event.kind {
        arkret_wire::EventKind::StrandCreate => {
            event
                .as_strand_create()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            Ok(arkret_wire::StrandId::from_event_id(basis_id) == *target)
        }
        arkret_wire::EventKind::StrandUpdate => {
            let payload = event
                .as_strand_update()
                .map_err(|error| PersistenceError::SchemaViolation(error.to_string()))?;
            Ok(payload.target_ref == *target)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod typed_basis_tests {
    use arkret_wire::{
        AccountId, ActorId, DidCoreId, EventId, EventKind, RealmId, ScopeRef, StrandId,
    };
    use serde_json::json;

    use super::*;

    fn basis(kind: EventKind, payload: Value) -> (BasisRow, EventId) {
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:rsvp-member.example").unwrap(),
            DidCoreId::new("ak:did_core:web:rsvp-station.example").unwrap(),
        ));
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            actor,
            payload,
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        let id = event.event_id.clone();
        (
            BasisRow {
                realm_id: realm.to_string(),
                kind: kind.as_str().to_owned(),
                envelope: serde_json::to_value(event).unwrap(),
                stream_ref: json!({}),
                stream_position: 1,
            },
            id,
        )
    }

    fn target(byte: u8) -> StrandId {
        StrandId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [byte; 32],
        ))
    }

    #[test]
    fn typed_update_basis_names_only_its_signed_target() {
        let expected = target(2);
        let (row, id) = basis(
            EventKind::StrandUpdate,
            json!({"target_ref": expected, "patch": {"metadata.title": {"$op": "set", "value": "Changed"}}}),
        );
        assert!(basis_names_target(&row, &id, &expected).unwrap());
        assert!(!basis_names_target(&row, &id, &target(3)).unwrap());
    }

    #[test]
    fn typed_create_basis_names_the_event_derived_strand() {
        let realm = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [1; 32],
        ));
        let actor = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:rsvp-member.example").unwrap(),
            DidCoreId::new("ak:did_core:web:rsvp-station.example").unwrap(),
        ));
        let strand = arkret_models_collaboration::objects::strand::Strand::new_create(
            realm, "Schedule", actor,
        );
        let (row, id) = basis(EventKind::StrandCreate, json!({"object": strand}));
        assert!(basis_names_target(&row, &id, &StrandId::from_event_id(&id)).unwrap());
        assert!(!basis_names_target(&row, &id, &target(3)).unwrap());
    }

    #[test]
    fn basis_rejects_row_identity_drift_and_malformed_payloads() {
        let expected = target(2);
        let (mut row, id) = basis(
            EventKind::StrandUpdate,
            json!({"target_ref": expected, "patch": {}}),
        );
        row.kind = EventKind::StrandCreate.as_str().to_owned();
        assert!(basis_names_target(&row, &id, &expected).is_err());
        row.kind = EventKind::StrandUpdate.as_str().to_owned();
        assert!(
            basis_names_target(
                &row,
                &EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [4; 32]),
                &expected
            )
            .is_err()
        );
        row.realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [5; 32],
        ))
        .to_string();
        assert!(basis_names_target(&row, &id, &expected).is_err());
        for payload in [
            json!({"target_ref": expected}),
            json!({"strand_id": expected, "patch": {}}),
            json!({"target_ref": expected, "patch": {}, "unexpected": true}),
        ] {
            let (row, id) = basis(EventKind::StrandUpdate, payload);
            assert!(basis_names_target(&row, &id, &expected).is_err());
        }
    }
}
