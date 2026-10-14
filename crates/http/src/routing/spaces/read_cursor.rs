//! Read cursor (`ak.self.read_cursor.*`) handlers.
//!
//! Protocol writes are caller-signed `ak.read_cursor.advance` actor-private
//! Events. Their only durable effect is the account-private
//! `ak.private.read_cursor.v1` winner (actor-private-effects.md §3.4); no
//! RealmCommit, Realm reducer or shared history is involved. Mounted on the
//! protocol surface at `/_arkret/self/read-cursors*`.

use arkret_models_collaboration::objects::read_receipts::{
    ReadCursor, ReadCursorAdvanceRequestBody, ReadCursorList, ReadMarkerOutcome,
};
use arkret_wire::{Event, ReadCursorScope, ReadScopeKind};
use coland_http::error::AppError;
use coland_storage::{ReadCursorAdvanceOutcome, ReadCursorAdvanceRefusal};
use salvo::oapi::endpoint;
use salvo::oapi::extract::{JsonBody, QueryParam};
use salvo::prelude::*;

use super::AuthArgs;
use crate::routing::identity::device_messages::{
    ActorPrivateDeviceUpdate, ActorPrivateReadCursorUpdate, DeviceMessageSender,
    fanout_actor_private_update,
};
use crate::state::AppState;
use crate::{JsonResult, json_ok};

#[endpoint(
    operation_id = "ak.self.read_cursor.command.advance",
    summary = "Advance a read cursor",
    tags("read_cursor")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.read_cursor.command.advance.v1"))]
pub(super) async fn set_read_cursor(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    body: JsonBody<ReadCursorAdvanceRequestBody>,
) -> JsonResult<ReadMarkerOutcome> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let submission = body.into_inner().advance_event;
    submission.validate().map_err(|error| {
        AppError::schema_violation(format!("invalid advance_event submission: {error}"))
    })?;
    let event = submission.event;
    let cursor =
        validate_caller_signed_read_cursor(&actor, session.require_human_device_id(), &event)?;
    let owner = actor
        .as_account_id()
        .cloned()
        .ok_or_else(|| AppError::capability_denied("a read cursor is owned by an Account"))?;
    // The owner is `payload.actor_id.account_id`, stored at that Account's own
    // Station (actor-private-effects.md §1); a session of another Station's
    // Account never reaches here.
    if owner.station_id != state.service_core_id() {
        return Err(AppError::capability_denied(
            "a read cursor is stored only at its owner's Station",
        ));
    }
    let producer_guard = crate::state::verify_self_event_producer(state, &session, &event)
        .await
        .map_err(crate::state::actor_private_refusal)?;
    let canonical_event_digest = crate::state::canonical_event_digest(&event)
        .map_err(crate::state::actor_private_refusal)?;
    let advance = coland_storage::ReadCursorAdvance {
        event,
        canonical_event_digest,
        cursor,
        owner,
        producer_guard: Some(producer_guard),
        station_id: state.service_core_id(),
        accepted_at: chrono::Utc::now(),
    };
    let outcome = state
        .persistence()
        .advance_read_cursor(&advance)
        .await
        .map_err(|error| crate::state::actor_private_refusal(error.into()))?;
    let marker = match outcome {
        ReadCursorAdvanceOutcome::Accepted {
            marker,
            candidate_won,
        } => {
            if candidate_won {
                fanout_read_cursor_winner(state, &session, &marker).await?;
            }
            marker
        }
        // The first outcome, without another write or device fanout.
        ReadCursorAdvanceOutcome::Replayed(marker) => marker,
        ReadCursorAdvanceOutcome::Refused(refusal) => return Err(advance_refusal(refusal)),
    };
    json_ok(marker)
}

/// Sibling devices observe a new winner as the `ak.read_cursor.update`
/// device message, whose `updated_at` is the winning advance's envelope time.
async fn fanout_read_cursor_winner(
    state: &AppState,
    session: &coland_services::identity::SessionIdentityState,
    marker: &ReadMarkerOutcome,
) -> Result<(), AppError> {
    let sender_account_id =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(state, session)
            .await?;
    let sender_device_id = arkret_identifiers::DeviceId::new(
        session.require_human_device_id().clone(),
    )
    .map_err(|error| AppError::internal(format!("authenticated device id is invalid: {error}")))?;
    fanout_actor_private_update(
        state,
        &session.actor,
        ActorPrivateDeviceUpdate::ReadCursor {
            sender: DeviceMessageSender::Account {
                sender_account_id,
                sender_device_id,
            },
            content: ActorPrivateReadCursorUpdate {
                schema: arkret_wire::SchemaId::READ_CURSOR_UPDATE_V1.to_owned(),
                actor_id: marker.actor_id.clone(),
                device_id: marker.device_id.clone(),
                realm_id: marker.realm_id.clone(),
                read_scope: marker.read_scope.clone(),
                position: marker.position.clone(),
                updated_at: marker.updated_at,
            },
            created_at: marker.updated_at,
        },
    )
    .await;
    Ok(())
}

/// Every refusal of the actor-private contract writes nothing. A position this
/// Station cannot prove visible or causally ordered stays provisional and is
/// retryable; the caller cannot tell a missing Event from an invisible one.
fn advance_refusal(refusal: ReadCursorAdvanceRefusal) -> AppError {
    match refusal {
        ReadCursorAdvanceRefusal::DuplicateConflict => crate::app_error!(
            DuplicateConflict,
            "advance_event is already accepted with different canonical bytes"
        ),
        ReadCursorAdvanceRefusal::NotMember => {
            AppError::capability_denied("the read cursor owner is not a joined Realm member")
        }
        ReadCursorAdvanceRefusal::PositionNotInRealm => {
            AppError::param_invalid("position.event_id is not a committed Event of realm_id")
        }
        // Decision 0108 (0809): a known position outside the owner's readable
        // interval is `param_invalid`, not a retryable unproved position.
        ReadCursorAdvanceRefusal::PositionNotReadable => {
            AppError::param_invalid("position.event_id is outside the owner's readable interval")
        }
        ReadCursorAdvanceRefusal::Unproved(detail) => {
            crate::app_error!(
                TemporarilyUnavailable,
                "read cursor position unproved: {detail}"
            )
        }
    }
}

fn validate_caller_signed_read_cursor(
    actor: &arkret_wire::ActorId,
    session_device_id: &str,
    event: &Event,
) -> Result<ReadCursor, AppError> {
    if event.kind != arkret_wire::EventKind::ReadCursorAdvance {
        return Err(AppError::param_invalid(
            "advance_event.event.kind must be ak.read_cursor.advance",
        ));
    }
    if &event.actor_id != actor {
        return Err(AppError::param_invalid(
            "advance_event.event.actor_id must be the authenticated caller",
        ));
    }
    let cursor: ReadCursor = serde_json::from_value(
        serde_json::to_value(&event.payload)
            .map_err(|error| AppError::param_invalid(format!("cursor payload: {error}")))?,
    )
    .map_err(|error| AppError::param_invalid(format!("cursor payload: {error}")))?;
    if cursor.actor_id != event.actor_id {
        return Err(AppError::param_invalid(
            "advance_event payload.actor_id must equal event.actor_id",
        ));
    }
    if cursor.realm_id != event.realm_id {
        return Err(AppError::param_invalid(
            "advance_event payload.realm_id must equal event.realm_id",
        ));
    }
    if cursor.device_id.as_str() != session_device_id {
        return Err(AppError::param_invalid(
            "advance_event payload.device_id must equal the authenticated session device",
        ));
    }
    // No payload/envelope timestamp comparison: the cursor object carries no
    // `updated_at` at all (read-receipts.md §6.1). A payload that still ships
    // one is rejected above by the closed `ReadCursor` shape.
    validate_read_scope(&cursor.read_scope)?;
    // `position` needs no local check: `ReadCursorPosition` carries the SDK
    // `EventId` and `Hlc` newtypes, so a non-canonical Event token or HLC is
    // already rejected when the payload is decoded.
    Ok(cursor)
}

#[endpoint(
    operation_id = "ak.self.read_cursor.read.list",
    summary = "List read cursors",
    tags("read_cursor")
)]
#[tracing::instrument(skip_all, fields(op = "ak.self.read_cursor.read.list.v1"))]
pub(super) async fn get_read_cursors(
    aa: AuthArgs,
    depot: &mut Depot,
    req: &mut Request,
    realm_id: QueryParam<String, false>,
) -> JsonResult<ReadCursorList> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    let actor =
        crate::routing::identity::session_actor::session_actor_from_credential(state, &session)?;
    let Some(owner) = actor.as_account_id() else {
        return json_ok(ReadCursorList {
            markers: Vec::new(),
        });
    };
    let realm_id = realm_id
        .into_inner()
        .filter(|value| !value.is_empty())
        .map(|value| {
            arkret_wire::RealmId::new(value)
                .map_err(|error| AppError::param_invalid(format!("realm_id: {error}")))
        })
        .transpose()?;
    let markers = state
        .persistence()
        .read_cursor_winners(owner, realm_id.as_ref())
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(ReadCursorList { markers })
}

fn validate_read_scope(scope: &ReadCursorScope) -> Result<(), AppError> {
    // A read cursor supports only the realm/circle/space/strand/thread subset of
    // the shared read-scope discriminator family (read-cursor.schema.json §2.2).
    // view/message/morph are receipt-only and MUST be rejected here so Circle and
    // Space read isolation can be expressed without admitting receipt-only kinds.
    if !scope.kind.valid_for_read_cursor() {
        return Err(AppError::param_invalid(
            "read_scope.kind must be one of realm/circle/space/strand/thread for a read cursor",
        ));
    }
    match &scope.kind {
        ReadScopeKind::Realm => {
            if scope.container_ref.is_some() || scope.track.is_some() {
                return Err(AppError::param_invalid(
                    "read_scope.container_ref/track_name must be omitted when kind is realm",
                ));
            }
        }
        _ => {
            let Some(container_ref) = scope
                .container_ref
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return Err(AppError::param_invalid(
                    "read_scope.container_ref is required when kind is not realm",
                ));
            };
            validate_scope_ref(&scope.kind, container_ref)?;
            if !matches!(scope.kind, ReadScopeKind::Strand) && scope.track.is_some() {
                return Err(AppError::param_invalid(
                    "read_scope.track_name is only valid when kind is strand",
                ));
            }
        }
    }

    if matches!(scope.kind, ReadScopeKind::Strand)
        && let Some(track) = scope.track.as_deref()
    {
        validate_track(track)?;
    }

    Ok(())
}

fn validate_scope_ref(kind: &ReadScopeKind, object_ref: &str) -> Result<(), AppError> {
    let expected_prefix = match kind {
        ReadScopeKind::Circle => "ak:circle:",
        ReadScopeKind::Space => "ak:space:",
        ReadScopeKind::Strand => "ak:strand:",
        ReadScopeKind::Thread => "ak:message:",
        ReadScopeKind::Realm => return Ok(()),
        _ => {
            return Err(AppError::param_invalid(
                "read_scope.kind must be one of realm/circle/space/strand/thread for a read cursor",
            ));
        }
    };
    if !object_ref.starts_with(expected_prefix) {
        return Err(AppError::param_invalid(format!(
            "read_scope.ref must use {expected_prefix} for this kind"
        )));
    }
    Ok(())
}

fn validate_track(track: &str) -> Result<(), AppError> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err(AppError::param_invalid(
            "read_scope.track_name must not be empty",
        ));
    };
    if !first.is_ascii_lowercase()
        || track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AppError::param_invalid("invalid read_scope.track_name"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const ACTOR_DID: &str = "did:webvh:z6mkalice:alice.example";
    const ACTOR_ID: &str = "ak:did_core:webvh:z6mkalice";
    const DEVICE_ID: &str = "ak:device:01964137-0000-7000-8000-000000000001";
    const REALM_ID: &str = "ak:realm:ATp5qI_DaGqeL1spvchnU-p10lfIfsboDfYyWaObd1Y6";

    fn actor() -> arkret_wire::ActorId {
        crate::test_account_actor(&arkret_wire::Did::new(ACTOR_DID).unwrap())
    }

    fn signed_shape() -> Event {
        let created_at = "2026-08-08T00:00:00.000Z".parse().expect("timestamp");
        crate::test_event::raw_event_at(
            arkret_wire::EventKind::ReadCursorAdvance.as_str(),
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(REALM_ID).expect("realm"),
            },
            crate::test_actor_id_str(ACTOR_DID),
            1,
            "019641370000-0000-00000001".parse().expect("hlc"),
            json!({
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": actor(),
                "device_id": DEVICE_ID,
                "realm_id": REALM_ID,
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": "ak:event:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                    "hlc": "019641370000-0000-00000001"
                }
            }),
            created_at,
        )
        .expect("event")
    }

    #[test]
    fn accepts_exact_holder_and_session_device_binding() {
        let cursor = validate_caller_signed_read_cursor(&actor(), DEVICE_ID, &signed_shape())
            .expect("valid caller-signed cursor");
        assert_eq!(cursor.actor_id.signing_principal_id().as_str(), ACTOR_ID);
        assert_eq!(cursor.device_id.as_str(), DEVICE_ID);
        assert_eq!(cursor.realm_id.as_str(), REALM_ID);
    }

    #[test]
    fn rejects_cross_device_signed_cursor() {
        let error = validate_caller_signed_read_cursor(
            &actor(),
            "ak:device:01964137-0000-7000-8000-000000000002",
            &signed_shape(),
        )
        .expect_err("cross-device cursor must fail closed");
        assert!(error.message.contains("session device"));
    }

    #[test]
    fn rejects_payload_updated_at() {
        // read-receipts.md §6.1: the cursor is never updated in place, so the
        // object has no `updated_at` and the update time is the envelope
        // `created_at`. A payload restating it is a closed-shape violation, not
        // a value the service compares against the envelope.
        let mut event = signed_shape();
        event.payload.insert(
            "updated_at".to_owned(),
            serde_json::Value::String("2026-08-08T00:00:00.000Z".to_owned()),
        );
        let error = validate_caller_signed_read_cursor(&actor(), DEVICE_ID, &event)
            .expect_err("payload updated_at must fail closed");
        assert!(error.message.contains("updated_at"), "{}", error.message);
    }

    #[test]
    fn rejects_payload_id() {
        // private-objects.md §2.3: the cursor has no typed id. Identity is the
        // (actor_id, realm_id, read_scope) tuple, so a payload `id` is a
        // closed-shape violation exactly like `updated_at`.
        let mut event = signed_shape();
        event.payload.insert(
            "id".to_owned(),
            serde_json::Value::String("unstructured-read-cursor-object-id".to_owned()),
        );
        let error = validate_caller_signed_read_cursor(&actor(), DEVICE_ID, &event)
            .expect_err("payload id must fail closed");
        assert!(error.message.contains("id"), "{}", error.message);
    }

    #[test]
    fn rejects_same_principal_cursor_from_another_station() {
        let remote = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(ACTOR_ID).unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        validate_caller_signed_read_cursor(&remote, DEVICE_ID, &signed_shape())
            .expect_err("a different Station is a different cursor owner");
    }
}
