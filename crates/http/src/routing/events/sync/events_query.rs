//! Multi-Realm / multi-actor committed-event stream
//! (`ak.self.committed_event.stream.subscribe.v1`), committed-event scan
//! (`ak.self.committed_event.read.scan.v1`), signed snapshot-manifest head, plus the NDJSON framing
//! and reconnect-gate helpers shared by both subscribe surfaces.

use super::*;

/// `ak.self.committed_event.stream.subscribe.v1` at `GET /_arkret/self/committed-events/subscribe`.
/// Each NDJSON line is a formal committed-event subscription frame. An opaque
/// continuation covers independent signed Commit identities and readable floors;
/// notifications only wake a fresh authorized durable scan.
#[handler]
#[tracing::instrument(skip_all, fields(op = "ak.self.committed_event.stream.subscribe.v1"))]
pub(crate) async fn events_subscribe(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    super::committed_subscription::subscribe(depot, req, res).await;
}

/// Serialize a JSON frame to a canonical NDJSON line. Each line ends with `\n`
/// per the NDJSON / JSON-Lines
/// convention so streaming clients can split-on-newline incrementally
/// without parsing the whole buffer.
pub(crate) fn ndjson_line(value: &impl serde::Serialize) -> Bytes {
    let mut bytes = arkret_canonical::canonical_json_bytes(value)
        .expect("account and Event stream frames must be canonically serializable");
    bytes.push(b'\n');
    Bytes::from(bytes)
}

pub(crate) fn subscribe_subject(req: &Request, session: Option<&SessionIdentityState>) -> String {
    match session {
        Some(session) => format!(
            "session:{}:{}",
            session.actor,
            session.human_device_id().unwrap_or(&session.token_hash)
        ),
        None => format!("remote:{}", req.remote_addr()),
    }
}

/// Scope `filter_digest` the realm subscribe stream binds its cursors to.
///
/// Resume cursors minted by `sync_token_for_events_query` are bound to this
/// digest, and `parse_and_validate_events_query_cursor` rejects a token whose
/// digest does not match — so a cursor issued for one realm-set cannot be
/// replayed against another (`cursor_integrity_invalid`). Distinct from the
/// account stream's filter (different `operation_id`), keeping the two streams'
/// cursors non-interchangeable per `encoding.md` §8.3.1.
pub(crate) fn events_subscribe_filter_digest(
    accessible_realms: &[String],
    actors: &BTreeSet<String>,
) -> String {
    let realms = accessible_realms
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    sync_filter_digest(Some(&json!({
        "operation_id": arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
        "realm_ids": realms,
        "actor_ids": actors.iter().map(|actor| serde_json::from_str::<arkret_wire::ActorId>(actor)
            .expect("actor selector was validated before cursor binding")).collect::<Vec<_>>(),
    })))
}

pub(crate) fn canonical_actor_selectors(
    actors: &[String],
) -> Result<BTreeSet<String>, coland_http::error::AppError> {
    if actors.len() > 256 {
        return Err(coland_http::error::AppError::param_invalid(
            "actor_ids exceeds 256 entries",
        ));
    }
    let mut selectors = BTreeSet::new();
    for encoded in actors {
        let actor: arkret_wire::ActorId = serde_json::from_str(encoded).map_err(|_| {
            coland_http::error::AppError::param_invalid(
                "actor_ids requires canonical JCS ActorId objects",
            )
        })?;
        actor
            .validate()
            .map_err(|error| coland_http::error::AppError::param_invalid(error.to_string()))?;
        if actor.to_string() != *encoded || !selectors.insert(encoded.clone()) {
            return Err(coland_http::error::AppError::param_invalid(
                "actor_ids must be canonical and unique",
            ));
        }
    }
    Ok(selectors)
}

pub(crate) async fn authorize_actor_only_selectors(
    state: &AppState,
    session: Option<&SessionIdentityState>,
    actors: &BTreeSet<String>,
) -> Result<(), coland_http::error::AppError> {
    use coland_http::error::AppError;
    let unauthorized = || {
        crate::app_error!(
            CapabilityDenied,
            "actor-only selectors require an exact holder-owned ActorId",
        )
    };
    let session = session.ok_or_else(unauthorized)?;
    let account_id =
        crate::routing::identity::auth_grant_dpop::authenticated_session_account_id(state, session)
            .await?;
    let account = state
        .identities()
        .account(&account_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    let account_pk = account.map(|account| account.pk);
    let holder_actor = arkret_wire::ActorId::account(account_id).to_string();
    for selector in actors {
        if *selector == holder_actor {
            continue;
        }
        let actor: arkret_wire::ActorId =
            serde_json::from_str(selector).map_err(|_| unauthorized())?;
        let arkret_wire::ActorId::Account {
            account_id:
                arkret_wire::AccountId {
                    principal_id,
                    station_id,
                },
        } = actor
        else {
            return Err(unauthorized());
        };
        let agent = state
            .agent_pairings()
            .agent(principal_id.as_str())
            .await
            .map_err(|error| AppError::internal(error.to_string()))?
            .ok_or_else(unauthorized)?;
        if account_pk.is_none()
            || agent.controller_account_pk != account_pk
            || agent.recipient_id.as_deref() != Some(station_id.as_str())
            || agent.state
                != arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
        {
            return Err(unauthorized());
        }
        crate::routing::identity::agent_pcr::validate_agent_controller_binding(
            state,
            &agent,
            Utc::now(),
        )
        .await
        .map_err(|_| unauthorized())?;
    }
    Ok(())
}

pub(crate) fn reject_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    res: &mut Response,
) -> bool {
    let retry_after_ms = state
        .sync()
        .subscribe_retry_after_ms(subscribe_scope_key, Utc::now());
    if let Some(retry_after_ms) = retry_after_ms {
        render_subscribe_rate_limited(res, retry_after_ms);
        return true;
    }
    false
}

pub(crate) fn arm_subscribe_reconnect(
    state: &AppState,
    subscribe_scope_key: &str,
    reconnect_after_ms: u64,
) {
    state.sync().arm_subscribe_reconnect(
        subscribe_scope_key.to_owned(),
        Utc::now(),
        reconnect_after_ms,
    );
}

fn render_subscribe_rate_limited(res: &mut Response, retry_after_ms: u64) {
    let retry_after_seconds = retry_after_ms.div_ceil(1000).max(1);
    res.status_code(StatusCode::TOO_MANY_REQUESTS);
    res.headers_mut()
        .insert(header::RETRY_AFTER, retry_after_seconds.into());
    crate::error::render_problem_envelope(
        res,
        StatusCode::TOO_MANY_REQUESTS,
        arkret_wire::problem_details::Problem::from_code(
            "rate_limited",
            "Subscribe reconnect window is still active.",
        )
        .with_instance(ids::generate_request_id())
        .with_retry_after_ms(Some(retry_after_ms)),
    );
}

#[cfg(test)]
#[derive(Clone, Debug)]
#[expect(
    dead_code,
    reason = "The test fixture retains its complete envelope while each unit case inspects only its relevant fields."
)]
struct EventsQueryParts {
    realms: Vec<String>,
    actors: Vec<String>,
    after: Option<String>,
    before: Option<String>,
    order: String,
    limit: usize,
    filters: Option<Value>,
}

pub(super) fn events_query_cursor_error(error: SyncCursorError) -> coland_http::error::AppError {
    match error {
        SyncCursorError::Unavailable(message) => crate::app_error!(TemporarilyUnavailable, message),
        SyncCursorError::Expired => crate::app_error!(CursorExpired, "cursor has expired",),
        // encoding.md §8.3 closed set: syntax/schema failures pin the top-level
        // `param_invalid` code with reason `invalid_cursor`.
        SyncCursorError::Invalid(message) => coland_http::error::AppError::param_invalid(message)
            .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        SyncCursorError::Mismatch(message) | SyncCursorError::Integrity(message) => {
            crate::app_error!(CursorIntegrityInvalid, message,)
        }
        SyncCursorError::Revoked => {
            crate::app_error!(CursorRevoked, "cursor authority has been revoked",)
        }
    }
}

#[cfg(test)]
fn events_query_direction(parts: &EventsQueryParts) -> bool {
    parts.order == "descending"
        || (parts.order == "default" && (parts.before.is_some() || parts.after.is_none()))
}

#[cfg(test)]
fn event_kind_visible_in_shared_realm_query(kind: &arkret_wire::EventKind) -> bool {
    *kind != arkret_wire::EventKind::ReadCursorAdvance
}

#[cfg(test)]
/// Bounds are absolute canonical positions; order controls presentation only.
fn canonical_query_page(
    ids: &[&str],
    after: Option<&str>,
    before: Option<&str>,
    backward: bool,
    limit: usize,
) -> Result<(Vec<usize>, bool), coland_http::error::AppError> {
    let position = |id: &str| {
        ids.iter().position(|value| *value == id).ok_or_else(|| {
            coland_http::error::AppError::param_invalid("cursor position unavailable")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR)
        })
    };
    let start = after
        .map(position)
        .transpose()?
        .map_or(0, |index| index + 1);
    let end = before.map(position).transpose()?.unwrap_or(ids.len());
    if end < start {
        return Err(
            coland_http::error::AppError::param_invalid("cursor bounds are reversed")
                .with_reason_code(arkret_wire::ReasonCode::INVALID_CURSOR),
        );
    }
    let indices: Vec<_> = if backward {
        (start..end).rev().take(limit).collect()
    } else {
        (start..end).take(limit).collect()
    };
    let has_more = indices
        .iter()
        .min()
        .map_or(after.is_some() && start > 1, |index| *index > 0);
    Ok((indices, has_more))
}

#[cfg(test)]
/// Enrich visible projection rows to the closed `CommittedEventView` union.
/// Canonical rows return the complete signed Event and Commit. Content-hidden
/// rows keep their stream slot with only the Commit and minimal withheld marker.
/// Visibility and pagination are already applied to `projection_rows` by the
/// caller. Every selected projection row must resolve to its canonical Event;
/// returning a shorter successful page would hide an accepted Event while the
/// cursor advances past it.
async fn full_events_from_projection_json(
    state: &AppState,
    projection_rows: &[Value],
) -> Result<Vec<arkret_wire::CommittedEventView>, coland_http::error::AppError> {
    let mut events = Vec::with_capacity(projection_rows.len());
    for row in projection_rows {
        events.push(event_read_row_from_projection_json(state, row).await?);
    }
    Ok(events)
}

#[cfg(test)]
async fn event_read_row_from_projection_json(
    state: &AppState,
    row: &Value,
) -> Result<arkret_wire::CommittedEventView, coland_http::error::AppError> {
    let event_id = row.get("event_id").and_then(Value::as_str).ok_or_else(|| {
        coland_http::error::AppError::internal(
            "projected Event row is missing its canonical event_id",
        )
    })?;
    let record = state
        .event_queries()
        .canonical_event(event_id)
        .await
        .map_err(|error| {
            coland_http::error::AppError::internal(format!(
                "canonical Event lookup failed for projected row {event_id}: {error}"
            ))
        })?
        .ok_or_else(|| {
            coland_http::error::AppError::internal(format!(
                "projected Event row {event_id} has no canonical Event record"
            ))
        })?;
    let view = super::super::event_log::canonical_event_read_row(state, &record).await?;
    let retained = row["payload"]["retention_tombstone"].as_bool() == Some(true);
    let erased = row["sender"].as_str()
        == Some(coland_services::projection::tombstone::ERASED_USER_PLACEHOLDER);
    if !projection_row_is_redacted_message_tombstone(row) && !retained && !erased {
        return Ok(view);
    }
    Ok(super::super::event_log::withheld_event_read_row(
        view.commit().clone(),
    ))
}

#[cfg(test)]
fn projection_row_is_redacted_message_tombstone(row: &Value) -> bool {
    row.get("event_kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| {
            matches!(
                kind,
                arkret_wire::event_kind_str::MESSAGE_CREATE
                    | arkret_wire::event_kind_str::MESSAGE_REVISE
            )
        })
        && row.get("payload").is_some_and(|payload| {
            payload.get("redacted").and_then(Value::as_bool) == Some(true)
                || payload.get("state").and_then(Value::as_str) == Some("redacted")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_REALM: &str = "ak:realm:ATdMSXE70ijF1u9M9PvT4WFuWRgKpqVf-tiHDAD-_stf";
    const TEST_ACTOR_CORE: &str = "ak:did_core:web:alice.example";

    #[test]
    fn shared_realm_query_excludes_actor_private_read_cursor_events() {
        assert!(!event_kind_visible_in_shared_realm_query(
            &arkret_wire::EventKind::ReadCursorAdvance,
        ));
        assert!(event_kind_visible_in_shared_realm_query(
            &arkret_wire::EventKind::MessageCreate,
        ));
    }

    #[test]
    fn ndjson_frames_are_byte_for_byte_canonical_json() {
        let line = ndjson_line(&json!({
            "z": 1,
            "a": {"second": true, "first": false},
        }));
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(
            &line[..line.len() - 1],
            arkret_canonical::canonical_json_bytes(&json!({
                "z": 1,
                "a": {"second": true, "first": false},
            }))
            .unwrap()
        );
    }

    #[test]
    fn canonical_page_bounds_are_independent_of_presentation_direction() {
        let ids = ["a", "b", "c", "d"];
        assert_eq!(
            canonical_query_page(&ids, None, None, true, 2).unwrap(),
            (vec![3, 2], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("b"), None, true, 2).unwrap(),
            (vec![3, 2], true)
        );
        assert_eq!(
            canonical_query_page(&ids, None, Some("d"), true, 2).unwrap(),
            (vec![2, 1], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("a"), Some("d"), false, 1).unwrap(),
            (vec![1], true)
        );
        assert_eq!(
            canonical_query_page(&ids, Some("d"), None, false, 2).unwrap(),
            (vec![], true)
        );
        assert!(canonical_query_page(&ids, Some("missing"), None, false, 2).is_err());
        assert!(canonical_query_page(&ids, Some("d"), Some("b"), true, 2).is_err());
    }

    fn test_state() -> AppState {
        let mut config = crate::config::AppConfig::test_default();
        config.seed_demo_data = false;
        AppState::new(config, coland_storage_postgres::Db { pool: None })
    }

    fn selector_at(station: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(TEST_ACTOR_CORE).unwrap(),
            arkret_wire::DidCoreId::new(station).unwrap(),
        ))
    }

    #[test]
    fn actor_selectors_require_unique_canonical_full_identity() {
        let first = selector_at("ak:did_core:web:station-a.example").to_string();
        let second = selector_at("ak:did_core:web:station-b.example").to_string();
        assert_eq!(
            canonical_actor_selectors(&[first.clone(), second])
                .unwrap()
                .len(),
            2
        );
        assert!(canonical_actor_selectors(&[TEST_ACTOR_CORE.to_owned()]).is_err());
        assert!(canonical_actor_selectors(&[first.clone(), first.clone()]).is_err());
        assert!(canonical_actor_selectors(&[format!(" {first}")]).is_err());
        assert!(canonical_actor_selectors(&vec![first; 257]).is_err());
    }

    #[test]
    fn subscribe_cursor_scope_binds_station_and_normalizes_selector_order() {
        let first = selector_at("ak:did_core:web:station-a.example").to_string();
        let second = selector_at("ak:did_core:web:station-b.example").to_string();
        let realms = vec![TEST_REALM.to_owned()];
        assert_ne!(
            events_subscribe_filter_digest(&realms, &BTreeSet::from([first.clone()])),
            events_subscribe_filter_digest(&realms, &BTreeSet::from([second.clone()])),
        );
        assert_eq!(
            events_subscribe_filter_digest(
                &realms,
                &BTreeSet::from([first.clone(), second.clone()])
            ),
            events_subscribe_filter_digest(&realms, &BTreeSet::from([second, first])),
        );
    }

    #[tokio::test]
    async fn actor_only_selector_requires_authenticated_exact_holder() {
        let error = authorize_actor_only_selectors(
            &test_state(),
            None,
            &BTreeSet::from([selector_at("ak:did_core:web:station-a.example").to_string()]),
        )
        .await
        .unwrap_err();
        assert_eq!(error.wire_code(), "capability_denied");
    }

    #[tokio::test]
    async fn committed_event_subscribe_requires_authenticated_stream_reader() {
        let state = test_state();
        let router = salvo::Router::new()
            .hoop(salvo::affix_state::inject(state))
            .get(events_subscribe);
        let response =
            salvo::test::TestClient::get(format!("http://server/?realm_ids={TEST_REALM}"))
                .send(&salvo::Service::new(router))
                .await;
        assert_eq!(response.status_code, Some(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn events_query_default_direction_matches_boundary_contract() {
        let mut parts = EventsQueryParts {
            realms: vec![TEST_REALM.to_owned()],
            actors: Vec::new(),
            after: None,
            before: None,
            order: "default".to_owned(),
            limit: 100,
            filters: None,
        };
        assert!(events_query_direction(&parts));

        parts.after = Some("ak:cursor:newer".to_owned());
        assert!(!events_query_direction(&parts));

        parts.before = Some("ak:cursor:older".to_owned());
        assert!(events_query_direction(&parts));
    }

    #[tokio::test]
    async fn projection_enrichment_fails_when_canonical_event_is_missing() {
        let state = test_state();
        let error = full_events_from_projection_json(
            &state,
            &[json!({
                "event_id": "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
                "event_kind": arkret_wire::EventKind::MessageCreate.as_str(),
                "payload": {}
            })],
        )
        .await
        .expect_err("a projection row without its canonical Event must fail the page");

        assert_eq!(error.code, coland_http::error::ErrorCode::InternalError);
        assert!(error.message.contains("has no canonical Event record"));
    }
}

#[endpoint(operation_id = "ak.self.realm_state_snapshot.read.manifest_head")]
#[tracing::instrument(
    skip_all,
    fields(op = "ak.self.realm_state_snapshot.read.manifest_head.v1")
)]
pub(super) async fn realm_state_snapshot_head(
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::GuardedJsonResult<arkret_wire::RealmStateSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| coland_http::error::AppError::param_missing("realm_id is required"))?;
    let realm_id = scope_selector_to_realm_id(&realm_id)?;
    let session = authenticated_session(state, req)
        .await
        .map_err(|(_status, code, message)| {
            let typed = coland_http::error::ErrorCode::from_wire(code)
                .unwrap_or(coland_http::error::ErrorCode::Unauthenticated);
            coland_http::error::AppError::from_rejection(typed, message)
        })?;
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let account = actor
        .as_account_id()
        .ok_or_else(|| coland_http::error::AppError::not_found("not found"))?;
    if is_realm_deleted(state, &realm_id).await
        || !crate::routing::realm_state_snapshot::account_is_joined_member(
            state, &realm_id, account,
        )
        .await?
    {
        return Err(coland_http::error::AppError::not_found("not found"));
    }
    let manifest = realm_state_snapshot_manifest_for_realm(state, &realm_id, account)
        .await
        .map_err(|error| {
            if matches!(
                error.code,
                coland_http::error::ErrorCode::NotFound
                    | coland_http::error::ErrorCode::PayloadTooLarge
                    | coland_http::error::ErrorCode::InternalError
            ) {
                error
            } else {
                crate::app_error!(RealmStateSnapshotUnavailable, error.message,)
            }
        })?;
    let input = coland_storage::AccountContentDeliveryInput::snapshot(&manifest);
    let guard = super::content_delivery_guard(state, &session, &input).await?;
    coland_http::result::guarded_json_ok(manifest, guard)
}

#[endpoint(operation_id = "ak.self.realm_state_snapshot.read.by_ref")]
#[tracing::instrument(skip_all, fields(op = "ak.self.realm_state_snapshot.read.by_ref.v1"))]
pub(super) async fn realm_state_snapshot_by_ref(
    depot: &mut Depot,
    req: &mut Request,
) -> coland_http::result::GuardedJsonResult<arkret_wire::RealmStateSnapshot> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let snapshot_id = req
        .param::<String>("snapshot_id")
        .and_then(|value| arkret_wire::RealmSnapshotId::new(value).ok())
        .ok_or_else(|| coland_http::error::AppError::param_invalid("invalid snapshot_id"))?;
    let realm_id = query_param(req, "realm_id")
        .ok_or_else(|| coland_http::error::AppError::param_missing("realm_id is required"))?;
    let realm_id = scope_selector_to_realm_id(&realm_id)?;
    let session = authenticated_session(state, req)
        .await
        .map_err(|(_status, code, message)| {
            let typed = coland_http::error::ErrorCode::from_wire(code)
                .unwrap_or(coland_http::error::ErrorCode::Unauthenticated);
            coland_http::error::AppError::from_rejection(typed, message)
        })?;
    // The registered error mapping sends every authorization failure of the
    // exact read through the universal `capability_denied` surface; absent or
    // no longer disclosable bytes are `realm_state_snapshot_unavailable`.
    let denied = || {
        coland_http::error::AppError::capability_denied(
            "the Realm snapshot is not readable by this caller",
        )
    };
    let actor =
        crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    let account = actor.as_account_id().ok_or_else(denied)?;
    if is_realm_deleted(state, &realm_id).await
        || !crate::routing::realm_state_snapshot::account_is_joined_member(
            state, &realm_id, account,
        )
        .await?
    {
        return Err(denied());
    }
    let snapshot = crate::routing::realm_state_snapshot::issued_realm_state_snapshot_for_account(
        state,
        &realm_id,
        &snapshot_id,
        account,
    )
    .await?;
    let input = coland_storage::AccountContentDeliveryInput::snapshot(&snapshot);
    let guard = super::content_delivery_guard(state, &session, &input).await?;
    coland_http::result::guarded_json_ok(snapshot, guard)
}
