use arkret_models_collaboration::events_payloads::audit::{
    AuditAccessedKind, AuditAccessedPayload,
};
use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchLevel, StrandWatchSetPayload,
};

use super::super::*;

/// `strand-and-message.md` §8.4 — the one `refs` role that carries the
/// `.others` audit pairing edge.
const AUDIT_PAIR_ROLE: &str = "audit_pair";

pub(crate) fn is_encrypted_message(parsed: &ValidatedEventEnvelope, envelope: &Value) -> bool {
    if parsed.kind != arkret_wire::EventKind::MessageCreate.as_str() {
        return false;
    }
    envelope
        .pointer("/payload/encrypted_content")
        .is_some_and(Value::is_object)
}

/// The one `ak.audit.accessed` rule that is not stateable in the payload
/// schema: the declared writer is this Event's own actor.
///
/// Everything else about the payload — the closed field set, the `access_kind`
/// enum, DID / object-ref / timestamp shapes, and the closed field set are
/// enforced against
/// `event-payload.schema.json#/$defs/audit_accessed_payload` by the SDK
/// payload validator catalog in `validate_event_schema_and_payload`, which runs
/// earlier in this same admission pass. A hand-written second copy of those
/// rules used to live here, and it is exactly how a `writer_did` field name
/// survived after the schema settled on `writer_actor_id`: the duplicate was
/// the only thing rejecting conformant payloads. Parse through the SDK type
/// instead, so a schema change breaks the build rather than the wire.
pub(super) fn validate_audit_accessed_payload(
    kind: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::AUDIT_ACCESSED {
        return Ok(());
    }
    let payload = audit_accessed_payload(object)?;
    let writer = object
        .get("actor_id")
        .cloned()
        .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok());
    if writer.as_ref() != Some(&payload.writer_actor_id) {
        return Err(event_validation_error(
            StatusCode::FORBIDDEN,
            "capability_denied",
            "ak.audit.accessed writer_actor_id must match actor_id",
        ));
    }
    Ok(())
}

fn audit_accessed_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<AuditAccessedPayload, EventValidationError> {
    typed_payload(object, arkret_wire::event_kind_str::AUDIT_ACCESSED)
}

fn strand_watch_set_payload(
    object: &serde_json::Map<String, Value>,
) -> Result<StrandWatchSetPayload, EventValidationError> {
    typed_payload(object, arkret_wire::event_kind_str::STRAND_WATCH_SET)
}

fn typed_payload<T: serde::de::DeserializeOwned>(
    object: &serde_json::Map<String, Value>,
    kind: &str,
) -> Result<T, EventValidationError> {
    let payload = object.get("payload").cloned().unwrap_or(Value::Null);
    serde_json::from_value(payload).map_err(|error| {
        event_validation_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "schema_violation",
            format!("{kind} payload does not match its registered wire type: {error}"),
        )
    })
}

/// Per-event half of the `.others` watch rules: the level constraints, which need
/// nothing but this envelope.
///
/// The audit pairing itself is **not** checked here. Under content-bound ids the audit
/// Event is authored after the write it records (encoding.md 6.0.1 forbids the two from
/// naming each other), so the pairing is only decidable once the whole submit batch is in
/// hand — see [`validate_watch_set_others_audit_pairs`].
pub(super) fn validate_strand_watch_manage_others_levels(
    kind: &str,
    object: &serde_json::Map<String, Value>,
    actor_id: &arkret_wire::ActorId,
) -> Result<(), EventValidationError> {
    if kind != arkret_wire::event_kind_str::STRAND_WATCH_SET {
        return Ok(());
    }
    let payload = strand_watch_set_payload(object)?;
    if &payload.watcher_actor_id == actor_id {
        return Ok(());
    }
    // `muted` suppresses mention / moderation routing and `level_public` is a
    // personal publication opt-in, so neither may be written on someone's
    // behalf. The dedicated reasons in strand-and-message.md 8.4 are still
    // reserved in the registry, so retain the failed-precondition rejection.
    if matches!(payload.level, Some(StrandWatchLevel::Muted)) {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "manage_others strand watch writes cannot set level=muted",
        ));
    }
    if payload.level_public == Some(true) {
        return Err(event_validation_error(
            StatusCode::CONFLICT,
            arkret_wire::ErrorCode::FAILED_PRECONDITION,
            "manage_others strand watch writes cannot set level_public=true",
        ));
    }
    // The write is the first Event of the pair to form, so it cannot name the
    // audit that names it. Rejecting the pre-migration shape here means a
    // producer still authoring the old mutual edge fails on the edge itself
    // rather than on an `event_id` that cannot be computed.
    if !event_refs_with_role(object, AUDIT_PAIR_ROLE)?.is_empty() {
        return Err(manage_others_audit_error(
            "a cross-actor strand watch write MUST NOT reference its audit event; \
             the audit_pair edge runs audit -> write",
        ));
    }
    // The paired audit carrier is closed. The current-state CAS and atomic
    // write provider still need to be wired before admitting this operation.
    Err(manage_others_audit_error(
        "cross-actor watch current-state CAS provider is unavailable",
    ))
}

/// Batch half: every cross-actor `.others` watch write MUST be paired with exactly one
/// `ak.audit.accessed` Event **in the same submit batch**, and the pairing edge runs
/// audit -> write (strand-and-message.md 8.4).
///
/// The direction is forced: `refs` is inside the `event_digest` preimage and `event_id`
/// derives from that digest, so a write naming its audit while the audit commits to the
/// write's id would make the two Events preimages of each other, with no fixed
/// point (encoding.md 6.0.1). The write is therefore formed first and the audit second,
/// which is also why this cannot be decided one envelope at a time.
pub(in crate::routing) fn validate_watch_set_others_audit_pairs(
    envelopes: &[Value],
) -> Result<(), EventValidationError> {
    // Audits whose payload does not parse are not collected: they cannot pair,
    // and the envelope pass that runs after this one reports the real reason.
    let audits: Vec<(&serde_json::Map<String, Value>, AuditAccessedPayload)> = envelopes
        .iter()
        .filter_map(Value::as_object)
        .filter(|object| {
            object.get("kind").and_then(Value::as_str)
                == Some(arkret_wire::EventKind::AuditAccessed.as_str())
        })
        .filter_map(|object| Some((object, audit_accessed_payload(object).ok()?)))
        .collect();

    for envelope in envelopes {
        let Some(object) = envelope.as_object() else {
            continue;
        };
        if object.get("kind").and_then(Value::as_str)
            != Some(arkret_wire::EventKind::StrandWatchSet.as_str())
        {
            continue;
        }
        let (Some(actor_id), Some(event_id)) = (
            object
                .get("actor_id")
                .cloned()
                .and_then(|value| serde_json::from_value::<arkret_wire::ActorId>(value).ok()),
            object.get("event_id").and_then(Value::as_str),
        ) else {
            continue;
        };
        let payload = strand_watch_set_payload(object)?;
        if payload.watcher_actor_id == actor_id {
            continue;
        }
        let matches = audits
            .iter()
            .filter(|(audit, audit_payload)| {
                matches!(audit_payload.access_kind, AuditAccessedKind::WatchSetOthers)
                    && audit_payload.writer_actor_id == actor_id
                    && audit.get("actor_id").cloned().and_then(|value| {
                        serde_json::from_value::<arkret_wire::ActorId>(value).ok()
                    }).as_ref() == Some(&actor_id)
                    && audit_payload.target_actor_id.as_ref()
                        == Some(&payload.watcher_actor_id)
                    && audit_payload.target_ref == payload.strand_id.as_str()
                    && audit_payload
                        .paired_event_id
                        .as_ref()
                        .is_some_and(|paired| paired.as_str() == event_id)
                    // The typed Event id losslessly carries the digest suite
                    // and digest. Repeating that digest in the payload would
                    // create a second truth source; the critical `refs` edge
                    // keeps the audit causally dependent on the write.
                    && event_refs_with_role(audit, AUDIT_PAIR_ROLE).is_ok_and(|refs| {
                        refs.iter()
                            .any(|edge| edge.id == event_id && edge.critical)
                    })
            })
            .count();
        match matches {
            1 => {
                return Err(manage_others_audit_error(
                    "cross-actor watch current-state CAS provider is unavailable",
                ));
            }
            0 => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require a same-batch ak.audit.accessed event \
                     whose refs[role=audit_pair] and paired_event_id name this write",
                ));
            }
            _ => {
                return Err(manage_others_audit_error(
                    "cross-actor strand watch writes require exactly one paired \
                     ak.audit.accessed event in the batch",
                ));
            }
        }
    }
    Ok(())
}

/// One `refs[]` entry carrying the requested role.
///
/// `critical` travels with the id because the audit pairing edge is specified
/// as `critical: true`: a non-critical edge is a weaker claim and MUST NOT
/// satisfy the pairing, while on the write side *any* `audit_pair` entry is
/// already the wrong direction.
struct RoleRef {
    id: String,
    critical: bool,
}

fn event_refs_with_role(
    object: &serde_json::Map<String, Value>,
    role: &str,
) -> Result<Vec<RoleRef>, EventValidationError> {
    let Some(values) = object.get("semantic_refs").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut refs = Vec::new();
    for value in values {
        let Some(reference) = value.as_object() else {
            continue;
        };
        if reference.get("role").and_then(Value::as_str) == Some(role) {
            let id = reference.get("id").and_then(Value::as_str).ok_or_else(|| {
                event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "refs entries require id",
                )
            })?;
            if !is_valid_event_id(id) {
                return Err(event_validation_error(
                    StatusCode::BAD_REQUEST,
                    "param_invalid",
                    "audit_pair refs must use ak:event: typed ids",
                ));
            }
            refs.push(RoleRef {
                id: id.to_owned(),
                critical: reference.get("critical").and_then(Value::as_bool) == Some(true),
            });
        }
    }
    Ok(refs)
}

fn manage_others_audit_error(message: impl Into<String>) -> EventValidationError {
    event_validation_error(
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
        message,
    )
}

mod tests {
    use super::*;

    fn parsed(kind: &str) -> ValidatedEventEnvelope {
        ValidatedEventEnvelope {
            event_id: EventId::new(
                "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            )
            .unwrap(),
            actor: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            )),
            actor_id: DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            device_id: Some(
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002".to_owned()).unwrap(),
            ),
            realm_id: RealmId::new(
                "ak:realm:AdA2LFMgPUC2EAmzvOPY69_DX8_NLEXKyCwX9zR989nv".to_owned(),
            )
            .unwrap(),
            kind: kind.to_owned(),
            schema_id: arkret_wire::SchemaId::EVENT_V1.to_owned(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
            canonical_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            canonical_bytes: Vec::new(),
            producer_signing_key: None,
        }
    }

    const WRITE_ID: &str = "ak:event:AcLYVbj_1rgVJeGiPPDHp4GUgpcNGjkVCg8NW-2p21m6";
    const WRITER: &str = "ak:did_core:web:alice.example";
    const TARGET: &str = "ak:did_core:web:bob.example";
    const STRAND: &str = "ak:strand:AU6JCWNYlBGUETxX5NBB9hy8YgtevzngI2Yj3vKnYDWb";

    fn actor(principal: &str) -> arkret_wire::ActorId {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new(principal).unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn others_watch_write() -> Value {
        json!({
            "event_id": WRITE_ID,
            "kind": arkret_wire::EventKind::StrandWatchSet,
            "actor_id": actor(WRITER),
            "realm_id": "ak:realm:AdA2LFMgPUC2EAmzvOPY69_DX8_NLEXKyCwX9zR989nv",
            "payload": {
                "strand_id": STRAND,
                "watcher_actor_id": actor(TARGET),
                "level": "participating"
            }
        })
    }

    fn paired_audit() -> Value {
        json!({
            "event_id": "ak:event:ARYFDQjhXHE479tnu9g71RR9SxducTw_bWQIMigD_pYL",
            "kind": arkret_wire::EventKind::AuditAccessed,
            "actor_id": actor(WRITER),
            "semantic_refs": [{"id": WRITE_ID, "role": "audit_pair", "critical": true}],
            "payload": {
                "access_kind": "watch_set_others",
                "writer_actor_id": actor(WRITER),
                "target_actor_id": actor(TARGET),
                "target_ref": STRAND,
                "paired_event_id": WRITE_ID,
                "purpose": "seed strand watchers on create",
                "accessed_at": "2026-08-06T00:00:00.000Z"
            }
        })
    }

    fn check(envelopes: &[Value]) -> Result<(), EventValidationError> {
        validate_watch_set_others_audit_pairs(envelopes)
    }

    #[test]
    fn others_watch_write_needs_a_same_batch_audit_naming_it() {
        check(&[others_watch_write(), paired_audit()])
            .expect_err("the closed audit carrier lacks the normative result/head binding");

        let alone = check(&[others_watch_write()]).expect_err("a lone .others write is rejected");
        assert_eq!(alone.code, arkret_wire::ErrorCode::FAILED_PRECONDITION);
        assert_eq!(alone.status, StatusCode::CONFLICT);

        let mut wrong_target = paired_audit();
        wrong_target["payload"]["target_actor_id"] = json!(actor("ak:did_core:web:carol.example"));
        check(&[others_watch_write(), wrong_target])
            .expect_err("an audit for another target does not pair");
    }

    #[test]
    fn audit_pair_requires_the_exact_writer_and_target_accounts() {
        for (field, principal) in [("writer_actor_id", WRITER), ("target_actor_id", TARGET)] {
            let mut wrong_station = paired_audit();
            wrong_station["payload"][field]["account_id"]["station_id"] =
                json!("ak:did_core:web:other-station.example");
            check(&[others_watch_write(), wrong_station])
                .expect_err("an account at another Station cannot satisfy the audit pair");
            let mut wrong_kind = paired_audit();
            wrong_kind["payload"][field] = json!(arkret_wire::ActorId::service(
                DidCoreId::new(principal).unwrap(),
            ));
            check(&[others_watch_write(), wrong_kind])
                .expect_err("a Service cannot substitute for an Account with the same principal");
        }
        let mut forged_writer = paired_audit();
        forged_writer["payload"]["writer_actor_id"]["account_id"]["station_id"] =
            json!("ak:did_core:web:other-station.example");
        validate_audit_accessed_payload(
            arkret_wire::event_kind_str::AUDIT_ACCESSED,
            forged_writer.as_object().unwrap(),
        )
        .expect_err("declared audit writer must equal the complete Event Actor");
    }

    #[test]
    fn duplicate_audits_for_one_write_are_rejected() {
        check(&[others_watch_write(), paired_audit(), paired_audit()])
            .expect_err("two audits naming the same write are ambiguous");
    }

    #[test]
    fn self_watch_writes_need_no_audit() {
        let mut own = others_watch_write();
        own["payload"]["watcher_actor_id"] = json!(actor(WRITER));
        check(&[own]).expect("writing your own watch state needs no audit pair");
    }

    #[test]
    fn same_principal_at_another_station_is_not_a_self_watch_write() {
        let mut remote = others_watch_write();
        remote["payload"]["watcher_actor_id"] =
            json!(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new(WRITER).unwrap(),
                DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
            )));
        check(&[remote.clone()]).expect_err("another Account requires its own audit pair");
        remote["payload"]["level"] = json!("muted");
        let error = validate_strand_watch_manage_others_levels(
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            remote.as_object().unwrap(),
            &actor(WRITER),
        )
        .expect_err("muting another Account is not a self write");
        assert_eq!(error.code, arkret_wire::ErrorCode::FAILED_PRECONDITION);
    }

    #[test]
    fn the_audit_pair_edge_must_be_present_and_critical() {
        let mut no_edge = paired_audit();
        no_edge["semantic_refs"] = json!([]);
        check(&[others_watch_write(), no_edge])
            .expect_err("an audit without refs[role=audit_pair] does not pair");

        let mut not_critical = paired_audit();
        not_critical["semantic_refs"] =
            json!([{"id": WRITE_ID, "role": "audit_pair", "critical": false}]);
        check(&[others_watch_write(), not_critical])
            .expect_err("a non-critical audit_pair edge does not pair");
    }

    #[test]
    fn the_closed_audit_carrier_cannot_authorize_cross_actor_writes() {
        check(&[others_watch_write(), paired_audit()])
            .expect_err("missing normative result/head fields must fail closed");
    }

    /// The write forms first, so naming the audit is the cycle the migration
    /// removed. Rejecting it is what stops a pre-migration producer from
    /// getting a confusing digest failure instead of the real reason.
    #[test]
    fn a_cross_actor_write_must_not_reference_its_audit() {
        let mut old_direction = others_watch_write();
        old_direction["semantic_refs"] = json!([{
            "id": "ak:event:ARYFDQjhXHE479tnu9g71RR9SxducTw_bWQIMigD_pYL",
            "role": "audit_pair",
            "critical": true
        }]);
        let error = validate_strand_watch_manage_others_levels(
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            old_direction.as_object().unwrap(),
            &actor(WRITER),
        )
        .expect_err("the write must not carry the audit_pair edge");
        assert_eq!(error.code, arkret_wire::ErrorCode::FAILED_PRECONDITION);

        validate_strand_watch_manage_others_levels(
            arkret_wire::EventKind::StrandWatchSet.as_str(),
            others_watch_write().as_object().unwrap(),
            &actor(WRITER),
        )
        .expect_err("the closed audit carrier cannot yet authorize this write");
    }

    #[test]
    fn muted_and_public_levels_report_their_own_reason_codes() {
        let mut muted = others_watch_write();
        muted["payload"]["level"] = json!("muted");
        assert_eq!(
            validate_strand_watch_manage_others_levels(
                arkret_wire::EventKind::StrandWatchSet.as_str(),
                muted.as_object().unwrap(),
                &actor(WRITER),
            )
            .expect_err("muted cannot be written for someone else")
            .code,
            arkret_wire::ErrorCode::FAILED_PRECONDITION
        );

        let mut public = others_watch_write();
        public["payload"]["level_public"] = json!(true);
        assert_eq!(
            validate_strand_watch_manage_others_levels(
                arkret_wire::EventKind::StrandWatchSet.as_str(),
                public.as_object().unwrap(),
                &actor(WRITER),
            )
            .expect_err("level_public is a personal opt-in")
            .code,
            arkret_wire::ErrorCode::FAILED_PRECONDITION
        );
    }

    #[test]
    fn the_audit_writer_must_be_the_audit_events_own_actor() {
        let mut impersonating = paired_audit();
        impersonating["actor_id"] = json!(actor(TARGET));
        let error = validate_audit_accessed_payload(
            arkret_wire::EventKind::AuditAccessed.as_str(),
            impersonating.as_object().unwrap(),
        )
        .expect_err("an audit cannot record a write as someone else");
        assert_eq!(error.code, arkret_wire::ErrorCode::CAPABILITY_DENIED);

        validate_audit_accessed_payload(
            arkret_wire::EventKind::AuditAccessed.as_str(),
            paired_audit().as_object().unwrap(),
        )
        .expect("the paired audit fixture is well formed");
    }

    #[test]
    fn encrypted_message_is_detected() {
        assert!(is_encrypted_message(
            &parsed(arkret_wire::EventKind::MessageCreate.as_str()),
            &json!({
                "payload": {
                    "encrypted_content": {
                        "version": 1,
                        "content_type": "application/octet-stream",
                        "encryption_context": "message",
                        "ciphertext": "ciphertext"
                    }
                }
            }),
        ));
    }

    #[test]
    fn plaintext_message_is_not_encrypted() {
        assert!(!is_encrypted_message(
            &parsed(arkret_wire::EventKind::MessageCreate.as_str()),
            &json!({"payload": {"content": {"body": "hello"}}}),
        ));
    }
}
