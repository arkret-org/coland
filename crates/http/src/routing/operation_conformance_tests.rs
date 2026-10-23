use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_identifiers::OperationId;
use coland_storage_postgres::Db;
use serde_json::{Value, json};

use super::*;
use crate::AppState;
use crate::config::AppConfig;

struct OperationVector {
    name: &'static str,
    kind: arkret_wire::EventKind,
    payload: Value,
    valid: bool,
}

fn test_state() -> AppState {
    AppState::new(
        AppConfig {
            development_mode: true,
            // Tests use fixed-time HLC fixtures (`0189c4d2af00...`) which
            // are years in the past relative to wall-clock; disable
            // replay-window enforcement so they pass.
            seed_demo_data: true,
            ..AppConfig::test_default()
        },
        Db { pool: None },
    )
}

fn operation(index: usize, kind: impl AsRef<str>, payload: Value) -> Operation {
    // Build a deterministic UUIDv7 from the index (last 12 hex pad as hex of the index).
    let payload_part = format!("{:012x}", index);
    let op_id = format!("ak:operation:01904100-0000-7000-8000-{payload_part}");
    let realm_id = "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K".to_owned();
    arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(op_id).unwrap(),
        arkret_identifiers::RealmId::new(realm_id).unwrap(),
        kind.as_ref(),
        payload,
    )
}

#[test]
fn builtin_operation_conformance_vectors_cover_registry() {
    let state = test_state();
    let account_actor = |principal: &str| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_identifiers::DidCoreId::new(principal.to_owned()).unwrap(),
            crate::test_event::station_id(),
        ))
    };
    let vectors = vec![
        OperationVector {
            name: "message create",
            kind: arkret_wire::EventKind::MessageCreate,
            payload: json!({
                "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
            valid: true,
        },
        OperationVector {
            name: "message revise",
            kind: arkret_wire::EventKind::MessageRevise,
            payload: json!({"message_id": "ak:message:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR", "content": {"kind": "ak.content.text", "body": "edited"}}),
            valid: true,
        },
        OperationVector {
            name: "message redact",
            kind: arkret_wire::EventKind::MessageRedact,
            payload: json!({"message_id": "ak:message:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR"}),
            valid: true,
        },
        OperationVector {
            name: "generic redaction",
            kind: arkret_wire::EventKind::Redaction,
            // ak.redaction validates its payload against
            // cross_object_redaction_payload: target_ref is the single required
            // target carrier, additionalProperties=false. Its target set
            // excludes Message: message_id is not a member and target_ref cannot
            // spell ak:message:, because Message reaches state=redacted only
            // through ak.message.redact (common-fields.md 5.1 Message exemption).
            payload: json!({"target_ref": "ak:event:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR"}),
            valid: true,
        },
        OperationVector {
            name: "reaction add",
            kind: arkret_wire::EventKind::ReactionAdd,
            // reaction_payload: required {target_ref, key}, additionalProperties=false;
            // v1 core reactions target only a Message (strand-and-message.md 9.8.2).
            payload: json!({"target_ref": "ak:message:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR", "key": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "reaction remove",
            kind: arkret_wire::EventKind::ReactionRemove,
            // reaction_payload: same schema as add (remove tombstones the (actor,target_ref,key)
            // add).
            payload: json!({"target_ref": "ak:message:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR", "key": "+1"}),
            valid: true,
        },
        OperationVector {
            name: "relation create",
            kind: arkret_wire::EventKind::RelationCreate,
            // relation_create_payload: the signed primary conflict domain, the
            // null CAS opening of a never-written domain, and the closed
            // authoring region; materialized Relation members are forbidden.
            payload: json!({
                "primary_conflict_domain": {
                    "domain_kind": "tuple",
                    "relation_kind": "blocks",
                    "from_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                    "to_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"
                },
                "expected_revision": null,
                "relation": {
                    "relation_kind": "blocks",
                    "from_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                    "to_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "relation create with a flat assembled payload",
            kind: arkret_wire::EventKind::RelationCreate,
            // The negative half of the same rule: a flat payload without the
            // signed domain and CAS basis is not a closed create.
            payload: json!({
                "relation_id": "ak:relation:AQwWjzRLsPZDMwr_k34oj279cixhgwgnqTCDF9OPB6aA",
                "kind": "blocks",
                "from_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                "to_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"
            }),
            valid: false,
        },
        OperationVector {
            name: "relation update",
            kind: arkret_wire::EventKind::RelationUpdate,
            // relation_update_payload: domain, exact revision, relation_id and
            // an ak.patch.v1 map over the updatable members.
            payload: json!({
                "primary_conflict_domain": {
                    "domain_kind": "tuple",
                    "relation_kind": "blocks",
                    "from_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                    "to_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"
                },
                "expected_revision": {
                    "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                    "stream_position": 4
                },
                "relation_id": "ak:relation:AQwWjzRLsPZDMwr_k34oj279cixhgwgnqTCDF9OPB6aA",
                "patch": {"fields.weight": 1}
            }),
            valid: true,
        },
        OperationVector {
            name: "relation delete",
            kind: arkret_wire::EventKind::RelationTombstone,
            // relation_tombstone_payload: domain, exact revision and relation_id.
            payload: json!({
                "primary_conflict_domain": {
                    "domain_kind": "tuple",
                    "relation_kind": "blocks",
                    "from_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                    "to_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"
                },
                "expected_revision": {
                    "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                    "stream_position": 4
                },
                "relation_id": "ak:relation:AQwWjzRLsPZDMwr_k34oj279cixhgwgnqTCDF9OPB6aA"
            }),
            valid: true,
        },
        OperationVector {
            name: "member state join",
            kind: arkret_wire::EventKind::MemberState,
            // Membership names an exact Station-bound actor; routing follows that identity.
            payload: json!({"realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K", "member_id": account_actor("ak:did_core:web:alice.example"), "membership": "join"}),
            valid: true,
        },
        OperationVector {
            name: "member state leave",
            kind: arkret_wire::EventKind::MemberState,
            payload: json!({"member_id": account_actor("ak:did_core:web:alice.example"), "membership": "leave"}),
            valid: true,
        },
        OperationVector {
            name: "member state ban",
            kind: arkret_wire::EventKind::MemberState,
            payload: json!({"member_id": account_actor("ak:did_core:web:bob.example"), "membership": "ban"}),
            valid: true,
        },
        OperationVector {
            name: "member state knock",
            kind: arkret_wire::EventKind::MemberState,
            payload: json!({"member_id": account_actor("ak:did_core:web:bob.example"), "membership": "knock"}),
            valid: true,
        },
        OperationVector {
            name: "read marker missing event_id",
            kind: arkret_wire::EventKind::ReadCursorAdvance,
            payload: json!({
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": account_actor("ak:did_core:web:alice.example"),
                "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "read_scope": {"kind": "realm"},
                "position": {"hlc": "019041000000-0000-00000001"}
            }),
            valid: false,
        },
        OperationVector {
            name: "read marker valid",
            kind: arkret_wire::EventKind::ReadCursorAdvance,
            payload: json!({
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": account_actor("ak:did_core:web:alice.example"),
                "device_id": "ak:device:01964137-0000-7000-8000-000000000001",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": "ak:event:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR",
                    "hlc": "019041000000-0000-00000001"
                }
            }),
            valid: true,
        },
        OperationVector {
            name: "space create",
            kind: arkret_wire::EventKind::RealmCreate,
            payload: json!({"object": {
                "schema": "ak.schema.realm_genesis.v1",
                "purpose": "collaboration",
                "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "trust_domain": "ak:trust_domain:local",
                "security_class": "standard",
                "governance_station_id": "ak:did_core:web:station.example",
                "initial_join_rule": "invite",
                "initial_history_access": "since_join",
                "initial_discoverability": "invite_only"
            }}),
            valid: true,
        },
        OperationVector {
            name: "realm profile",
            kind: arkret_wire::EventKind::RealmProfile,
            payload: json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Launch 2"
            }),
            valid: true,
        },
        OperationVector {
            name: "space destroy",
            kind: arkret_wire::EventKind::RealmDestroy,
            // realm_destroy_payload: required {reason}, additionalProperties=false.
            payload: json!({"reason": "project_completed"}),
            valid: true,
        },
        OperationVector {
            name: "space container archive",
            kind: arkret_wire::EventKind::SpaceArchive,
            payload: json!({"space_id": "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore",
            kind: arkret_wire::EventKind::SpaceRestore,
            payload: json!({"space_id": "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid"}),
            valid: true,
        },
        OperationVector {
            name: "space container tombstone",
            kind: arkret_wire::EventKind::SpaceTombstone,
            payload: json!({"space_id": "ak:space:Af5YDKFhOiySm76T_pF7GQrzaF8vEejTcqTWpmnqGUid"}),
            valid: true,
        },
        OperationVector {
            name: "space container restore missing space_id",
            kind: arkret_wire::EventKind::SpaceRestore,
            payload: json!({"reason": "release_reopened"}),
            valid: false,
        },
        // Strand / Morph lifecycle conformance vectors.
        OperationVector {
            name: "strand create",
            kind: arkret_wire::EventKind::StrandCreate,
            // strand_create_payload wraps the Strand preimage. Its id is
            // derived from the accepted create Event and therefore MUST NOT
            // be supplied by the producer.
            payload: json!({"object": {
                "schema": "ak.schema.strand.v1",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "tracks": {"discussion": {}},
                "created_by": account_actor("ak:did_core:web:alice.example"),
                "created_at": "2026-05-20T00:00:00.000Z",
                "metadata": {"title": "Launch"}
            }}),
            valid: true,
        },
        OperationVector {
            name: "strand update",
            kind: arkret_wire::EventKind::StrandUpdate,
            payload: json!({"target_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp", "patch": {"metadata.title": { "$op": "set", "value": "Launch v2" }}}),
            valid: true,
        },
        OperationVector {
            name: "strand archive",
            kind: arkret_wire::EventKind::StrandArchive,
            payload: json!({"target_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp"}),
            valid: true,
        },
        OperationVector {
            name: "strand restore",
            kind: arkret_wire::EventKind::StrandRestore,
            payload: json!({"target_ref": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp"}),
            valid: true,
        },
        OperationVector {
            name: "strand archive missing target_ref",
            kind: arkret_wire::EventKind::StrandArchive,
            payload: json!({"reason": "stale_room"}),
            valid: false,
        },
        // Strand position event vectors.
        OperationVector {
            name: "strand move",
            kind: arkret_wire::EventKind::StrandMove,
            payload: json!({
                "strand_id": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                "board_space_id": "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj",
                "target_space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand reorder",
            kind: arkret_wire::EventKind::StrandReorder,
            payload: json!({
                "strand_id": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp",
                "board_space_id": "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj",
                "space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99",
                "rank": "a1",
            }),
            valid: true,
        },
        OperationVector {
            name: "strand move missing board_space_id",
            kind: arkret_wire::EventKind::StrandMove,
            payload: json!({"strand_id": "ak:strand:AUtQ1IrDq4bUl2tchpqyVaLFC99If4UbReAATcBFDUhp"}),
            valid: false,
        },
        OperationVector {
            name: "strand reorder missing strand_id",
            kind: arkret_wire::EventKind::StrandReorder,
            payload: json!({"board_space_id": "ak:space:AWxSgbLLtif391fvK_KYoPG0O0dFZnh9BWozK_Z3AoCj", "space_id": "ak:space:AcYTKs4ZiqRv25YJCWQZHLEXQk6KYMtujf2hpo1tUy99", "rank": "a1"}),
            valid: false,
        },
        OperationVector {
            name: "morph create",
            kind: arkret_wire::EventKind::MorphCreate,
            // morph_create_payload wraps the Morph preimage. Its id is
            // derived from the accepted create Event and therefore MUST NOT
            // be supplied by the producer.
            payload: json!({"object": {
                "schema": "ak.schema.morph.v1",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "schema_refs": ["ak.schema.morph.v1"],
                "morph_kind": "task",
                "stage": "draft",
                "created_by": account_actor("ak:did_core:web:alice.example"),
                "created_at": "2026-05-20T00:00:00.000Z",
                "metadata": {"title": "Backfill"}
            }}),
            valid: true,
        },
        OperationVector {
            name: "morph update",
            kind: arkret_wire::EventKind::MorphUpdate,
            payload: json!({"target_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb", "patch": {"metadata.title": "Backfill v2"}}),
            valid: true,
        },
        OperationVector {
            name: "morph archive",
            kind: arkret_wire::EventKind::MorphArchive,
            payload: json!({"target_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore",
            kind: arkret_wire::EventKind::MorphRestore,
            payload: json!({"target_ref": "ak:morph:AQ-DRvjAp7PmXKkjoqk8vbmRDFZoSMbThbqNN0j6guzb"}),
            valid: true,
        },
        OperationVector {
            name: "morph restore missing target_ref",
            kind: arkret_wire::EventKind::MorphRestore,
            payload: json!({"reason": "reopen"}),
            valid: false,
        },
        // Applet protocol family conformance vectors.
        OperationVector {
            name: "applet registration",
            kind: arkret_wire::EventKind::AppletRegistration,
            // applet_registration_payload is now a CLOSED class (additionalProperties=false)
            // with required fields; the generic fallback no longer applies since the
            // exact def exists in the current spec.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "service_id": "ak:did_core:web:applet.example",
                "expected_revision": null,
                "controller_principal_id": "ak:did_core:web:applet.example",
                "base_url": "https://applet.example/runtime",
                "protocols": ["http_custom"],
                "namespaces": {
                    "realms": [{"exclusive": false, "pattern": "*"}],
                    "handles": []
                },
                "receive_events": true,
                "receive_signals": false,
                "rate_limited": true,
                "requested_scopes": ["read"],
                "claimed_profiles": [
                    "ak.profile.applet_bridge.v1",
                    "ak.profile.applet_service.v1"
                ],
                "registration_epoch": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                // applet-package.schema.json#/$defs/webhook_auth is closed and
                // requires kind + key_ref + accepted_signature_algorithms.
                "webhook_auth": {
                    "kind": "http_message_signature",
                    "key_ref": "did:web:applet.example#server-key-1",
                    "accepted_signature_algorithms": ["ed25519"]
                },
                "manifest": {
                    "claimed_profiles": [
                        "ak.profile.applet_bridge.v1",
                        "ak.profile.applet_service.v1"
                    ],
                    "limits": {},
                    "ghost_policy": {"enabled": false},
                    "delegation_policy": {"enabled": false},
                    "e2ee_policy": {"enabled": false},
                    "registration_epoch_evidence": {
                        "did": "did:webvh:zQ3shExampleScid:applet.example",
                        "document_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "method_version_evidence": {
                            "method": "did:webvh",
                            "version_id": "1-QmExampleServiceVersion",
                            "unversioned_refetch": false
                        },
                        "accepted_signing_keys": [{
                            "key_ref": "did:webvh:zQ3shExampleScid:applet.example#server-key-1",
                            "public_key_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        }]
                    }
                },
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:web:applet.example#server-key-1",
                    "payload_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "created_at": "2026-05-20T00:00:00.000Z",
                    "jws": "AAAA..BBBB"
                },
                "created_at": "2026-05-20T00:00:00.000Z",
            }),
            valid: true,
        },
        OperationVector {
            name: "applet registration missing namespace",
            kind: arkret_wire::EventKind::AppletRegistration,
            // Same closed class, but omits the required `namespaces` field.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "service_id": "ak:did_core:web:applet.example",
                "expected_revision": null,
                "controller_principal_id": "ak:did_core:web:applet.example",
                "base_url": "https://applet.example/runtime",
                "protocols": ["http_custom"],
                "receive_events": true,
                "receive_signals": false,
                "rate_limited": true,
                "requested_scopes": ["read"],
                "claimed_profiles": [
                    "ak.profile.applet_bridge.v1",
                    "ak.profile.applet_service.v1"
                ],
                "registration_epoch": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                // applet-package.schema.json#/$defs/webhook_auth is closed and
                // requires kind + key_ref + accepted_signature_algorithms.
                "webhook_auth": {
                    "kind": "http_message_signature",
                    "key_ref": "did:web:applet.example#server-key-1",
                    "accepted_signature_algorithms": ["ed25519"]
                },
                "manifest": {
                    "claimed_profiles": [
                        "ak.profile.applet_bridge.v1",
                        "ak.profile.applet_service.v1"
                    ],
                    "limits": {},
                    "ghost_policy": {"enabled": false},
                    "delegation_policy": {"enabled": false},
                    "e2ee_policy": {"enabled": false},
                    "registration_epoch_evidence": {
                        "did": "did:webvh:zQ3shExampleScid:applet.example",
                        "document_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        "method_version_evidence": {
                            "method": "did:webvh",
                            "version_id": "1-QmExampleServiceVersion",
                            "unversioned_refetch": false
                        },
                        "accepted_signing_keys": [{
                            "key_ref": "did:webvh:zQ3shExampleScid:applet.example#server-key-1",
                            "public_key_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        }]
                    }
                },
                "proof": {
                    "kind": "detached_jws",
                    "verification_method": "did:web:applet.example#server-key-1",
                    "payload_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "created_at": "2026-05-20T00:00:00.000Z",
                    "jws": "AAAA..BBBB"
                },
                "created_at": "2026-05-20T00:00:00.000Z",
            }),
            valid: false,
        },
        OperationVector {
            name: "applet discovery",
            kind: arkret_wire::EventKind::AppletDiscovery,
            payload: json!({
                "resource_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
                "value": {
                    "resource_kind": "applet",
                    "discoverability": "listed",
                    "directory_ids": ["ak:did_core:web:directory.example"]
                },
            }),
            valid: true,
        },
        OperationVector {
            name: "applet discovery missing directory services",
            kind: arkret_wire::EventKind::AppletDiscovery,
            payload: json!({
                "resource_id": "ak:did_core:web:applet.example",
                "value": {
                    "resource_kind": "applet",
                    "discoverability": "listed"
                },
            }),
            valid: false,
        },
        OperationVector {
            name: "applet bridge error",
            kind: arkret_wire::EventKind::AppletBridgeError,
            // applet_bridge_error_payload: required {applet_id, realm_id, failed_transaction_ref,
            // error_class, error_code, retriable, visibility_scope}; additionalProperties=false.
            payload: json!({
                "applet_id": "ak:applet:01904100-0000-7000-8000-aa55aa55aa55",
                "realm_id": "ak:realm:Abeq9pC3fxOERl1X0ivHa5cJCBy41KfYu5LKvGfPFq5K",
                "failed_transaction_ref": "ak:event:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR",
                "error_class": "external_network",
                "error_code": "bridge_unavailable",
                "retriable": true,
                "visibility_scope": "realm_admins",
                "message": "no upstream",
            }),
            valid: true,
        },
        OperationVector {
            name: "unknown kind",
            kind: "ak.unknown.operation".into(),
            payload: json!({"body": "bad"}),
            valid: false,
        },
        OperationVector {
            name: "reaction missing key",
            kind: arkret_wire::EventKind::ReactionAdd,
            // reaction_payload requires {target_ref, key}; this omits the required `key`.
            payload: json!({"target_ref": "ak:event:ASVxAZxIUYM__aicHMtZdYI9scFpXAK99QLzn2_HB7oR"}),
            valid: false,
        },
    ];

    for (index, vector) in vectors.into_iter().enumerate() {
        let operation = operation(index, vector.kind, vector.payload);
        let result = validate_operation_semantics(&state, &[operation]);
        assert_eq!(
            result.is_ok(),
            vector.valid,
            "operation conformance vector failed: {} ({:?})",
            vector.name,
            result.err()
        );
    }
}

#[test]
fn key_backup_download_quota_limits_after_daily_cap() {
    // Spec key-management.md §7.8 — per-principal rolling-24h quota on
    // full-ciphertext key-backup downloads.
    let state = test_state();
    let principal = "did:web:alice.example";
    let limit = 4;
    // Downloads up to the cap are allowed.
    for n in 1..=limit {
        let outcome = state.record_key_backup_download(principal, limit);
        assert!(!outcome.rate_limited, "download {n} within quota must pass");
        assert_eq!(outcome.count, n);
    }
    // The next download over the cap is withheld with a backoff hint.
    let over = state.record_key_backup_download(principal, limit);
    assert!(
        over.rate_limited,
        "download over the daily cap must be limited"
    );
    assert!(
        over.retry_after_ms > 0,
        "limited download must surface backoff"
    );
    // A different principal is tracked independently.
    let other = state.record_key_backup_download("did:web:bob.example", limit);
    assert!(!other.rate_limited, "distinct principal has its own window");
}
