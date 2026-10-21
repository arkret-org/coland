use serde_json::json;

use super::*;

const TEST_REALM: &str = "ak:realm:AWBLVNs9HeoGO5lSMOgHAujzyX_u-d_6wfDWF_3lEM2J";
const TEST_STRAND: &str = "ak:strand:ATXlnYLuNA5AB7Pide0IGeEtDJ6YeQ19_FUbKXtjQhum";
const TEST_STRAND_2: &str = "ak:strand:AbGG69lPDSbhcQKggUhmn2pvWMDjx2tZmKL9GHisS290";
const TEST_SPACE: &str = "ak:space:ATu1E_hCvaxzpXDswPMlN3ypwETWAa7O994Etg387rA6";
const TEST_RELATION: &str = "ak:relation:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml";
const TEST_CIRCLE: &str = "ak:circle:AQk4t8f1mPAFEQjKNzmTl_TZMxmpSbc_1ldQlxRUZBZ7";
const TEST_ISSUER: &str = "ak:did_core:web:alice.example";
const TEST_SUBJECT: &str = "ak:did_core:web:bob.example";
const TEST_STATION: &str = "ak:did_core:web:coland.example";

fn wire_operation(kind: arkret_wire::EventKind, payload: Value) -> Operation {
    arkret_event_draft::test_support::raw_projected_operation(
        arkret_identifiers::OperationId::new(format!("ak:operation:{}", uuid::Uuid::now_v7()))
            .unwrap(),
        arkret_identifiers::RealmId::new(TEST_REALM.to_owned()).unwrap(),
        kind.as_str(),
        payload,
    )
}

#[test]
fn consent_replace_accepts_full_set_and_empty_with_exact_expected_current() {
    for permissions in [
        json!([]),
        json!([{"consent_scope":"invite"},{"consent_scope":"presence"}]),
    ] {
        let operation = wire_operation(
            arkret_wire::EventKind::ConsentReplace,
            json!({
                "peer":{"kind":"actor","actor_id":{"kind":"account","account_id":{"principal_id":TEST_SUBJECT,"station_id":TEST_STATION}}},
                "expected_current":{"state":"never_written"},"permissions":permissions
            }),
        );
        assert!(
            operation
                .typed_payload::<arkret_wire::event_spec::ConsentReplace>()
                .is_ok()
        );
    }
}

/// `relation.md` §2 — `effective_scope` is reducer-stamped, and on the create
/// side the criterion now belongs entirely to the schema:
/// `relation_create_object` reuses `relation.schema.json` and forbids `id`,
/// `type` and `effective_scope`, so the SDK artifact schema rejects the payload
/// before this validator runs. Re-deciding it here would be a second, drifting
/// copy of a rule the schema owns.
#[test]
fn relation_create_effective_scope_ban_is_owned_by_the_payload_schema() {
    let stamped = wire_operation(
        arkret_wire::EventKind::RelationCreate,
        json!({"relation": {
            "kind": "references",
            "from_ref": TEST_STRAND,
            "to_ref": TEST_STRAND_2,
            "effective_scope": {"kind": "circle", "circle_id": TEST_CIRCLE}
        }}),
    );
    assert_eq!(validate_relation_operation_payload(&stamped), Ok(()));
}

/// The update side stays in this layer because `payload.patch` is the generic
/// `ak.schema.patch.v1` document, whose paths no generic patch schema can
/// enumerate. The forbidden set comes from the SDK projection of
/// `registry/reducer-managed-path-registry.json`, never from a local list.
#[test]
fn relation_update_rejects_effective_scope_patch_paths() {
    let canonical = wire_operation(
        arkret_wire::EventKind::RelationUpdate,
        json!({"relation_id": TEST_RELATION, "patch": {"fields.label": "ok"}}),
    );
    assert_eq!(validate_relation_operation_payload(&canonical), Ok(()));

    for path in ["effective_scope", "effective_scope.circle_id"] {
        let patched = wire_operation(
            arkret_wire::EventKind::RelationUpdate,
            json!({"relation_id": TEST_RELATION, "patch": {path: {"$op": "set", "value": "x"}}}),
        );
        assert_eq!(
            validate_relation_operation_payload(&patched),
            Err("effective_scope_reducer_managed")
        );
    }
}

/// The derived-edge rule needs the Relation pre-state, so the stateless
/// validator MUST NOT re-decide it.
#[test]
fn relation_derived_edge_admission_is_not_duplicated_in_the_payload_validator() {
    let derived = wire_operation(
        arkret_wire::EventKind::RelationCreate,
        json!({"relation": {"kind": "contains", "from_ref": TEST_SPACE, "to_ref": TEST_STRAND}}),
    );
    assert_eq!(validate_relation_operation_payload(&derived), Ok(()));
}

fn capability_grant_payload() -> Value {
    let account_actor = |principal| {
        arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(principal).unwrap(),
            arkret_wire::DidCoreId::new(TEST_STATION).unwrap(),
        ))
    };
    let grant = json!({
        "schema": "ak.schema.capability.v1",
        "realm_id": TEST_REALM,
        "issuer_id": account_actor(TEST_ISSUER),
        "subject": account_actor(TEST_SUBJECT),
        "actions": ["ak.strand.read"],
        "resources": [{"kind": "strand", "realm_id": TEST_REALM, "strand_id": TEST_STRAND}],
        "issued_at": "2026-08-17T00:00:00.000Z",
        "issuer_authority_refs": [{
            "kind": "realm_root",
            "realm_id": TEST_REALM,
            "authority_event_ref": "ak:event:AWBLVNs9HeoGO5lSMOgHAujzyX_u-d_6wfDWF_3lEM2J",
            "authority_generation": 0
        }]
    });
    json!({"grant": grant})
}

#[test]
fn capability_grant_resources_pass_the_artifact_schema() {
    let canonical = wire_operation(
        arkret_wire::EventKind::CapabilityGrant,
        capability_grant_payload(),
    );
    validate_operation_schema_from_sdk_artifact(
        &arkret_wire::EventKind::CapabilityGrant,
        &canonical,
    )
    .expect("canonical `resources` grant passes the artifact schema");
}

#[test]
fn membership_target_reads_member_id() {
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(TEST_SUBJECT).unwrap(),
        arkret_wire::DidCoreId::new(TEST_STATION).unwrap(),
    ));
    let canonical = wire_operation(
        arkret_wire::EventKind::MemberState,
        json!({"member_id": actor, "membership": "join"}),
    );
    assert_eq!(membership_target(&canonical), Some(actor));
}
