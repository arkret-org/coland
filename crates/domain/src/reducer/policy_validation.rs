//! Join / admission policy validation and encryption-floor helpers.
//!
//! Split out of the `reducer` mod file; re-exported there so the
//! `crate::reducer::validate_join_policy_payload` public path and the
//! sibling `apply_*` modules' `super::*` access stay unchanged.

use std::collections::BTreeSet;

use arkret_models_collaboration::governance::membership_invite::{
    JoinGateProof, JoinGateProofKind,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// AKP-0007 §8 — pulling *another* actor into a Circle (none/left → active by
/// an actor other than the target) requires the requester_id to hold
/// `ak.circle.member.manage` (narrowed by `allowed_circle_ids`) on this Circle.
/// The HTTP surface decides it from the durable authorization cut and stamps a
/// verdict into the operation payload; the reducer fails closed when that
/// verdict is absent or false, so an unauthorised one-way add is rejected even
/// if it bypasses the HTTP gate.
pub(crate) const CIRCLE_MEMBER_MANAGE_CAPABILITY_REQUIRED: &str =
    "circle_member_manage_capability_required";
/// AKP-0007 §8 — a self-service join (none/left → active *by the target actor*)
/// is only permitted on an `open` Circle. Self-joining a non-`open` Circle must
/// go through an invite/manage path.
pub(crate) const CIRCLE_JOIN_NOT_OPEN: &str = "circle_join_not_open";
pub(crate) fn state_payload_value(payload: &Value) -> &Value {
    payload.get("value").unwrap_or(payload)
}

const SEARCH_POLICY_PROFILES: &[&str] = &[
    arkret_wire::ProfileId::SEARCH_CLIENT_INDEX_V1,
    arkret_wire::ProfileId::SEARCH_BLIND_INDEX_V1,
    arkret_wire::ProfileId::SEARCH_FORWARD_PRIVATE_V1,
];
const SEARCH_POLICY_DATA_CLASSES: &[&str] = &[
    "encrypted_index",
    "blind_tokens",
    "plaintext",
    "reversible_summary",
];
const SEARCH_POLICY_LEAKAGE_CLASSES: &[&str] =
    &["deterministic_token", "forward_private", "access_hiding"];
const SEARCH_POLICY_REVOCATION_BEHAVIORS: &[&str] = &["fail_closed", "drop_stale"];

fn required_string_array(
    policy: &Value,
    field: &'static str,
    allowed: Option<&[&str]>,
    invalid_reason: &'static str,
) -> Result<Vec<String>, &'static str> {
    let Some(items) = policy.get(field).and_then(Value::as_array) else {
        return Err(invalid_reason);
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(value) = item.as_str().filter(|value| !value.trim().is_empty()) else {
            return Err(invalid_reason);
        };
        if let Some(allowed) = allowed
            && !allowed.contains(&value)
        {
            return Err(invalid_reason);
        }
        if !seen.insert(value.to_owned()) {
            return Err(invalid_reason);
        }
        out.push(value.to_owned());
    }
    Ok(out)
}

pub(crate) fn validate_realm_search_policy_payload(policy: &Value) -> Result<(), &'static str> {
    let Some(object) = policy.as_object() else {
        return Err("search_policy_invalid");
    };
    let profiles = required_string_array(
        policy,
        "enabled_profile_refs",
        Some(SEARCH_POLICY_PROFILES),
        "search_policy_enabled_profile_refs_invalid",
    )?;
    required_string_array(
        policy,
        "allowed_service_ids",
        None,
        "search_policy_allowed_service_ids_invalid",
    )?;
    let data_classes = required_string_array(
        policy,
        "data_classes",
        Some(SEARCH_POLICY_DATA_CLASSES),
        "search_policy_data_class_invalid",
    )?;
    if data_classes.is_empty() {
        return Err("search_policy_data_classes_empty");
    }
    let revocation_behavior = object
        .get("revocation_behavior")
        .and_then(Value::as_str)
        .ok_or("search_policy_revocation_behavior_missing")?;
    if !SEARCH_POLICY_REVOCATION_BEHAVIORS.contains(&revocation_behavior) {
        return Err("search_policy_revocation_behavior_invalid");
    }
    let leakage_class = object
        .get("leakage_class")
        .and_then(Value::as_str)
        .unwrap_or("deterministic_token");
    if !SEARCH_POLICY_LEAKAGE_CLASSES.contains(&leakage_class) {
        return Err("search_policy_leakage_class_invalid");
    }
    if leakage_class == "access_hiding" {
        return Err("search_policy_access_hiding_unsupported");
    }
    let forward_private_enabled = profiles
        .iter()
        .any(|profile| profile == arkret_wire::ProfileId::SEARCH_FORWARD_PRIVATE_V1);
    if forward_private_enabled && leakage_class != "forward_private" {
        return Err("search_policy_forward_private_leakage_class_required");
    }
    if leakage_class == "forward_private" && !forward_private_enabled {
        return Err("search_policy_forward_private_profile_required");
    }
    if forward_private_enabled
        && !profiles
            .iter()
            .any(|profile| profile == arkret_wire::ProfileId::SEARCH_BLIND_INDEX_V1)
    {
        return Err("search_policy_forward_private_blind_index_required");
    }
    if let Some(value) = object.get("token_rotation_cadence_ms")
        && value.as_u64().is_none()
    {
        return Err("search_policy_token_rotation_cadence_invalid");
    }
    if forward_private_enabled && object.get("token_rotation_cadence_ms").is_none() {
        return Err("search_policy_forward_private_token_rotation_required");
    }
    if let Some(value) = object.get("index_retention_ms")
        && value.as_u64().is_none()
    {
        return Err("search_policy_index_retention_invalid");
    }
    Ok(())
}

/// The closed v1 gate set. `event-payload.schema.json#/$defs/join_policy_gate`
/// is a five-arm `oneOf` and join-policy.md 1 states that v1 defines no
/// application or review workflow, so an application_form / manual_review gate
/// has no carrier to be accepted under.
const JOIN_POLICY_GATE_KINDS: &[&str] = &[
    "claim_required",
    "challenge_response",
    "parent_membership",
    "principal_admission",
    "cooldown",
];

const CHALLENGE_KINDS: &[&str] = &["captcha", "pow", "attested_human", "idp_oidc"];

/// Validate the Join Policy subset that the reducer must enforce before
/// accepting the policy-components cell.
pub fn validate_join_policy_payload(join_policy: &Value) -> Result<(), &'static str> {
    let Some(object) = join_policy.as_object() else {
        return Err("join_policy must be an object");
    };
    match object.get("combinator").and_then(Value::as_str) {
        Some("all" | "any") => {}
        Some(_) => return Err("join_policy_combinator_invalid"),
        None => return Err("join_policy_combinator_missing"),
    }
    let Some(gates) = object.get("gates").and_then(Value::as_array) else {
        return Err("join_policy requires gates");
    };
    if gates.is_empty() {
        return Err("join_policy requires at least one gate");
    }
    if gates.len() > 16 {
        return Err("join_policy_too_many_gates");
    }
    let mut seen_gate_ids = BTreeSet::new();
    for gate in gates {
        let Some(gate) = gate.as_object() else {
            return Err("join_policy gates must be objects");
        };
        let Some(gate_id) = gate.get("gate_id").and_then(Value::as_str) else {
            return Err("join_policy gate requires gate_id");
        };
        if gate_id.is_empty() || !seen_gate_ids.insert(gate_id.to_owned()) {
            return Err("join_policy_duplicate_gate_id");
        }
        let Some(kind) = gate.get("kind").and_then(Value::as_str) else {
            return Err("join_policy_gate_kind_invalid");
        };
        if !JOIN_POLICY_GATE_KINDS.contains(&kind) {
            return Err("join_policy_gate_kind_invalid");
        }
        match kind {
            "principal_admission" => validate_principal_admission_gate(gate)?,
            "parent_membership" => validate_parent_membership_gate(gate)?,
            "challenge_response" => validate_challenge_response_gate(gate)?,
            "cooldown" => validate_cooldown_gate(gate)?,
            "claim_required" => validate_claim_required_gate(gate)?,
            _ => unreachable!("gate kind checked above"),
        }
    }
    Ok(())
}

/// join-policy.md 3.1: `auto_resolve` is optional and, when present, may only
/// be `true`. Every v1 gate is reducer-evaluable, so there is no arm that
/// carries `false`.
fn validate_auto_resolve(gate: &serde_json::Map<String, Value>) -> Result<(), &'static str> {
    if let Some(value) = gate.get("auto_resolve")
        && value.as_bool() != Some(true)
    {
        return Err("join_policy_gate_auto_resolve_invalid");
    }
    Ok(())
}

pub(crate) fn validate_principal_admission_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate)?;
    validate_did_method_list(gate, "allowed_did_methods")?;
    validate_account_id_list(gate, "allowed_account_ids")?;
    validate_account_id_list(gate, "denied_account_ids")?;
    validate_actor_id_list(gate, "allowed_actor_ids")?;
    validate_actor_id_list(gate, "denied_actor_ids")?;
    validate_did_list(gate, "allowed_principal_ids")?;
    validate_did_list(gate, "denied_principal_ids")?;
    if ![
        "allowed_did_methods",
        "allowed_account_ids",
        "denied_account_ids",
        "allowed_actor_ids",
        "denied_actor_ids",
        "allowed_principal_ids",
        "denied_principal_ids",
    ]
    .iter()
    .any(|field| gate.contains_key(*field))
    {
        return Err("principal_admission_requires_selector");
    }
    Ok(())
}

fn validate_account_id_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), &'static str> {
    let Some(values) = object.get(field) else {
        return Ok(());
    };
    let Some(values) = values.as_array() else {
        return Err("principal_admission_accounts_invalid");
    };
    if values
        .iter()
        .any(|value| serde_json::from_value::<arkret_wire::AccountId>(value.clone()).is_err())
    {
        return Err("principal_admission_accounts_invalid");
    }
    Ok(())
}

fn validate_actor_id_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), &'static str> {
    let Some(values) = object.get(field) else {
        return Ok(());
    };
    let Some(values) = values.as_array() else {
        return Err("principal_admission_actors_invalid");
    };
    if values
        .iter()
        .any(|value| serde_json::from_value::<arkret_wire::ActorId>(value.clone()).is_err())
    {
        return Err("principal_admission_actors_invalid");
    }
    Ok(())
}

pub(crate) fn validate_parent_membership_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate)?;
    let Some(source_realms) = gate
        .get("membership_source_realm_ids")
        .and_then(Value::as_array)
    else {
        return Err("parent_membership_sources_invalid");
    };
    if source_realms.is_empty() {
        return Err("parent_membership_sources_invalid");
    }
    let mut seen = BTreeSet::new();
    for source in source_realms {
        let Some(source) = source.as_str().filter(|value| !value.trim().is_empty()) else {
            return Err("parent_membership_sources_invalid");
        };
        if arkret_identifiers::RealmId::new(source.to_owned()).is_err() {
            return Err("parent_membership_sources_invalid");
        }
        if !seen.insert(source.to_owned()) {
            return Err("parent_membership_sources_invalid");
        }
    }
    match gate.get("require_min_membership").and_then(Value::as_str) {
        Some("join") => Ok(()),
        _ => Err("parent_membership_min_membership_invalid"),
    }
}

pub(crate) fn validate_challenge_response_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate)?;
    let Some(provider_did) = gate.get("provider_did").and_then(Value::as_str) else {
        return Err("challenge_response_provider_invalid");
    };
    if arkret_identifiers::Did::new(provider_did.to_owned()).is_err() {
        return Err("challenge_response_provider_invalid");
    }
    let Some(kinds) = gate.get("challenge_kinds").and_then(Value::as_array) else {
        return Err("challenge_response_kinds_invalid");
    };
    if kinds.is_empty() {
        return Err("challenge_response_kinds_invalid");
    }
    let mut seen = BTreeSet::new();
    for kind in kinds {
        let Some(kind) = kind.as_str() else {
            return Err("challenge_response_kinds_invalid");
        };
        if !CHALLENGE_KINDS.contains(&kind) || !seen.insert(kind.to_owned()) {
            return Err("challenge_response_kinds_invalid");
        }
    }
    let Some(max_age) = gate.get("max_proof_age").and_then(Value::as_str) else {
        return Err("challenge_response_max_proof_age_invalid");
    };
    parse_iso8601_duration(max_age)
        .filter(|duration| *duration > Duration::zero())
        .ok_or("challenge_response_max_proof_age_invalid")?;
    Ok(())
}

pub(crate) fn validate_cooldown_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate)?;
    let Some(min_interval) = gate.get("min_interval_since_leave").and_then(Value::as_str) else {
        return Err("cooldown_min_interval_invalid");
    };
    parse_iso8601_duration(min_interval)
        .filter(|duration| *duration > Duration::zero())
        .ok_or("cooldown_min_interval_invalid")?;
    Ok(())
}

pub(crate) fn validate_claim_required_gate(
    gate: &serde_json::Map<String, Value>,
) -> Result<(), &'static str> {
    validate_auto_resolve(gate)?;
    let Some(claims) = gate.get("required_claims").and_then(Value::as_array) else {
        return Err("claim_required_claims_invalid");
    };
    if claims.is_empty() {
        return Err("claim_required_claims_invalid");
    }
    // join-policy.md 3.1: the issuer boundary is required material. A gate
    // without one accepts a claim the applicant signed for themselves, so a
    // policy that omits it is not admissible in the first place.
    let Some(issuers) = gate.get("trusted_issuer_ids").and_then(Value::as_array) else {
        return Err("claim_required_trusted_issuers_invalid");
    };
    if issuers.is_empty() {
        return Err("claim_required_trusted_issuers_invalid");
    }
    for issuer in issuers {
        let valid = issuer
            .as_str()
            .is_some_and(|did| arkret_identifiers::DidCoreId::new(did.to_owned()).is_ok());
        if !valid {
            return Err("claim_required_trusted_issuers_invalid");
        }
    }
    Ok(())
}

pub(crate) fn validate_did_method_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_methods_invalid");
    };
    for value in values {
        let Some(method) = value.as_str() else {
            return Err("principal_admission_methods_invalid");
        };
        if normalize_policy_did_method(method).is_none() {
            return Err("principal_admission_methods_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn validate_did_list(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<bool, &'static str> {
    let Some(value) = object.get(field) else {
        return Ok(false);
    };
    let Some(values) = value.as_array() else {
        return Err("principal_admission_dids_invalid");
    };
    for value in values {
        let Some(did) = value.as_str() else {
            return Err("principal_admission_dids_invalid");
        };
        if arkret_identifiers::DidCoreId::new(did.to_owned()).is_err() {
            return Err("principal_admission_dids_invalid");
        }
    }
    Ok(!values.is_empty())
}

pub(crate) fn normalize_policy_did_method(value: &str) -> Option<&str> {
    let method = value.strip_prefix("did:")?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(method)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalAdmissionSubjectClass {
    RealmManaged,
    Human,
    Agent,
    Service,
}

pub(crate) fn principal_admission_gate_allows(
    gate: &serde_json::Map<String, Value>,
    member: &str,
    subject_class: PrincipalAdmissionSubjectClass,
    resolved_did: Option<&arkret_identifiers::Did>,
) -> bool {
    if !principal_admission_gate_has_selector(gate) {
        return false;
    }
    let Ok(actor_id) = serde_json::from_str::<arkret_wire::ActorId>(member) else {
        return false;
    };
    let member_id = actor_id.signing_principal_id();
    if did_list_contains(gate, "denied_principal_ids", member_id.as_str()) {
        return false;
    }
    if gate.contains_key("allowed_principal_ids")
        && !did_list_contains(gate, "allowed_principal_ids", member_id.as_str())
    {
        return false;
    }
    let actor_value = serde_json::to_value(&actor_id).ok();
    match subject_class {
        PrincipalAdmissionSubjectClass::Human => {
            let Some(account_id) = actor_id.as_account_id() else {
                return false;
            };
            let account_value = serde_json::to_value(account_id).ok();
            if json_list_contains(gate, "denied_account_ids", account_value.as_ref())
                || (gate.contains_key("allowed_account_ids")
                    && !json_list_contains(gate, "allowed_account_ids", account_value.as_ref()))
            {
                return false;
            }
        }
        PrincipalAdmissionSubjectClass::Agent
        | PrincipalAdmissionSubjectClass::Service
        | PrincipalAdmissionSubjectClass::RealmManaged => {
            if json_list_contains(gate, "denied_actor_ids", actor_value.as_ref())
                || (gate.contains_key("allowed_actor_ids")
                    && !json_list_contains(gate, "allowed_actor_ids", actor_value.as_ref()))
            {
                return false;
            }
        }
    }
    if let Some(methods) = gate.get("allowed_did_methods").and_then(Value::as_array)
        && !methods.is_empty()
    {
        let Some(did) = resolved_did.filter(|did| {
            arkret_wire::project_did_to_core_id(did).is_ok_and(|projected| projected == *member_id)
        }) else {
            return false;
        };
        if !methods.iter().any(|value| {
            value
                .as_str()
                .and_then(normalize_policy_did_method)
                .is_some_and(|allowed| allowed == did.method())
        }) {
            return false;
        }
    }
    true
}

pub(crate) fn principal_admission_gate_has_selector(gate: &serde_json::Map<String, Value>) -> bool {
    [
        "allowed_did_methods",
        "allowed_account_ids",
        "denied_account_ids",
        "allowed_actor_ids",
        "denied_actor_ids",
        "allowed_principal_ids",
        "denied_principal_ids",
    ]
    .iter()
    .any(|field| gate.contains_key(*field))
}

fn json_list_contains(
    gate: &serde_json::Map<String, Value>,
    field: &str,
    expected: Option<&Value>,
) -> bool {
    expected.is_some_and(|expected| {
        gate.get(field)
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value == expected))
    })
}

pub(crate) fn did_list_contains(
    gate: &serde_json::Map<String, Value>,
    field: &str,
    did: &str,
) -> bool {
    gate.get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(did)))
}

/// `join-policy.md` §4 rule 4 — the binding tuple every gate proof carries.
///
/// This is compared before any signature is looked at, so a proof minted for
/// another Realm, another applicant or an older policy revision is rejected by
/// field comparison alone. Freshness uses the enclosing Event's own signed
/// `created_at`: a receiver clock would make the same Event admissible on one
/// replay and not on another.
pub(crate) fn join_gate_proof_binding_holds(
    proof: &JoinGateProof,
    realm_id: &str,
    applicant_actor_id: &arkret_wire::ActorId,
    policy_digest: &arkret_wire::Hash,
    event_created_at: DateTime<Utc>,
    max_proof_age: Option<Duration>,
) -> bool {
    if proof.realm_id.as_str() != realm_id
        || &proof.applicant_actor_id != applicant_actor_id
        || &proof.policy_digest != policy_digest
    {
        return false;
    }
    // A proof stamped after the Event that carries it was not in the
    // applicant's hands when they signed, so it cannot be evidence for it.
    if proof.created_at > event_created_at {
        return false;
    }
    match max_proof_age {
        Some(max_age) => event_created_at.signed_duration_since(proof.created_at) <= max_age,
        None => true,
    }
}

/// `join-policy.md` §3.1 `claim_required` — the presented claims have to come
/// from an issuer the gate trusts and cover everything it requires.
///
/// The issuer boundary is not optional: a gate with no `trusted_issuer_ids`
/// would accept a self-signed claim, so an absent or empty list rejects.
pub(crate) fn claim_required_gate_has_proof(
    gate: &serde_json::Map<String, Value>,
    proof: &JoinGateProof,
) -> bool {
    if proof.kind != JoinGateProofKind::ClaimRequired {
        return false;
    }
    let Some(issuer_id) = proof.issuer_id.as_ref() else {
        return false;
    };
    if !did_list_contains(gate, "trusted_issuer_ids", issuer_id.as_str()) {
        return false;
    }
    let required_claims = gate
        .get("required_claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|claim| !claim.trim().is_empty())
        .collect::<Vec<_>>();
    if required_claims.is_empty() {
        return false;
    }
    let presented = proof
        .claims
        .as_ref()
        .map(|claims| {
            claims
                .iter()
                .map(|claim| claim.as_str())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    required_claims
        .iter()
        .all(|claim| presented.contains(claim))
}

/// `join-policy.md` §3.1 `challenge_response` — the solved challenge has to be
/// one of the families the gate accepts, and identify itself so the provider
/// can treat it as single-use.
///
/// The signature over the proof, and the resolution of its
/// `verification_method` to a key controlled by the gate's `provider_did`,
/// are the admission layer's job: they need DID resolution, which a reducer
/// replaying accepted history cannot perform.
pub(crate) fn challenge_response_gate_allows(
    gate: &serde_json::Map<String, Value>,
    proof: &JoinGateProof,
) -> bool {
    if proof.kind != JoinGateProofKind::ChallengeResponse {
        return false;
    }
    if gate
        .get("provider_did")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return false;
    }
    if proof
        .challenge_id
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        return false;
    }
    let Some(challenge_kind) = proof.challenge_kind else {
        return false;
    };
    let Ok(challenge_kind) = serde_json::to_value(challenge_kind) else {
        return false;
    };
    gate.get("challenge_kinds")
        .and_then(Value::as_array)
        .is_some_and(|kinds| kinds.contains(&challenge_kind))
}

/// The gate's `max_proof_age`, which bounds how stale a proof may be relative
/// to the Event carrying it. A gate that declares an unparseable duration has
/// no evaluable freshness bound and fails closed at the call site.
pub(crate) fn gate_max_proof_age(gate: &serde_json::Map<String, Value>) -> Option<Duration> {
    gate.get("max_proof_age")
        .and_then(Value::as_str)
        .and_then(parse_iso8601_duration)
}

pub(crate) fn parse_iso8601_duration(value: &str) -> Option<Duration> {
    let rest = value.strip_prefix('P')?;
    if rest.is_empty() {
        return None;
    }
    let mut total_seconds: i64 = 0;
    let mut digits = String::new();
    let mut in_time = false;
    for ch in rest.chars() {
        if ch == 'T' {
            if in_time || !digits.is_empty() {
                return None;
            }
            in_time = true;
            continue;
        }
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.is_empty() {
            return None;
        }
        let value = digits.parse::<i64>().ok()?;
        digits.clear();
        let scale = match (in_time, ch) {
            (false, 'Y') => 365 * 24 * 60 * 60,
            (false, 'M') => 30 * 24 * 60 * 60,
            (false, 'W') => 7 * 24 * 60 * 60,
            (false, 'D') => 24 * 60 * 60,
            (true, 'H') => 60 * 60,
            (true, 'M') => 60,
            (true, 'S') => 1,
            _ => return None,
        };
        total_seconds = total_seconds.checked_add(value.checked_mul(scale)?)?;
    }
    if !digits.is_empty() {
        return None;
    }
    Some(Duration::seconds(total_seconds))
}

#[cfg(test)]
mod policy_bundle_component_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn challenge_provider_is_a_resolvable_did_not_a_typed_core_id() {
        let valid = json!({
            "auto_resolve": true,
            "provider_did": "did:webvh:z6mkfixture:captcha.example",
            "challenge_kinds": ["captcha"],
            "max_proof_age": "PT5M"
        });
        validate_challenge_response_gate(valid.as_object().unwrap()).unwrap();

        let typed_core = json!({
            "auto_resolve": true,
            "provider_did": "ak:did_core:webvh:z6mkfixture",
            "challenge_kinds": ["captcha"],
            "max_proof_age": "PT5M"
        });
        assert_eq!(
            validate_challenge_response_gate(typed_core.as_object().unwrap()),
            Err("challenge_response_provider_invalid")
        );
    }
}
