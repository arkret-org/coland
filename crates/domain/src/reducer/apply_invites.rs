use arkret_models_collaboration::governance::third_party_invite::ThirdPartyInvite;
use serde_json::Value;

use super::*;

/// Membership role a 3PID claim lands with. The Invite object registers no
/// role member; elevated capability arrives separately through
/// `capability_grant_refs` after accept (`governance-objects.md` §5.3).
const INVITE_MEMBER_ROLE: &str = "member";
const INVITE_STATE_PENDING: &str = "pending";
const INVITE_STATE_CLAIMED: &str = "claimed";

impl ProjectionState {
    pub(crate) fn apply_invite_third_party(
        &mut self,
        operation: &Operation,
        admission_time: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::InviteThirdParty)
        {
            return ProjectionEffect::Ignored;
        }
        let Some(payload) = operation.payload.as_object() else {
            return rejected("invite_payload_not_object");
        };
        if payload.get("invite").is_some() || payload.get("invite_id").is_some() {
            return rejected("invite_id_must_be_event_derived");
        }
        let Some(invite_id) =
            arkret_identifiers::EventId::new(operation.context.event_id.to_string())
                .ok()
                .map(|event_id| arkret_identifiers::InviteId::from_event_id(&event_id).to_string())
        else {
            return rejected("invite_create_event_id_required");
        };
        let realm_id = operation.realm_id.to_string();
        let inviter_id = operation.context.sender.to_string();
        let Some(raw_third_party_invite) = payload.get("third_party_invite") else {
            return rejected("third_party_invite_required");
        };
        if let Err(reason) = validate_third_party_invite(raw_third_party_invite) {
            return rejected(reason);
        }
        let Ok(third_party_invite) =
            serde_json::from_value::<ThirdPartyInvite>(raw_third_party_invite.clone())
        else {
            return rejected("third_party_invite_invalid");
        };
        let Some(expires_at) = payload
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp)
        else {
            return rejected("expires_at_required");
        };
        let created_at = operation.created_at;
        if expires_at <= admission_time || created_at > admission_time {
            return rejected("expired_invite_token");
        }
        if let Some(existing) = self.invites.get(&invite_id) {
            return ProjectionEffect::InviteStateChanged {
                invite_id: existing.invite_id.clone(),
                realm_id: existing.realm_id.clone(),
                state: existing.state.clone(),
                invitee_id: existing.invitee_id.clone(),
            };
        }
        if let Some(token_commitment) = token_commitment_for_third_party(&third_party_invite)
            && self.invites.values().any(|existing| {
                existing.invite_id != invite_id
                    && matches!(
                        existing.state.as_str(),
                        INVITE_STATE_PENDING | INVITE_STATE_CLAIMED
                    )
                    && existing
                        .third_party_invite
                        .as_ref()
                        .and_then(token_commitment_for_third_party)
                        == Some(token_commitment)
            })
        {
            return rejected("duplicate_token_commitment");
        }

        let projection = InviteProjection {
            invite_id: invite_id.clone(),
            realm_id: realm_id.clone(),
            inviter_id,
            invitee_id: None,
            third_party_invite: Some(third_party_invite),
            state: INVITE_STATE_PENDING.to_owned(),
            expires_at,
            created_at,
            updated_at: created_at,
            claim_nonces: BTreeMap::new(),
        };
        let state = projection.state.clone();
        let invitee_id = projection.invitee_id.clone();
        self.invites.insert(invite_id.clone(), projection);
        ProjectionEffect::InviteStateChanged {
            invite_id,
            realm_id,
            state,
            invitee_id,
        }
    }

    pub(crate) fn apply_invite_claim(
        &mut self,
        operation: &Operation,
        admission_time: chrono::DateTime<chrono::Utc>,
    ) -> ProjectionEffect {
        if crate::kinds::canonical_kind_for_operation(operation)
            != Some(arkret_wire::EventKind::InviteClaim)
        {
            return ProjectionEffect::Ignored;
        }
        let typed = match serde_json::from_value::<
            arkret_models_collaboration::governance::membership_invite::InviteClaimPayload,
        >(operation.payload.clone())
        {
            Ok(payload) if payload.validate().is_ok() => payload,
            _ => return rejected("invite_claim_payload_invalid"),
        };
        let invite_id = typed.invite_id.to_string();
        let subject_account_id = typed.subject_account_id.clone();
        let subject_id = arkret_wire::ActorId::account(subject_account_id.clone()).to_string();
        let token_commitment = typed.token_commitment.to_string();
        let claim_nonce = typed.claim_nonce.clone();
        let binding_proof = serde_json::to_value(&typed.binding_proof)
            .expect("validated binding proof remains serializable");
        let subject_proof = serde_json::to_value(&typed.subject_proof)
            .expect("validated subject proof remains serializable");
        let realm_policy_bundle = self
            .realm_policy_bundle_value(operation.realm_id.as_str())
            .cloned();

        let Some(invite) = self.invites.get_mut(&invite_id) else {
            return rejected("not_found");
        };
        match invite.claim_nonces.get(&claim_nonce) {
            Some(existing_operation_id)
                if existing_operation_id != operation.operation_id.as_str() =>
            {
                return rejected("duplicate_conflict");
            }
            Some(_) => {}
            None => {}
        }
        if !arkret_models_collaboration::governance::membership_invite::
            invite_claim_within_canonical_expiry(admission_time, invite.expires_at)
        {
            return rejected("expired_invite_token");
        }
        if invite.realm_id != operation.realm_id.as_str() {
            return rejected("not_found");
        }
        match invite.state.as_str() {
            INVITE_STATE_PENDING => {}
            INVITE_STATE_CLAIMED => return rejected("duplicate_conflict"),
            _ => return rejected("not_found"),
        }
        if let Some(existing_invitee) = invite.invitee_id.as_deref()
            && existing_invitee != subject_id
        {
            return rejected("not_found");
        }
        let Some(third_party_invite) = invite.third_party_invite.as_ref() else {
            return rejected("not_found");
        };
        let Some(expected_token_commitment) = token_commitment_for_third_party(third_party_invite)
        else {
            return rejected("not_found");
        };
        if expected_token_commitment != token_commitment {
            return rejected("not_found");
        }
        // third-party-invites.md 3PID claim is only in v1 base scope for
        // `invite` / `restricted` Realms. The authority is the Realm's own
        // effective default_join_rule, not a copy materialized on the Invite:
        // governance-objects.md 5.3 makes the create Event's CBS basis the
        // admission basis and forbids a materialized snapshot.
        if let Err(reason) = validate_claim_join_rule(
            self.realm_join_rules
                .get(&invite.realm_id)
                .map(String::as_str),
        ) {
            return rejected(reason);
        }
        if let Err(reason) = validate_binding_proof(
            &binding_proof,
            third_party_invite,
            &invite.realm_id,
            &subject_account_id,
            &claim_nonce,
            admission_time,
            invite.expires_at,
            realm_policy_bundle.as_ref(),
        ) {
            return rejected(reason);
        }
        if let Err(reason) = validate_subject_proof(
            &subject_proof,
            &binding_proof,
            &invite_id,
            &invite.realm_id,
            &subject_account_id,
            &token_commitment,
            &claim_nonce,
            third_party_invite,
        ) {
            return rejected(reason);
        }

        invite
            .claim_nonces
            .insert(claim_nonce, operation.operation_id.to_string());
        invite.state = INVITE_STATE_CLAIMED.to_owned();
        invite.invitee_id = Some(subject_id.clone());
        invite.updated_at = admission_time;
        cleanup_third_party_projection(invite);
        self.members.insert(
            (invite.realm_id.clone(), subject_id.clone()),
            ColandMembershipState {
                member: subject_id.clone(),
                realm_id: invite.realm_id.clone(),
                state: "invite".to_owned(),
                role: INVITE_MEMBER_ROLE.to_owned(),
                membership_event_ref: None,
                invited_at: Some(admission_time),
                joined_at: admission_time,
                updated_at: admission_time,
                reason: None,
            },
        );

        ProjectionEffect::InviteStateChanged {
            invite_id,
            realm_id: invite.realm_id.clone(),
            state: INVITE_STATE_CLAIMED.to_owned(),
            invitee_id: Some(subject_id),
        }
    }
}

fn rejected(reason: &str) -> ProjectionEffect {
    ProjectionEffect::Rejected {
        reason: reason.to_owned(),
    }
}

fn parse_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn valid_hash(value: &str) -> bool {
    value.starts_with("sha256:") && arkret_identifiers::Hash::new(value.to_owned()).is_ok()
}

fn validate_third_party_invite(third_party_invite: &Value) -> Result<(), &'static str> {
    let Some(object) = third_party_invite.as_object() else {
        return Err("third_party_invite_not_object");
    };
    for forbidden in ["token", "plaintext_token", "email", "phone", "address"] {
        if object.contains_key(forbidden) {
            return Err("third_party_invite_contains_plaintext_secret");
        }
    }
    let Some(service_id) = object
        .get("verification_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Err("verification_service_id_required");
    };
    if arkret_identifiers::DidCoreId::new(service_id.to_owned()).is_err() {
        return Err("verification_service_id_invalid");
    }
    if object
        .get("verification_public_key")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Err("verification_public_key_required");
    }
    if let Some(max_claims) = object.get("max_claims").and_then(Value::as_u64)
        && max_claims > 1
    {
        return Err("unsupported_max_claims");
    }
    let token_commitment = object
        .get("token_commitment")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(token_commitment) = token_commitment
        && !valid_hash(token_commitment)
    {
        return Err("token_commitment_invalid");
    }
    if object.get("lookup_table_ref").is_none() && token_commitment.is_none() {
        return Err("token_commitment_required");
    }
    Ok(())
}

fn token_commitment_for_third_party(third_party_invite: &ThirdPartyInvite) -> Option<&str> {
    third_party_invite
        .token_commitment
        .as_ref()
        .map(arkret_identifiers::Hash::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// `third-party-invites.md`: v1 base conformance carries a 3PID claim into
/// `ak.invite.create` only on `invite` / `restricted` Realms. `knock_restricted`
/// needs a declared candidate profile, so it is rejected here with
/// `unsupported_join_rule`. An unset Realm rule means no `ak.realm.join_rule`
/// state has been accepted yet, which is the `invite` default.
fn validate_claim_join_rule(realm_join_rule: Option<&str>) -> Result<(), &'static str> {
    match realm_join_rule.unwrap_or("invite") {
        "invite" | "restricted" => Ok(()),
        _ => Err("unsupported_join_rule"),
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_binding_proof(
    binding_proof: &Value,
    third_party_invite: &ThirdPartyInvite,
    invite_realm_id: &str,
    subject_account_id: &arkret_wire::AccountId,
    claim_nonce: &str,
    now: chrono::DateTime<chrono::Utc>,
    invite_expires_at: chrono::DateTime<chrono::Utc>,
    realm_policy_bundle: Option<&Value>,
) -> Result<(), &'static str> {
    let binding_proof: arkret_models_collaboration::governance::membership_invite::InviteClaimBindingProof =
        serde_json::from_value(binding_proof.clone()).map_err(|_| "binding_proof_invalid")?;
    binding_proof
        .validate()
        .map_err(|_| "binding_proof_invalid")?;
    let service_id = binding_proof.verification_id.as_str();
    let expected_service_id = third_party_invite.verification_id.as_str();
    if service_id != expected_service_id {
        return Err("verification_service_not_authorized");
    }
    if !realm_policy_bundle.is_some_and(|value| value_allowlists_service(value, service_id)) {
        return Err("verification_service_not_authorized");
    }
    if &binding_proof.subject_account_id != subject_account_id {
        return Err("binding_proof_subject_mismatch");
    }
    if binding_proof.realm_id.as_str() != invite_realm_id {
        return Err("binding_proof_realm_mismatch");
    }
    if binding_proof.audience
        != arkret_models_collaboration::governance::membership_invite::INVITE_CLAIM_AUDIENCE
    {
        return Err("binding_proof_audience_mismatch");
    }
    if binding_proof.claim_nonce != claim_nonce {
        return Err("binding_proof_nonce_mismatch");
    }
    let expires_at =
        parse_timestamp(&binding_proof.expires_at).ok_or("binding_proof_expires_at_invalid")?;
    if expires_at <= now || expires_at > invite_expires_at {
        return Err("binding_proof_expired");
    }
    let method = binding_proof.verification_method.as_str();
    let expected_method = third_party_invite.verification_public_key.trim();
    if expected_method.starts_with("did:") && method != expected_method {
        return Err("binding_proof_method_mismatch");
    }
    Ok(())
}

fn validate_subject_proof(
    subject_proof: &Value,
    binding_proof: &Value,
    invite_id: &str,
    realm_id: &str,
    subject_account_id: &arkret_wire::AccountId,
    token_commitment: &str,
    claim_nonce: &str,
    third_party_invite: &ThirdPartyInvite,
) -> Result<(), &'static str> {
    if !subject_proof.is_object() {
        return Err("subject_proof_not_object");
    };
    let subject_proof: arkret_models_collaboration::governance::membership_invite::InviteSubjectProof =
        serde_json::from_value(subject_proof.clone()).map_err(|_| "subject_proof_invalid")?;
    if subject_proof.verification_method.trim().is_empty() {
        return Err("subject_proof_method_required");
    }
    let subject_method = subject_proof.verification_method.as_str();
    let (controller, fragment) = subject_method.rsplit_once('#').ok_or("claim_invalid")?;
    let subject_did = arkret_wire::Did::new(controller.to_owned()).map_err(|_| "claim_invalid")?;
    if arkret_wire::DeviceId::new(fragment.to_owned()).is_ok()
        || arkret_wire::project_did_to_core_id(&subject_did).map_err(|_| "claim_invalid")?
            != subject_account_id.principal_id
    {
        return Err("claim_invalid");
    }
    if subject_proof.signature_algorithm
        != arkret_models_collaboration::governance::membership_invite::INVITE_SUBJECT_PROOF_ALG
    {
        return Err("subject_proof_alg_unsupported");
    }
    if subject_proof.signature.trim().is_empty() {
        return Err("subject_proof_signature_required");
    }
    subject_proof
        .validate()
        .map_err(|_| "subject_proof_invalid")?;
    let binding_proof: arkret_models_collaboration::governance::membership_invite::InviteClaimBindingProof =
        serde_json::from_value(binding_proof.clone()).map_err(|_| "binding_proof_invalid")?;
    let binding_digest = binding_proof
        .canonical_digest()
        .map_err(|_| "binding_proof_digest_invalid")?;
    let expected_digest = arkret_models_collaboration::governance::membership_invite::invite_subject_proof_transcript_digest(
        subject_account_id,
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        third_party_invite.verification_id.as_str(),
        binding_digest.as_str(),
    )
    .map_err(|_| "subject_proof_transcript_invalid")?;
    if subject_proof.transcript_digest != expected_digest {
        return Err("subject_proof_transcript_mismatch");
    }
    Ok(())
}

/// `third-party-invites.md` — the only authority for third-party invite
/// verification services is the current accepted
/// `ak.realm.policy_bundle` component
/// `allowed_third_party_invite_verification_ids`. It is read at the
/// bundle's top level only: the payload is the flat closed
/// `realm_policy_bundle_payload` object and every revision carries the whole
/// component set forward, so a nested occurrence is never authoritative.
///
/// Absent component and empty array both mean deny-all. There is no
/// deployment config, `ServiceDescribe` self-declaration or local allow row
/// fallback, and no alternate spelling of the field name is honoured — a
/// service that guesses its way into some other key must not gain claim
/// authority.
fn value_allowlists_service(policy_bundle: &Value, service_id: &str) -> bool {
    policy_bundle
        .get("allowed_third_party_invite_verification_ids")
        .and_then(Value::as_array)
        .is_some_and(|allowset| {
            allowset
                .iter()
                .any(|allowed| allowed.as_str() == Some(service_id))
        })
}

fn cleanup_third_party_projection(invite: &mut InviteProjection) {
    // The typed carrier has no `token_salt` / `pepper` fields: the closed
    // schema never admitted them, so only the registered handles are cleared.
    if let Some(third_party_invite) = invite.third_party_invite.as_mut() {
        third_party_invite.token_salt_id = None;
        third_party_invite.lookup_table_ref = None;
        third_party_invite.pepper_id = None;
    }
}
