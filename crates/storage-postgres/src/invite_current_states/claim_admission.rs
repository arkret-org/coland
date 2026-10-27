//! 3PID claim signatures and one-time consume at the exact accepting cut.
use arkret_models_collaboration::governance::membership_invite::{
    InviteSubjectProofBody, invite_binding_proof_transcript_bytes,
};
use coland_storage::InviteClaimProofCommit;

use super::*;

#[derive(diesel::QueryableByName)]
struct AcceptedCreateRow {
    #[diesel(sql_type = Jsonb)]
    envelope: Value,
    #[diesel(sql_type = Jsonb)]
    commit_json: Value,
}

fn invalid(detail: impl std::fmt::Display) -> PersistenceError {
    PersistenceError::Conflict(format!("claim_invalid: {detail}"))
}

pub(super) async fn commit_claim(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    evidence: Option<&InviteClaimProofCommit>,
) -> PersistenceResult<()> {
    let claim: InviteClaimPayload = typed_payload(event)?;
    claim.validate().map_err(invalid)?;
    let proof = evidence.ok_or_else(|| invalid("historical claim proof is unavailable"))?;
    if proof.event_id != event.event_id
        || proof.committed_at != commit.committed_at
        || proof.event_digest
            != event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .map_err(invalid)?
        || event.actor_id.as_account_id() != Some(&claim.subject_account_id)
    {
        return Err(invalid(
            "claim evidence does not bind the candidate authority cut",
        ));
    }
    lock_realm_authorization_cut(conn, &event.realm_id).await?;
    let lifecycle = locked_lifecycle(conn, event.realm_id.as_str(), &claim.invite_id)
        .await?
        .ok_or_else(|| invalid("invite is unavailable"))?;
    if lifecycle != InviteState::Pending {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "third-party Invite is no longer pending",
        ));
    }
    let row = diesel::sql_query(
        "SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.envelope->>'event_id'=$1 AND e.realm_id=$2 AND e.kind=$3 AND e.state='committed' \
         AND c.stream_position<$4 AND c.stream_ref->>'kind'='realm'")
        .bind::<Text,_>(claim.invite_id.event_id().as_str())
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(EventKind::InviteThirdParty.as_str())
        .bind::<BigInt,_>(stream_position(commit)?)
        .get_result::<AcceptedCreateRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?
        .ok_or_else(|| invalid("accepted third-party create is unavailable at predecessor cut"))?;
    let create: arkret_wire::Event = serde_json::from_value(row.envelope).map_err(corrupt)?;
    let create_commit: arkret_wire::RealmCommit =
        serde_json::from_value(row.commit_json).map_err(corrupt)?;
    let expected_ref = arkret_wire::CommittedEventRef {
        event_id: create.event_id.clone(),
        commit_id: create_commit.commit_id.clone(),
        stream_ref: create_commit.stream_ref.clone(),
        stream_position: create_commit.stream_position,
    };
    if proof.create_ref != expected_ref || create_commit.event_ref != create.event_id {
        return Err(invalid("claim proof names different accepted create facts"));
    }
    let creator_cut = crate::realm_authorization_cut::RealmAuthorizationCut::read(
        conn,
        &event.realm_id,
        &create.actor_id,
    )
    .await?;
    creator_cut
        .require_live_invite_creator(&create, commit.committed_at)
        .map_err(|error| invalid(format!("Invite creator is no longer authorized: {error}")))?;
    let material: InviteThirdPartyCreatePayload = typed_payload(&create)?;
    material.validate().map_err(invalid)?;
    if material.expires_at <= event.created_at || material.expires_at <= commit.committed_at {
        return Err(PersistenceError::Conflict(
            "expired_invite_token: Invite is expired at the claim cut".to_owned(),
        ));
    }
    let binding = &claim.binding_proof;
    let binding_expiry =
        arkret_canonical::parse_timestamp_canonical(&binding.expires_at).map_err(invalid)?;
    if binding_expiry <= event.created_at
        || binding_expiry <= commit.committed_at
        || binding_expiry > material.expires_at
        || material.third_party_invite.max_claim_count != 1
        || material.third_party_invite.token_commitment != claim.token_commitment
        || binding.verification_id != material.third_party_invite.verification_id
        || binding.realm_id != event.realm_id
    {
        return Err(invalid("claim binding differs from frozen create material"));
    }
    let policy =
        diesel::sql_query("SELECT value FROM realm_policy_bundle_current_states WHERE realm_id=$1")
            .bind::<Text, _>(event.realm_id.as_str())
            .get_result::<ValueRow>(&mut *conn)
            .await
            .optional()
            .map_err(PersistenceError::database)?
            .map(|row| {
                serde_json::from_value::<RealmPolicyBundlePayload>(row.value).map_err(corrupt)
            })
            .transpose()?;
    if !policy
        .as_ref()
        .and_then(|value| value.allowed_third_party_invite_verification_ids.as_ref())
        .is_some_and(|allowed| allowed.contains(&binding.verification_id))
    {
        return Err(invalid(
            "verifier is absent from current accepted allowlist",
        ));
    }
    let join_rule = diesel::sql_query(
        "SELECT b.value FROM realm_bootstrap_current_states b JOIN realm_commits c ON c.commit_id=b.current_commit_id \
         WHERE b.realm_id=$1 AND b.state_family='realm_join_rule' AND c.realm_id=b.realm_id \
         AND c.stream_position=b.current_stream_position AND c.stream_ref->>'kind'='realm'")
        .bind::<Text,_>(event.realm_id.as_str()).get_result::<ValueRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if !join_rule
        .as_ref()
        .and_then(|row| row.value.as_str())
        .is_some_and(|rule| matches!(rule, "invite" | "restricted"))
    {
        return Err(PersistenceError::Conflict(
            "unsupported_join_rule: 3PID claim requires invite or restricted".to_owned(),
        ));
    }
    crate::member_state_admission::require_ordinary_member(conn, &event.realm_id, &event.actor_id)
        .await?;
    if crate::member_state_admission::locked_membership(conn, &event.realm_id, &event.actor_id)
        .await?
        != "leave"
    {
        return Err(invalid("claim membership proposal requires leave"));
    }
    verify_signatures(event, &claim, &material, proof)?;
    let duplicates = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.kind=$2 AND e.state='committed' AND c.stream_position<$3 \
         AND (e.envelope->'payload'->>'token_commitment'=$4 OR \
           (e.envelope->'payload'->>'invite_id'=$5 AND e.envelope->'payload'->>'claim_nonce'=$6)) LIMIT 1")
        .bind::<Text,_>(event.realm_id.as_str()).bind::<Text,_>(EventKind::InviteClaim.as_str())
        .bind::<BigInt,_>(stream_position(commit)?).bind::<Text,_>(claim.token_commitment.as_str())
        .bind::<Text,_>(claim.invite_id.as_str()).bind::<Text,_>(&claim.claim_nonce)
        .get_result::<EnvelopeRow>(&mut *conn).await.optional().map_err(PersistenceError::database)?;
    if duplicates.is_some() {
        return Err(coded(
            ConflictCode::DuplicateConflict,
            "claim nonce or token was already consumed",
        ));
    }
    set_lifecycle(
        conn,
        event.realm_id.as_str(),
        &claim.invite_id,
        InviteState::Claimed,
        commit,
    )
    .await
}

fn verify_signatures(
    event: &arkret_wire::Event,
    claim: &InviteClaimPayload,
    create: &InviteThirdPartyCreatePayload,
    proof: &InviteClaimProofCommit,
) -> PersistenceResult<()> {
    let subject_method = claim.subject_proof.verification_method.as_str();
    let subject_did = arkret_identity::verification_method_did(subject_method).map_err(invalid)?;
    let fragment = subject_method
        .rsplit_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| invalid("subject method has no fragment"))?;
    if arkret_wire::DeviceId::new(fragment.to_owned()).is_ok() {
        return Err(invalid(
            "PCR device methods cannot authorize subject claims",
        ));
    }
    if let Some(control) = proof.subject_native_control.as_ref() {
        if control.principal() != &claim.subject_account_id.principal_id
            || control.method() != &claim.subject_proof.verification_method
            || control.public_key() != &proof.subject_public_key
            || proof
                .subject_control_history
                .as_ref()
                .and_then(|basis| basis.get("verified_at"))
                .and_then(Value::as_str)
                != Some(arkret_canonical::format_timestamp_canonical(proof.committed_at).as_str())
        {
            return Err(invalid(
                "native subject control differs from the exact historical cut",
            ));
        }
    } else if arkret_wire::project_did_to_core_id(&subject_did).map_err(invalid)?
        != claim.subject_account_id.principal_id
    {
        return Err(invalid("historical method belongs to another subject"));
    }
    if subject_did.method() == "key" {
        use arkret_identity::DidResolver as _;
        let document = arkret_identity::DidKeyResolver::new()
            .resolve_did_document(&subject_did)
            .map_err(invalid)?;
        let key =
            arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, subject_method)
                .map_err(invalid)?;
        if key.to_bytes() != proof.subject_public_key {
            return Err(invalid("subject historical key differs"));
        }
    } else if subject_did.method() != "webvh" {
        return Err(invalid("subject historical method is unavailable"));
    }
    let binding = &claim.binding_proof;
    let verifier_did =
        arkret_identity::verification_method_did(binding.verification_method.as_str())
            .map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&verifier_did).map_err(invalid)?
        != binding.verification_id
    {
        return Err(invalid("verifier method controller differs"));
    }
    let frozen_key = &create.third_party_invite.verification_public_key;
    if frozen_key.starts_with("did:") {
        if frozen_key != binding.verification_method.as_str()
            || !matches!(verifier_did.method(), "key" | "webvh")
        {
            return Err(invalid("binding historical method differs from create"));
        }
        if verifier_did.method() == "key" {
            use arkret_identity::DidResolver as _;
            let document = arkret_identity::DidKeyResolver::new()
                .resolve_did_document(&verifier_did)
                .map_err(invalid)?;
            let key =
                arkret_identity::jws::resolve_ed25519_pubkey_from_document(&document, frozen_key)
                    .map_err(invalid)?;
            if key.to_bytes() != proof.binding_public_key {
                return Err(invalid("binding key differs from immutable DID"));
            }
        }
    } else if arkret_canonical::decode_ed25519_multibase(frozen_key).map_err(invalid)?
        != proof.binding_public_key
    {
        return Err(invalid("binding key differs from accepted create"));
    }
    let invite_digest = arkret_canonical::canonical_sha256(&serde_json::json!({
        "invite_id":claim.invite_id,"realm_id":event.realm_id,
        "expires_at":arkret_canonical::format_timestamp_canonical(create.expires_at),
        "third_party_invite":create.third_party_invite,
    }))
    .map_err(invalid)?;
    let transcript = invite_binding_proof_transcript_bytes(
        binding,
        claim.invite_id.as_str(),
        claim.token_commitment.as_str(),
        &invite_digest,
    )
    .map_err(invalid)?;
    verify_raw(&transcript, &binding.signature, &proof.binding_public_key)?;
    let subject_body = InviteSubjectProofBody::from_wire_parts(
        claim.subject_account_id.clone(),
        claim.invite_id.as_str(),
        event.realm_id.as_str(),
        claim.token_commitment.as_str(),
        &claim.claim_nonce,
        binding.verification_id.as_str(),
        binding.canonical_digest().map_err(invalid)?.as_str(),
    )
    .map_err(invalid)?;
    if subject_body.transcript_digest().map_err(invalid)? != claim.subject_proof.transcript_digest {
        return Err(invalid("subject transcript digest differs"));
    }
    verify_raw(
        &subject_body.canonical_bytes().map_err(invalid)?,
        &claim.subject_proof.signature,
        &proof.subject_public_key,
    )
}

fn verify_raw(bytes: &[u8], signature: &str, key: &[u8; 32]) -> PersistenceResult<()> {
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        bytes,
        signature,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        },
    )
    .map_err(|_| invalid("claim signature is invalid"))
}

/// The exact accepted claim is the authority for a later third-party acceptance.
pub(super) async fn accepted_claimant(
    conn: &mut AsyncPgConnection,
    event: &arkret_wire::Event,
    commit: &arkret_wire::RealmCommit,
    invite_id: &InviteId,
) -> PersistenceResult<Option<AccountId>> {
    let claims = diesel::sql_query(
        "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk \
         WHERE e.realm_id=$1 AND e.kind=$2 AND e.state='committed' \
           AND e.envelope->'payload'->>'invite_id'=$3 AND c.stream_position<$4 \
           AND c.stream_ref->>'kind'='realm' AND c.realm_id=e.realm_id LIMIT 2",
    )
    .bind::<Text, _>(event.realm_id.as_str())
    .bind::<Text, _>(EventKind::InviteClaim.as_str())
    .bind::<Text, _>(invite_id.as_str())
    .bind::<BigInt, _>(stream_position(commit)?)
    .load::<EnvelopeRow>(&mut *conn)
    .await
    .map_err(PersistenceError::database)?;
    if claims.len() > 1 {
        return Err(corrupt("more than one accepted third-party claim"));
    }
    claims
        .into_iter()
        .next()
        .map(|row| {
            let accepted: arkret_wire::Event =
                serde_json::from_value(row.envelope).map_err(corrupt)?;
            let payload: InviteClaimPayload = typed_payload(&accepted)?;
            if accepted.actor_id.as_account_id() != Some(&payload.subject_account_id) {
                return Err(corrupt("accepted claim actor differs from subject"));
            }
            Ok(payload.subject_account_id)
        })
        .transpose()
}
