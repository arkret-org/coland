//! Included by ordinary_realm_bootstrap_unit to reuse its accepted bootstrap harness.
use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteClaimPayload, InviteSubjectProof, InviteSubjectProofBody,
    invite_binding_proof_transcript_bytes,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer as _, SigningKey};

use super::*;

async fn member_snapshot(
    pool: &coland_storage_postgres::PgPool,
    realm: &arkret_wire::RealmId,
) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT COALESCE(jsonb_agg(to_jsonb(m) ORDER BY m.member_id),'[]'::jsonb) AS value FROM member_state_current_results m WHERE realm_id=$1")
        .bind::<Text, _>(realm.as_str()).get_result::<Snapshot>(&mut *conn).await.unwrap().value
}

fn did_key(key: &SigningKey) -> (arkret_wire::Did, arkret_wire::DidUrl) {
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    (
        arkret_wire::Did::new(format!("did:key:{multibase}")).unwrap(),
        arkret_wire::DidUrl::new(format!("did:key:{multibase}#{multibase}")).unwrap(),
    )
}
fn sign(key: &SigningKey, bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(bytes).to_bytes())
}
fn claim_request(
    previous: &EventCommitRequest,
    create: &EventCommitRequest,
    subject: &arkret_wire::AccountId,
    subject_key: &SigningKey,
    verifier_key: &SigningKey,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> (EventCommitRequest, coland_storage::InviteClaimProofCommit) {
    let material:arkret_models_collaboration::governance::membership_invite::InviteThirdPartyCreatePayload=serde_json::from_value(serde_json::to_value(&create.authority_commit.event.payload).unwrap()).unwrap();
    let invite_id = arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id);
    let token = material
        .third_party_invite
        .token_commitment
        .clone()
        .unwrap();
    let (_, verifier_method) = did_key(verifier_key);
    let (_, subject_method) = did_key(subject_key);
    let digest=arkret_canonical::canonical_sha256(&serde_json::json!({"invite_id":invite_id,"realm_id":create.authority_commit.event.realm_id,"expires_at":arkret_canonical::format_timestamp_canonical(material.expires_at),"third_party_invite":material.third_party_invite})).unwrap();
    let nonce = "claim-admission-nonce-2162";
    let mut binding = InviteClaimBindingProof::new(
        material.third_party_invite.verification_id.clone(),
        subject.clone(),
        create.authority_commit.event.realm_id.clone(),
        nonce,
        arkret_canonical::format_timestamp_canonical(material.expires_at),
        verifier_method,
        "placeholder",
    );
    binding.signature = sign(
        verifier_key,
        &invite_binding_proof_transcript_bytes(
            &binding,
            invite_id.as_str(),
            token.as_str(),
            &digest,
        )
        .unwrap(),
    );
    let body = InviteSubjectProofBody::from_wire_parts(
        subject.clone(),
        invite_id.as_str(),
        create.authority_commit.event.realm_id.as_str(),
        token.as_str(),
        nonce,
        binding.verification_id.as_str(),
        binding.canonical_digest().unwrap().as_str(),
    )
    .unwrap();
    let payload = InviteClaimPayload {
        invite_id,
        subject_account_id: subject.clone(),
        token_commitment: token,
        claim_nonce: nonce.to_owned(),
        subject_proof: InviteSubjectProof::new(
            subject_method,
            body.transcript_digest().unwrap(),
            sign(subject_key, &body.canonical_bytes().unwrap()),
        ),
        binding_proof: binding,
        extensions: Default::default(),
    };
    let mut payload = serde_json::to_value(payload).unwrap();
    mutate(&mut payload);
    let request = realm_event_request_as(
        previous,
        subject,
        arkret_wire::EventKind::InviteClaim,
        payload,
    );
    let proof = coland_storage::InviteClaimProofCommit {
        event_id: request.authority_commit.event.event_id.clone(),
        event_digest: request.event.canonical_digest.clone(),
        committed_at: request.authority_commit.commit.committed_at,
        create_ref: arkret_wire::CommittedEventRef {
            event_id: create.authority_commit.event.event_id.clone(),
            commit_id: create.authority_commit.commit.commit_id.clone(),
            stream_ref: create.authority_commit.commit.stream_ref.clone(),
            stream_position: create.authority_commit.commit.stream_position,
        },
        subject_public_key: subject_key.verifying_key().to_bytes(),
        subject_native_control: None,
        subject_control_history: None,
        binding_public_key: verifier_key.verifying_key().to_bytes(),
    };
    (request, proof)
}
fn claim_batch(
    request: EventCommitRequest,
    proof: Option<coland_storage::InviteClaimProofCommit>,
) -> coland_storage::EventBatchCommitRequest {
    coland_storage::EventBatchCommitRequest {
        audit_unit: None,
        events: vec![request],
        invite_claim_proof: proof,
        event_approvals: None,
        realm_organization_proof: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

#[tokio::test]
async fn native_subject_claim_binds_prepared_history_to_the_exact_commit_time() {
    use arkret_identity::principal_control::{
        DirectIdentityControlPurpose, native_identity_control_key_from_verified_selection,
    };
    use arkret_signatures::webvh::{
        PrincipalInceptionInput, PrincipalRotationInput, prepare_principal_inception,
        prepare_principal_rotation,
    };
    use coland_storage::DeliveryPolicyStoreRegistry as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let creator = creator_account(&unit);
    let subject_key = SigningKey::from_bytes(&[0x25; 32]);
    let successor_key = SigningKey::from_bytes(&[0x26; 32]);
    let successor_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        successor_key.verifying_key().as_bytes(),
    );
    let endpoint = "https://native-claim-subject.example/".parse().unwrap();
    let inception = prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id: "native-claim-subject",
        also_known_as: &[],
        version_time: at - chrono::TimeDelta::hours(1),
        root_seed: &subject_key.to_bytes(),
        next_root_public_key_multibase: &successor_public,
        witness_policy: None,
    })
    .unwrap();
    let did = arkret_wire::Did::new(&inception.did).unwrap();
    let subject = arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&did).unwrap(),
        creator.station_id.clone(),
    );
    let verifier_key = SigningKey::from_bytes(&[0x64; 32]);
    let verifier = arkret_wire::project_did_to_core_id(&did_key(&verifier_key).0).unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let policy = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":2,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[verifier]}),
    );
    uow.commit_event(policy.clone()).await.unwrap();
    let create = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        serde_json::json!({"third_party_invite":{"oob_code_kind":"offline_token","token_commitment":format!("sha256:{}","d".repeat(64)),"token_salt_id":"native-claim-cut-salt","token_entropy_bits":128,"max_claims":1,"verification_id":verifier,"verification_public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(verifier_key.verifying_key().as_bytes())},"expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::hours(12))}),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let (request, mut proof) = claim_request(
        &create,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |_| {},
    );
    let history = arkret_identity::verify_did_webvh_v1_chain(
        &did,
        std::slice::from_ref(&inception.log_entry),
    )
    .unwrap();
    let selected =
        coland_services::identity::select_did_webvh_state_at(&did, &history, proof.committed_at)
            .unwrap();
    proof.subject_native_control = Some(
        native_identity_control_key_from_verified_selection(
            &selected.did,
            &subject.principal_id,
            &selected.update_keys,
            &did_key(&subject_key).1,
            DirectIdentityControlPurpose::InviteClaimSubject,
        )
        .unwrap(),
    );
    proof.subject_control_history = Some(serde_json::json!({
        "did": selected.did, "version_id": selected.version_id,
        "log_head_digest": selected.log_head_digest, "update_keys": selected.update_keys,
        "verified_at": arkret_canonical::format_timestamp_canonical(proof.committed_at),
    }));
    let realm = &create.authority_commit.event.realm_id;
    let before = invite_families(&pool, realm).await;
    let members = member_snapshot(&pool, realm).await;
    for case in [
        "missing_native_control",
        "missing_history",
        "wrong_history_time",
    ] {
        let mut invalid_proof = proof.clone();
        match case {
            "missing_native_control" => invalid_proof.subject_native_control = None,
            "missing_history" => invalid_proof.subject_control_history = None,
            "wrong_history_time" => {
                invalid_proof.subject_control_history.as_mut().unwrap()["verified_at"] =
                    serde_json::json!(arkret_canonical::format_timestamp_canonical(
                        at + chrono::TimeDelta::seconds(1)
                    ))
            }
            _ => unreachable!(),
        }
        let error = uow
            .commit_event_batch(claim_batch(request.clone(), Some(invalid_proof)))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("claim_invalid"),
            "{case}: {error}"
        );
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0,
            "{case}"
        );
        assert_eq!(invite_families(&pool, realm).await, before, "{case}");
        assert_eq!(member_snapshot(&pool, realm).await, members, "{case}");
    }
    // A genuine successor effective after the pinned cut must not replace
    // the historical root prepared for this candidate.
    let next_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&[0x27; 32])
            .verifying_key()
            .as_bytes(),
    );
    let rotation = prepare_principal_rotation(&PrincipalRotationInput {
        did: did.as_str(),
        local_id: &inception.local_id,
        previous_entries: std::slice::from_ref(&inception.log_entry),
        version_time: proof.committed_at + chrono::TimeDelta::seconds(1),
        current_root_seed: &successor_key.to_bytes(),
        next_root_public_key_multibase: &next_public,
        state: &inception.log_entry["state"],
    })
    .unwrap();
    let persistence = coland_storage_postgres::PgPersistenceStore::new(pool.clone());
    for (index, entry) in [inception.log_entry, rotation.log_entry]
        .into_iter()
        .enumerate()
    {
        persistence
            .webvh()
            .append_log_event(coland_storage::WebvhLogRecord {
                event_digest: arkret_canonical::canonical_sha256(&entry).unwrap(),
                did: did.to_string(),
                seq: index as u64 + 1,
                created_at: entry["versionTime"].as_str().unwrap().parse().unwrap(),
                operation: entry,
            })
            .await
            .unwrap();
    }
    uow.commit_event_batch(claim_batch(request.clone(), Some(proof)))
        .await
        .unwrap();
    assert_eq!(
        event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
        1
    );
    assert_eq!(member_snapshot(&pool, realm).await, members);
    let invites = PgInviteCurrentResultStore { pool: pool.clone() }
        .invites_in_realm(Some(realm))
        .await
        .unwrap();
    assert_eq!(invites[0].state, arkret_wire::InviteState::Claimed);
    assert_eq!(
        invites[0]
            .accepted_claim
            .as_ref()
            .unwrap()
            .subject_account_id,
        subject
    );
}

#[tokio::test]
async fn prepared_claim_racing_verifier_withdrawal_preserves_the_accepting_cut() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    PgAuthorityCommitStore { pool: pool.clone() }
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let creator = creator_account(&unit);
    let subject_key = SigningKey::from_bytes(&[0x24; 32]);
    let verifier_key = SigningKey::from_bytes(&[0x63; 32]);
    let subject = arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&did_key(&subject_key).0).unwrap(),
        creator.station_id.clone(),
    );
    let verifier = arkret_wire::project_did_to_core_id(&did_key(&verifier_key).0).unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let policy = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":2,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[verifier]}),
    );
    uow.commit_event(policy.clone()).await.unwrap();
    let create = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        serde_json::json!({"third_party_invite":{"oob_code_kind":"offline_token","token_commitment":format!("sha256:{}","c".repeat(64)),"token_salt_id":"salt-claim-policy-race","token_entropy_bits":128,"max_claims":1,"verification_id":verifier,"verification_public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(verifier_key.verifying_key().as_bytes())},"expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::hours(12))}),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let realm = &create.authority_commit.event.realm_id;
    let members_before = member_snapshot(&pool, realm).await;
    let (claim, proof) = claim_request(
        &create,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |_| {},
    );
    let withdraw = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":3,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[]}),
    );
    let (claimed, withdrawn) = tokio::join!(
        uow.commit_event_batch(claim_batch(claim.clone(), Some(proof))),
        uow.commit_event(withdraw.clone()),
    );
    let loser = match (&claimed, &withdrawn) {
        (Ok(_), Err(error)) | (Err(error), Ok(_)) => error,
        _ => panic!("exactly one cut must win: {claimed:?} {withdrawn:?}"),
    };
    assert_eq!(
        loser.conflict_code(),
        Some(coland_storage::ConflictCode::TemporarilyUnavailable)
    );
    if claimed.is_ok() {
        assert_eq!(
            event_row_count(&pool, withdraw.authority_commit.event.event_id.as_str()).await,
            0
        );
        let committed_withdraw = realm_event_request_as(
            &claim,
            &creator,
            arkret_wire::EventKind::RealmPolicyBundle,
            serde_json::to_value(&withdraw.authority_commit.event.payload).unwrap(),
        );
        let committed_withdraw = source_if_human(&pool, committed_withdraw).await;
        uow.commit_event(committed_withdraw).await.unwrap();
        let before_retry = invite_families(&pool, realm).await;
        uow.commit_event_batch(claim_batch(claim.clone(), None))
            .await
            .unwrap();
        assert_eq!(invite_families(&pool, realm).await, before_retry);
        assert_eq!(
            event_row_count(&pool, claim.authority_commit.event.event_id.as_str()).await,
            1
        );
    } else {
        assert_eq!(
            event_row_count(&pool, claim.authority_commit.event.event_id.as_str()).await,
            0
        );
        let (after, proof) = claim_request(
            &withdraw,
            &create,
            &subject,
            &subject_key,
            &verifier_key,
            |_| {},
        );
        let before_reject = invite_families(&pool, realm).await;
        let error = uow
            .commit_event_batch(claim_batch(after.clone(), Some(proof)))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("claim_invalid"), "{error}");
        assert_eq!(
            event_row_count(&pool, after.authority_commit.event.event_id.as_str()).await,
            0
        );
        assert_eq!(invite_families(&pool, realm).await, before_reject);
    }
    assert_eq!(member_snapshot(&pool, realm).await, members_before);
}

#[tokio::test]
async fn third_party_claim_verifies_signatures_at_cut_and_accepts_exact_claimant() {
    ordinary_realm::case_future(third_party_claim_case).await;
}

async fn third_party_claim_case() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    human_profile::admit(
        &pool,
        &arkret_wire::DidCoreId::new("ak:did_core:web:bootstrap-station.example").unwrap(),
        "bootstrap-actor",
    )
    .await;
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let unit = unit(&pool).await;
    let at = unit.transactions[0].commit.committed_at;
    store
        .admit_ordinary_realm_bootstrap_unit(&unit, at)
        .await
        .unwrap();
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let creator = creator_account(&unit);
    let subject_key = SigningKey::from_bytes(&[0x21; 32]);
    let verifier_key = SigningKey::from_bytes(&[0x62; 32]);
    let (subject_did, _) = did_key(&subject_key);
    let (verifier_did, _) = did_key(&verifier_key);
    let subject = arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&subject_did).unwrap(),
        creator.station_id.clone(),
    );
    let verifier = arkret_wire::project_did_to_core_id(&verifier_did).unwrap();
    let policy = realm_event_request_as(
        &bootstrap_tail(&unit),
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":2,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[verifier]}),
    );
    uow.commit_event(policy.clone()).await.unwrap();
    let create = realm_event_request_as(
        &policy,
        &creator,
        arkret_wire::EventKind::InviteThirdParty,
        serde_json::json!({"third_party_invite":{"oob_code_kind":"offline_token","token_commitment":format!("sha256:{}","a".repeat(64)),"token_salt_id":"salt-2162","token_entropy_bits":128,"max_claims":1,"verification_id":verifier,"verification_public_key":arkret_canonical::ed25519_pubkey_to_did_key_multibase(verifier_key.verifying_key().as_bytes())},"expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::hours(12))}),
    );
    uow.commit_event(create.clone()).await.unwrap();
    let realm = &create.authority_commit.event.realm_id;
    let before = invite_families(&pool, realm).await;
    let member_before = member_snapshot(&pool, realm).await;
    for case in [
        "missing_evidence",
        "binding_signature",
        "subject_signature",
        "pcr_device",
        "subject_key",
        "binding_key",
        "event_digest",
        "proof_cut",
        "create_ref",
        "token",
        "nonce",
    ] {
        let (request, mut proof) = claim_request(
            &create,
            &create,
            &subject,
            &subject_key,
            &verifier_key,
            |payload| match case {
                "binding_signature" => {
                    payload["binding_proof"]["signature"] =
                        serde_json::json!(URL_SAFE_NO_PAD.encode([0u8; 64]))
                }
                "subject_signature" => {
                    payload["subject_proof"]["signature"] =
                        serde_json::json!(URL_SAFE_NO_PAD.encode([0u8; 64]))
                }
                "pcr_device" => {
                    payload["subject_proof"]["verification_method"] = serde_json::json!(format!(
                        "{}#ak:device:01904100-0000-7000-8000-000000002162",
                        subject_did
                    ))
                }
                "token" => {
                    payload["token_commitment"] =
                        serde_json::json!(format!("sha256:{}", "b".repeat(64)))
                }
                "nonce" => {
                    payload["claim_nonce"] = serde_json::json!("claim-admission-other-nonce");
                    payload["binding_proof"]["claim_nonce"] =
                        serde_json::json!("claim-admission-other-nonce");
                }
                _ => (),
            },
        );
        match case {
            "subject_key" => proof.subject_public_key = [0u8; 32],
            "binding_key" => proof.binding_public_key = [0u8; 32],
            "event_digest" => {
                proof.event_digest = format!("sha256:{}", "0".repeat(64));
            }
            "proof_cut" => proof.committed_at += chrono::TimeDelta::seconds(1),
            "create_ref" => proof.create_ref.stream_position += 1,
            _ => (),
        }
        let evidence = if case == "missing_evidence" {
            None
        } else {
            Some(proof)
        };
        let error = uow
            .commit_event_batch(claim_batch(request.clone(), evidence))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("claim_invalid"),
            "{case}: {error}"
        );
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0,
            "{case}"
        );
        assert_eq!(invite_families(&pool, realm).await, before, "{case}");
        assert_eq!(member_snapshot(&pool, realm).await, member_before, "{case}");
    }
    // Exercise the cut inputs directly: membership and root controller are
    // current-result authority, so neither can be inherited from the create.
    for loss in ["inviter_left", "capability_loss"] {
        let mut conn = pool.get().await.unwrap();
        if loss == "inviter_left" {
            assert_eq!(diesel::sql_query("UPDATE member_state_current_results SET membership='leave', value='{\"membership\":\"leave\"}'::jsonb WHERE realm_id=$1 AND member_id=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(arkret_wire::ActorId::account(creator.clone()).to_string())
                .execute(&mut conn).await.unwrap(), 1, "authority cut fixture must change one exact Actor row");
        } else {
            assert_eq!(diesel::sql_query("UPDATE realm_authority_root_current_results SET controller_actor_id=$2 WHERE realm_id=$1")
                .bind::<Text,_>(realm.as_str()).bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(arkret_wire::ActorId::account(subject.clone())).unwrap())
                .execute(&mut conn).await.unwrap(), 1, "authority cut fixture must change one exact Actor row");
        }
        drop(conn);
        let membership_at_cut = member_snapshot(&pool, realm).await;
        let (request, proof) = claim_request(
            &create,
            &create,
            &subject,
            &subject_key,
            &verifier_key,
            |_| {},
        );
        let error = uow
            .commit_event_batch(claim_batch(request.clone(), Some(proof)))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("claim_invalid"),
            "{loss}: {error}"
        );
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0,
            "{loss}"
        );
        assert_eq!(invite_families(&pool, realm).await, before, "{loss}");
        assert_eq!(
            member_snapshot(&pool, realm).await,
            membership_at_cut,
            "{loss}"
        );
        let mut conn = pool.get().await.unwrap();
        if loss == "inviter_left" {
            assert_eq!(diesel::sql_query("UPDATE member_state_current_results SET membership='join', value='{\"membership\":\"join\"}'::jsonb WHERE realm_id=$1 AND member_id=$2")
                .bind::<Text,_>(realm.as_str()).bind::<Text,_>(arkret_wire::ActorId::account(creator.clone()).to_string())
                .execute(&mut conn).await.unwrap(), 1, "authority cut fixture must change one exact Actor row");
        } else {
            assert_eq!(diesel::sql_query("UPDATE realm_authority_root_current_results SET controller_actor_id=$2 WHERE realm_id=$1")
                .bind::<Text,_>(realm.as_str()).bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(arkret_wire::ActorId::account(creator.clone())).unwrap())
                .execute(&mut conn).await.unwrap(), 1, "authority cut fixture must change one exact Actor row");
        }
    }
    // Expiry cannot be bypassed by a backdated or delayed claim, and never expires the Invite
    // implicitly.
    let mut delayed = create.clone();
    delayed.authority_commit.commit.committed_at += chrono::TimeDelta::hours(13);
    let (expired, proof) = claim_request(
        &delayed,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |_| {},
    );
    let error = uow
        .commit_event_batch(claim_batch(expired.clone(), Some(proof)))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("expired_invite_token"),
        "{error}"
    );
    assert_eq!(
        event_row_count(&pool, expired.authority_commit.event.event_id.as_str()).await,
        0
    );
    assert_eq!(invite_families(&pool, realm).await, before);
    // A verifier authorized when the create was accepted can be removed before the claim cut.
    let deny = realm_event_request_as(
        &create,
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":3,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[]}),
    );
    uow.commit_event(deny.clone()).await.unwrap();
    let (denied, proof) = claim_request(
        &deny,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |_| {},
    );
    let before_denied = invite_families(&pool, realm).await;
    let error = uow
        .commit_event_batch(claim_batch(denied.clone(), Some(proof)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("claim_invalid"), "{error}");
    assert_eq!(
        event_row_count(&pool, denied.authority_commit.event.event_id.as_str()).await,
        0
    );
    assert_eq!(invite_families(&pool, realm).await, before_denied);
    let restored = realm_event_request_as(
        &deny,
        &creator,
        arkret_wire::EventKind::RealmPolicyBundle,
        serde_json::json!({"policy_revision":4,"federation_policy":"closed","allowed_third_party_invite_verification_ids":[verifier]}),
    );
    uow.commit_event(restored.clone()).await.unwrap();
    let (request, proof) = claim_request(
        &restored,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |_| {},
    );
    // Two valid claims race against the same predecessor: the authority cut admits exactly one.
    let rival_key = SigningKey::from_bytes(&[0x23; 32]);
    let (rival_did, _) = did_key(&rival_key);
    let rival_subject = arkret_wire::AccountId::new(
        arkret_wire::project_did_to_core_id(&rival_did).unwrap(),
        creator.station_id.clone(),
    );
    let (rival, rival_proof) = claim_request(
        &restored,
        &create,
        &rival_subject,
        &rival_key,
        &verifier_key,
        |_| {},
    );
    let (first, second) = tokio::join!(
        uow.commit_event_batch(claim_batch(request.clone(), Some(proof.clone()))),
        uow.commit_event_batch(claim_batch(rival.clone(), Some(rival_proof.clone())))
    );
    assert_ne!(
        first.is_ok(),
        second.is_ok(),
        "one concurrent claim must win: {first:?} {second:?}"
    );
    let (request, subject, subject_key) = if first.is_ok() {
        assert_eq!(
            event_row_count(&pool, rival.authority_commit.event.event_id.as_str()).await,
            0
        );
        (request, subject, subject_key)
    } else {
        assert_eq!(
            event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
            0
        );
        (rival, rival_subject, rival_key)
    };
    assert_eq!(
        member_snapshot(&pool, realm).await,
        member_before,
        "accepted claim is a proposal and cannot write membership"
    );
    // Exact replay returns the stored effect; evidence is not fetched anew.
    let accepted_state = invite_families(&pool, realm).await;
    uow.commit_event_batch(claim_batch(request.clone(), None))
        .await
        .unwrap();
    assert_eq!(invite_families(&pool, realm).await, accepted_state);
    assert_eq!(
        event_row_count(&pool, request.authority_commit.event.event_id.as_str()).await,
        1,
        "exact retry must not create another canonical Event"
    );
    let (reused, reused_proof) = claim_request(
        &request,
        &create,
        &subject,
        &subject_key,
        &verifier_key,
        |payload| {
            payload["claim_nonce"] = serde_json::json!("claim-admission-reused-nonce");
            payload["binding_proof"]["claim_nonce"] =
                serde_json::json!("claim-admission-reused-nonce");
        },
    );
    let before_reused = invite_families(&pool, realm).await;
    let error = uow
        .commit_event_batch(claim_batch(reused.clone(), Some(reused_proof)))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"), "{error}");
    assert_eq!(
        event_row_count(&pool, reused.authority_commit.event.event_id.as_str()).await,
        0
    );
    assert_eq!(invite_families(&pool, realm).await, before_reused);
    let current = PgInviteCurrentResultStore { pool: pool.clone() }
        .invites_in_realm(Some(realm))
        .await
        .unwrap();
    assert_eq!(current[0].state, arkret_wire::InviteState::Claimed);
    assert_eq!(
        current[0]
            .accepted_claim
            .as_ref()
            .unwrap()
            .subject_account_id,
        subject
    );
    assert!(current[0].invitee_account_id.is_none());
    let wrong = invite_account("wrong-claimant.example", "bootstrap-station.example");
    let accept_payload = serde_json::json!({"invite_id":arkret_wire::InviteId::from_event_id(&create.authority_commit.event.event_id),"previous_state":"claimed"});
    let denied = realm_event_request_as(
        &request,
        &wrong,
        arkret_wire::EventKind::InviteAccept,
        accept_payload.clone(),
    );
    let saved = invite_families(&pool, realm).await;
    assert!(uow.commit_event(denied.clone()).await.is_err());
    assert_eq!(invite_families(&pool, realm).await, saved);
    assert_eq!(
        event_row_count(&pool, denied.authority_commit.event.event_id.as_str()).await,
        0
    );
    let accept = realm_event_request_as(
        &request,
        &subject,
        arkret_wire::EventKind::InviteAccept,
        accept_payload,
    );
    uow.commit_event(accept).await.unwrap();
    assert_eq!(
        PgInviteCurrentResultStore { pool: pool.clone() }
            .invites_in_realm(Some(realm))
            .await
            .unwrap()[0]
            .state,
        arkret_wire::InviteState::Accepted
    );
}
