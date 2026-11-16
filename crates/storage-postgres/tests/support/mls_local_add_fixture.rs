//! Real local Add/Welcome originals at the ordinary PostgreSQL boundary.

use arkret_models_crypto::{MlsGovernanceBindingPayload, MlsKeyPackageRecord};
use coland_storage::{
    DeviceRevocationGateSelector, EventCommitRequest, EventCommitUnitOfWork, MlsGroupCurrentStore,
    MlsWelcomeClaimLedgerKey, VerifiedMlsWelcome,
};
use coland_storage_postgres::{PgEventCommitUnitOfWork, PgMlsGroupCurrentStore, PgPool};
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl;
use mls_public_fixture::MlsFixture;

use super::{
    historical_roster_attestor_resolution, mls_public_fixture, ordinary_realm, recipient_actor,
    signed_add_attestation, welcome,
};

#[allow(clippy::too_many_arguments)]
pub async fn add(
    pool: &PgPool,
    mls: &MlsFixture,
    previous: &EventCommitRequest,
    recipient: &DeviceRevocationGateSelector,
    seed: [u8; 32],
    claim_id: &str,
    revision: u64,
    original: Option<(&MlsKeyPackageRecord, &VerifiedMlsWelcome)>,
) -> (EventCommitRequest, MlsKeyPackageRecord) {
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        recipient_actor(recipient),
        arkret_wire::DeviceId::new(recipient.device_id.clone()).unwrap(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&seed),
        ),
    )
    .unwrap();
    Box::pin(add_for_identity(
        pool, mls, previous, recipient, &identity, claim_id, revision, original,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn add_for_identity(
    pool: &PgPool,
    mls: &MlsFixture,
    previous: &EventCommitRequest,
    recipient: &DeviceRevocationGateSelector,
    identity: &arkret_mls::ArkretMlsIdentity,
    claim_id: &str,
    revision: u64,
    original: Option<(&MlsKeyPackageRecord, &VerifiedMlsWelcome)>,
) -> (EventCommitRequest, MlsKeyPackageRecord) {
    let base = &previous.authority_commit.event.event_id;
    let epoch = previous.authority_commit.mls_state.as_ref().unwrap().epoch;
    let actor = recipient_actor(recipient);
    let mut package = original
        .map(|(package, _)| package.clone())
        .unwrap_or_else(|| identity.key_package_record().unwrap());
    package.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    package.claim_id = Some(claim_id.to_owned());
    let mut group = Box::pin(mls.accepted_private_group(base)).await;
    let mut tracker = mls.tracker(base);
    let binding = MlsGovernanceBindingPayload::realm(
        previous.authority_commit.event.realm_id.clone(),
        Some(base.clone()),
        epoch,
        epoch + 1,
        revision,
    )
    .unwrap();
    // Replacing the same accepted endpoint is a real Add + GCE + Remove,
    // and produces a fresh Welcome without inventing another Device key.
    let added = if group
        .member_endpoint_replacement_actor(&package.endpoint, &actor)
        .unwrap()
        .is_some()
    {
        group
            .replace_member_endpoint(&package, &actor, Some(&binding))
            .unwrap()
    } else {
        group
            .add_member_with_governance_binding(&package, &binding)
            .unwrap()
    };
    let proposals = mls_public_fixture::consume(&mut tracker, &added.commit);
    mls.register_package(&package, &proposals, &recipient.authorization_ref.event_id);
    let at = previous.authority_commit.commit.committed_at;
    let mut request = mls.transition(
        &previous.authority_commit,
        group,
        tracker,
        added.commit,
        binding,
        base,
        proposals,
        at,
    );
    let mut delivery = welcome(&request, recipient, claim_id);
    mls.seal_welcome(&mut delivery, &added.welcome);
    let leaf = request
        .authority_commit
        .mls_state
        .as_ref()
        .unwrap()
        .consumed_proposals
        .iter()
        .filter(|proposal| proposal.proposal_type == 1)
        .map(|proposal| arkret_mls::verify_add_proposal_leaf(&proposal.proposal_wire).unwrap())
        .find(|leaf| leaf.actor_id == actor)
        .unwrap();
    let mut verified = VerifiedMlsWelcome {
        delivery,
        claim: None,
        applet_device_scope_guard: None,
        roster_witness: None,
    };
    let resolution = historical_roster_attestor_resolution();
    assert_eq!(resolution.service_id, recipient.station_id);
    let current = PgMlsGroupCurrentStore { pool: pool.clone() }
        .current(&previous.authority_commit.event.scope_ref)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&current.value.current_mls_commit_event_ref, base);
    assert_eq!(current.value.epoch, epoch);
    let genesis = current.value.genesis_event_ref;
    let original_claim = original.map(|(_, original)| {
        let proof: arkret_models_collaboration::mls_roster_authority::MlsAttestAddRequestBody =
            serde_json::from_slice(
                &original
                    .roster_witness
                    .as_ref()
                    .unwrap()
                    .signed_attest_add_request_canonical_json,
            )
            .unwrap();
        proof.claim_outcome
    });
    let proof = signed_add_attestation(
        &request,
        &genesis,
        &verified,
        &package,
        &resolution.service_id,
        leaf.leaf_signature_key,
        recipient.authorization_ref.event_id.clone(),
        original_claim,
    );
    let receipt = &proof.claim_outcome.claim_receipt;
    let key = MlsWelcomeClaimLedgerKey {
        source_id: receipt.source_id.to_string(),
        claim_request_id: receipt.claim_request_id.to_string(),
        request_digest: receipt.request_digest.to_string(),
    };
    let outcome = serde_json::to_value(&proof.claim_outcome).unwrap();
    let mut conn = pool.get().await.unwrap();
    if let Some((_, original)) = original {
        assert_eq!(original.claim.as_ref(), Some(&key));
        // The reused claim retains the exact first signed record, including
        // its KeyPackage. The new transition changes only its consuming unit.
        #[derive(diesel::QueryableByName)]
        struct Outcome {
            #[diesel(sql_type = Jsonb)]
            outcome: serde_json::Value,
        }
        let stored = diesel::sql_query(
            "SELECT outcome FROM peer_keypackage_claims \
             WHERE source_id=$1 AND claim_request_id=$2 AND request_digest=$3",
        )
        .bind::<Text, _>(&key.source_id)
        .bind::<Text, _>(&key.claim_request_id)
        .bind::<Text, _>(&key.request_digest)
        .get_result::<Outcome>(&mut *conn)
        .await
        .unwrap();
        assert_eq!(stored.outcome, outcome);
    } else {
        // Trusted claim-service port: persist the complete genuinely signed
        // outcome which the production unit independently reads and verifies.
        diesel::sql_query(
            "INSERT INTO peer_keypackage_claims \
             (source_id,claim_request_id,request_digest,key_package_use,keypackage_id,outcome, \
              terminal_receipt,consume_receipt,claim_expires_at_unix_ms,expires_at,state,updated_at) \
             VALUES ($1,$2,$3,'single_use',NULL,$4,NULL,NULL,$5,$6,'claimed',$7)",
        )
        .bind::<Text, _>(&key.source_id)
        .bind::<Text, _>(&key.claim_request_id)
        .bind::<Text, _>(&key.request_digest)
        .bind::<Jsonb, _>(&outcome)
        .bind::<BigInt, _>(receipt.expires_at.timestamp_millis())
        .bind::<BigInt, _>(receipt.expires_at.timestamp())
        .bind::<BigInt, _>(at.timestamp())
        .execute(&mut *conn)
        .await
        .unwrap();
    }
    verified.claim = Some(key);
    verified.roster_witness = Some(coland_storage::VerifiedMlsRecipientRosterWitness {
        claim_issuer_resolution: None,
        accepted_genesis_event_ref: genesis,
        signed_attest_add_request_canonical_json: arkret_canonical::canonical_json_bytes(&proof)
            .unwrap(),
        local_attestor_resolution: Some(resolution),
    });
    request.authority_commit.welcomes = vec![verified];
    request.authority_commit.recipient_queue_capacity = 10;
    (request, package)
}

pub async fn left_member_commit(pool: &PgPool) -> EventCommitRequest {
    let discussion = Box::pin(ordinary_realm::open_discussion(
        pool,
        "mls-left-business-member",
    ))
    .await;
    let at = discussion.committed_at();
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let realm = discussion.realm_id();
    let mls = MlsFixture::new(pool.clone(), &discussion.head.authority_commit);
    let genesis = mls.with_installation(
        ordinary_realm::next_request(
            &discussion.head.authority_commit,
            arkret_wire::EventKind::MlsGenesis,
            founder.signing_principal_id(),
            mls.genesis_payload(&realm, at),
            at,
        ),
        None,
        0,
    );
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    Box::pin(uow.commit_event(genesis.clone())).await.unwrap();
    let leave = ordinary_realm::next_request(
        &genesis.authority_commit,
        arkret_wire::EventKind::MemberState,
        founder.signing_principal_id(),
        serde_json::json!({"member_id": founder, "membership": "leave"}),
        at,
    );
    let leave = Box::pin(ordinary_realm::source_request(pool, leave)).await;
    Box::pin(uow.commit_event(leave.clone())).await.unwrap();
    let current = PgMlsGroupCurrentStore { pool: pool.clone() }
        .current(&genesis.authority_commit.event.scope_ref)
        .await
        .unwrap()
        .unwrap();
    let base = &genesis.authority_commit.event.event_id;
    assert_eq!(current.value.current_mls_commit_event_ref, *base);
    assert_eq!(current.value.epoch, 0);
    assert!(current.value.current_key_access_revision > 0);
    assert_eq!(mls.tracker(base).leaves().unwrap()[0].actor_id, founder);
    let payload =
        Box::pin(mls.commit_payload(&realm, base, 0, current.value.current_key_access_revision))
            .await;
    let next = mls.with_installation(
        ordinary_realm::next_request(
            &leave.authority_commit,
            arkret_wire::EventKind::MlsCommit,
            founder.signing_principal_id(),
            payload,
            at,
        ),
        Some((base, 0)),
        1,
    );
    Box::pin(ordinary_realm::source_request(pool, next)).await
}
