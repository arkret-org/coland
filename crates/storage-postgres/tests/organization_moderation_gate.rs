#[path = "support/ordinary_realm.rs"]
#[expect(
    dead_code,
    reason = "Each integration binary uses only its subset of the shared Realm fixture."
)]
mod ordinary_realm;

use arkret_models_collaboration::{RealmOrganizationPayload, SignatureMaterial};
use base64::Engine as _;
use coland_storage::{
    AuthorityCommitStore, EventCommitUnitOfWork, RealmOrganizationStatementStore,
};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{
    PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool, PgRealmOrganizationStatementStore,
};
use diesel_async::RunQueryDsl;
use ed25519_dalek::Signer as _;

fn organization_request(
    previous: &coland_storage::AuthorityCommitTransaction,
    status: &str,
    scopes: serde_json::Value,
    reference: Option<&str>,
) -> (
    coland_storage::EventCommitRequest,
    coland_storage::RealmOrganizationProofCommit,
) {
    let at = previous.commit.committed_at;
    let key = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let did: arkret_wire::Did = format!("did:key:{multibase}").parse().unwrap();
    let core = arkret_wire::project_did_to_core_id(&did).unwrap();
    let method = arkret_wire::DidUrl::new(format!("{did}#{multibase}")).unwrap();
    let mut raw = serde_json::json!({
        "statement_id":uuid::Uuid::now_v7().to_string(), "realm_id":previous.event.realm_id,
        "organization_id":core,"relationship":"governance","status":status,
        "control_scopes":scopes,"issued_at":arkret_canonical::format_timestamp_canonical(at),
        "authorization":{"issuer_id":core,"issuer_role":"organization","verification_method":method,
            "signed_at":arkret_canonical::format_timestamp_canonical(at),"proof":"placeholder"}
    });
    if let Some(reference) = reference {
        raw[if status == "revoked" {
            "revokes_statement_id"
        } else {
            "supersedes_statement_id"
        }] = reference.into();
    }
    let mut payload: RealmOrganizationPayload = serde_json::from_value(raw).unwrap();
    let bytes =
        arkret_models_collaboration::realm_organization_statement_signing_bytes(&payload).unwrap();
    payload.authorization.proof = SignatureMaterial::NonEmptyString(
        arkret_wire::NonEmptyString::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes()),
        )
        .unwrap(),
    );
    let request = ordinary_realm::next_request_for_actor(
        previous,
        arkret_wire::EventKind::RealmOrganization,
        previous.event.actor_id.clone(),
        serde_json::to_value(payload).unwrap(),
        at,
    );
    let proof = coland_storage::RealmOrganizationProofCommit {
        event_id: request.authority_commit.event.event_id.clone(),
        verification_method: method,
        signed_at: at,
        public_key: key.verifying_key().to_bytes(),
    };
    (request, proof)
}

fn batch(
    request: coland_storage::EventCommitRequest,
    proof: coland_storage::RealmOrganizationProofCommit,
) -> coland_storage::EventBatchCommitRequest {
    coland_storage::EventBatchCommitRequest {
        events: vec![request],
        realm_organization_proof: Some(proof),
        invite_claim_proof: None,
        event_approvals: None,
        franking_replay_nonce: None,
        applet_record: None,
        applet_authoring_preview: None,
        agent_membership_cascade: None,
    }
}

async fn snapshot(pool: &PgPool) -> serde_json::Value {
    #[derive(diesel::QueryableByName)]
    struct Snapshot {
        #[diesel(sql_type=diesel::sql_types::Jsonb)]
        value: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object( \
        'events',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM canonical_events r), \
        'commits',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_commits r), \
        'authority',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_authorities r), \
        'relationships',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM realm_organization_current_results r), \
        'members',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM member_state_current_results r), \
        'invites',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM invite_lifecycle_current_results r), \
        'outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM federation_outbox r), \
        'event_outbox',(SELECT jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM event_federation_outbox r)) AS value")
        .get_result::<Snapshot>(&mut *conn).await.unwrap().value
}
// Human source and final Station proofs use the actual accepted PCR cut;
// the independent organization consent is an immutable-DID Ed25519 signature.
#[tokio::test]
async fn accepted_organization_scope_refuses_real_member_and_invite_join_with_zero_writes() {
    organization_scope_scenario().await;
}

#[inline(never)]
fn organization_scope_scenario() -> std::pin::Pin<Box<impl std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let station = ordinary_realm::station();
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let founder_account = scenario_future(|| {
            ordinary_realm::human_profile::admit(&pool, &station, "organization-founder")
        })
        .await;
        let bootstrap = ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            &founder_account,
            &ordinary_realm::human_profile::station_did(&station),
        );
        let bootstrap =
            scenario_future(|| ordinary_realm::source_bootstrap(&pool, bootstrap)).await;
        let authority = PgAuthorityCommitStore { pool: pool.clone() };
        let at = bootstrap.transactions[0].commit.committed_at;
        authority
            .admit_ordinary_realm_bootstrap_unit(&bootstrap, at)
            .await
            .unwrap();
        let head = bootstrap.transactions.last().unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let events = PgAuthorityCommitStore { pool: pool.clone() };
        let founder = head.event.actor_id.clone();
        let invitee = scenario_future(|| {
            ordinary_realm::human_profile::admit(&pool, &station, "organization-invitee")
        })
        .await;
        let invite = ordinary_realm::next_request_for_actor(
            head,
            arkret_wire::EventKind::InviteCreate,
            founder.clone(),
            serde_json::json!({"invitee_account_id":invitee,
            "introduction_evidence_digest":format!("sha256:{}","a".repeat(64)),
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::TimeDelta::days(1))}),
            at,
        );
        let invite = scenario_future(|| ordinary_realm::source_request(&pool, invite)).await;
        uow.commit_event(invite.clone()).await.unwrap();
        let (relationship, proof) = organization_request(
            &invite.authority_commit,
            "active",
            serde_json::json!(["moderation_policy"]),
            None,
        );
        let relationship =
            scenario_future(|| ordinary_realm::source_request(&pool, relationship)).await;
        let proof = coland_storage::RealmOrganizationProofCommit {
            event_id: relationship.authority_commit.event.event_id.clone(),
            ..proof
        };
        uow.commit_event_batch(batch(relationship.clone(), proof))
            .await
            .unwrap();
        let relationships = PgRealmOrganizationStatementStore { pool: pool.clone() };
        let list = relationships
            .accepted_relationships(&head.event.realm_id, at)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].lifecycle_phase,
        arkret_models_collaboration::governance::realm_governance::RealmOrganizationLifecyclePhase::VerifiedActive);
        let accepted = events
            .committed_event(&relationship.authority_commit.event.event_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.event, relationship.authority_commit.event);
        let statement = relationship.authority_commit.event.payload["statement_id"]
            .as_str()
            .unwrap();
        let joiner = scenario_future(|| {
            ordinary_realm::human_profile::admit(&pool, &station, "organization-public-joiner")
        })
        .await;
        let joiner = arkret_wire::ActorId::account(joiner);
        let member = ordinary_realm::next_request_for_actor(
            &relationship.authority_commit,
            arkret_wire::EventKind::MemberState,
            joiner.clone(),
            serde_json::json!({"member_id":joiner,"membership":"join"}),
            at,
        );
        let member = scenario_future(|| ordinary_realm::source_request(&pool, member)).await;
        let acceptance = ordinary_realm::next_request_for_actor(
            &relationship.authority_commit,
            arkret_wire::EventKind::InviteAccept,
            arkret_wire::ActorId::account(invitee.clone()),
            serde_json::json!({"invite_id":arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),
            "previous_state":"pending","invitee_account_id":invitee}),
            at,
        );
        let acceptance =
            scenario_future(|| ordinary_realm::source_request(&pool, acceptance)).await;
        let before = snapshot(&pool).await;
        for request in [member, acceptance.clone()] {
            let error = uow.commit_event(request.clone()).await.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("organization moderation policy authority is unavailable"),
                "{error}"
            );
            assert_eq!(
                snapshot(&pool).await,
                before,
                "failed dependency mutated the accepted cut"
            );
            assert!(
                events
                    .committed_event(&request.authority_commit.event.event_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let (revocation, proof) = organization_request(
            &relationship.authority_commit,
            "revoked",
            serde_json::json!(["moderation_policy"]),
            Some(statement),
        );
        let revocation =
            scenario_future(|| ordinary_realm::source_request(&pool, revocation)).await;
        let proof = coland_storage::RealmOrganizationProofCommit {
            event_id: revocation.authority_commit.event.event_id.clone(),
            ..proof
        };
        uow.commit_event_batch(batch(revocation.clone(), proof))
            .await
            .unwrap();
        let list = relationships
            .accepted_relationships(&head.event.realm_id, at)
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(
            list[0].statement_id.as_str(),
            revocation.authority_commit.event.payload["statement_id"]
                .as_str()
                .unwrap()
        );
        assert_eq!(list[0].lifecycle_phase,
        arkret_models_collaboration::governance::realm_governance::RealmOrganizationLifecyclePhase::RevokedOrExpired);
        let resumed = ordinary_realm::next_request_for_actor(
            &revocation.authority_commit,
            arkret_wire::EventKind::InviteAccept,
            acceptance.authority_commit.event.actor_id.clone(),
            serde_json::to_value(&acceptance.authority_commit.event.payload).unwrap(),
            at,
        );
        let resumed = scenario_future(|| ordinary_realm::source_request(&pool, resumed)).await;
        uow.commit_event(resumed.clone()).await.unwrap();
        assert!(
            events
                .committed_event(&resumed.authority_commit.event.event_id)
                .await
                .unwrap()
                .is_some()
        );
    })
}

#[tokio::test]
async fn organization_writer_refuses_missing_or_false_proof_and_wrong_statement_reference() {
    organization_proof_scenario().await;
}

#[inline(never)]
fn organization_proof_scenario() -> std::pin::Pin<Box<impl std::future::Future<Output = ()>>> {
    Box::pin(async move {
        let station = ordinary_realm::station();
        let database = TestDatabase::lease().await;
        let pool = database.pool();
        let founder_account = scenario_future(|| {
            ordinary_realm::human_profile::admit(&pool, &station, "organization-founder")
        })
        .await;
        let bootstrap = ordinary_realm::bootstrap_unit_for_account(
            &uuid::Uuid::now_v7().to_string(),
            &founder_account,
            &ordinary_realm::human_profile::station_did(&station),
        );
        let bootstrap =
            scenario_future(|| ordinary_realm::source_bootstrap(&pool, bootstrap)).await;
        let authority = PgAuthorityCommitStore { pool: pool.clone() };
        let at = bootstrap.transactions[0].commit.committed_at;
        authority
            .admit_ordinary_realm_bootstrap_unit(&bootstrap, at)
            .await
            .unwrap();
        let head = bootstrap.transactions.last().unwrap();
        let uow = PgEventCommitUnitOfWork::new(pool.clone());
        let (relationship, proof) =
            organization_request(head, "active", serde_json::json!(["official_badge"]), None);
        let relationship =
            scenario_future(|| ordinary_realm::source_request(&pool, relationship)).await;
        let proof = coland_storage::RealmOrganizationProofCommit {
            event_id: relationship.authority_commit.event.event_id.clone(),
            ..proof
        };
        let before = snapshot(&pool).await;
        assert!(uow.commit_event(relationship.clone()).await.is_err());
        assert_eq!(snapshot(&pool).await, before);
        let mut forged = proof.clone();
        forged.public_key = ed25519_dalek::SigningKey::from_bytes(&[82; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            uow.commit_event_batch(batch(relationship.clone(), forged))
                .await
                .is_err()
        );
        assert_eq!(snapshot(&pool).await, before);
        uow.commit_event_batch(batch(relationship.clone(), proof))
            .await
            .unwrap();
        let (wrong_ref, proof) = organization_request(
            &relationship.authority_commit,
            "revoked",
            serde_json::json!(["official_badge"]),
            Some("not-the-accepted-statement"),
        );
        let wrong_ref = scenario_future(|| ordinary_realm::source_request(&pool, wrong_ref)).await;
        let proof = coland_storage::RealmOrganizationProofCommit {
            event_id: wrong_ref.authority_commit.event.event_id.clone(),
            ..proof
        };
        let before = snapshot(&pool).await;
        assert!(
            uow.commit_event_batch(batch(wrong_ref, proof))
                .await
                .is_err()
        );
        assert_eq!(snapshot(&pool).await, before);
        // A genuine accepted organization badge has no implicit moderation scope.
        let joiner = scenario_future(|| {
            ordinary_realm::human_profile::admit(&pool, &station, "organization-badge-joiner")
        })
        .await;
        let joiner = arkret_wire::ActorId::account(joiner);
        let member = ordinary_realm::next_request_for_actor(
            &relationship.authority_commit,
            arkret_wire::EventKind::MemberState,
            joiner.clone(),
            serde_json::json!({"member_id":joiner,"membership":"join"}),
            at,
        );
        let member = scenario_future(|| ordinary_realm::source_request(&pool, member)).await;
        uow.commit_event(member).await.unwrap();
    })
}

#[inline(never)]
fn scenario_future<F, Fut>(make: F) -> std::pin::Pin<Box<Fut>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future,
{
    Box::pin(make())
}
