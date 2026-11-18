//! G-private membership source tests, independent of H no-Add/Add readiness.
//! Public RFC state is genuine; ordinary serving verification enters at its
//! existing trusted PG port. These tests do not claim native HTTP or Blob IO.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_wire::{ActorId, CommitStreamRef, ScopeRef};
use coland_storage::ConflictCode;
use diesel::sql_types::{BigInt, Jsonb, Text};
use diesel_async::RunQueryDsl as _;
use serde_json::{Value, json};

use super::*;

struct ControllerGroup {
    owner: OwnedConsumerFixture,
    sidecar: SidecarId,
    genesis: coland_storage::EventCommitRequest,
    strand: arkret_wire::StrandId,
    sidecar_head: coland_storage::AuthorityCommitTransaction,
}

async fn controller_group() -> Box<ControllerGroup> {
    let owner = fixture_step(boxed_owned_consumer_fixture(0)).await;
    let pool = &owner.pool;
    let controller = &owner.controller.history.account;
    let at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now().max(owner.head.commit.committed_at + chrono::TimeDelta::milliseconds(1)),
    );
    let strand = ordinary_realm::next_request_for_actor(
        &owner.head,
        EventKind::StrandCreate,
        ActorId::account(controller.clone()),
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":owner.head.event.realm_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Controller membership source"},"state":"active",
            "created_by":ActorId::account(controller.clone()),
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    let strand = ordinary_realm::source_request(pool, strand).await;
    fixture_commit_step(pool, strand.clone()).await.unwrap();
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.authority_commit.event.event_id);
    let create = ordinary_realm::next_request_for_actor(
        &strand.authority_commit,
        EventKind::SidecarCreate,
        ActorId::account(controller.clone()),
        json!({}),
        at,
    );
    let create = ordinary_realm::source_request(pool, create).await;
    fixture_commit_step(pool, create.clone()).await.unwrap();
    let realm = &create.authority_commit.event.realm_id;
    let sidecar = SidecarId::from_event_id(&create.authority_commit.event.event_id);
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let cut = read(pool, realm, &sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(cut.desired_agent_ids.is_empty());
    let binding = MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        cut.participant_authority_digest,
    )
    .unwrap();
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(controller.clone()),
        owner.controller.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(
            ed25519_dalek::SigningKey::from_bytes(
                &owner.controller.history.founding_device_signing_seed,
            ),
        ),
    )
    .unwrap();
    let group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let tracker = arkret_mls::MlsPublicGroupTracker::from_external(
        &info,
        &tree,
        group.group_id().as_str(),
        0,
    )
    .unwrap();
    let blob = |bytes: &[u8]| {
        arkret_wire::BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(bytes)
        ))
        .unwrap()
    };
    let authorization = owner
        .controller
        .history
        .events
        .iter()
        .find(|event| event.kind == EventKind::DeviceAuthorize)
        .unwrap();
    let payload = json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "group_info_ref":blob(&info),"ratchet_tree_ref":blob(&tree),
        "creator_leaf_authority":{
            "leaf_signature_key_base64url":arkret_canonical::base64url_encode(
                ed25519_dalek::SigningKey::from_bytes(&owner.controller.history.founding_device_signing_seed)
                    .verifying_key().as_bytes()),
            "endpoint":{"kind":"device","device_id":owner.controller.history.founding_device_id},
            "authorization_event_ref":authorization.event_id},
        "governance_binding":binding,"created_at":arkret_canonical::format_timestamp_canonical(at)});
    let event = device_authorization_history::sign_event(
        ordinary_realm::event_for_actor(
            EventKind::MlsGenesis,
            scope.clone(),
            ActorId::account(controller.clone()),
            payload,
            at,
        ),
        owner.controller.history.device_verification_method.clone(),
        owner.controller.history.founding_device_signing_seed,
    );
    let mut genesis = ordinary_realm::request_for_event(&create.authority_commit, event, at);
    genesis.authority_commit.commit.stream_ref = CommitStreamRef::from_scope(&scope, None).unwrap();
    genesis.authority_commit.commit.stream_position = 0;
    genesis.authority_commit.commit.previous_commit_ref = None;
    let public_blob = |bytes: &[u8]| {
        let sha256 = arkret_canonical::sha256_digest(bytes)
            .trim_start_matches("sha256:")
            .to_owned();
        coland_storage::MlsPublicBlob {
            blob_ref: blob(bytes),
            size_bytes: bytes.len() as i64,
            storage_backend: "local".into(),
            storage_key: format!("sha256/{sha256}"),
            sha256,
        }
    };
    genesis.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: scope,
        base: None,
        epoch: 0,
        public_state: tracker.export_state().unwrap(),
        member_principals: tracker
            .leaves()
            .unwrap()
            .into_iter()
            .map(|leaf| leaf.actor_id)
            .collect(),
        consumed_proposals: vec![],
        public_blobs: vec![public_blob(&info), public_blob(&tree)],
    });
    source_candidate(pool, &mut genesis).await;
    let genesis = ordinary_realm::source_request(pool, genesis).await;
    assert!(
        fixture_commit_step(pool, genesis.clone())
            .await
            .unwrap()
            .event_inserted
    );
    let mut context_event = ordinary_realm::event_for_actor(
        EventKind::SidecarContextAttach,
        genesis.authority_commit.event.scope_ref.clone(),
        ActorId::account(controller.clone()),
        json!({"sidecar_id":sidecar,
            "source_context_ref":{"kind":"strand","strand_id":strand_id},"version":1}),
        at + chrono::TimeDelta::milliseconds(1),
    );
    context_event.semantic_refs = vec![arkret_wire::SemanticRef::new(
        create.authority_commit.event.event_id.to_string(),
        "after",
    )];
    let context_event = device_authorization_history::sign_event(
        context_event,
        owner.controller.history.device_verification_method.clone(),
        owner.controller.history.founding_device_signing_seed,
    );
    let mut context = ordinary_realm::request_for_event(
        &genesis.authority_commit,
        context_event,
        at + chrono::TimeDelta::milliseconds(1),
    );
    context.authority_commit.commit.stream_ref = genesis.authority_commit.commit.stream_ref.clone();
    source_candidate(pool, &mut context).await;
    let context = ordinary_realm::source_request(pool, context).await;
    fixture_commit_step(pool, context.clone()).await.unwrap();
    Box::new(ControllerGroup {
        owner,
        sidecar,
        genesis,
        strand: strand_id,
        sidecar_head: context.authority_commit,
    })
}

#[derive(diesel::QueryableByName)]
struct StoredSource {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn stored(fixture: &ControllerGroup) -> Value {
    let mut conn = fixture.owner.pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('basis',c.sidecar_membership_basis,'event',e.envelope, \
        'commit',c.commit_json,'current',g.value,'public_state',encode(g.public_state,'hex'), \
        'events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits)) AS value \
        FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk \
        JOIN mls_group_current_states g ON g.current_commit_id=c.commit_id WHERE c.commit_id=$1")
        .bind::<Text,_>(fixture.genesis.authority_commit.commit.commit_id.as_str())
        .get_result::<StoredSource>(&mut *conn).await.unwrap().value
}

#[tokio::test]
async fn controller_only_mls_source_is_frozen_and_exact_replay_preserves_it() {
    fixture_step(fixture_future(controller_only_source_case)).await;
}

async fn controller_only_source_case() {
    let fixture = fixture_step(fixture_future(controller_group)).await;
    let before = stored(&fixture).await;
    assert_eq!(
        before["basis"],
        json!({
        "controller_join_event_ref":fixture.owner.controller_join.event.event_id,
        "agent_join_event_refs":[]})
    );
    let mut conn = fixture.owner.pool.get().await.unwrap();
    assert_eq!(
        diesel::sql_query(
            "UPDATE realm_commits SET sidecar_membership_basis=$1 WHERE commit_id=$2"
        )
        .bind::<Jsonb, _>(&before["basis"])
        .bind::<Text, _>(fixture.genesis.authority_commit.commit.commit_id.as_str())
        .execute(&mut *conn)
        .await
        .unwrap(),
        1
    );
    drop(conn);
    let replay = fixture_commit_step(&fixture.owner.pool, fixture.genesis.clone())
        .await
        .unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(replay.projections_inserted, 0);
    assert_eq!(replay.outbox_inserted, 0);
    assert_eq!(stored(&fixture).await, before);
}

#[tokio::test]
async fn controller_rejoin_keeps_empty_roster_source_and_does_not_read_old_join_for_current_send() {
    fixture_step(fixture_future(controller_rejoin_case)).await;
}

async fn controller_rejoin_case() {
    let fixture = fixture_step(fixture_future(controller_group)).await;
    let pool = &fixture.owner.pool;
    let controller = &fixture.owner.controller.history.account;
    let realm = &fixture.genesis.authority_commit.event.realm_id;
    let before = stored(&fixture).await;
    let at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now()
            .max(fixture.owner.head.commit.committed_at + chrono::TimeDelta::milliseconds(1)),
    );
    let previous = PgAuthorityCommitStore { pool: pool.clone() }
        .held_stream_head_commit(&CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let mut head = fixture.owner.head.clone();
    head.event = PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event(&previous.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    head.commit = previous;
    let leave = ordinary_realm::next_request_for_actor(
        &head,
        EventKind::MemberState,
        ActorId::account(fixture.owner.founder.clone()),
        json!({"member_id":ActorId::account(controller.clone()),"membership":"leave"}),
        at,
    );
    let leave = ordinary_realm::source_request(pool, leave).await;
    fixture_commit_step(pool, leave.clone()).await.unwrap();
    let rejoin = ordinary_realm::next_request_for_actor(
        &leave.authority_commit,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        json!({"member_id":ActorId::account(controller.clone()),"membership":"join"}),
        at + chrono::TimeDelta::milliseconds(1),
    );
    let rejoin = ordinary_realm::source_request(pool, rejoin).await;
    fixture_commit_step(pool, rejoin.clone()).await.unwrap();
    assert_ne!(
        rejoin.authority_commit.event.event_id,
        fixture.owner.controller_join.event.event_id
    );
    let after = stored(&fixture).await;
    assert_eq!(after["basis"], before["basis"]);
    assert_eq!(after["current"], before["current"]);
    assert_eq!(after["public_state"], before["public_state"]);
    let cut = read(pool, realm, &fixture.sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert!(cut.desired_agent_ids.is_empty());
    let binding: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
        serde_json::from_value(
            serde_json::to_value(&fixture.genesis.authority_commit.event.payload).unwrap(),
        )
        .unwrap();
    assert_eq!(
        cut.participant_authority_digest,
        binding
            .governance_binding
            .sidecar_binding()
            .unwrap()
            .participant_authority_digest
    );
    let mut changed = before["basis"].clone();
    changed["controller_join_event_ref"] = json!(rejoin.authority_commit.event.event_id);
    let mut conn = pool.get().await.unwrap();
    let error = diesel::sql_query(
        "UPDATE realm_commits SET sidecar_membership_basis=$1 WHERE commit_id=$2",
    )
    .bind::<Jsonb, _>(changed)
    .bind::<Text, _>(fixture.genesis.authority_commit.commit.commit_id.as_str())
    .execute(&mut *conn)
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("accepted Sidecar membership provenance is immutable"),
        "{error}"
    );
    // Corrupt only this old join's Full locator after the genuine rejoin.
    // This is a negative dependency control, not an accepted-current seed.
    #[derive(diesel::QueryableByName)]
    struct EventPk {
        #[diesel(sql_type = BigInt)]
        event_pk: i64,
    }
    let old = diesel::sql_query("SELECT event_pk FROM realm_commits WHERE commit_id=$1")
        .bind::<Text, _>(fixture.owner.controller_join.commit.commit_id.as_str())
        .get_result::<EventPk>(&mut *conn)
        .await
        .unwrap()
        .event_pk;
    assert_eq!(
        diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE commit_id=$1")
            .bind::<Text, _>(fixture.owner.controller_join.commit.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap(),
        1
    );
    drop(conn);
    let at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now()
            .max(rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1)),
    );
    let event = device_authorization_history::sign_event(
        ordinary_realm::event_for_actor(
            EventKind::MessageCreate,
            fixture.genesis.authority_commit.event.scope_ref.clone(),
            ActorId::account(controller.clone()),
            ordinary_realm::message_payload(&fixture.strand, "Current controller gate"),
            at,
        ),
        fixture
            .owner
            .controller
            .history
            .device_verification_method
            .clone(),
        fixture
            .owner
            .controller
            .history
            .founding_device_signing_seed,
    );
    let mut message = ordinary_realm::request_for_event(&fixture.sidecar_head, event, at);
    message.authority_commit.commit.stream_ref =
        fixture.genesis.authority_commit.commit.stream_ref.clone();
    source_candidate(pool, &mut message).await;
    let message = ordinary_realm::source_request(pool, message).await;
    let error = fixture_commit_step(pool, message.clone())
        .await
        .unwrap_err();
    let mut conn = pool.get().await.unwrap();
    assert_eq!(
        diesel::sql_query("UPDATE realm_commits SET event_pk=$1 WHERE commit_id=$2")
            .bind::<BigInt, _>(old)
            .bind::<Text, _>(fixture.owner.controller_join.commit.commit_id.as_str())
            .execute(&mut *conn)
            .await
            .unwrap(),
        1
    );
    drop(conn);
    assert_eq!(
        error.conflict_code(),
        Some(ConflictCode::MlsActivationRequired),
        "{error}"
    );
    assert!(
        PgAuthorityCommitStore { pool: pool.clone() }
            .committed_event(&message.authority_commit.event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(stored(&fixture).await, after);
}

/// Called only after the existing real Add, Welcome join and durable consume
/// have completed. Future/refused/unknown delivery branches return None before
/// the parent reaches this call; their state machines are not duplicated here.
#[allow(clippy::too_many_arguments)]
pub(super) async fn assert_agent_generation_after_consume(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    original_join: &coland_storage::AuthorityCommitTransaction,
    accepted_add: &coland_storage::AuthorityCommitTransaction,
    sidecar: &SidecarId,
    group: &mut arkret_mls::ArkretMlsGroup,
    recipient: &mut arkret_mls::ArkretMlsGroup,
) {
    use coland_storage::MlsGroupCurrentStore as _;
    let controller = &principal.history.account;
    let realm = &accepted_add.event.realm_id;
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let stream = CommitStreamRef::from_scope(&scope, None).unwrap();
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore { pool: pool.clone() };
    let original_source = source_for_event(pool, &accepted_add.event.event_id).await;
    assert_eq!(
        original_source["basis"]["agent_join_event_refs"],
        json!([original_join.event.event_id])
    );
    assert_eq!(
        original_source["basis"]["controller_join_event_ref"],
        original_join.event.payload["agent_controller_binding"]["controller_membership_generation_ref"]
    );
    let original_endpoint = agent_origin(pool, &scope, agent).await;
    let before = groups.current(&scope).await.unwrap().unwrap();
    assert!(
        governing_history_snapshot(
            pool,
            principal,
            controller,
            sidecar,
            &original_join.commit.commit_id,
        )
        .await
        .unwrap()
        .is_none(),
        "wrong subject: an accepted Agent join cannot issue a Q for its controller"
    );
    // Exercise the exact G-only issuer with accepted sources. This trusted PG
    // boundary does not claim that a remote H request or HTTP gate ran here.
    let history = governing_history_snapshot(
        pool,
        principal,
        agent,
        sidecar,
        &original_join.commit.commit_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        history.purpose,
        arkret_wire::RealmSnapshotPurpose::StreamHistory
    );
    let history_basis = history.history_basis.as_ref().unwrap();
    assert_eq!(history_basis.account_id, *agent);
    assert_eq!(history_basis.stream_ref, stream);
    assert_eq!(history_basis.accepted_dependency_refs.len(), 2);
    assert!(
        history_basis
            .accepted_dependency_refs
            .iter()
            .any(|source| source.commit_id == original_join.commit.commit_id
                && source.event_id == original_join.event.event_id)
    );
    assert!(
        history
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream
                && floor.oldest_position == accepted_add.commit.stream_position)
    );
    assert!(
        coland_storage_postgres::PgIssuedRealmSnapshotArchive::new(pool.clone())
            .by_ref(agent, realm, &history.snapshot_id, &controller.station_id)
            .await
            .is_err(),
        "an H-held floor original does not grant ordinary Agent by-ref access to its dependencies"
    );
    assert_eq!(
        before.value.current_mls_commit_event_ref,
        accepted_add.event.event_id
    );
    assert_eq!(group.epoch(), before.value.epoch);
    assert_eq!(recipient.epoch(), before.value.epoch);
    let parent = store
        .held_stream_head_commit(&CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let mut realm_head = original_join.clone();
    realm_head.event = store
        .committed_event(&parent.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    realm_head.commit = parent;
    let at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now().max(realm_head.commit.committed_at + chrono::TimeDelta::milliseconds(1)),
    );
    let leave = ordinary_realm::next_request_for_actor(
        &realm_head,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        json!({"member_id":ActorId::account(agent.clone()),"membership":"leave"}),
        at,
    );
    let leave = ordinary_realm::source_request(pool, leave).await;
    fixture_commit_step(pool, leave.clone()).await.unwrap();
    let rejoin = ordinary_realm::next_request_for_actor(
        &leave.authority_commit,
        EventKind::MemberState,
        ActorId::account(controller.clone()),
        json!({"member_id":ActorId::account(agent.clone()),
            "membership":"join","agent_controller_binding":original_join.event.payload["agent_controller_binding"]}),
        at + chrono::TimeDelta::milliseconds(1),
    );
    let rejoin = ordinary_realm::source_request(pool, rejoin).await;
    fixture_commit_step(pool, rejoin.clone()).await.unwrap();
    assert_ne!(
        rejoin.authority_commit.event.event_id,
        original_join.event.event_id
    );
    assert!(
        governing_history_snapshot(
            pool,
            principal,
            agent,
            sidecar,
            &original_join.commit.commit_id
        )
        .await
        .unwrap()
        .is_none(),
        "the prior join cannot disclose the new Agent incarnation"
    );
    let pending = store
        .realm_state_snapshot_material_for_account(realm, agent)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !pending
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream),
        "Ja1 cannot give Ja2 a confirmed Sidecar floor"
    );
    assert_eq!(
        source_for_event(pool, &accepted_add.event.event_id).await,
        original_source
    );
    let cut = read(pool, realm, sidecar, controller)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cut.desired_agent_ids, vec![agent.principal_id.clone()]);
    let binding = MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        Some(before.value.current_mls_commit_event_ref.clone()),
        before.value.epoch,
        before.value.epoch + 1,
        before.value.current_key_access_revision,
        cut.participant_authority_digest,
    )
    .unwrap();
    let controller_bindings = group.verified_leaf_bindings().unwrap();
    let recipient_bindings = recipient.verified_leaf_bindings().unwrap();
    let envelope = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let (info, tree) = group
        .pending_public_group_state_bytes(&envelope, &binding)
        .unwrap();
    let mut tracker = arkret_mls::MlsPublicGroupTracker::restore(
        &before.public_state,
        group.group_id().as_str(),
        before.value.epoch,
    )
    .unwrap();
    let arkret_mls::MlsPublicHandshakeTransition::Commit {
        consumed_proposals, ..
    } = tracker
        .process_public_handshake(&arkret_canonical::base64url_decode(&envelope.commit).unwrap())
        .unwrap()
    else {
        panic!("a real controller Update is required")
    };
    assert!(
        !consumed_proposals
            .iter()
            .any(|proposal| proposal.proposal_type == 1),
        "a new membership generation does not require a fresh Add"
    );
    assert_eq!(tracker.ratchet_tree_bytes().unwrap(), tree);
    let payload = coland_test_support::mls_content::commit_payload(
        group,
        before.value.current_mls_commit_event_ref.clone(),
        before.value.current_key_access_revision,
        &envelope,
        binding,
    )
    .unwrap();
    let scope_head = store
        .held_stream_head_commit(&stream)
        .await
        .unwrap()
        .unwrap();
    let mut previous = accepted_add.clone();
    previous.event = store
        .committed_event(&scope_head.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    previous.commit = scope_head;
    let at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now()
            .max(rejoin.authority_commit.commit.committed_at + chrono::TimeDelta::milliseconds(1))
            .max(previous.commit.committed_at + chrono::TimeDelta::milliseconds(1)),
    );
    let event = device_authorization_history::sign_event(
        ordinary_realm::event_for_actor(
            EventKind::MlsCommit,
            scope.clone(),
            ActorId::account(controller.clone()),
            serde_json::to_value(payload).unwrap(),
            at,
        ),
        principal.history.device_verification_method.clone(),
        principal.history.founding_device_signing_seed,
    );
    let mut update = ordinary_realm::request_for_event(&previous, event, at);
    update.authority_commit.commit.stream_ref = stream.clone();
    let leaf =
        |leaf: arkret_mls::MlsPublicEndpointLeaf| coland_storage::MlsProposalLeafProvenance {
            leaf_index: leaf.leaf_index,
            actor_id: leaf.actor_id,
            signature_key: leaf.signature_key,
        };
    update.authority_commit.mls_state = Some(coland_storage::MlsStateInstallation {
        effective_scope: scope.clone(),
        base: Some(coland_storage::MlsInstalledBase {
            current_mls_commit_event_ref: before.value.current_mls_commit_event_ref.clone(),
            epoch: before.value.epoch,
        }),
        epoch: envelope.epoch,
        public_state: tracker.export_state().unwrap(),
        member_principals: tracker
            .leaves()
            .unwrap()
            .into_iter()
            .map(|leaf| leaf.actor_id)
            .collect(),
        consumed_proposals: consumed_proposals
            .into_iter()
            .map(|proposal| coland_storage::MlsConsumedProposalInstallation {
                ordinal: proposal.ordinal,
                proposal_ref: proposal.proposal_ref,
                proposal_type: proposal.proposal_type,
                proposal_wire: proposal.proposal_wire,
                sender_leaf: leaf(proposal.sender_leaf),
                target_before: proposal.target_before.map(leaf),
                target_after: proposal.target_after.map(leaf),
            })
            .collect(),
        public_blobs: [info, tree]
            .into_iter()
            .map(|bytes| {
                let digest = arkret_canonical::sha256_digest(&bytes);
                let sha256 = digest.trim_start_matches("sha256:").to_owned();
                coland_storage::MlsPublicBlob {
                    blob_ref: arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap(),
                    size_bytes: bytes.len() as i64,
                    storage_backend: "local".into(),
                    storage_key: format!("sha256/{sha256}"),
                    sha256,
                }
            })
            .collect(),
    });
    source_candidate(pool, &mut update).await;
    let update = ordinary_realm::source_request(pool, update).await;
    fixture_commit_step(pool, update.clone()).await.unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: update.authority_commit.event.clone(),
        commit: update.authority_commit.commit.clone(),
    };
    group
        .install_accepted_commit(&accepted, &before.value)
        .unwrap();
    group
        .install_verified_leaf_bindings(controller_bindings)
        .unwrap();
    recipient
        .install_accepted_commit(&accepted, &before.value)
        .unwrap();
    recipient
        .install_verified_leaf_bindings(recipient_bindings)
        .unwrap();
    assert_eq!(group.epoch(), before.value.epoch + 1);
    assert_eq!(recipient.epoch(), group.epoch());
    assert_eq!(agent_origin(pool, &scope, agent).await, original_endpoint);
    let confirmed = source_for_event(pool, &accepted.event.event_id).await;
    assert_eq!(
        confirmed["basis"]["agent_join_event_refs"],
        json!([rejoin.authority_commit.event.event_id])
    );
    assert_eq!(
        confirmed["basis"]["controller_join_event_ref"],
        original_source["basis"]["controller_join_event_ref"]
    );
    assert_eq!(
        source_for_event(pool, &accepted_add.event.event_id).await,
        original_source
    );
    assert!(
        governing_history_snapshot(
            pool,
            principal,
            agent,
            sidecar,
            &original_join.commit.commit_id
        )
        .await
        .unwrap()
        .is_none(),
        "a newly confirmed MLS cut does not revive the old join request"
    );
    let history = governing_history_snapshot(
        pool,
        principal,
        agent,
        sidecar,
        &rejoin.authority_commit.commit.commit_id,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        history
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream
                && floor.oldest_position == accepted.commit.stream_position)
    );
    let snapshot = store
        .realm_state_snapshot_material_for_account(realm, agent)
        .await
        .unwrap()
        .unwrap();
    assert!(
        snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| floor.stream_ref == stream
                && floor.oldest_position == accepted.commit.stream_position)
    );
    let scan = store
        .scan_stream_for_account(
            &arkret_wire::StreamScanRequestBody {
                realm_id: realm.clone(),
                stream_ref: stream.clone(),
                direction: arkret_wire::StreamScanDirection::After(None),
                limit: 16,
            },
            agent,
            &controller.station_id,
        )
        .await
        .unwrap();
    let coland_storage::AccountStreamScan::Page(page) = scan else {
        panic!("the genuine new Update confirms this exact Agent generation")
    };
    assert_eq!(
        page.committed_events
            .as_slice()
            .first()
            .unwrap()
            .commit()
            .commit_id,
        accepted.commit.commit_id
    );
    let replay = fixture_commit_step(pool, update).await.unwrap();
    assert!(!replay.event_inserted);
    assert_eq!(replay.projections_inserted, 0);
    assert_eq!(replay.outbox_inserted, 0);
    assert_eq!(
        source_for_event(pool, &accepted.event.event_id).await,
        confirmed
    );
    let head = store
        .held_stream_head_commit(&CommitStreamRef::Realm {
            realm_id: realm.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    let mut previous = rejoin.authority_commit.clone();
    previous.event = store
        .committed_event(&head.event_ref)
        .await
        .unwrap()
        .unwrap()
        .event;
    previous.commit = head;
    let founder = store
        .committed_event(&realm.event_id())
        .await
        .unwrap()
        .unwrap()
        .event
        .actor_id;
    let policy_id = format!("ak:policy:{}", uuid::Uuid::now_v7());
    let created_at = arkret_canonical::format_timestamp_canonical(
        previous.commit.committed_at + chrono::TimeDelta::milliseconds(1),
    );
    let mut prior_policy = None;
    for stage in ["event_read_denied", "deliver_denied", "allowed"] {
        let rule = if stage == "event_read_denied" {
            json!({"rule_id":"g_history_delivery","kind":"agent","effect":"deny",
                "agent_target":{"kind":"controller","controller_account_id":controller},
                "agent_operations":["read","deliver"],"actions":["ak.event.read"]})
        } else {
            json!({"rule_id":"g_history_delivery","kind":"agent",
                "effect":if stage == "deliver_denied" { "deny" } else { "allow" },
                "agent_target":{"kind":"controller","controller_account_id":controller},
                "agent_operations":["deliver"]})
        };
        let at = previous.commit.committed_at + chrono::TimeDelta::milliseconds(1);
        let candidate = ordinary_realm::next_request_for_actor(
            &previous,
            EventKind::PolicySet,
            founder.clone(),
            json!({"policy_id":policy_id,"expected_commit_id":prior_policy,
                "value":{"schema":"ak.schema.policy.v1","id":policy_id,"realm_id":realm,
                    "policy_kind":"agent","default_effect":"allow",
                    "created_by":founder,"created_at":created_at,
                    "rules":[rule]}}),
            at,
        );
        let candidate = ordinary_realm::source_request(pool, candidate).await;
        fixture_commit_step(pool, candidate.clone()).await.unwrap();
        previous = candidate.authority_commit;
        prior_policy = Some(previous.commit.commit_id.clone());
        let issued = governing_history_snapshot(
            pool,
            principal,
            agent,
            sidecar,
            &rejoin.authority_commit.commit.commit_id,
        )
        .await;
        if stage == "deliver_denied" {
            assert!(
                issued
                    .unwrap_err()
                    .to_string()
                    .contains("capability_denied"),
                "G Deliver deny must refuse despite Read default allow"
            );
        } else {
            assert!(
                issued.unwrap().is_some(),
                "ObjectRead rows remain available when only EventRead is denied or Deliver is allowed"
            );
        }
    }
}

async fn governing_history_snapshot(
    pool: &coland_storage_postgres::PgPool,
    principal: &pcr_genesis::PcrGenesisFixture,
    agent: &AccountId,
    sidecar: &SidecarId,
    join: &arkret_wire::RealmCommitId,
) -> coland_storage::PersistenceResult<Option<arkret_wire::RealmStateSnapshot>> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
    let method =
        arkret_wire::DidUrl::new(format!("{}#notary-key", principal.history.station_did)).unwrap();
    let sign_calls = std::sync::atomic::AtomicUsize::new(0);
    let sign = |material: &coland_storage::RealmStateSnapshotMaterial| {
        sign_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            material.purpose,
            arkret_wire::RealmSnapshotPurpose::StreamHistory,
            "G must not sign a full-recovery object before the narrow original"
        );
        coland_services::authority_commit::build_signed_realm_state_snapshot(
            material,
            method.clone(),
            &key,
            chrono::Utc::now(),
        )
        .map_err(|error| coland_storage::PersistenceError::Internal(error.to_string()))
    };
    let realm = sidecar_realm(pool, join).await;
    let result = coland_storage_postgres::issue_governing_sidecar_agent_history_for_test(
        pool,
        &realm,
        agent,
        &principal.history.account.station_id,
        sidecar,
        join,
        &sign,
    )
    .await;
    if !matches!(&result, Ok(Some(_))) {
        assert_eq!(
            std::sync::atomic::AtomicUsize::load(&sign_calls, std::sync::atomic::Ordering::Relaxed,),
            0,
            "a refused or absent G disclosure must not invoke the signer"
        );
    }
    let Some(snapshot) = result? else {
        return Ok(None);
    };
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap();
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().as_bytes().to_vec(),
        },
    )
    .unwrap();
    snapshot.validate_purpose().unwrap();
    Ok(Some(snapshot))
}

async fn sidecar_realm(
    pool: &coland_storage_postgres::PgPool,
    join: &arkret_wire::RealmCommitId,
) -> arkret_wire::RealmId {
    PgAuthorityCommitStore { pool: pool.clone() }
        .committed_event_by_commit_id(join)
        .await
        .unwrap()
        .unwrap()
        .event
        .realm_id
}

async fn source_for_event(
    pool: &coland_storage_postgres::PgPool,
    event: &arkret_wire::EventId,
) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('basis',c.sidecar_membership_basis,'event',e.envelope,'commit',c.commit_json) AS value \
        FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed'")
        .bind::<Text,_>(event.as_str()).get_result::<StoredSource>(&mut *conn).await.unwrap().value
}

async fn agent_origin(
    pool: &coland_storage_postgres::PgPool,
    scope: &ScopeRef,
    agent: &AccountId,
) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('origin_event_ref',b.origin_event_ref, \
        'origin_signature_key',b.origin_signature_key,'binding',b.binding) AS value \
        FROM mls_endpoint_current_bindings b JOIN mls_group_current_states g ON g.scope_key=b.scope_key \
        WHERE g.value->'effective_scope'=$1 AND b.actor_id=$2")
        .bind::<Jsonb,_>(json!(scope)).bind::<Jsonb,_>(json!(ActorId::account(agent.clone())))
        .get_result::<StoredSource>(&mut *conn).await.unwrap().value
}
