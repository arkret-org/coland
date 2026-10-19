//! Real PostgreSQL Call genesis and capability admission. These UoW fixtures
//! are structural TCB inputs; HTTP tests separately prove producer signatures.
#[path = "support/human_profile.rs"]
#[allow(dead_code)]
mod human_profile;
#[path = "support/ordinary_realm.rs"]
#[allow(dead_code)]
mod ordinary_realm;

use arkret_wire::{ActorId, EventKind};
use coland_storage::{AuthorityCommitStore, EventCommitRequest, EventCommitUnitOfWork};
use coland_storage_postgres::test_database::TestDatabase;
use coland_storage_postgres::{PgAuthorityCommitStore, PgEventCommitUnitOfWork, PgPool};
use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl;
use serde_json::{Value, json};

#[derive(diesel::QueryableByName)]
struct ValueRow {
    #[diesel(sql_type = Jsonb)]
    value: Value,
}

async fn footprint(pool: &PgPool) -> Value {
    let mut conn = pool.get().await.unwrap();
    diesel::sql_query("SELECT jsonb_build_object('events',(SELECT count(*) FROM canonical_events),'commits',(SELECT count(*) FROM realm_commits),'issuer_keys',(SELECT count(*) FROM call_participant_issuer_sources),'calls',(SELECT count(*) FROM call_state_current_results),'axes',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY realm_id,call_id,selector),'[]') FROM call_component_current_results t)) AS value")
        .get_result::<ValueRow>(&mut *conn).await.unwrap().value
}

#[tokio::test]
async fn three_initial_states_derive_call_ids_and_exact_replay_preserves_current() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-initial").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let mut head = discussion.head.clone();
    for state in ["scheduled", "ringing", "connecting"] {
        let request = ordinary_realm::next_request(
            &head.authority_commit,
            EventKind::CallCreate,
            head.authority_commit.event.actor_id.signing_principal_id(),
            json!({"initial_state":state}),
            head.authority_commit.commit.committed_at + chrono::Duration::seconds(1),
        );
        uow.commit_event(request.clone()).await.unwrap();
        let before = footprint(&pool).await;
        uow.commit_event(request.clone()).await.unwrap();
        assert_eq!(footprint(&pool).await, before);
        let mut conn = pool.get().await.unwrap();
        let record = diesel::sql_query("SELECT jsonb_build_object('value',value,'source',source_stream_ref,'commit',current_commit_id,'position',current_stream_position,'create',create_event_id) AS value FROM call_state_current_results WHERE realm_id=$1 AND call_id=$2")
            .bind::<Text,_>(discussion.realm_id().as_str())
            .bind::<Text,_>(arkret_wire::CallId::from_event_id(&request.authority_commit.event.event_id).as_str())
            .get_result::<ValueRow>(&mut *conn).await.unwrap().value;
        assert_eq!(record["value"], json!({"from":null,"to":state}));
        assert_eq!(
            record["source"],
            json!(request.authority_commit.commit.stream_ref)
        );
        assert_eq!(
            record["commit"],
            json!(request.authority_commit.commit.commit_id)
        );
        assert_eq!(
            record["create"],
            json!(request.authority_commit.event.event_id)
        );
        assert_eq!(
            record["position"],
            json!(request.authority_commit.commit.stream_position)
        );
        drop(conn);
        let snapshot = PgAuthorityCommitStore { pool: pool.clone() }
            .realm_state_snapshot_material_for_account(
                &discussion.realm_id(),
                request
                    .authority_commit
                    .event
                    .actor_id
                    .as_account_id()
                    .unwrap(),
            )
            .await
            .unwrap()
            .expect("joined caller sees the accepted Call current");
        assert!(snapshot.current_state_entries.iter().any(|entry| matches!(entry,
            arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::CallState {call_id}, value, .. }
            if call_id == &arkret_wire::CallId::from_event_id(&request.authority_commit.event.event_id)
                && value == &json!({"from":null,"to":state}))));
        head = request;
    }
}

async fn refused(uow: &PgEventCommitUnitOfWork, pool: &PgPool, request: EventCommitRequest) {
    let before = footprint(pool).await;
    uow.commit_event(request).await.unwrap_err();
    assert_eq!(
        footprint(pool).await,
        before,
        "refusal leaves no Event, Commit or Call current"
    );
}

#[tokio::test]
async fn terminal_states_supplied_call_ids_and_wrong_scope_have_no_writes() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-refusal").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let head = &discussion.head.authority_commit;
    for state in ["active", "ended", "missed", "failed", "cancelled"] {
        let before = footprint(&pool).await;
        let request = ordinary_realm::next_request(
            head,
            EventKind::CallCreate,
            head.event.actor_id.signing_principal_id(),
            json!({"initial_state":state}),
            head.commit.committed_at,
        );
        let error = uow.commit_event(request).await.unwrap_err();
        assert_eq!(
            error.conflict_code(),
            Some(coland_storage::ConflictCode::CallStateTransitionInvalid),
            "{state}: {error}"
        );
        assert_eq!(footprint(&pool).await, before);
    }
    for payload in [
        json!({"initial_state":"unknown"}),
        json!({"initial_state":false}),
        json!({}),
        json!({"initial_state":"ringing","call_id":arkret_wire::CallId::from_event_id(&head.event.event_id)}),
    ] {
        let before = footprint(&pool).await;
        let request = ordinary_realm::next_request(
            head,
            EventKind::CallCreate,
            head.event.actor_id.signing_principal_id(),
            payload,
            head.commit.committed_at,
        );
        let error = uow.commit_event(request).await.unwrap_err();
        assert!(
            matches!(error, coland_storage::PersistenceError::SchemaViolation(_)),
            "{error}"
        );
        assert_eq!(footprint(&pool).await, before);
    }
    let mut event = ordinary_realm::event(
        EventKind::CallCreate,
        arkret_wire::ScopeRef::Circle {
            realm_id: discussion.realm_id(),
            circle_id: arkret_wire::CircleId::from_event_id(&head.event.event_id),
        },
        head.event.actor_id.signing_principal_id(),
        &ordinary_realm::station(),
        json!({"initial_state":"ringing"}),
        head.commit.committed_at,
    );
    ordinary_realm::reseal(&mut event);
    refused(
        &uow,
        &pool,
        ordinary_realm::request_for_event(head, event, head.commit.committed_at),
    )
    .await;
}

#[tokio::test]
async fn joined_account_needs_call_join_grant_and_other_station_cannot_borrow_it() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-capability").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let member = human_profile::admit(&pool, &ordinary_realm::station(), "call-member").await;
    let mut head = discussion.head;
    let at = head.authority_commit.commit.committed_at;
    let invite = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::InviteCreate,
        founder.clone(),
        json!({
        "invitee_account_id":member,"introduction_evidence_digest":format!("sha256:{}","a".repeat(64)),
        "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::days(7))}),
        at,
    );
    uow.commit_event(invite.clone()).await.unwrap();
    let join = ordinary_realm::next_request_for_actor(
        &invite.authority_commit,
        EventKind::InviteAccept,
        ActorId::account(member.clone()),
        json!({
        "invite_id":arkret_wire::InviteId::from_event_id(&invite.authority_commit.event.event_id),"previous_state":"pending","invitee_account_id":member}),
        at,
    );
    uow.commit_event(join.clone()).await.unwrap();
    head = join;
    let no_grant = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::CallCreate,
        ActorId::account(member.clone()),
        json!({"initial_state":"ringing"}),
        at,
    );
    let before = footprint(&pool).await;
    let error = uow.commit_event(no_grant).await.unwrap_err();
    assert_eq!(
        error.conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(footprint(&pool).await, before);
    let realm = head.authority_commit.event.realm_id.clone();
    #[derive(diesel::QueryableByName)]
    struct RootRow {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
    }
    let mut conn = pool.get().await.unwrap();
    let root = diesel::sql_query(
        "SELECT authority_event_ref FROM realm_authority_root_current_results WHERE realm_id=$1",
    )
    .bind::<Text, _>(realm.as_str())
    .get_result::<RootRow>(&mut *conn)
    .await
    .unwrap()
    .authority_event_ref;
    drop(conn);
    let grant = ordinary_realm::next_request_for_actor(
        &head.authority_commit,
        EventKind::CapabilityGrant,
        founder.clone(),
        json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":discussion.unit.transactions[0].event.actor_id,
        "subject":ActorId::account(member.clone()),"actions":["ak.call.join"],"resources":[{"kind":"realm","realm_id":realm}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":root,"authority_generation":0}],
        "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        at,
    );
    uow.commit_event(grant.clone()).await.unwrap();
    let call = ordinary_realm::next_request_for_actor(
        &grant.authority_commit,
        EventKind::CallCreate,
        ActorId::account(member.clone()),
        json!({"initial_state":"ringing"}),
        at,
    );
    uow.commit_event(call.clone()).await.unwrap();
    let unauthorized_moderation = ordinary_realm::next_request_for_actor(
        &call.authority_commit,
        EventKind::CallState,
        ActorId::account(member.clone()),
        json!({"call_id":arkret_wire::CallId::from_event_id(&call.authority_commit.event.event_id),
        "moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":ActorId::account(member.clone()),"action":"ban",
            "removed_by":member.principal_id,"removed_at":arkret_canonical::format_timestamp_canonical(at)
        }}}),
        at,
    );
    let before = footprint(&pool).await;
    assert_eq!(
        uow.commit_event(unauthorized_moderation)
            .await
            .unwrap_err()
            .conflict_code(),
        Some(coland_storage::ConflictCode::CapabilityDenied)
    );
    assert_eq!(footprint(&pool).await, before);
    let other = arkret_wire::AccountId::new(
        member.principal_id.clone(),
        arkret_wire::DidCoreId::new("ak:did_core:web:other-call-station.example").unwrap(),
    );
    refused(
        &uow,
        &pool,
        ordinary_realm::next_request_for_actor(
            &call.authority_commit,
            EventKind::CallCreate,
            ActorId::account(other),
            json!({"initial_state":"ringing"}),
            at,
        ),
    )
    .await;
    // Exercise the actual storage final permission cut after accepted revokes.
    // Voluntary ingress proof verification belongs to the real HTTP suite;
    // this isolates membership and grants without a stale/missing roster leg.
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let call_id = arkret_wire::CallId::from_event_id(&call.authority_commit.event.event_id);
    let issuer = ordinary_realm::station();
    let media = ordinary_realm::next_request_for_actor(
        &call.authority_commit,
        EventKind::RealmMediaService,
        founder.clone(),
        json!({"value":{"service_id":issuer,"foci":[{
            "focus_id":"permission-cut","focus_kind":"livekit",
            "token_endpoint":"https://media.example/token","connect_url":"wss://media.example"
        }]}}),
        at,
    );
    uow.commit_event(media.clone()).await.unwrap();
    let focus = ordinary_realm::next_request_for_actor(
        &media.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"focus":{"mode":"sfu","session_focus":"permission-cut"}}),
        at,
    );
    uow.commit_event(focus.clone()).await.unwrap();
    let member_history = human_profile::fixture(&ordinary_realm::station(), "call-member").history;
    assert_eq!(member_history.account, member);
    let device = member_history.founding_device_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&member_history.founding_device_signing_seed);
    let now = arkret_canonical::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut request = arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody {
        realm_id: realm.clone(), call_id, actor_id: ActorId::account(member.clone()), device_id: device,
        focus_id: "permission-cut".to_owned(), capability_refs: Vec::new(), desired_media: None,
        join_context: arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(
            arkret_models_collaboration::call_invitation::CallVoluntaryJoinContext {
                kind: arkret_models_collaboration::call_invitation::CallVoluntaryJoinKind::Voluntary,
                created_at: now, expires_at: now+chrono::Duration::seconds(60),
                nonce: arkret_canonical::base64url_encode([71;32]),
                proof: arkret_models_collaboration::call_invitation::CallVoluntaryJoinProof {
                    verification_method: member_history.device_verification_method.to_string(),
                    jws: "unused-at-storage-final-cut".to_owned(),
                },
            }),
    };
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key).unwrap();
    assert!(
        store
            .check_call_media_release(&request, &issuer)
            .await
            .unwrap()
    );
    let revoked = ordinary_realm::next_request_for_actor(
        &focus.authority_commit,
        EventKind::CapabilityRevoke,
        founder.clone(),
        json!({"grant_id":arkret_wire::GrantId::from_event_id(&grant.authority_commit.event.event_id),
            "expected_revision":{"commit_id":grant.authority_commit.commit.commit_id,
                "stream_position":grant.authority_commit.commit.stream_position}}),
        at,
    );
    uow.commit_event(revoked.clone()).await.unwrap();
    if let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(intent) =
        &mut request.join_context
    {
        intent.nonce = arkret_canonical::base64url_encode([72; 32]);
    }
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key).unwrap();
    assert!(
        !store
            .check_call_media_release(&request, &issuer)
            .await
            .unwrap()
    );
    let renewed = ordinary_realm::next_request_for_actor(
        &revoked.authority_commit,
        EventKind::CapabilityGrant,
        founder,
        {
            let mut payload = serde_json::to_value(&grant.authority_commit.event.payload).unwrap();
            payload["grant"]["issued_at"] = json!(arkret_canonical::format_timestamp_canonical(
                at + chrono::Duration::milliseconds(1),
            ));
            payload
        },
        at + chrono::Duration::milliseconds(1),
    );
    uow.commit_event(renewed.clone()).await.unwrap();
    if let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(intent) =
        &mut request.join_context
    {
        intent.nonce = arkret_canonical::base64url_encode([73; 32]);
    }
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key).unwrap();
    assert!(
        store
            .check_call_media_release(&request, &issuer)
            .await
            .unwrap()
    );
    let membership = arkret_models_collaboration::governance::membership_invite::MembershipPayload::transition(
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
        ActorId::account(member), "Call final membership cut",
    ).with_realm_id(realm).to_value().unwrap();
    let left = ordinary_realm::next_request_for_actor(
        &renewed.authority_commit,
        EventKind::MemberState,
        request.actor_id.clone(),
        membership,
        at + chrono::Duration::milliseconds(1),
    );
    uow.commit_event(left).await.unwrap();
    if let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(intent) =
        &mut request.join_context
    {
        intent.nonce = arkret_canonical::base64url_encode([74; 32]);
    }
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key).unwrap();
    assert!(
        !store
            .check_call_media_release(&request, &issuer)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn moderation_entries_retain_bans_kicks_and_guard_the_whole_axis() {
    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-moderation-current").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let call = ordinary_realm::next_request_for_actor(
        &discussion.head.authority_commit,
        EventKind::CallCreate,
        founder.clone(),
        json!({"initial_state":"ringing"}),
        at,
    );
    uow.commit_event(call.clone()).await.unwrap();
    let call_id = arkret_wire::CallId::from_event_id(&call.authority_commit.event.event_id);
    let ban = ordinary_realm::next_request_for_actor(
        &call.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":founder,"action":"ban","removed_by":founder.signing_principal_id(),
            "removed_at":arkret_canonical::format_timestamp_canonical(at)
        }}}),
        at,
    );
    uow.commit_event(ban.clone()).await.unwrap();
    let kick = ordinary_realm::next_request_for_actor(
        &ban.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":founder,"device_id":"ak:device:01904100-0000-7000-8000-00000000000a",
            "action":"kick","removed_by":founder.signing_principal_id(),
            "removed_at":arkret_canonical::format_timestamp_canonical(at)
        }}}),
        at,
    );
    uow.commit_event(kick.clone()).await.unwrap();
    let restore = |revision: &arkret_wire::RealmCommit| {
        ordinary_realm::next_request_for_actor(
            &kick.authority_commit,
            EventKind::CallState,
            founder.clone(),
            json!({"call_id":call_id,"moderation_delta":{"op":"restore_participant",
                "actor_id":founder,"restored_by":founder.signing_principal_id(),
                "restored_at":arkret_canonical::format_timestamp_canonical(at),
                "expected_revision":{"commit_id":revision.commit_id,"stream_position":revision.stream_position}
            }}),
            at,
        )
    };
    let before = footprint(&pool).await;
    assert!(
        uow.commit_event(restore(&ban.authority_commit.commit))
            .await
            .is_err()
    );
    assert_eq!(footprint(&pool).await, before);
    let restored = restore(&kick.authority_commit.commit);
    uow.commit_event(restored.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let value = diesel::sql_query("SELECT value FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector->>'kind'='call_moderation'")
        .bind::<Text,_>(discussion.realm_id().as_str()).bind::<Text,_>(call_id.as_str())
        .get_result::<ValueRow>(&mut *conn).await.unwrap().value;
    let current: arkret_models_collaboration::events_payloads::call::CallModerationCurrentValue =
        serde_json::from_value(value).unwrap();
    current
        .validate_for_axis(
            &restored.authority_commit.commit.stream_ref,
            &arkret_wire::CurrentRevision {
                commit_id: restored.authority_commit.commit.commit_id.clone(),
                stream_position: restored.authority_commit.commit.stream_position,
            },
        )
        .unwrap();
    assert_eq!(current.entries.len(), 1);
    assert_eq!(
        current.last_source.source_commit,
        restored.authority_commit.commit
    );
    let effective = current.effective_removals().unwrap();
    assert_eq!(effective.len(), 1);
    assert_eq!(
        effective[0].action,
        arkret_models_collaboration::events_payloads::call::CallParticipantRemovalAction::Kick
    );
    assert_eq!(
        current.entries[0].source_commit,
        kick.authority_commit.commit
    );
    for original in [&ban, &kick, &restored] {
        let retained = diesel::sql_query("SELECT EXISTS(SELECT 1 FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.commit_json->>'commit_id'=$1) AS found")
            .bind::<Text,_>(original.authority_commit.commit.commit_id.as_str())
            .get_result::<RetainedSource>(&mut *conn).await.unwrap();
        assert!(retained.found);
    }
    drop(conn);
    let snapshot = PgAuthorityCommitStore { pool: pool.clone() }
        .realm_state_snapshot_material_for_account(
            &discussion.realm_id(),
            founder.as_account_id().unwrap(),
        )
        .await
        .unwrap()
        .expect("moderator receives the complete accepted current");
    assert!(snapshot.current_state_entries.iter().any(|row| matches!(row,
        arkret_wire::TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::CallModeration { call_id: selected }, value, ..
        } if selected == &call_id && value == &serde_json::to_value(&current).unwrap()
    )));
    // Keep one effective kick while repeated ban/restore history grows.
    // The actual PG writer and read remain bounded by effective entries.
    let mut latest = restored;
    for index in 1..=16 {
        let started = std::time::Instant::now();
        let changed_at = at + chrono::Duration::seconds(index * 2);
        let remove = ordinary_realm::next_request_for_actor(
            &latest.authority_commit,
            EventKind::CallState,
            founder.clone(),
            json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
                "actor_id":founder,"action":"ban","removed_by":founder.signing_principal_id(),
                "removed_at":arkret_canonical::format_timestamp_canonical(changed_at)
            }}}),
            changed_at,
        );
        uow.commit_event(remove.clone()).await.unwrap();
        let restore = ordinary_realm::next_request_for_actor(
            &remove.authority_commit,
            EventKind::CallState,
            founder.clone(),
            json!({"call_id":call_id,"moderation_delta":{"op":"restore_participant",
                "actor_id":founder,"restored_by":founder.signing_principal_id(),
                "restored_at":arkret_canonical::format_timestamp_canonical(changed_at),
                "expected_revision":{"commit_id":remove.authority_commit.commit.commit_id,
                    "stream_position":remove.authority_commit.commit.stream_position}
            }}),
            changed_at,
        );
        uow.commit_event(restore.clone()).await.unwrap();
        let mut conn = pool.get().await.unwrap();
        let value = diesel::sql_query("SELECT value FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector->>'kind'='call_moderation'")
            .bind::<Text,_>(discussion.realm_id().as_str()).bind::<Text,_>(call_id.as_str())
            .get_result::<ValueRow>(&mut *conn).await.unwrap().value;
        assert_eq!(value["entries"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["entries"][0]["source_commit"],
            json!(kick.authority_commit.commit)
        );
        assert_eq!(
            value["last_source"]["source_commit"],
            json!(restore.authority_commit.commit)
        );
        let bytes = arkret_canonical::canonical_json_bytes(&value)
            .unwrap()
            .len();
        assert!(bytes < 8192);
        if matches!(index, 1 | 8 | 16) {
            eprintln!(
                "call_effective_moderation_cost ban_restore_pairs={index} entries=1 wire_bytes={bytes} actual_pg_us={}",
                started.elapsed().as_micros()
            );
        }
        latest = restore;
    }
}

#[tokio::test]
async fn full_actor_roster_refresh_rejects_other_station_old_leg_kick_and_leave() {
    use arkret_models_collaboration::call_invitation::{
        CallInvitationMedia, CallMediaJoinContext, CallRefreshJoinContext, CallRefreshJoinKind,
    };
    use arkret_models_collaboration::objects::media::{
        CallMediaDesiredMedia, CallMediaTokenExchangeRequestBody,
    };
    use ed25519_dalek::Signer as _;

    let database = TestDatabase::lease().await;
    let pool = database.pool();
    let discussion = ordinary_realm::open_human_discussion(&pool, "call-full-actor-roster").await;
    let uow = PgEventCommitUnitOfWork::new(pool.clone());
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    let founder = discussion.head.authority_commit.event.actor_id.clone();
    let at = discussion.head.authority_commit.commit.committed_at;
    let call = ordinary_realm::next_request_for_actor(
        &discussion.head.authority_commit,
        EventKind::CallCreate,
        founder.clone(),
        json!({"initial_state":"ringing"}),
        at,
    );
    uow.commit_event(call.clone()).await.unwrap();
    let call_id = arkret_wire::CallId::from_event_id(&call.authority_commit.event.event_id);
    let device = call
        .authority_commit
        .event
        .account_device_producer()
        .unwrap()
        .unwrap()
        .device_id;
    let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(2115);
    let endpoint = url::Url::parse("https://media.example/").unwrap();
    let inception = arkret_signatures::webvh::prepare_service_inception_with_did_key_seed(
        &mut rng,
        &arkret_signatures::webvh::ServiceInceptionInput {
            principal_endpoint: &endpoint,
            local_id: "service",
            also_known_as: &[],
            version_time: at - chrono::Duration::seconds(60),
            did_key_fragment: Some("issuer"),
        },
        &[23; 32],
    )
    .unwrap();
    let did = arkret_wire::Did::new(inception.did.clone()).unwrap();
    let issuer = arkret_wire::project_did_to_core_id(&did).unwrap();
    let issuer_kid = inception.did_key_id.clone();
    let first_history = arkret_identity::build_authenticated_webvh_service_resolution(
        issuer.clone(),
        "media_service".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        at,
    )
    .unwrap();
    let rotated_key = ed25519_dalek::SigningKey::from_bytes(&[24; 32]);
    let mut rotated_state = inception.log_entry["state"].clone();
    rotated_state["verificationMethod"][0]["publicKeyMultibase"] =
        json!(arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            rotated_key.verifying_key().as_bytes()
        ));
    let next_update = ed25519_dalek::SigningKey::from_bytes(&[25; 32]);
    let next_update_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        next_update.verifying_key().as_bytes(),
    );
    let previous_entries = vec![inception.log_entry.clone()];
    let rotation = arkret_signatures::webvh::prepare_service_rotation(
        &arkret_signatures::webvh::ServiceRotationInput {
            did: did.as_str(),
            previous_entries: &previous_entries,
            state: &rotated_state,
            current_update_seed: &inception.next_update_key_seed,
            next_update_public_key_multibase: &next_update_public,
            version_time: at + chrono::Duration::seconds(2),
        },
    )
    .unwrap();
    let rotated_history = arkret_identity::build_authenticated_webvh_service_resolution(
        issuer.clone(),
        "media_service".into(),
        serde_json::from_value(rotated_state).unwrap(),
        vec![inception.log_entry.clone(), rotation.log_entry],
        vec![],
        at + chrono::Duration::seconds(3),
    )
    .unwrap();
    let service = ordinary_realm::next_request_for_actor(
        &call.authority_commit,
        EventKind::RealmMediaService,
        founder.clone(),
        json!({"value":{"service_id":issuer,"foci":[{
            "focus_id":"direct-actor","focus_kind":"livekit",
            "token_endpoint":"https://media.example/token","connect_url":"wss://media.example"
        }]}}),
        at,
    );
    uow.commit_event(service.clone()).await.unwrap();
    let realm_id = discussion.realm_id();
    let join = |previous: &coland_storage::AuthorityCommitTransaction, index: u32| {
        let key = if index < 3 { &key } else { &rotated_key };
        let history = if index < 3 {
            &first_history
        } else {
            &rotated_history
        };
        let participant = format!("ak:rtc_participant:01964137-0000-7000-8000-{index:012x}");
        let expires_at = at + chrono::Duration::seconds(300 + i64::from(index));
        let fields = arkret_signatures::media::ParticipantBindingContext {
            actor_id: &founder,
            device_id: &device,
            call_id: &call_id,
            realm_id: &realm_id,
            focus_id: "direct-actor",
            participant_id: &participant,
            expires_at,
            issuer_kid: &issuer_kid,
            media: CallInvitationMedia {
                audio: true,
                video: false,
                screen: false,
            },
        };
        let signature = arkret_canonical::base64url_encode(
            key.sign(
                &arkret_signatures::media::participant_binding_signing_input(&fields).unwrap(),
            )
            .to_bytes(),
        );
        let mut request = ordinary_realm::next_request_for_actor(
            previous,
            EventKind::CallState,
            founder.clone(),
            json!({"call_id":call_id,"focus":{"mode":"sfu","session_focus":"direct-actor"},
            "roster_delta":{"op":"join","participant":{
                "actor_id":founder,"device_id":device,"focus_id":"direct-actor",
                "participant_id":participant,"media":{"audio":true,"video":false,"screen":false},
                "participant_binding":{"expires_at":arkret_canonical::format_timestamp_canonical(expires_at),
                    "issuer_kid":issuer_kid,"sig":signature}
            }}}),
            at + chrono::Duration::seconds(i64::from(index)),
        );
        request.verified_media_participant =
            arkret_signatures::media::VerifiedCallParticipant::verify(
                &request.authority_commit.event,
                &issuer,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            )
            .unwrap()
            .map(|verified| verified.with_issuer_history(history.clone()));
        request
    };
    let joined = join(&service.authority_commit, 1);
    let mut missing_native_history = joined.clone();
    missing_native_history.verified_media_participant =
        arkret_signatures::media::VerifiedCallParticipant::verify(
            &missing_native_history.authority_commit.event,
            &issuer,
            &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().to_bytes().to_vec(),
            },
        )
        .unwrap();
    let before_missing_history = footprint(&pool).await;
    assert!(uow.commit_event(missing_native_history).await.is_err());
    assert_eq!(
        footprint(&pool).await,
        before_missing_history,
        "missing native history must roll back the focus, issuer material and original Event/Commit together"
    );
    uow.commit_event(joined.clone()).await.unwrap();
    let cut = store
        .call_current_cut(&discussion.realm_id(), &call_id, &founder)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cut.participants.len(), 1);
    assert_eq!(cut.participants[0].0.actor_id, founder);
    assert_eq!(cut.participants[0].0.device_id, device.as_str());
    let mut refresh = CallMediaTokenExchangeRequestBody {
        realm_id: discussion.realm_id(),
        call_id: call_id.clone(),
        actor_id: founder.clone(),
        device_id: device.clone(),
        focus_id: "direct-actor".into(),
        capability_refs: vec![],
        desired_media: Some(CallMediaDesiredMedia {
            audio: Some(true),
            video: Some(false),
            screen: Some(false),
        }),
        join_context: CallMediaJoinContext::Refresh(CallRefreshJoinContext {
            kind: CallRefreshJoinKind::Refresh,
            participant_id: cut.participants[0].0.participant_id.clone().unwrap(),
        }),
    };
    assert!(
        store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let mut other_station = refresh.clone();
    let mut account = founder.as_account_id().unwrap().clone();
    account.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    other_station.actor_id = ActorId::account(account);
    assert!(
        !store
            .check_call_media_release(&other_station, &issuer)
            .await
            .unwrap()
    );
    let mut other_device = refresh.clone();
    other_device.device_id = "ak:device:01964137-0000-7000-8000-00000000dead"
        .parse()
        .unwrap();
    assert!(
        !store
            .check_call_media_release(&other_device, &issuer)
            .await
            .unwrap()
    );
    let mut expansion = refresh.clone();
    expansion.desired_media.as_mut().unwrap().video = Some(true);
    assert!(
        !store
            .check_call_media_release(&expansion, &issuer)
            .await
            .unwrap()
    );
    let kick = ordinary_realm::next_request_for_actor(
        &joined.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":founder,"device_id":device,"action":"kick",
            "removed_by":founder.signing_principal_id(),"removed_at":arkret_canonical::format_timestamp_canonical(at)
        }}}),
        at + chrono::Duration::seconds(2),
    );
    uow.commit_event(kick.clone()).await.unwrap();
    assert!(
        !store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let rejoined = join(&kick.authority_commit, 3);
    uow.commit_event(rejoined.clone()).await.unwrap();
    assert!(
        !store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let current = store
        .call_current_cut(&discussion.realm_id(), &call_id, &founder)
        .await
        .unwrap()
        .unwrap();
    if let CallMediaJoinContext::Refresh(context) = &mut refresh.join_context {
        context.participant_id = current.participants[0].0.participant_id.clone().unwrap();
    }
    assert!(
        store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let mut latest = rejoined;
    for index in 4..=35 {
        let next = join(&latest.authority_commit, index);
        let started = std::time::Instant::now();
        uow.commit_event(next.clone()).await.unwrap();
        let mut conn = pool.get().await.unwrap();
        let value=diesel::sql_query("SELECT value FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector->>'kind'='call_roster'")
            .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(call_id.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap().value;
        let projected: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
            serde_json::from_value(value.clone()).unwrap();
        assert_eq!(projected.entries.len(), 1);
        assert_eq!(
            projected.last_source.source_commit,
            next.authority_commit.commit
        );
        assert!(
            arkret_canonical::canonical_json_bytes(&value)
                .unwrap()
                .len()
                < 8192
        );
        if matches!(index, 4 | 11 | 19 | 35) {
            eprintln!(
                "call_effective_cost accepted_join={index} entries=1 wire_bytes={} actual_pg_us={}",
                arkret_canonical::canonical_json_bytes(&value)
                    .unwrap()
                    .len(),
                started.elapsed().as_micros()
            );
        }
        latest = next;
    }
    let latest_cut = store
        .call_current_cut(&realm_id, &call_id, &founder)
        .await
        .unwrap()
        .unwrap();
    if let CallMediaJoinContext::Refresh(context) = &mut refresh.join_context {
        context.participant_id = latest_cut.participants[0].0.participant_id.clone().unwrap();
    }
    assert!(
        store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let banned = ordinary_realm::next_request_for_actor(
        &latest.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"moderation_delta":{"op":"remove_participant","removal":{
            "actor_id":founder,"action":"ban","removed_by":founder.signing_principal_id(),
            "removed_at":arkret_canonical::format_timestamp_canonical(at)
        }}}),
        at + chrono::Duration::seconds(36),
    );
    uow.commit_event(banned.clone()).await.unwrap();
    assert!(
        !store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let restored = ordinary_realm::next_request_for_actor(
        &banned.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"moderation_delta":{"op":"restore_participant",
            "actor_id":founder,"restored_by":founder.signing_principal_id(),
            "restored_at":arkret_canonical::format_timestamp_canonical(at),
            "expected_revision":{"commit_id":banned.authority_commit.commit.commit_id,
                "stream_position":banned.authority_commit.commit.stream_position}
        }}),
        at + chrono::Duration::seconds(37),
    );
    uow.commit_event(restored.clone()).await.unwrap();
    assert!(
        store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let moderation = store
        .call_current_cut(&realm_id, &call_id, &founder)
        .await
        .unwrap()
        .unwrap()
        .moderation_current
        .unwrap();
    assert_eq!(moderation.entries.len(), 1);
    assert_eq!(
        moderation.entries[0].source_commit,
        kick.authority_commit.commit
    );
    latest = restored;
    let left = ordinary_realm::next_request_for_actor(
        &latest.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"roster_delta":{"op":"leave","actor_id":founder,
            "device_id":device,"expected_revision":latest_cut.roster_revision.unwrap()}}),
        at + chrono::Duration::seconds(38),
    );
    uow.commit_event(left.clone()).await.unwrap();
    let mut conn = pool.get().await.unwrap();
    let retained=diesel::sql_query("SELECT jsonb_build_object('current',(SELECT value FROM call_component_current_results WHERE realm_id=$1 AND call_id=$2 AND selector->>'kind'='call_roster'),'original_keys',(SELECT count(*) FROM call_participant_issuer_sources WHERE realm_id=$1 AND call_id=$2)) AS value")
        .bind::<Text,_>(realm_id.as_str()).bind::<Text,_>(call_id.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap().value;
    assert_eq!(retained["current"]["entries"], json!([]));
    assert_eq!(
        retained["current"]["last_source"]["source_commit"],
        json!(left.authority_commit.commit)
    );
    assert_eq!(retained["original_keys"], json!(34));
    let original_key=diesel::sql_query("SELECT jsonb_build_object('key',public_key_b64u,'history',issuer_history) AS value FROM call_participant_issuer_sources WHERE source_commit_id=$1")
        .bind::<Text,_>(joined.authority_commit.commit.commit_id.as_str()).get_result::<ValueRow>(&mut *conn).await.unwrap().value;
    assert_eq!(
        original_key["key"],
        json!(arkret_canonical::base64url_encode(
            key.verifying_key().as_bytes()
        ))
    );
    assert_ne!(
        original_key["key"],
        json!(arkret_canonical::base64url_encode(
            rotated_key.verifying_key().as_bytes()
        ))
    );
    assert!(original_key["history"].is_object());

    drop(conn);
    assert!(
        !store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    // A new accepted leg is usable after leave, until the accepted lifecycle
    // becomes terminal. This isolates the terminal gate from the missing leg.
    let joined_again = join(&left.authority_commit, 39);
    uow.commit_event(joined_again.clone()).await.unwrap();
    let active = store
        .call_current_cut(&realm_id, &call_id, &founder)
        .await
        .unwrap()
        .unwrap();
    if let CallMediaJoinContext::Refresh(context) = &mut refresh.join_context {
        context.participant_id = active.participants[0].0.participant_id.clone().unwrap();
    }
    assert!(
        store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
    let cancelled = ordinary_realm::next_request_for_actor(
        &joined_again.authority_commit,
        EventKind::CallState,
        founder.clone(),
        json!({"call_id":call_id,"state_transition":{"from":"ringing","to":"cancelled"}}),
        at + chrono::Duration::seconds(40),
    );
    uow.commit_event(cancelled).await.unwrap();
    assert!(
        !store
            .check_call_media_release(&refresh, &issuer)
            .await
            .unwrap()
    );
}

#[derive(diesel::QueryableByName)]
struct RetainedSource {
    #[diesel(sql_type=diesel::sql_types::Bool)]
    found: bool,
}
