//! Real allocation serialized against the native two-Event recovery unit.

use std::sync::Arc;

use arkret_models_crypto::*;
use arkret_wire::*;
use coland_storage::{
    DeviceRevocationGateSelector, IdentityStoreRegistry as _, MlsKeyPackageClaimAdmission,
    MlsKeyPackageRow, MlsKeyPackageStore as _, PeerKeyPackageClaimAttempt,
    PeerKeyPackageClaimAttemptResult, PeerKeyPackageClaimLedgerRecord, PersistenceResult,
};
use coland_storage_postgres::{PgMlsKeyPackageStore, PgPersistenceStore, PgPool};
use diesel::sql_types::Integer;
use diesel_async::SimpleAsyncConnection as _;
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::FutureExt as _;
use horme::RunQueryDsl as _;

use super::{RootFixture, identity_recovery, random};

#[derive(Clone)]
struct PreparedClaim {
    row: MlsKeyPackageRow,
    admission: Arc<MlsKeyPackageClaimAdmission>,
    selector: DeviceRevocationGateSelector,
    ledger: PeerKeyPackageClaimLedgerRecord,
}

impl PreparedClaim {
    fn remote_intent(&self) -> KeyPackagesClaimRequestBody {
        let mut request = self.admission.request.clone();
        request.claim_request_id = random();
        let destination = DidCoreId::new("ak:did_core:web:remote-claim-target.example").unwrap();
        request.service_binding.destination_id = destination.clone();
        request.target_account_id = Some(AccountId::new(
            DidCoreId::new("ak:did_core:web:remote-claim-member.example").unwrap(),
            destination,
        ));
        request.target_device_ids =
            vec![DeviceId::new(format!("ak:device:{}", uuid::Uuid::now_v7())).unwrap()];
        request.target_keypackage_ref = None;
        sign_request(&mut request, 81);
        request.validate_shape().unwrap();
        request
    }

    fn without_local_realm_guard(&self) -> Self {
        // A real Human signing key does not make its caller-declared Realm
        // Actor a native managed requester. This is only a negative request.
        let mut forged = self.clone();
        let admission = Arc::make_mut(&mut forged.admission);
        let request = &mut admission.request;
        let account = request.requester_account_id.take().unwrap();
        request.requester_actor_id = Some(ActorId::realm(RealmActorId::new(
            request.intended_realm_id.clone(),
            account.principal_id,
        )));
        let PeerKeyPackageRequesterAuthorization::Device {
            verification_method,
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            signature,
        } = request.requester_authorization.clone()
        else {
            unreachable!()
        };
        request.requester_authorization = PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method: verification_method.clone(),
            requester_device_id,
            device_authorize_event_id,
            signed_at,
            signature,
        };
        let bytes = keypackage_claim_authorization_signing_bytes(
            &request.unsigned_request(),
            &request.service_binding,
            &request.requester_authorization,
        )
        .unwrap();
        let PeerKeyPackageRequesterAuthorization::RealmDevice { signature, .. } =
            &mut request.requester_authorization
        else {
            unreachable!()
        };
        *signature = operation_signature(verification_method.as_str(), [81; 32], &bytes);
        request.validate_shape().unwrap();
        let digest = Hash::new(arkret_canonical::canonical_sha256(request).unwrap()).unwrap();
        let mut outcome: KeyPackagesClaimResponseBody =
            serde_json::from_value(forged.ledger.outcome.clone().unwrap()).unwrap();
        outcome.claim_receipt.request_digest = digest.clone();
        outcome.claim_receipt.request = request.unsigned_request();
        let method = outcome.claim_receipt.signature.kid.clone();
        outcome.claim_receipt.signature = operation_signature(
            method.as_str(),
            [83; 32],
            &peer_keypackage_claim_receipt_signing_bytes(&outcome.claim_receipt).unwrap(),
        );
        outcome.validate_shape().unwrap();
        forged.ledger.request_digest = digest.to_string();
        forged.ledger.outcome = Some(serde_json::to_value(outcome).unwrap());
        forged
    }

    async fn allocate(
        &self,
        pool: &PgPool,
        with_command: bool,
    ) -> PersistenceResult<PeerKeyPackageClaimAttemptResult> {
        PgMlsKeyPackageStore { pool: pool.clone() }
            .try_claim_peer(PeerKeyPackageClaimAttempt {
                admission: with_command.then(|| self.admission.clone()),
                applet_device_scope_guard: None,
                keypackage_id: &self.row.id,
                mls_group_id: self.admission.request.mls_group_id.as_str(),
                device_authorize_event_id: self.row.device_authorize_event_id.as_deref(),
                agent_key_authorize_event_id: None,
                device_revocation_gate: Some(self.selector.clone()),
                claimed_at_unix_ms: self.ledger.updated_at * 1000,
                claim_expires_at_unix_ms: self.ledger.claim_expires_at_unix_ms.unwrap(),
                ledger: &self.ledger,
            })
            .await
    }
}

fn operation_signature(method: &str, seed: [u8; 32], bytes: &[u8]) -> KeyOperationSignature {
    arkret_signatures::keypackages::keypackage_signature_from_bytes(
        method,
        &SigningKey::from_bytes(&seed).sign(bytes).to_bytes(),
    )
    .unwrap()
}

fn sign_request(request: &mut KeyPackagesClaimRequestBody, seed: u8) {
    let input = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device {
        verification_method,
        signature,
        ..
    } = &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = operation_signature(verification_method.as_str(), [seed; 32], &input);
}

async fn exercise_origin(pool: &PgPool, request: &KeyPackagesClaimRequestBody) {
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    let deadline = chrono::Utc::now() + chrono::Duration::minutes(5);
    let digest = arkret_canonical::canonical_sha256(request).unwrap();
    assert!(
        store
            .peer_claim_original(request.claim_request_id.as_str(), &digest)
            .await
            .unwrap()
            .is_none()
    );
    let mut bad = request.clone();
    sign_request(&mut bad, 82);
    assert!(
        store
            .prepare_ordinary_claim_source(&bad, deadline)
            .await
            .is_err()
    );
    assert!(
        store
            .peer_claim_original(request.claim_request_id.as_str(), &digest)
            .await
            .unwrap()
            .is_none()
    );
    let mut other_subject = request.clone();
    other_subject
        .requester_account_id
        .as_mut()
        .unwrap()
        .principal_id = DidCoreId::new("ak:did_core:web:another-origin-subject.example").unwrap();
    sign_request(&mut other_subject, 81);
    assert!(
        store
            .prepare_ordinary_claim_source(&other_subject, deadline)
            .await
            .is_err()
    );
    assert!(
        store
            .peer_claim_original(request.claim_request_id.as_str(), &digest)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .prepare_ordinary_claim_source(
                request,
                chrono::Utc::now() - chrono::Duration::seconds(1)
            )
            .await
            .is_err()
    );
    // This proves only the real local requester's signed intent. No remote
    // membership, KeyPackage, outcome or network delivery is fabricated.
    assert!(
        store
            .prepare_ordinary_claim_source(request, deadline)
            .await
            .unwrap()
    );
    assert!(
        !store
            .prepare_ordinary_claim_source(request, deadline)
            .await
            .unwrap()
    );
    let archived = store
        .peer_claim_original(request.claim_request_id.as_str(), &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&archived).unwrap(),
        arkret_canonical::canonical_json_bytes(request).unwrap()
    );
    let mut conflict = request.clone();
    conflict.expires_at -= chrono::Duration::seconds(1);
    sign_request(&mut conflict, 81);
    let error = store
        .prepare_ordinary_claim_source(&conflict, deadline)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("duplicate_conflict"), "{error}");
    assert!(
        store
            .get_peer_claim(
                request.service_binding.source_id.as_str(),
                request.claim_request_id.as_str()
            )
            .await
            .unwrap()
            .is_none()
    );
    #[derive(diesel::QueryableByName)]
    struct NativeRow {
        #[diesel(sql_type = diesel::sql_types::Jsonb)]
        payload: serde_json::Value,
    }
    let mut conn = pool.get().await.unwrap();
    let row = diesel::sql_query("SELECT jsonb_build_object('actor',s.actor_id,'authorization',e.envelope->>'event_id','authorization_state',e.state,'commit',c.commit_json->>'event_ref','counter_count',(SELECT count(*) FROM keypackage_claim_attempts t WHERE t.source_id=s.source_id AND t.claim_request_id=s.claim_request_id)) AS payload FROM ordinary_keypackage_claim_sources s JOIN canonical_events e ON e.pk=s.authorization_event_pk JOIN realm_commits c ON c.commit_id=s.authorization_commit_id WHERE s.source_id=$1 AND s.claim_request_id=$2")
        .bind::<diesel::sql_types::Text, _>(request.service_binding.source_id.as_str())
        .bind::<diesel::sql_types::Text, _>(request.claim_request_id.as_str())
        .get_result::<NativeRow>(&mut *conn).await.unwrap();
    let PeerKeyPackageRequesterAuthorization::Device {
        device_authorize_event_id,
        ..
    } = &request.requester_authorization
    else {
        unreachable!()
    };
    assert_eq!(
        row.payload["actor"],
        serde_json::to_value(ActorId::account(
            request.requester_account_id.clone().unwrap()
        ))
        .unwrap()
    );
    assert_eq!(
        row.payload["authorization"],
        serde_json::json!(device_authorize_event_id)
    );
    assert_eq!(
        row.payload["commit"],
        serde_json::json!(device_authorize_event_id)
    );
    assert_eq!(row.payload["authorization_state"], "committed");
    assert_eq!(row.payload["counter_count"], 0);
}

async fn prepare(pool: &PgPool, fixture: &RootFixture, seed: u8) -> PreparedClaim {
    let history = &fixture.pcr.history;
    let account = history.account.clone();
    let actor = ActorId::account(account.clone());
    let persistence = PgPersistenceStore::new(pool.clone());
    if persistence
        .accounts()
        .get(&account)
        .await
        .unwrap()
        .is_none()
    {
        // Only the local display/storage index is materialized here. Authority
        // remains the already accepted real PCR unit and Device original.
        persistence
            .accounts()
            .put(&coland_storage::AccountRecord {
                pk: coland_storage::AccountPk(0),
                principal_id: account.principal_id.clone(),
                station_id: account.station_id.clone(),
                localpart: "claim-owner".into(),
                display_name: None,
                biography: None,
                avatar_blob_ref: None,
                created_at: history.events[0].created_at,
            })
            .await
            .unwrap();
    }
    let device = history.founding_device_id.clone();
    let authorize = history.events[1].event_id.clone();
    let scope = ScopeRef::Realm {
        realm_id: history.events[0].realm_id.clone(),
    };
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[seed; 32])),
    )
    .unwrap();
    let package = identity.key_package_record().unwrap();
    let row = MlsKeyPackageRow {
        id: package.keypackage_id,
        keypackage_ref: package.keypackage_ref.to_string(),
        keypackage_digest: package.keypackage_ref.to_string(),
        owner_actor_id: actor.clone(),
        effective_scope: None,
        actor_id: account.principal_id.to_string(),
        device_id: Some(device.to_string()),
        endpoint_verification_method: None,
        key_package_bytes: arkret_canonical::base64url_decode(&package.keypackage).unwrap(),
        capabilities: package.capabilities.clone(),
        capabilities_digest: arkret_canonical::canonical_sha256(&package.capabilities).unwrap(),
        last_resort: false,
        last_resort_realm_id: None,
        lifetime_not_before: package.created_at.timestamp(),
        lifetime_not_after: package.expires_at.unwrap().timestamp(),
        claimed_by_mls_group_id: None,
        device_authorize_event_id: Some(authorize.to_string()),
        agent_key_authorize_event_id: None,
        claimed_at: None,
        claim_expires_at_unix_ms: None,
        consumed_at: None,
        created_at: package.created_at.timestamp(),
    };
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    assert!(store.put(&row).await.unwrap());
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let method = history.device_verification_method.clone();
    let mut request = KeyPackagesClaimRequestBody {
        claim_request_id: random(),
        target_account_id: Some(account.clone()),
        target_actor_id: None,
        requester_account_id: Some(account.clone()),
        requester_actor_id: None,
        intended_realm_id: scope.realm_id().clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: package
            .capabilities
            .iter()
            .map(|cap| NonEmptyString::new(cap).unwrap())
            .collect(),
        expires_at: at + chrono::Duration::minutes(4),
        target_device_ids: vec![device.clone()],
        target_keypackage_ref: Some(KeyPackageRef::new(row.keypackage_ref.clone()).unwrap()),
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: None,
        service_binding: KeyPackagesClaimServiceBinding {
            source_id: account.station_id.clone(),
            destination_id: account.station_id.clone(),
        },
        requester_authorization: PeerKeyPackageRequesterAuthorization::Device {
            verification_method: method.clone(),
            requester_device_id: device.clone(),
            device_authorize_event_id: authorize.clone(),
            signed_at: at,
            signature: operation_signature(method.as_str(), [81; 32], b"unsigned construction"),
        },
    };
    let transcript = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = operation_signature(method.as_str(), [81; 32], &transcript);
    request.validate_shape().unwrap();
    assert_eq!(
        store.record_peer_claim_attempt(&request).await.unwrap(),
        coland_storage::PeerKeyPackageClaimRateDecision::Allowed
    );
    let digest = Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap();
    let claims = vec![KeyPackageClaimRecord {
        claim_id: format!("ak:keypackage_claim:{}", uuid::Uuid::now_v7()),
        keypackage_ref: row.keypackage_ref.clone(),
        actor_id: actor,
        principal_id: account.principal_id.clone(),
        device_id: Some(device.clone()),
        agent_id: None,
        agent_verification_method: None,
        keypackage: package.keypackage,
        capabilities: package.capabilities,
        device_authorize_event_id: Some(authorize.clone()),
        agent_key_authorize_event_id: None,
        expires_at: request.expires_at,
        revocation_status: Some("active".into()),
        last_resort: None,
    }];
    let station_method = history.authority_method();
    let mut receipt = PeerKeyPackageClaimReceipt {
        claim_request_id: request.claim_request_id.clone(),
        request_digest: digest.clone(),
        claims_digest: Hash::new(arkret_canonical::canonical_sha256(&claims).unwrap()).unwrap(),
        source_id: account.station_id.clone(),
        destination_id: account.station_id.clone(),
        claim_authority_ref: None,
        request: request.unsigned_request(),
        claimed_at: at,
        expires_at: request.expires_at,
        signature: operation_signature(station_method.as_str(), [83; 32], b"unsigned construction"),
    };
    receipt.signature = operation_signature(
        station_method.as_str(),
        [83; 32],
        &peer_keypackage_claim_receipt_signing_bytes(&receipt).unwrap(),
    );
    let outcome = KeyPackagesClaimResponseBody {
        claim_request_id: request.claim_request_id.clone(),
        claims,
        claim_receipt: receipt,
    };
    outcome.validate_shape().unwrap();
    let ledger = PeerKeyPackageClaimLedgerRecord {
        source_id: account.station_id.to_string(),
        claim_request_id: request.claim_request_id.to_string(),
        request_digest: digest.to_string(),
        key_package_use: "single_use".into(),
        keypackage_id: Some(row.id.clone()),
        outcome: Some(serde_json::to_value(outcome).unwrap()),
        terminal_receipt: None,
        consume_receipt: None,
        claim_expires_at_unix_ms: Some(request.expires_at.timestamp_millis()),
        expires_at: (request.expires_at + chrono::Duration::minutes(10)).timestamp(),
        state: "claimed".into(),
        updated_at: at.timestamp(),
    };
    PreparedClaim {
        row,
        ledger,
        admission: Arc::new(MlsKeyPackageClaimAdmission {
            request,
            requester: None,
            mimi_room_uri: None,
            claim_issuer_resolution: None,
        }),
        selector: DeviceRevocationGateSelector {
            principal_id: account.principal_id,
            station_id: account.station_id,
            device_id: device.to_string(),
            authorization_ref: CommittedEventRef {
                event_id: authorize,
                commit_id: history.commits[1].commit_id.clone(),
                stream_ref: history.commits[1].stream_ref.clone(),
                stream_position: history.commits[1].stream_position,
            },
        },
    }
}

#[derive(diesel::QueryableByName)]
struct Pid {
    #[diesel(sql_type = Integer)]
    pid: i32,
}

async fn waiting_on(
    conn: &mut diesel_async::AsyncPgConnection,
    blocker: i32,
    query: &str,
    minimum: usize,
) -> Option<i32> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        // Use the already held monitor connection: the leased pool has four
        // slots, exactly enough for the holder, recovery and both writers.
        // Its transaction stays open, so explicitly refresh activity stats.
        diesel::sql_query("SELECT pg_stat_clear_snapshot()")
            .execute(&mut *conn)
            .await
            .unwrap();
        // PostgreSQL may queue one row waiter behind another. Follow the
        // actual blocker chain rather than requiring two direct blockers.
        let rows = diesel::sql_query("WITH RECURSIVE blocked(pid,path) AS (SELECT a.pid,ARRAY[$1,a.pid] FROM pg_stat_activity a WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)) UNION ALL SELECT a.pid,b.path||a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid=ANY(pg_blocking_pids(a.pid)) WHERE a.datname=current_database() AND NOT a.pid=ANY(b.path)) SELECT DISTINCT a.pid FROM blocked b JOIN pg_stat_activity a ON a.pid=b.pid WHERE a.query ILIKE $2")
            .bind::<Integer, _>(blocker).bind::<diesel::sql_types::Text, _>(query)
            .get_results::<Pid>(&mut *conn).await.unwrap();
        if rows.len() >= minimum
            && let Some(row) = rows.first()
        {
            return Some(row.pid);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

pub(super) async fn recover(
    pool: &PgPool,
    fixture: &mut RootFixture,
) -> (DeviceId, EventId, DidUrl, [u8; 32], RecoverySessionId) {
    let store = PgMlsKeyPackageStore { pool: pool.clone() };
    let positive = prepare(pool, fixture, 130).await;
    assert!(positive.allocate(pool, false).await.is_err());
    let error = positive
        .without_local_realm_guard()
        .allocate(pool, true)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("native managed scope guard"),
        "{error}"
    );
    assert!(matches!(
        positive.allocate(pool, true).await.unwrap(),
        PeerKeyPackageClaimAttemptResult::Claimed(_)
    ));
    let retained_origin = positive.remote_intent();
    Box::pin(exercise_origin(pool, &retained_origin)).await;
    let candidate = prepare(pool, fixture, 131).await;
    let racing_origin = candidate.remote_intent();
    let id = candidate.row.id.clone();
    let request_id = candidate.ledger.claim_request_id.clone();
    let request_digest = candidate.ledger.request_digest.clone();
    let source = candidate.ledger.source_id.clone();
    let mut holder = pool.get().await.unwrap();
    holder.batch_execute("CREATE FUNCTION test_recovery_generation_claim_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(53182346); RETURN NEW; END $$; CREATE TRIGGER test_recovery_generation_claim_wait AFTER UPDATE ON pcr_device_generation_current_states FOR EACH ROW EXECUTE FUNCTION test_recovery_generation_claim_wait();")
        .await.unwrap();
    holder
        .batch_execute("BEGIN; SELECT pg_advisory_xact_lock(53182346);")
        .await
        .unwrap();
    let holder_pid = diesel::sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Pid>(&mut *holder)
        .await
        .unwrap()
        .pid;
    let race = async {
        let recovery_pid = waiting_on(
            &mut holder,
            holder_pid,
            "%pcr_device_generation_current_states%",
            1,
        )
        .await;
        let claim_pool = pool.clone();
        let claim = tokio::spawn(async move { candidate.allocate(&claim_pool, true).await });
        let origin_pool = pool.clone();
        let original = racing_origin.clone();
        let origin = tokio::spawn(async move {
            PgMlsKeyPackageStore { pool: origin_pool }
                .prepare_ordinary_claim_source(
                    &original,
                    chrono::Utc::now() + chrono::Duration::minutes(5),
                )
                .await
        });
        let blocked = if let Some(pid) = recovery_pid {
            waiting_on(&mut holder, pid, "%realm_authorities%", 2)
                .await
                .is_some()
        } else {
            false
        };
        holder.batch_execute("ROLLBACK").await.unwrap();
        (
            recovery_pid.is_some(),
            blocked,
            claim.await.unwrap(),
            origin.await.unwrap(),
        )
    };
    let recovery =
        std::panic::AssertUnwindSafe(Box::pin(identity_recovery::recover(pool, fixture)))
            .catch_unwind();
    let (recovered, (paused, blocked, claim, origin)) = tokio::join!(recovery, race);
    holder.batch_execute("DROP TRIGGER test_recovery_generation_claim_wait ON pcr_device_generation_current_states; DROP FUNCTION test_recovery_generation_claim_wait();").await.unwrap();
    drop(holder);
    let recovered = recovered.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(
        paused,
        "real native recovery must pause after its actual generation update"
    );
    assert!(
        blocked,
        "allocation and outbound origin retention must both wait on the real recovery cut; allocation={:?}, origin={origin:?}",
        claim
            .as_ref()
            .map(|_| "accepted")
            .map_err(ToString::to_string),
    );
    assert!(
        claim.is_err(),
        "old authorization must not allocate after recovery commits"
    );
    assert!(
        origin.is_err(),
        "fenced old Device cannot register a new outbound intent"
    );
    assert!(
        store
            .peer_claim_original(
                racing_origin.claim_request_id.as_str(),
                &arkret_canonical::canonical_sha256(&racing_origin).unwrap()
            )
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .prepare_ordinary_claim_source(
                &retained_origin,
                chrono::Utc::now() + chrono::Duration::minutes(5)
            )
            .await
            .is_err(),
        "archived intent is not permission for a fenced Device to dispatch again"
    );
    let archived = store
        .peer_claim_original(
            retained_origin.claim_request_id.as_str(),
            &arkret_canonical::canonical_sha256(&retained_origin).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&archived).unwrap(),
        arkret_canonical::canonical_json_bytes(&retained_origin).unwrap()
    );
    assert_eq!(
        store
            .get(&id)
            .await
            .unwrap()
            .unwrap()
            .claimed_by_mls_group_id,
        None
    );
    assert!(
        store
            .get_peer_claim(&source, &request_id)
            .await
            .unwrap()
            .is_none()
    );
    // The durable intent remains; no failed allocation result is invented.
    assert!(
        store
            .peer_claim_original(&request_id, &request_digest)
            .await
            .unwrap()
            .is_some()
    );
    recovered
}
