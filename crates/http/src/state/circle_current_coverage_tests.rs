//! Real PG current and the production HTTPS bootstrap/scan consumer. Initial
//! anchored state is installed through the existing trusted storage port; all
//! recovery replies below are built from the governor's actual accepted store.
//! This is not Coauth/session middleware or a native-consumer proof.
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use diesel::sql_types::{Jsonb, Text};
use diesel_async::RunQueryDsl as _;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapFault {
    None,
    WrongNonce,
    WrongSigner,
}

struct CircleScene {
    governor: AppState,
    governor_pool: PgPool,
    origin: AppState,
    origin_pool: PgPool,
    owner: historical_human::HumanFixture,
    alice: historical_human::HumanFixture,
    realm_join: coland_storage::EventCommitRequest,
    circle_join: coland_storage::EventCommitRequest,
    realm_head: coland_storage::AuthorityCommitTransaction,
    circle: arkret_wire::CircleId,
    listener: Arc<RegisteredTlsPeer>,
    _leases: [Arc<dyn coland_storage::PersistenceStore>; 2],
}

impl CircleScene {
    fn source(&self) -> PgAuthorityCommitStore {
        PgAuthorityCommitStore {
            pool: self.governor_pool.clone(),
        }
    }

    fn member(&self) -> PgAuthorityCommitStore {
        PgAuthorityCommitStore {
            pool: self.origin_pool.clone(),
        }
    }

    fn stream(&self) -> arkret_wire::CommitStreamRef {
        self.circle_join.authority_commit.commit.stream_ref.clone()
    }

    fn replica(
        &self,
        request: &coland_storage::EventCommitRequest,
        opening: bool,
    ) -> CommittedReplica {
        CommittedReplica {
            local_service_id: self.origin.service_core_id(),
            authority: request.authority_commit.expected_authority.clone(),
            historical_commit: None,
            event: request.authority_commit.event.clone(),
            commit: request.authority_commit.commit.clone(),
            producer_signer_fact: request.authority_commit.producer_signer_fact.clone(),
            genesis_event_ref: None,
            role: if opening {
                CommittedReplicaRole::OpeningJoin {
                    member_account_id: self.alice.pcr.history.account.clone(),
                }
            } else {
                CommittedReplicaRole::HeldStream
            },
            received_at: request.authority_commit.commit.committed_at,
            welcomes: Vec::new(),
        }
    }

    async fn install_actual_snapshot(&self, account: &AccountId, join: &arkret_wire::RealmCommit) {
        let material = self
            .source()
            .member_station_bootstrap_material(&join.realm_id, account, &join.commit_id)
            .await
            .unwrap()
            .expect("the real governor admits this exact current joined reader");
        let snapshot = signed_snapshot(&material, &self.governor);
        assert_eq!(
            snapshot.retention_and_history_floor,
            material.retention_and_history_floor
        );
        let head = material
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == join.stream_ref)
            .unwrap()
            .clone();
        self.member()
            .install_replica_anchor(&ReplicaAnchorInstall {
                realm_id: join.realm_id.clone(),
                join_commit_id: join.commit_id.clone(),
                governance_generation: material.governance_generation,
                snapshot_head: head,
                visible_stream_heads: material.visible_stream_heads,
                current_state_entries: material.current_state_entries,
                verified_snapshot: snapshot,
            })
            .await
            .unwrap();
    }

    async fn remove_only_derived_circle_metadata(&self) {
        let mut conn = self.origin_pool.get().await.unwrap();
        // Fault injection removes only a derived cache row. It creates no
        // accepted source, grant, membership, head, receipt or proof marker.
        assert_eq!(
            diesel::sql_query(
                "DELETE FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2"
            )
            .bind::<Text, _>(self.realm_join.authority_commit.event.realm_id.as_str())
            .bind::<Text, _>(self.circle.as_str())
            .execute(&mut *conn)
            .await
            .unwrap(),
            1
        );
    }

    async fn owner_circle_join(&self) -> coland_storage::EventCommitRequest {
        let parent = historical_human::ordinary_realm::parent_membership_revision(
            &self.governor_pool,
            &self.realm_join.authority_commit.event.realm_id,
            &ActorId::account(self.owner.pcr.history.account.clone()),
        )
        .await;
        owner_request(
            &self.governor,
            &self.governor_pool,
            &self.owner,
            &self.circle_join.authority_commit,
            EventKind::CircleMemberState,
            serde_json::json!({"circle_id":self.circle,
                "member_id":ActorId::account(self.owner.pcr.history.account.clone()),
                "membership":"join","expected_membership":null,
                "parent_membership_revision":parent}),
        )
        .await
    }

    async fn alice_leave(
        &self,
        previous: &coland_storage::AuthorityCommitTransaction,
    ) -> coland_storage::EventCommitRequest {
        let mut request = Box::pin(foreign_request(
            &self.origin,
            &self.alice,
            &self.owner,
            previous,
            EventKind::CircleMemberState,
            serde_json::json!({"circle_id":self.circle,
                "member_id":ActorId::account(self.alice.pcr.history.account.clone()),
                "membership":"leave","expected_membership":"join"}),
        ))
        .await;
        seal_service_commit(&mut request.authority_commit.commit, &self.governor);
        admit_fixture_event(&self.governor_pool, request.clone()).await;
        request
    }

    async fn bob_realm_snapshot(&self) -> AccountId {
        let bob = Box::pin(historical_human::HumanFixture::new(
            &self.origin_pool,
            self.origin.service_did(),
        ))
        .await;
        let mut join = Box::pin(foreign_request(
            &self.origin,
            &bob,
            &self.owner,
            &self.realm_head,
            EventKind::MemberState,
            serde_json::json!({"realm_id":self.realm_head.event.realm_id,
                "member_id":ActorId::account(bob.pcr.history.account.clone()),
                "membership":"join","reason":"independent Realm-only reader"}),
        ))
        .await;
        seal_service_commit(&mut join.authority_commit.commit, &self.governor);
        admit_fixture_event(&self.governor_pool, join.clone()).await;
        self.member()
            .install_committed_replica(&self.replica(&join, false))
            .await
            .unwrap();
        self.install_actual_snapshot(&bob.pcr.history.account, &join.authority_commit.commit)
            .await;
        assert!(
            self.member()
                .accepted_current_member_joined(
                    &join.authority_commit.event.realm_id,
                    &ActorId::account(bob.pcr.history.account.clone()),
                )
                .await
                .unwrap()
        );
        let request = StreamScanRequestBody {
            realm_id: join.authority_commit.event.realm_id.clone(),
            stream_ref: join.authority_commit.commit.stream_ref.clone(),
            direction: StreamScanDirection::Before(Some(
                join.authority_commit.commit.stream_position + 1,
            )),
            limit: 1,
        };
        assert!(matches!(
            self.member()
                .scan_stream_for_account(
                    &request,
                    &bob.pcr.history.account,
                    &self.origin.service_core_id(),
                )
                .await
                .unwrap(),
            coland_storage::AccountStreamScan::Page(_)
        ));
        bob.pcr.history.account.clone()
    }
}

fn signed_snapshot(
    material: &coland_storage::RealmStateSnapshotMaterial,
    signer: &AppState,
) -> arkret_wire::RealmStateSnapshot {
    coland_services::authority_commit::build_signed_realm_state_snapshot(
        material,
        signer.service_verification_method("notary-key").unwrap(),
        &ed25519_dalek::SigningKey::from_bytes(&historical_human::station_authority_seed()),
        Utc::now(),
    )
    .unwrap()
}

async fn owner_request(
    state: &AppState,
    pool: &PgPool,
    owner: &historical_human::HumanFixture,
    previous: &coland_storage::AuthorityCommitTransaction,
    kind: EventKind,
    payload: serde_json::Value,
) -> coland_storage::EventCommitRequest {
    let at = previous.commit.committed_at + Duration::seconds(1);
    let mut event = historical_human::signed_ordinary_event(owner, previous, kind, payload, at);
    if event.kind == EventKind::CircleMemberState {
        event.scope_ref = arkret_wire::ScopeRef::Circle {
            realm_id: previous.event.realm_id.clone(),
            circle_id: serde_json::from_value(event.payload["circle_id"].clone()).unwrap(),
        };
        event = coland_test_support::device_authorization_history::sign_event(
            event,
            owner.pcr.history.device_verification_method.clone(),
            owner.pcr.history.founding_device_signing_seed,
        );
    }
    let mut request = historical_human::request_for_event(owner, previous, event, at);
    request.authority_commit.commit.stream_ref =
        arkret_wire::CommitStreamRef::from_scope(&request.authority_commit.event.scope_ref, None)
            .unwrap();
    let fact = PgAuthorityCommitStore { pool: pool.clone() }
        .prepare_account_device_signer_fact(&request.authority_commit.event, at)
        .await
        .unwrap()
        .unwrap();
    request.authority_commit.commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    request.authority_commit.producer_signer_fact = Some(fact.into());
    seal_service_commit(&mut request.authority_commit.commit, state);
    admit_fixture_event(pool, request.clone()).await;
    request
}

async fn circle_scene() -> CircleScene {
    let listener = registered_tls_peer();
    let base = format!("https://{}/", listener.listener.local_addr().unwrap());
    let (governor, governor_pool, governor_lease) = station_with_webvh(base.clone());
    let (origin, origin_pool, origin_lease) =
        station_with_webvh("https://circle-coverage-member.internal/".into());
    let mut owner = Box::pin(historical_human::HumanFixture::new(
        &governor_pool,
        governor.service_did(),
    ))
    .await;
    let source = PgAuthorityCommitStore {
        pool: governor_pool.clone(),
    };
    let mut previous = None;
    for (index, tx) in owner.unit.transactions.iter_mut().enumerate() {
        tx.producer_signer_fact = source
            .prepare_account_device_signer_fact(&tx.event, tx.commit.committed_at)
            .await
            .unwrap()
            .map(Into::into);
        tx.commit.producer_signer_fact_digest = tx
            .producer_signer_fact
            .as_ref()
            .map(|fact| fact.digest().unwrap());
        tx.commit.previous_commit_ref = previous;
        seal_service_commit(&mut tx.commit, &governor);
        previous = Some(tx.commit.commit_id.clone());
        owner.unit.submission.events[index] = EventAdmissionSubmission::new(tx.event.clone());
    }
    owner.unit.exact_request_body = serde_json::to_vec(
        &SelfAuthoritySubmitRequestBody::OrdinaryRealmBootstrap(owner.unit.submission.clone()),
    )
    .unwrap();
    Box::pin(owner.admit(&governor_pool)).await;
    let alice = Box::pin(historical_human::HumanFixture::new(
        &origin_pool,
        origin.service_did(),
    ))
    .await;
    let owner_actor = ActorId::account(owner.pcr.history.account.clone());
    let previous = owner.unit.transactions.last().unwrap();
    let at = previous.commit.committed_at + Duration::seconds(1);
    let create = Box::pin(owner_request(
        &governor,
        &governor_pool,
        &owner,
        previous,
        EventKind::CircleCreate,
        serde_json::json!({"object":{"schema":"ak.schema.circle.v1",
            "realm_id":previous.event.realm_id,"title":"Private current coverage",
            "display":{"short_name":"Coverage","color_token":"blue","symbol":{"glyph":"lock"}},
            "directory_visibility":"members","join_rule":"public","history_access":"since_join",
            "state":"active","created_by":owner_actor,
            "created_at":arkret_canonical::format_timestamp_canonical(at)}}),
    ))
    .await;
    let circle = arkret_wire::CircleId::from_event_id(&create.authority_commit.event.event_id);
    #[derive(diesel::QueryableByName)]
    struct Root {
        #[diesel(sql_type = Text)]
        authority_event_ref: String,
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        authority_generation: i64,
    }
    let mut conn = governor_pool.get().await.unwrap();
    let root = diesel::sql_query("SELECT authority_event_ref,authority_generation FROM realm_authority_root_current_states WHERE realm_id=$1")
        .bind::<Text,_>(create.authority_commit.event.realm_id.as_str())
        .get_result::<Root>(&mut *conn).await.unwrap();
    drop(conn);
    let mut previous = create.authority_commit;
    for subject in [
        ActorId::account(alice.pcr.history.account.clone()),
        owner_actor.clone(),
    ] {
        let at = previous.commit.committed_at + Duration::seconds(1);
        previous = Box::pin(owner_request(
            &governor, &governor_pool, &owner, &previous, EventKind::CapabilityGrant,
            serde_json::json!({"grant":{"schema":"ak.schema.capability.v1",
                "realm_id":previous.event.realm_id,"issuer_id":owner_actor,"subject":subject,
                "actions":["ak.circle.member.add"],
                "resources":[{"kind":"circle","realm_id":previous.event.realm_id,"circle_id":circle}],
                "issuer_authority_refs":[{"kind":"realm_root","realm_id":previous.event.realm_id,
                    "authority_event_ref":root.authority_event_ref,
                    "authority_generation":u64::try_from(root.authority_generation).unwrap().to_string()}],
                "issued_at":arkret_canonical::format_timestamp_canonical(at)}}),
        )).await.authority_commit;
    }
    let actor = ActorId::account(alice.pcr.history.account.clone());
    let mut realm_join = Box::pin(foreign_request(
        &origin,
        &alice,
        &owner,
        &previous,
        EventKind::MemberState,
        serde_json::json!({"realm_id":previous.event.realm_id,"member_id":actor,
            "membership":"join","reason":"current coverage reader"}),
    ))
    .await;
    seal_service_commit(&mut realm_join.authority_commit.commit, &governor);
    admit_fixture_event(&governor_pool, realm_join.clone()).await;
    let route =
        crate::routing::system::service_resolution::current_authenticated_service_resolution(
            &governor,
        )
        .await
        .unwrap();
    let boundary = route.method_history_evidence.boundary();
    origin.test_install_service_route_fetcher(Arc::new(VerifiedSourceRoute(
        VerifiedRouteCandidate {
            description: VerifiedServiceDescribeMetadata {
                service_id: governor.service_core_id(),
                service_kind: "station".into(),
                service_resolution: ResolutionCommitment {
                    did: governor.service_did(),
                    method_history_head: boundary.to_method_history_head.clone(),
                    version_id: boundary.to_version_id.clone(),
                },
                http_json_base_url: base,
                trust_domain: governor.config().trust_domain.clone(),
                protocol_version: arkret_wire::PROTOCOL_VERSION.into(),
                supported_profiles: Vec::new(),
                supported_operation_bundles: vec![
                    arkret_wire::role_describe_bundle_descriptor(arkret_wire::ServiceKind::Station)
                        .unwrap()
                        .operation_bundle_id
                        .into(),
                ],
            },
            evidence: route,
        },
    )));
    register_original_peer_history(&listener, &governor, &governor_pool).await;
    let mut circle_join = Box::pin(foreign_request(
        &origin,
        &alice,
        &owner,
        &realm_join.authority_commit,
        EventKind::CircleMemberState,
        serde_json::json!({"circle_id":circle,"member_id":actor,"membership":"join",
            "expected_membership":null,"parent_membership_revision":{
                "commit_id":realm_join.authority_commit.commit.commit_id,
                "stream_position":realm_join.authority_commit.commit.stream_position}}),
    ))
    .await;
    seal_service_commit(&mut circle_join.authority_commit.commit, &governor);
    admit_fixture_event(&governor_pool, circle_join.clone()).await;
    let scene = CircleScene {
        governor,
        governor_pool,
        origin,
        origin_pool,
        owner,
        alice,
        realm_head: realm_join.authority_commit.clone(),
        realm_join,
        circle_join,
        circle,
        listener,
        _leases: [governor_lease, origin_lease],
    };
    scene
        .member()
        .install_committed_replica(&scene.replica(&scene.realm_join, true))
        .await
        .unwrap();
    scene
        .install_actual_snapshot(
            &scene.alice.pcr.history.account,
            &scene.realm_join.authority_commit.commit,
        )
        .await;
    scene
        .member()
        .install_committed_replica(&scene.replica(&scene.circle_join, true))
        .await
        .unwrap();
    scene
        .install_actual_snapshot(
            &scene.alice.pcr.history.account,
            &scene.circle_join.authority_commit.commit,
        )
        .await;
    // Prime only real verified source method/authority history before a
    // negative test takes its zero-effect acceptance footprint. Otherwise a
    // legitimate first-time key-history cache write could obscure that check.
    let peer = LivePeer::start(&scene, BootstrapFault::None);
    let authority = crate::routing::realm_join::resolve_verified_authority_of_service(
        &scene.origin,
        &scene.realm_join.authority_commit.event.realm_id,
        &scene.governor.service_core_id(),
    )
    .await
    .unwrap();
    assert_eq!(
        authority.authority.current_service_id(),
        &scene.governor.service_core_id()
    );
    assert_eq!(
        peer.finish().await,
        vec!["/_arkret/open/realm-authority/bundle".to_owned()]
    );
    scene
}

struct LivePeer {
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl LivePeer {
    fn start(scene: &CircleScene, fault: BootstrapFault) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (end, calls) = (stop.clone(), requests.clone());
        let listener = scene.listener.clone();
        let governor = scene.governor.clone();
        let other_signer = scene.origin.clone();
        let pool = scene.governor_pool.clone();
        let source_id = scene.origin.service_core_id();
        let runtime = tokio::runtime::Handle::current();
        let worker = tokio::task::spawn_blocking(move || {
            listener.listener.set_nonblocking(true).unwrap();
            while !AtomicBool::load(end.as_ref(), Ordering::SeqCst) {
                let socket = match listener.listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("isolated Circle peer accept: {error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut stream = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(listener.tls.clone()).unwrap(),
                    socket,
                );
                let mut bytes = Vec::new();
                let mut buf = [0_u8; 2048];
                let header_end = loop {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    assert!(bytes.len() < 1024 * 1024);
                    if let Some(p) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let header = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let first = header.lines().next().unwrap();
                let path = first.split_whitespace().nth(1).unwrap().to_owned();
                let fields = header
                    .lines()
                    .filter_map(|line| {
                        line.split_once(':')
                            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    })
                    .collect::<std::collections::BTreeMap<_, _>>();
                let is_get = first.starts_with("GET ");
                let length = fields
                    .get("content-length")
                    .map_or(0, |v| v.parse::<usize>().unwrap());
                assert!(length < 1024 * 1024);
                while bytes.len() < header_end + length {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                }
                let (status, body) = if is_get {
                    let history = listener.history.read().unwrap();
                    (
                        200,
                        history
                            .get(&path)
                            .expect("only registered actual method history")
                            .clone(),
                    )
                } else {
                    let body = &bytes[header_end..header_end + length];
                    calls.lock().unwrap().push(path.clone());
                    if path != "/_arkret/open/realm-authority/bundle" {
                        assert_eq!(
                            fields.get("source-service-id"),
                            Some(&source_id.to_string())
                        );
                        assert_eq!(
                            fields.get("destination-service-id"),
                            Some(&governor.service_core_id().to_string())
                        );
                        for name in ["signature-input", "signature", "content-digest"] {
                            assert!(fields.contains_key(name));
                        }
                    }
                    runtime.block_on(actual_peer_reply(
                        &governor,
                        &other_signer,
                        &pool,
                        &source_id,
                        &path,
                        body,
                        fault,
                    ))
                };
                let response = format!(
                    "HTTP/1.1 {status} Circle fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
                stream.flush().unwrap();
                assert!(!stream.conn.is_handshaking());
            }
        });
        Self {
            stop,
            requests,
            worker: Some(worker),
        }
    }

    async fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().await.unwrap();
        let requests = self.requests.lock().unwrap().clone();
        drop(self);
        requests
    }
}

impl Drop for LivePeer {
    fn drop(&mut self) {
        // An assertion failure must not strand an isolated blocking accept loop.
        self.stop.store(true, Ordering::SeqCst);
    }
}

async fn actual_peer_reply(
    governor: &AppState,
    other_signer: &AppState,
    pool: &PgPool,
    recipient: &DidCoreId,
    path: &str,
    body: &[u8],
    fault: BootstrapFault,
) -> (u16, Vec<u8>) {
    let store = PgAuthorityCommitStore { pool: pool.clone() };
    if path == "/_arkret/open/realm-authority/bundle" {
        let request: arkret_wire::RealmAuthorityBundleRequestBody =
            serde_json::from_slice(body).unwrap();
        let bundle = crate::routing::realm_join::local_authority_bundle(
            governor,
            &request.realm_id,
            &request.nonce,
        )
        .await
        .unwrap();
        return (
            200,
            arkret_canonical::canonical_json_bytes(&bundle).unwrap(),
        );
    }
    if path == "/_arkret/peer/realm-joins/bootstrap" {
        let request: arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapRequestBody = serde_json::from_slice(body).unwrap();
        assert_eq!(&request.member_account_id.station_id, recipient);
        let Some(material) = store
            .member_station_bootstrap_material(
                &request.realm_id,
                &request.member_account_id,
                &request.membership_commit_id,
            )
            .await
            .unwrap()
        else {
            return (
                403,
                arkret_canonical::canonical_json_bytes(&arkret_wire::Problem::new(
                    "capability_denied",
                    403,
                    "the real source has no current joined bootstrap reader",
                ))
                .unwrap(),
            );
        };
        let nonce = if fault == BootstrapFault::WrongNonce {
            Base64UrlString::new(arkret_canonical::base64url_encode([0x49; 32])).unwrap()
        } else {
            crate::routing::realm_join::nonce_for_request(&request.request_id).unwrap()
        };
        let bundle =
            crate::routing::realm_join::local_authority_bundle(governor, &request.realm_id, &nonce)
                .await
                .unwrap();
        let snapshot = signed_snapshot(
            &material,
            if fault == BootstrapFault::WrongSigner {
                other_signer
            } else {
                governor
            },
        );
        let response = arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapResponseBody {
            request_id: request.request_id, visible_stream_heads:snapshot.visible_stream_heads.clone(),
            snapshot, authority_bundle:bundle,
        };
        return (
            200,
            arkret_canonical::canonical_json_bytes(&response).unwrap(),
        );
    }
    assert_eq!(path, "/_arkret/peer/streams/scan");
    let request: StreamScanRequestBody = serde_json::from_slice(body).unwrap();
    let coland_storage::PeerStreamScan::Page(page) = store
        .scan_stream_for_peer(&request, recipient, &governor.service_core_id())
        .await
        .unwrap()
    else {
        panic!("test requests only a real retained peer interval")
    };
    page.validate_for_request(&request).unwrap();
    (200, arkret_canonical::canonical_json_bytes(&page).unwrap())
}

async fn settle(scene: &CircleScene) {
    crate::state::replica_anchor::spawn_converge_stream(&scene.origin, scene.stream());
    crate::state::replica_anchor::wait_for_converge_stream(&scene.origin, &scene.stream()).await;
}

#[tokio::test]
async fn qualified_circle_refresh_precedes_full_tail_when_metadata_is_physically_absent() {
    scenario_future(|| async {
        let scene = scenario_future(circle_scene).await;
        Box::pin(scene.bob_realm_snapshot()).await;
        Box::pin(scene.remove_only_derived_circle_metadata()).await;
        assert!(
            scene
                .member()
                .replica_stream_has_hosted_member(&scene.stream(), &scene.origin.service_core_id())
                .await
                .is_err(),
            "an anchored unproved Circle is not None/no-replica or a known departure"
        );
        let tail = Box::pin(scene.owner_circle_join()).await;
        let before = realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await;
        assert!(
            scene
                .member()
                .install_committed_replica(&scene.replica(&tail, false))
                .await
                .is_err(),
            "an actual Full source receipt does not prove current recipient metadata"
        );
        assert_eq!(
            realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await,
            before
        );
        let peer = LivePeer::start(&scene, BootstrapFault::None);
        settle(&scene).await;
        let calls = peer.finish().await;
        assert!(
            calls.len() <= 4,
            "one authority lookup, one bootstrap round and a bounded tail"
        );
        let bootstrap = calls
            .iter()
            .position(|p| p == "/_arkret/peer/realm-joins/bootstrap")
            .expect("qualified refresh actually happened");
        let scan = calls
            .iter()
            .position(|p| p == "/_arkret/peer/streams/scan")
            .expect("real source tail was fetched");
        assert!(
            bootstrap < scan,
            "ordinary Full fill must not prevent the required fresh bootstrap"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|p| p.as_str() == "/_arkret/peer/realm-joins/bootstrap")
                .count(),
            1
        );
        assert_eq!(
            scene
                .member()
                .committed_event(&tail.authority_commit.event.event_id)
                .await
                .unwrap()
                .unwrap()
                .commit,
            tail.authority_commit.commit
        );
        assert_eq!(
            scene
                .member()
                .producer_signer_fact(&tail.authority_commit.event, &tail.authority_commit.commit)
                .await
                .unwrap(),
            tail.authority_commit.producer_signer_fact
        );
        assert!(
            scene
                .member()
                .circle_view_for_actor(
                    &scene.circle,
                    &ActorId::account(scene.alice.pcr.history.account.clone())
                )
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            scene
                .member()
                .replica_stream_has_hosted_member(&scene.stream(), &scene.origin.service_core_id())
                .await
                .unwrap(),
            Some(true)
        );
    })
    .await;
}

#[tokio::test]
async fn unproved_circle_rejects_wrong_nonce_and_other_station_snapshot_without_effects() {
    scenario_future(|| async {
        for fault in [BootstrapFault::WrongNonce,BootstrapFault::WrongSigner] {
            let scene = scenario_future(circle_scene).await;
            Box::pin(scene.bob_realm_snapshot()).await;
            Box::pin(scene.remove_only_derived_circle_metadata()).await;
            let tail = Box::pin(scene.owner_circle_join()).await;
            let before = realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await;
            let peer = LivePeer::start(&scene,fault);
            settle(&scene).await;
            let calls = peer.finish().await;
            assert!(calls.len() <= 4, "a rejected proof must not create an unbounded recovery loop");
            assert_eq!(calls.iter().filter(|p|p.as_str()=="/_arkret/peer/realm-joins/bootstrap").count(),1);
            assert!(scene.member().committed_event(&tail.authority_commit.event.event_id).await.unwrap().is_none());
            assert_eq!(realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await,before,
                "a real signed reply with wrong request nonce or source signer changes no accepted state");
        }
    }).await;
}

#[tokio::test]
async fn refused_fresh_bootstrap_still_consumes_actual_withheld_prefix_and_exact_self_leave() {
    scenario_future(|| async {
        let scene = scenario_future(circle_scene).await;
        let predecessor = Box::pin(scene.owner_circle_join()).await;
        let leave = Box::pin(scene.alice_leave(&predecessor.authority_commit)).await;
        let bob = Box::pin(scene.bob_realm_snapshot()).await;
        let scan = StreamScanRequestBody { realm_id:leave.authority_commit.event.realm_id.clone(),
            stream_ref:scene.stream(),direction:StreamScanDirection::After(Some(scene.circle_join.authority_commit.commit.stream_position)),limit:128 };
        let coland_storage::PeerStreamScan::Page(page) = scene.source().scan_stream_for_peer(
            &scan,&scene.origin.service_core_id(),&scene.governor.service_core_id()).await.unwrap() else { panic!("real terminated interval"); };
        assert_eq!(page.committed_events.len(),2);
        assert!(matches!(&page.committed_events[0],arkret_wire::CommittedEventView::Withheld(v) if v.commit==predecessor.authority_commit.commit));
        assert!(matches!(&page.committed_events[1],arkret_wire::CommittedEventView::Full(v) if v.event==leave.authority_commit.event&&v.commit==leave.authority_commit.commit));
        assert!(scene.source().member_station_bootstrap_material(&leave.authority_commit.event.realm_id,
            &scene.alice.pcr.history.account,&scene.circle_join.authority_commit.commit.commit_id).await.unwrap().is_none());
        let before = realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await;
        assert!(scene.member().install_committed_replica(&scene.replica(&predecessor,false)).await.is_err(),
            "a retained interval does not permit an ordinary Full when current metadata is unproved");
        assert_eq!(realm_terminal_peer_tests::terminal_persistent_rows(&scene.origin_pool).await,before);
        let peer = LivePeer::start(&scene,BootstrapFault::None);
        settle(&scene).await;
        let calls = peer.finish().await;
        assert!(calls.len() <= 4, "closing recovery keeps the existing bounded request round");
        assert_eq!(calls.iter().filter(|p|p.as_str()=="/_arkret/peer/realm-joins/bootstrap").count(),1);
        assert_eq!(scene.member().committed_event(&leave.authority_commit.event.event_id).await.unwrap().unwrap().commit,
            leave.authority_commit.commit);
        assert!(scene.member().committed_event(&predecessor.authority_commit.event.event_id).await.unwrap().is_none(),
            "the actually withheld predecessor is continuity only");
        assert!(scene.member().circle_view_for_actor(&scene.circle,
            &ActorId::account(scene.alice.pcr.history.account.clone())).await.unwrap().is_none());
        assert!(!scene.member().replica_stream_has_hosted_member(&scene.stream(),&scene.origin.service_core_id()).await.unwrap().unwrap());
        let read = StreamScanRequestBody { realm_id:leave.authority_commit.event.realm_id.clone(),
            stream_ref:scene.stream(),direction:StreamScanDirection::Before(Some(leave.authority_commit.commit.stream_position+1)),limit:1 };
        assert!(matches!(scene.member().scan_stream_for_account(&read,&scene.alice.pcr.history.account,
            &scene.origin.service_core_id()).await.unwrap(),coland_storage::AccountStreamScan::Unproved("the caller has no held Circle join")));
        assert!(scene.member().accepted_current_member_joined(&leave.authority_commit.event.realm_id,
            &ActorId::account(bob.clone())).await.unwrap(),"A departure cannot revoke B's unrelated Realm join");
        let realm_read = StreamScanRequestBody { realm_id:scene.realm_head.event.realm_id.clone(),
            stream_ref:scene.realm_head.commit.stream_ref.clone(),direction:StreamScanDirection::Before(None),limit:1 };
        assert!(matches!(scene.member().scan_stream_for_account(&realm_read,&bob,
            &scene.origin.service_core_id()).await.unwrap(),coland_storage::AccountStreamScan::Page(_)));
        let mut conn=scene.origin_pool.get().await.unwrap();
        #[derive(diesel::QueryableByName)]
        struct Attempts { #[diesel(sql_type=Jsonb)] value:serde_json::Value }
        let attempts=diesel::sql_query("SELECT coalesce(jsonb_agg(to_jsonb(f)),'[]'::jsonb) AS value FROM authority_forward_attempts f")
            .get_result::<Attempts>(&mut *conn).await.unwrap();
        assert_eq!(attempts.value,serde_json::json!([]),"ordinary HeldStream closes without fabricated own-forward evidence");
    }).await;
}
