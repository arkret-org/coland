//! Real Realm Device transport, remote Account keys and accepted MLS writes.
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::governance::grant_constraint::{
    GrantConstraintEffect, GrantConstraintKind, GrantConstraintSubkind, ManagedActorRole,
};
use arkret_models_crypto::*;
use arkret_wire::{DeviceId, DidUrl, GrantId, ServiceOperationId};
use coland_storage::MlsGroupCurrentStore as _;

use super::realm_native_fixture::boxed_step;
use super::*;

pub(super) fn enable(package: &mut AppletPackage) {
    let method = package.proof.as_ref().unwrap().verification_method.clone();
    package.e2ee_policy.enabled = true;
    package.e2ee_policy.mls_join_requested = Some(true);
    package
        .claimed_profiles
        .push(arkret_wire::ProfileId::APPLET_E2EE_JOIN_V1.into());
    package.claimed_profiles.sort();
    package.requested_scopes.extend(
        [
            "ak.circle.member.add",
            "ak.event.read",
            "ak.mls.commit",
            "ak.mls.genesis",
            "ak.object.read_content",
            "ak.strand.create",
            "ak.message.redact",
        ]
        .map(str::to_owned),
    );
    package.requested_scopes.sort();
    package
        .stamp_registration_epoch(&applet_registration_epoch_evidence(package))
        .unwrap();
    package.stamp_package_digest().unwrap();
    let did = arkret_identity::verification_method_did(method.as_str()).unwrap();
    package
        .sign(
            &Ed25519PayloadSigner::from_did_key_seed([13; 32], did, method.clone()),
            &method,
        )
        .unwrap();
}

fn signed_event(
    package: &AppletPackage,
    actor: ActorId,
    scope: ScopeRef,
    kind: EventKind,
    payload: Value,
    grant: Option<&GrantId>,
    signer: &Ed25519PayloadSigner,
) -> Event {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event =
        arkret_wire::test_support::raw_event_for_actor_at(kind.as_str(), scope, actor, payload, at)
            .unwrap();
    event.applet_id = Some(package.applet_id.clone());
    event.authorization_ref = grant.cloned().map(Into::into);
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut authored,
        signer,
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )
    .unwrap();
    authored.into_event()
}

async fn read_service_grants(
    fixture: &Fixture,
    package: &AppletPackage,
    subject: &ActorId,
    tamper_subject: Option<&ActorId>,
) -> (StatusCode, Value) {
    let path = "/_arkret/self/authz/effective-grants";
    let operation = ServiceOperationId::SELF_AUTHZ_GRANTS_READ_EFFECTIVE_V1;
    let mut url = url::Url::parse(&format!("http://server{path}")).unwrap();
    url.query_pairs_mut()
        .append_pair("realm_id", fixture.realm.as_str())
        .append_pair("subject_actor_id", &subject.to_string());
    let scheme = fixture
        .state
        .config()
        .public_base_url
        .split_once("://")
        .unwrap()
        .0;
    let mut signed_url = url.clone();
    signed_url.set_scheme(scheme).unwrap();
    let parts = SignedRequestParts {
        method: "GET".into(),
        target_uri: signed_url.to_string(),
        authority: "server".into(),
        path: path.into(),
        headers: vec![
            ("arkret-operation".into(), operation.into()),
            ("source-service-id".into(), package.service_id.to_string()),
            (
                "destination-service-id".into(),
                fixture.state.service_id().to_owned(),
            ),
        ],
        body_digest: None,
    };
    let signature = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::ServiceToServiceV1,
        &[],
        "sig1",
        package.webhook_auth.key_ref.as_str(),
        chrono::Utc::now().timestamp(),
        &applet_service_signing_key(&package.webhook_auth.key_ref),
    )
    .unwrap();
    if let Some(other) = tamper_subject {
        url.set_query(None);
        url.query_pairs_mut()
            .append_pair("realm_id", fixture.realm.as_str())
            .append_pair("subject_actor_id", &other.to_string());
    }
    let request = TestClient::get(url.as_str())
        .add_header("Arkret-Operation", operation, true)
        .add_header("Source-Service-ID", package.service_id.as_str(), true)
        .add_header("Destination-Service-ID", fixture.state.service_id(), true)
        .add_header("Signature-Input", signature.signature_input_header, true)
        .add_header("Signature", signature.signature_header, true);
    let router = service(fixture.state.clone());
    let mut response = boxed_step(|| request.send(&router)).await;
    (
        response.status_code.unwrap(),
        response.take_json().await.unwrap(),
    )
}

async fn business_grant(fixture: &Fixture, package: &AppletPackage, actor: &ActorId) -> GrantId {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    boxed_step(|| business_authority(fixture, package, actor, false, &scope)).await
}

pub(super) async fn business_parent(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    scope: &ScopeRef,
) -> GrantId {
    boxed_step(|| business_authority(fixture, package, actor, true, scope)).await
}

async fn business_authority(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    parent_only: bool,
    scope: &ScopeRef,
) -> GrantId {
    eprintln!("native MLS: Service business parent");
    let service_actor = ActorId::service(package.service_id.clone());
    let scope = scope.clone();
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(false);
    control.max_authority_depth = Some(0);
    control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
    let parent = CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
        realm_id: Some(fixture.realm.clone()),
        issuer_id: ActorId::account(fixture.pcr.history.account.clone()),
        subject: CapabilitySubject::Actor(service_actor.clone()),
        actions: vec![
            "ak.applet.join".into(),
            "ak.circle.member.add".into(),
            "ak.event.read".into(),
            "ak.message.create".into(),
            "ak.mls.commit".into(),
            "ak.mls.genesis".into(),
            "ak.object.read_content".into(),
            "ak.strand.create".into(),
            "ak.message.redact".into(),
        ],
        resources: vec![match &scope {
            ScopeRef::Circle {
                realm_id,
                circle_id,
            } => arkret_wire::WireResourceSelector::circle(realm_id.clone(), circle_id.clone()),
            _ => arkret_wire::WireResourceSelector::realm(fixture.realm.clone()),
        }],
        constraints: vec![
            GrantConstraint::applet_authority(
                package.applet_id.clone(),
                service_actor.clone(),
                package.registration_epoch.clone(),
            ),
            control,
        ],
        issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
            realm_id: fixture.realm.clone(),
            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
            authority_generation: 0,
        }],
        issued_at: chrono::Utc::now(),
    };
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        scope.clone(),
        json!(CapabilityGrantPayload {
            grant: parent.clone()
        }),
    );
    let parent_id = GrantId::from_event_id(&event.event_id);
    let parent_request = event.event_id.to_string();
    let (status, value) = fixture
        .admin_post_network(
            "/_arkret/self/events",
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event)
            )),
            &parent_request,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "real business parent: {value}");
    let (status, grants) =
        boxed_step(|| read_service_grants(fixture, package, &service_actor, None)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Service effective grant read: {grants}"
    );
    let grants: arkret_models_collaboration::governance::authorization::GrantList =
        serde_json::from_value(grants).unwrap();
    assert!(grants.grants.iter().any(|row| row.grant.id == parent_id));
    let (status, _) = boxed_step(|| read_service_grants(fixture, package, actor, None)).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "Service must not read another subject's grants"
    );
    let (status, _) =
        boxed_step(|| read_service_grants(fixture, package, &service_actor, Some(actor))).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "query substitution must fail the real HTTP signature"
    );
    if parent_only {
        return parent_id;
    }
    boxed_step(|| business_terminal_child(fixture, package, actor, scope, parent, parent_id)).await
}

async fn business_terminal_child(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    scope: ScopeRef,
    parent: CapabilityGrantCreateBody,
    parent_id: GrantId,
) -> GrantId {
    let service_actor = ActorId::service(package.service_id.clone());
    let mut child = parent;
    child.issuer_id = service_actor.clone();
    child.subject = CapabilitySubject::Actor(actor.clone());
    child.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
        grant_id: parent_id.clone(),
    }];
    child.issued_at = chrono::Utc::now();
    for constraint in &mut child.constraints {
        if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            constraint.executed_by = Some(actor.clone());
        } else if constraint.constraint_kind == GrantConstraintKind::AuthorityControl {
            constraint.allowed_managed_actor_roles.clear();
        }
    }
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&package.webhook_auth.key_ref),
        applet_service_did(package),
        package.webhook_auth.key_ref.clone(),
    );
    let event = signed_event(
        package,
        service_actor,
        scope,
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload { grant: child }),
        Some(&parent_id),
        &signer,
    );
    let child_id = GrantId::from_event_id(&event.event_id);
    eprintln!("native MLS: Service terminal child");
    let (status, value) = fixture
        .service_post(
            package,
            "/_arkret/edge/applet/transactions",
            ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
            &json!(AppletEventTransactionRequestBody {
                applet_id: package.applet_id.clone(),
                source_id: package.service_id.clone(),
                events: vec![event],
                committed_events: vec![],
                signals: vec![],
            }),
            "realm-mls-business-child",
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real terminal business child: {value}"
    );
    let result: AppletTransactionOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(
        result.status(),
        AppletTransactionStatus::Accepted,
        "{result:?}"
    );
    eprintln!("native MLS: terminal child accepted");
    boxed_step(|| {
        service_cannot_proxy_terminal_child_membership(fixture, package, actor, &child_id, &signer)
    })
    .await;
    child_id
}

async fn service_cannot_proxy_terminal_child_membership(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    child: &GrantId,
    signer: &Ed25519PayloadSigner,
) {
    let before =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    for membership in ["join", "leave"] {
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::MemberState.as_str(),
            ScopeRef::Realm {
                realm_id: fixture.realm.clone(),
            },
            actor.clone(),
            json!({"member_id":actor,"membership":membership}),
            at,
        )
        .unwrap();
        event.applet_id = Some(package.applet_id.clone());
        event.authorization_ref = Some(child.clone().into());
        event.executed_by = Some(ActorId::service(package.service_id.clone()));
        event.producer_proof = None;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            signer,
            arkret_signatures::SignEventOptions::new().with_created_at(at),
        )
        .unwrap();
        let request = SelfAuthoritySubmitRequest::Event(
            arkret_wire::EventAdmissionSubmission::new(authored.into_event()),
        );
        request.validate().unwrap();
        let (status, problem) = boxed_step(|| async {
            fixture
                .service_post(
                    package,
                    "/_arkret/self/events",
                    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
                    &json!(request),
                    &format!("service-cannot-proxy-terminal-child-{membership}"),
                )
                .await
        })
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Service proxy {membership}: {problem}"
        );
        assert_eq!(
            problem["type"],
            "https://arkret.org/problems/capability_denied"
        );
        assert_eq!(
            boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await,
            before,
            "Service must not borrow the accepted Realm actor terminal child for {membership}"
        );
    }
}

async fn device_post(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    path: &str,
    operation: ServiceOperationId,
    body: Value,
) -> (StatusCode, Value) {
    let metadata = AppletManagedDeviceMetadata {
        actor_id: authority.actor_id.clone(),
        device_id: authority.device_id.clone(),
        authorization_event_id: authority.authorization_ref.event_id.clone(),
        applet_id: authority.applet_id.clone(),
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        nonce: arkret_canonical::base64url_encode(rand::random::<[u8; 32]>()),
    };
    let key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    super::realm_native_fixture::managed_device_post(
        fixture,
        &metadata,
        &DidUrl::new(format!("did:key:{key}#{key}")).unwrap(),
        path,
        operation,
        &body,
        &[79; 32],
    )
    .await
}

async fn public_material(fixture: &Fixture, bytes: Vec<u8>) -> arkret_wire::BlobRef {
    let digest = arkret_canonical::sha256_digest(&bytes);
    let sha256 = digest.strip_prefix("sha256:").unwrap();
    let reference = arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap();
    let storage_key = fixture.state.test_object_key_for_sha256(sha256);
    let record = coland_storage::BlobRecord {
        sha256: sha256.into(),
        size_bytes: bytes.len() as i64,
        storage_backend: "memory".into(),
        storage_key: storage_key.clone(),
        media_type: "application/octet-stream".into(),
        filename: None,
        realm_id: Some(fixture.realm.to_string()),
        encryption: None,
        legal_hold: false,
        redacted: false,
        visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
        uploaded_by: fixture.pcr.history.account.principal_id.to_string(),
        created_at: chrono::Utc::now(),
    };
    fixture
        .state
        .test_put_object(&storage_key, bytes)
        .await
        .unwrap();
    fixture
        .state
        .test_persistence()
        .blobs()
        .put(reference.as_str(), &record)
        .await
        .unwrap();
    reference
}

async fn foreign_member(governor: &Fixture, member: &Fixture) {
    for (source, target) in [(governor, member), (member, governor)] {
        let id = target.state.service_core_id();
        source
            .state
            .service_route_resolver()
            .unwrap()
            .resolve_carrier(
                &arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
                    resolution_url: format!(
                        "{}{}",
                        target.state.config().public_base_url.trim_end_matches('/'),
                        arkret_models_identity::canonical_service_resolution_path(&id)
                    ),
                },
                &id,
                "station",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
    }
    let scope = ScopeRef::Realm {
        realm_id: governor.realm.clone(),
    };
    let invite = governor.admin_event(EventKind::InviteCreate, scope.clone(), json!({
        "invitee_account_id":member.pcr.history.account,
        "introduction_evidence_digest":format!("sha256:{}", "c".repeat(64)),
        "expires_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now()+chrono::Duration::hours(1))
    }));
    let (status, value) = governor
        .admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(invite.clone())
            )),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "foreign invitation: {value}");
    let authority = governor
        .state
        .test_persistence()
        .authority_commits()
        .current_authority(&governor.realm)
        .await
        .unwrap()
        .unwrap();
    member
        .state
        .test_persistence()
        .authority_commits()
        .record_remote_authority(&authority, &member.state.service_core_id())
        .await
        .unwrap();
    let accept = member.admin_event(
        EventKind::InviteAccept,
        scope,
        json!({
            "invite_id":arkret_wire::InviteId::from_event_id(&invite.event_id),
            "previous_state":"pending","invitee_account_id":member.pcr.history.account
        }),
    );
    let (status, value) = member
        .admin_post(
            "/_arkret/self/events",
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
            &json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(accept)
            )),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "foreign member accepted through own Station: {value}"
    );
}

fn claim_request_with_lifetime(
    authority: &coland_storage::AppletManagedDeviceAuthority,
    target: &Fixture,
    keypackage: &str,
    lifetime: chrono::Duration,
) -> KeyPackagesClaimRequestBody {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let method = DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap();
    let scope = ScopeRef::Realm {
        realm_id: authority.realm_id.clone(),
    };
    let mut request = KeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            rand::random::<[u8; 32]>(),
        ))
        .unwrap(),
        target_account_id: Some(target.pcr.history.account.clone()),
        target_actor_id: None,
        requester_account_id: None,
        requester_actor_id: Some(authority.actor_id.clone()),
        intended_realm_id: authority.realm_id.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: at + lifetime,
        target_device_ids: vec![target.pcr.history.founding_device_id.clone()],
        target_keypackage_ref: Some(arkret_wire::KeyPackageRef::new(keypackage).unwrap()),
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: None,
        service_binding: KeyPackagesClaimServiceBinding {
            source_id: authority.governance_service_id.clone(),
            destination_id: target.state.service_core_id(),
        },
        requester_authorization: PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method: method.clone(),
            requester_device_id: authority.device_id.clone(),
            device_authorize_event_id: authority.authorization_ref.event_id.clone(),
            signed_at: at,
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                method.as_str(),
                &[0; 64],
            )
            .unwrap(),
        },
    };
    let input = keypackage_claim_authorization_signing_bytes(
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
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        method.as_str(),
        &input,
    )
    .unwrap();
    request.validate_shape().unwrap();
    request
}

pub(super) async fn run(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
) {
    let authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, device, chrono::Utc::now())
        .await
        .unwrap()
        .unwrap();
    boxed_step(|| realm_device_multi_parent_shared_ancestor_quota(fixture, package, &authority))
        .await;
    let child = boxed_step(|| business_grant(fixture, package, &candidate.actor_id)).await;
    eprintln!("native MLS: foreign member");
    let database = boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
    let (recipient, _server) =
        boxed_step(|| super::realm_native_fixture::network_fixture(database.pool())).await;
    eprintln!("native MLS: foreign Station ready");
    boxed_step(|| foreign_member(fixture, &recipient)).await;
    eprintln!("native MLS: foreign member joined");
    let mut group =
        boxed_step(|| genesis(fixture, package, candidate, device, &authority, &child)).await;
    let _additional_recipient = boxed_step(|| {
        realm_device_prepared_add_writer_wait_crosses_claim_deadline(
            fixture, package, candidate, device, &authority, &child, &recipient, &group,
        )
    })
    .await;
    boxed_step(|| {
        realm_device_prepared_claim_guard_crosses_actual_deadline(fixture, package, &authority)
    })
    .await;
    boxed_step(|| {
        realm_device_owned_query_prepared_guard_crosses_deadline(fixture, package, &authority)
    })
    .await;
    let (recipient_identity, claim) =
        boxed_step(|| claim_remote(fixture, &recipient, &authority)).await;
    let original_deadline = claim.claim_receipt.expires_at;
    let (accepted_add, original_commit) = boxed_step(|| {
        commit_add(
            fixture,
            package,
            candidate,
            device,
            &authority,
            &child,
            &recipient,
            recipient_identity,
            claim,
            &mut group,
        )
    })
    .await;
    boxed_step(|| {
        realm_device_consume_writer_wait_crosses_physical_device_expiry(
            fixture, package, candidate, device, &authority, &child, &mut group,
        )
    })
    .await;
    tokio::time::sleep(
        (original_deadline - chrono::Utc::now())
            .to_std()
            .unwrap_or_default()
            + std::time::Duration::from_millis(40),
    )
    .await;
    assert!(chrono::Utc::now() >= original_deadline);
    let before_retry = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let recipient_before_retry = boxed_step(|| obligation_mls_footprint(&recipient)).await;
    let (status, replay) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(accepted_add),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "accepted Add replay after reservation expiry: {replay}"
    );
    let replay: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
        serde_json::from_value(replay).unwrap();
    let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome::Ordinary(
        arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. },
    ) = replay
    else {
        panic!("accepted Add replay must restore its original Commit");
    };
    assert_eq!(commit, original_commit);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before_retry
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(&recipient)).await,
        recipient_before_retry
    );
}

async fn genesis(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
) -> Box<arkret_mls::ArkretMlsGroup> {
    eprintln!("native MLS: create Genesis");
    let scope = candidate.creation_scope.clone();
    let key = SigningKey::from_bytes(&[79; 32]);
    let signer = Ed25519PayloadSigner::new(
        key.clone(),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap(),
    );
    let identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        candidate.actor_id.clone(),
        device.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    eprintln!("native MLS: creator identity ready");
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    eprintln!("native MLS: creator group ready");
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let info = boxed_step(|| public_material(fixture, info)).await;
    let tree = boxed_step(|| public_material(fixture, tree)).await;
    eprintln!("native MLS: public material ready");
    let genesis = signed_event(
        package,
        candidate.actor_id.clone(),
        scope.clone(),
        EventKind::MlsGenesis,
        json!({
            "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref":info,"ratchet_tree_ref":tree,
            "creator_leaf_authority":{
                "leaf_signature_key_b64u":arkret_canonical::base64url_encode(key.verifying_key().as_bytes()),
                "endpoint":{"kind":"device","device_id":device},
                "authorization_event_ref":authority.authorization_ref.event_id
            },"governance_binding":binding,
            "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
        }),
        Some(&child),
        &signer,
    );
    eprintln!("native MLS: submitting Genesis");
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(genesis)
            )),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm Device actual MLS Genesis: {value}"
    );
    group
        .install_local_creator_binding(
            candidate.actor_id.clone(),
            Some(authority.authorization_ref.event_id.clone()),
        )
        .unwrap();
    eprintln!("native MLS: Genesis accepted");
    Box::new(group)
}

pub(super) async fn human_message(
    fixture: &Fixture,
    scope: &ScopeRef,
    group: &mut arkret_mls::ArkretMlsGroup,
    strand_id: arkret_wire::StrandId,
    attachment: arkret::EncryptedAttachment,
    mentioned: &ActorId,
) -> (Event, arkret::MessageCreatePayload) {
    let scope = scope.clone();
    let reference = attachment.blob_ref().to_string();
    let mut plaintext = arkret::MessageCreatePayload::with_content(
        strand_id,
        "discussion",
        arkret::ContentBlock::new(arkret::ContentBlockKind::File, "Human to native Ghost")
            .with_field("blob_ref", json!(reference))
            .with_field("filename", json!("private.txt"))
            .with_field("mime_type", json!(attachment.media_type()))
            .with_field("size_bytes", json!(attachment.size_bytes()))
            .with_field("attachments", json!([attachment]))
            .with_direct_mention_nodes(vec![arkret::MentionNode::RealmMention(
                arkret::RealmMention::new(mentioned.clone()).unwrap(),
            )])
            .unwrap(),
    );
    plaintext.blob_refs = vec![reference];
    let event = submit_human_message_content(fixture, &scope, group, &plaintext, None, None).await;
    (event, plaintext)
}

pub(super) async fn invalid_human_messages(
    fixture: &Fixture,
    scope: &ScopeRef,
    group: &mut arkret_mls::ArkretMlsGroup,
    strand_id: arkret_wire::StrandId,
    mentioned: &ActorId,
) -> Event {
    let mut foreign = mentioned.as_realm_actor_id().unwrap().clone();
    foreign.realm_id = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x93; 32],
    ));
    assert_ne!(&foreign.realm_id, scope.realm_id());
    let content = arkret::ContentBlock::text("Authenticated but invalid target")
        .with_direct_mention_nodes(vec![arkret::MentionNode::RealmMention(
            arkret::RealmMention::new(ActorId::realm(foreign)).unwrap(),
        )])
        .unwrap();
    let plaintext =
        arkret::MessageCreatePayload::with_content(strand_id.clone(), "discussion", content);
    submit_human_message_content(fixture, scope, group, &plaintext, None, None).await;
    let valid = arkret::MessageCreatePayload::with_content(
        strand_id,
        "discussion",
        arkret::ContentBlock::text("This body must not execute with malformed metadata"),
    );
    submit_human_message_content(fixture, scope, group, &valid, Some(b"{"), None).await;
    submit_human_message_content(fixture, scope, group, &valid, None, Some(b"{")).await
}

async fn submit_human_message_content(
    fixture: &Fixture,
    scope: &ScopeRef,
    group: &mut arkret_mls::ArkretMlsGroup,
    plaintext: &arkret::MessageCreatePayload,
    raw_content: Option<&[u8]>,
    raw_metadata: Option<&[u8]>,
) -> Event {
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let mut encrypted = plaintext.clone();
    let content = encrypted.content.take().unwrap();
    let content = arkret_canonical::canonical_json_bytes(&content).unwrap();
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        arkret::MESSAGE_CONTENT_BLOCK_MLS_CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        group.epoch(),
        current.current_mls_commit_event_ref.clone(),
        group.local_content_sender_domain().unwrap(),
        arkret::EventContentRoutingContext::None,
    )
    .unwrap();
    encrypted.encrypted_content = Some(
        arkret_mls::encrypted_envelope_from_payload(
            &group
                .encrypt_payload(header, raw_content.unwrap_or(&content))
                .unwrap(),
        )
        .unwrap(),
    );
    if let Some(bytes) = raw_metadata {
        let header = arkret::EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            arkret::MESSAGE_METADATA_MLS_CONTENT_TYPE,
            arkret::EncryptedPayloadScheme::MlsRfc9420,
            scope.clone(),
            EventKind::MessageCreate.as_str(),
            group.epoch(),
            current.current_mls_commit_event_ref,
            group.local_content_sender_domain().unwrap(),
            arkret::EventContentRoutingContext::None,
        )
        .unwrap();
        encrypted.encrypted_metadata = Some(
            arkret_mls::encrypted_envelope_from_payload(
                &group.encrypt_payload(header, bytes).unwrap(),
            )
            .unwrap(),
        );
    }
    let event = fixture.admin_event(EventKind::MessageCreate, scope.clone(), json!(encrypted));
    submit_human_event(fixture, event.clone()).await;
    event
}

async fn submit_human_event(fixture: &Fixture, event: Event) {
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            Some(json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event)
            ))),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary member original accepted: {value}"
    );
}

pub(super) async fn human_updates_group(
    fixture: &Fixture,
    scope: &ScopeRef,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let commit = group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &commit,
        binding,
    )
    .unwrap();
    let event = fixture.admin_event(EventKind::MlsCommit, scope.clone(), json!(payload));
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: Vec::new(),
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            Some(json!(submission)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary member update during Bot processing: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event,
                commit: accepted.commit,
            },
            &current,
        )
        .unwrap();
}

pub(super) async fn verify_runtime_message(
    fixture: &Fixture,
    group: &mut arkret_mls::ArkretMlsGroup,
    event_id: &str,
    actor: &ActorId,
    expected: &arkret::ContentBlock,
) {
    use arkret::EventPayloadExt as _;
    let original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event_id.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&original.event.actor_id, actor);
    assert!(original.event.executed_by.is_none());
    let method = original
        .event
        .producer_proof
        .as_ref()
        .unwrap()
        .verification_method
        .clone();
    let selector = arkret::SignerKeyQuerySelector::HistoricalRealmDevice {
        sender_kind: arkret_models_identity::RealmDeviceSignerKind::RealmDevice,
        actor_id: actor.clone(),
        device_id: method.as_str().rsplit_once('#').unwrap().1.parse().unwrap(),
        verification_method: method,
        committed_event_ref: arkret_wire::CommittedEventRef {
            event_id: original.event.event_id.clone(),
            commit_id: original.commit.commit_id.clone(),
            stream_ref: original.commit.stream_ref.clone(),
            stream_position: original.commit.stream_position,
        },
    };
    let mut wrong = selector.clone();
    if let arkret::SignerKeyQuerySelector::HistoricalRealmDevice {
        committed_event_ref,
        ..
    } = &mut wrong
    {
        committed_event_ref.stream_position += 1;
    }
    let request = arkret::SignerKeysQueryRequestBody {
        request_id: format!("ak:request:{}", uuid::Uuid::now_v7())
            .parse()
            .unwrap(),
        realm_id: fixture.realm.clone(),
        recipient_account_id: Some(fixture.pcr.history.account.clone()),
        recipient_actor_id: None,
        queries: vec![selector, wrong],
    };
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/signer-keys/query",
            ServiceOperationId::SelfSignerKeysReadResolveV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary reader verifies native author: {value}"
    );
    let keys: arkret::SignerKeysQueryOutcome = serde_json::from_value(value).unwrap();
    keys.validate_for_request(&request).unwrap();
    assert!(matches!(
        keys.results[0],
        arkret::SignerKeyQueryOutcome::HistoricalRealmDeviceResolved { .. }
    ));
    assert!(matches!(
        keys.results[1],
        arkret::SignerKeyQueryOutcome::Unavailable { .. }
    ));
    let payload = original.event.as_message_create().unwrap();
    assert!(payload.content.is_none());
    let envelope = payload.encrypted_content.unwrap();
    let sender = String::from_utf8(arkret::mls_basic_credential_identity(actor).unwrap()).unwrap();
    let header = envelope
        .reconstruct_pre_encryption_header(
            arkret::EncryptedPayloadScheme::MlsRfc9420,
            original.event.scope_ref,
            EventKind::MessageCreate.as_str(),
            &sender,
            None,
        )
        .unwrap();
    let encrypted =
        arkret_mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header).unwrap();
    let plaintext: arkret::ContentBlock =
        serde_json::from_slice(&group.decrypt_payload(&encrypted).unwrap()).unwrap();
    assert_eq!(&plaintext, expected);
}

pub(super) struct ContentSink {
    pub event: Event,
    pub plaintext: arkret::MessageCreatePayload,
    pub attempts: std::sync::atomic::AtomicUsize,
}

pub(super) fn attachment_plaintext() -> Vec<u8> {
    (0..96 * 1024).map(|index| (index % 256) as u8).collect()
}

pub(super) struct TextOnlySink;

#[async_trait::async_trait]
impl arkret_bridge_runtime::managed_device::NativeContentSink for TextOnlySink {
    async fn deliver(
        &self,
        recipient: &arkret_bridge_runtime::managed_device::NativeContentRecipient,
        content: &arkret_bridge_runtime::managed_device::NativeContent,
    ) -> arkret_bridge_runtime::Result<()> {
        assert_eq!(recipient.scope(), &content.original().event.scope_ref);
        assert!(recipient.actor_id().as_realm_actor_id().is_some());
        recipient.validate_current().await?;
        let message = content.message().unwrap();
        assert!(!message.blob_refs.is_empty());
        for reference in &message.blob_refs {
            assert!(content.attachment_bytes(reference).is_none());
        }
        Err(arkret_bridge_runtime::BridgeError::App(
            "leave the text-only delivery pending for the media consumer".into(),
        ))
    }
}

#[async_trait::async_trait]
impl arkret_bridge_runtime::managed_device::NativeContentSink for ContentSink {
    fn requires_attachments(&self) -> bool {
        true
    }
    async fn deliver(
        &self,
        recipient: &arkret_bridge_runtime::managed_device::NativeContentRecipient,
        content: &arkret_bridge_runtime::managed_device::NativeContent,
    ) -> arkret_bridge_runtime::Result<()> {
        assert_eq!(recipient.scope(), &content.original().event.scope_ref);
        assert!(recipient.actor_id().as_realm_actor_id().is_some());
        recipient.validate_current().await?;
        assert_eq!(content.original().event, self.event);
        assert_eq!(
            serde_json::to_value(content.message()).unwrap(),
            serde_json::to_value(&self.plaintext).unwrap()
        );
        let descriptor = self
            .plaintext
            .content
            .as_ref()
            .unwrap()
            .rendered_encrypted_attachment()
            .unwrap()
            .unwrap();
        assert_eq!(
            content
                .attachment_bytes(descriptor.blob_ref().as_str())
                .unwrap(),
            attachment_plaintext()
        );
        if self
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            return Err(arkret_bridge_runtime::BridgeError::App(
                "external delivery temporarily unavailable".into(),
            ));
        }
        Ok(())
    }
}

async fn claim_remote(
    fixture: &Fixture,
    recipient: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) -> (arkret_mls::ArkretMlsIdentity, KeyPackagesClaimOutcome) {
    boxed_step(|| {
        claim_remote_with_lifetime(
            fixture,
            recipient,
            authority,
            chrono::Duration::seconds(60),
            true,
        )
    })
    .await
}

async fn claim_remote_with_lifetime(
    fixture: &Fixture,
    recipient: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    lifetime: chrono::Duration,
    exercise_writer_wait: bool,
) -> (arkret_mls::ArkretMlsIdentity, KeyPackagesClaimOutcome) {
    eprintln!("native MLS: remote KeyPackage claim");
    let recipient_key = SigningKey::from_bytes(&recipient.pcr.history.founding_device_signing_seed);
    let recipient_identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        ActorId::account(recipient.pcr.history.account.clone()),
        recipient.pcr.history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(recipient_key),
    )
    .unwrap();
    let record = recipient_identity.key_package_record().unwrap();
    let upload = recipient_identity
        .signed_key_packages_upload_request(
            &[record],
            recipient.pcr.history.device_verification_method.as_str(),
        )
        .unwrap();
    let (status, value) = recipient
        .admin_post(
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1.as_str(),
            &json!(upload),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real foreign Account package upload: {value}"
    );
    assert_eq!(value["accepted"], 1);
    let command = claim_request_with_lifetime(
        &authority,
        &recipient,
        &upload.keypackages[0].keypackage_ref,
        lifetime,
    );
    if exercise_writer_wait {
        boxed_step(|| {
            realm_device_claim_writer_wait_crosses_deadline(fixture, recipient, authority, &command)
        })
        .await;
    }
    let before = recipient
        .state
        .test_persistence()
        .mls_key_packages()
        .snapshot_all()
        .await
        .unwrap();
    let mut invalid = command.clone();
    let PeerKeyPackageRequesterAuthorization::RealmDevice { signature, .. } =
        &mut invalid.requester_authorization
    else {
        unreachable!()
    };
    signature.sig =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64])).unwrap();
    let (status, _) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(invalid),
        )
    })
    .await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(
        before,
        recipient
            .state
            .test_persistence()
            .mls_key_packages()
            .snapshot_all()
            .await
            .unwrap()
    );
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(command),
        )
    })
    .await;
    if status != StatusCode::OK {
        let stored = fixture
            .state
            .test_persistence()
            .mls_key_packages()
            .realm_claim_source(
                command.service_binding.source_id.as_str(),
                command.claim_request_id.as_str(),
            )
            .await
            .unwrap();
        eprintln!(
            "native MLS: retained source state {:?}",
            stored.and_then(|row| row.result).map(|result| result.state)
        );
        let stored = recipient
            .state
            .test_persistence()
            .mls_key_packages()
            .get_peer_claim(
                command.service_binding.source_id.as_str(),
                command.claim_request_id.as_str(),
            )
            .await
            .unwrap();
        eprintln!(
            "native MLS: recipient ledger state {:?}",
            stored.map(|row| row.state)
        );
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm requester claims foreign ordinary device: {value}"
    );
    let claim: KeyPackagesClaimOutcome = serde_json::from_value(value.clone()).unwrap();
    let (status, replay) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(command),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "exact original retry: {replay}");
    assert_eq!(replay, value);
    let stored = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .realm_claim_source(
            command.service_binding.source_id.as_str(),
            command.claim_request_id.as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(json!(stored.result.unwrap().claim_outcome.unwrap()), value);
    eprintln!("native MLS: remote claim retained");
    (recipient_identity, claim)
}

async fn commit_add(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    recipient: &Fixture,
    recipient_identity: arkret_mls::ArkretMlsIdentity,
    claim: KeyPackagesClaimOutcome,
    group: &mut arkret_mls::ArkretMlsGroup,
) -> (SelfAuthoritySubmitRequest, arkret_wire::RealmCommit) {
    let scope = candidate.creation_scope.clone();
    let key = SigningKey::from_bytes(&[79; 32]);
    let signer = Ed25519PayloadSigner::new(
        key.clone(),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap(),
    );
    let groups = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    };
    let current = groups.current(&scope).await.unwrap().unwrap().value;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let package_record = arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap();
    let added = group
        .add_member_with_governance_binding(&package_record, &binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.current_mls_commit_event_ref.clone(),
        current.current_key_access_revision,
        &added.commit,
        binding,
    )
    .unwrap();
    let event = signed_event(
        package,
        candidate.actor_id.clone(),
        scope.clone(),
        EventKind::MlsCommit,
        json!(payload),
        Some(&child),
        &signer,
    );
    let at = event.created_at;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: fixture.realm.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: ActorId::account(recipient.pcr.history.account.clone()),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient.pcr.history.founding_device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_b64: added.welcome.ciphertext_b64,
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            DidUrl::new(format!("{}#{}", authority.native_did, device)).unwrap(),
            at,
            &key,
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        welcome.producer_proof.verification_method.clone(),
        at,
        &key,
    )
    .unwrap();
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            &authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(submission),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "Realm Device complete foreign Add/Welcome: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    group.install_accepted_commit(&accepted, &current).unwrap();
    assert_eq!(
        groups.current(&scope).await.unwrap().unwrap().value.epoch,
        1
    );
    boxed_step(|| {
        receive_and_consume(
            fixture,
            recipient,
            recipient_identity,
            &welcome,
            &accepted,
            &claim,
        )
    })
    .await;
    (submission, accepted.commit)
}

async fn account_request(
    account: &Fixture,
    method: reqwest::Method,
    path: &str,
    operation: ServiceOperationId,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let url = format!(
        "{}{path}",
        account.state.config().public_base_url.trim_end_matches('/')
    );
    let dpop = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new(method.as_str(), url.clone())
            .access_token(account.token.clone()),
        &account.holder_key,
    )
    .unwrap();
    let client =
        super::realm_native_fixture::native_http_client(std::time::Duration::from_secs(30));
    let mut request = client
        .request(method, url)
        .header("authorization", format!("DPoP {}", account.token))
        .header("dpop", dpop.header_value)
        .header("arkret-operation", operation.as_str());
    if let Some(body) = body {
        if operation == ServiceOperationId::SelfKeysKeypackagesCommandClaimV1 {
            let claim: KeyPackagesClaimRequestBody = serde_json::from_value(body.clone()).unwrap();
            request = request.header("idempotency-key", claim.claim_request_id.as_str());
        }
        request = request
            .header("content-type", "application/json")
            .body(arkret_canonical::canonical_json_bytes(&body).unwrap());
    }
    let response = request.send().await.unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    (status, response.json().await.unwrap())
}

async fn receive_and_consume(
    governor: &Fixture,
    recipient: &Fixture,
    identity: arkret_mls::ArkretMlsIdentity,
    welcome: &arkret_wire::MlsWelcomeDelivery,
    accepted: &arkret_wire::CommittedEventFullView,
    claim: &KeyPackagesClaimOutcome,
) {
    use arkret_models_collaboration::device_messages::{
        DeviceMessagesAckOutcome, DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
        RecipientDelivery,
    };
    let sender =
        coland_http::routing::federation::outbox::FederationDispatcher::new(governor.state.clone());
    let receiver = coland_http::routing::federation::outbox::FederationDispatcher::new(
        recipient.state.clone(),
    );
    let mut queued = None;
    let mut delivered_page = None;
    for _ in 0..12 {
        boxed_step(|| sender.run_one_pass()).await.unwrap();
        boxed_step(|| receiver.run_one_pass()).await.unwrap();
        let (status, value) = boxed_step(|| {
            account_request(
                recipient,
                reqwest::Method::GET,
                "/_arkret/self/device_messages",
                ServiceOperationId::SelfDeviceMessagesReadListV1,
                None,
            )
        })
        .await;
        assert_eq!(status, StatusCode::OK, "real recipient queue: {value}");
        let page: DeviceMessagesGetOutcome = serde_json::from_value(value).unwrap();
        assert_ne!(page.lost, Some(true));
        queued = page.deliveries.iter().find_map(|item| match item {
            RecipientDelivery::MlsWelcome { mls_welcome }
                if mls_welcome.welcome_id == welcome.welcome_id =>
            {
                Some(mls_welcome.clone())
            }
            _ => None,
        });
        if queued.is_some() {
            delivered_page = Some(page);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    let queued = queued.expect("remote committed replication must queue the original Welcome");
    assert_eq!(json!(queued), json!(welcome));
    // The authentic recipient acknowledges the delivered prefix. Consume must
    // remain independent of the queue row and recover the retained claim.
    let delivered_page = delivered_page.unwrap();
    let ack = DeviceMessagesAckRequestBody {
        ack_token: delivered_page.ack_token.unwrap(),
    };
    let (status, acknowledged) = boxed_step(|| {
        account_request(
            recipient,
            reqwest::Method::POST,
            "/_arkret/self/device_messages/ack",
            ServiceOperationId::SelfDeviceMessagesCommandAckV1,
            Some(json!(ack)),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "actual Welcome ACK: {acknowledged}");
    let acknowledged: DeviceMessagesAckOutcome = serde_json::from_value(acknowledged).unwrap();
    assert!(acknowledged.pruned_count > 0);
    let (status, after_ack) = boxed_step(|| {
        account_request(
            recipient,
            reqwest::Method::GET,
            "/_arkret/self/device_messages",
            ServiceOperationId::SelfDeviceMessagesReadListV1,
            None,
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual queue after ACK: {after_ack}"
    );
    let after_ack: DeviceMessagesGetOutcome = serde_json::from_value(after_ack).unwrap();
    assert!(!after_ack.deliveries.iter().any(|delivery| matches!(delivery,
        RecipientDelivery::MlsWelcome { mls_welcome } if mls_welcome.welcome_id == welcome.welcome_id
    )), "ACK must prune the original even without a continuation cursor");
    let replicated = recipient
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&accepted.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(json!(replicated.event), json!(accepted.event));
    assert_eq!(json!(replicated.commit), json!(accepted.commit));
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(&[79; 32]).verifying_key().as_bytes(),
        ),
    };
    arkret_signatures::detached_object::verify_detached_object_signature(
        &queued.producer_proof,
        &arkret_canonical::unsigned_value(&queued, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        &key,
    )
    .unwrap();
    let mut joined = arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
        identity, &queued, accepted,
    )
    .unwrap();
    boxed_step(|| install_received_roster(recipient, accepted, &mut joined)).await;
    let record = joined.export_state_record().unwrap();
    let checkpoint =
        std::env::temp_dir().join(format!("arkret-realm-mls-{}.json", uuid::Uuid::now_v7()));
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&checkpoint)
            .unwrap();
        file.write_all(&serde_json::to_vec(&record).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    let restored = arkret_mls::ArkretMlsGroup::restore_from_state_record(
        &serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(restored.epoch(), 1);
    let receipt = RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .unwrap(),
        claim_request_id: claim.claim_request_id.clone(),
        key_package_ref: arkret_wire::NonEmptyString::new(claim.claims[0].keypackage_ref.clone())
            .unwrap(),
        recipient: RecipientMlsDurableSigner::Device {
            recipient_account_id: recipient.pcr.history.account.clone(),
            recipient_device_id: recipient.pcr.history.founding_device_id.clone(),
            device_verification_method: recipient.pcr.history.device_verification_method.clone(),
        },
        recipient_id: recipient.state.service_core_id(),
        realm_id: queued.realm_id.clone(),
        mls_group_id: queued.effective_scope.canonical_mls_group_id().unwrap(),
        mls_epoch: restored.epoch(),
        welcome_ref: queued.welcome_id.clone(),
        welcome_digest: queued.durable_receipt_digest().unwrap(),
        durable_at: chrono::Utc::now(),
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(
                recipient.pcr.history.device_verification_method.to_string(),
            )
            .unwrap(),
            signature_algorithm: None,
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).unwrap(),
        },
    };
    let command = joined
        .identity()
        .signed_key_packages_consume_request(
            queued.keypackage_claim_ref.clone(),
            joined
                .identity()
                .sign_recipient_mls_durable_receipt(receipt)
                .unwrap(),
        )
        .unwrap();
    let before_refusals =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(recipient)).await;
    for (name, digest, epoch) in [
        (
            "wrong_welcome_digest",
            arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64))).unwrap(),
            restored.epoch(),
        ),
        (
            "wrong_epoch",
            queued.durable_receipt_digest().unwrap(),
            restored.epoch() + 1,
        ),
    ] {
        let mut rejected = command.clone();
        rejected.recipient_durable_receipt.welcome_digest = digest;
        rejected.recipient_durable_receipt.mls_epoch = epoch;
        rejected.recipient_durable_receipt = joined
            .identity()
            .sign_recipient_mls_durable_receipt(rejected.recipient_durable_receipt)
            .unwrap();
        rejected = joined
            .identity()
            .signed_key_packages_consume_request(
                queued.keypackage_claim_ref.clone(),
                rejected.recipient_durable_receipt,
            )
            .unwrap();
        let (status, problem) = boxed_step(|| {
            account_request(
                recipient,
                reqwest::Method::POST,
                "/_arkret/self/keys/keypackages/consume",
                ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
                Some(json!(rejected)),
            )
        })
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{name}: {problem}");
        assert_eq!(
            problem["type"], "https://arkret.org/problems/conflict",
            "{name}"
        );
        assert_eq!(
            boxed_step(|| { super::realm_native_fixture::native_business_footprint(recipient) })
                .await,
            before_refusals,
            "{name}: signed invalid receipt must leave the claim live and unchanged"
        );
    }
    let (status, consumed) = boxed_step(|| {
        account_request(
            recipient,
            reqwest::Method::POST,
            "/_arkret/self/keys/keypackages/consume",
            ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
            Some(json!(command)),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "real recipient consume: {consumed}");
    let (status, replay) = boxed_step(|| {
        account_request(
            recipient,
            reqwest::Method::POST,
            "/_arkret/self/keys/keypackages/consume",
            ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
            Some(json!(command)),
        )
    })
    .await;
    assert_eq!(status, StatusCode::OK, "real consume replay: {replay}");
    assert_eq!(consumed, replay);
    let ledger = recipient
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim_by_claim_id(queued.keypackage_claim_ref.as_str())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.state, "consumed");
    std::fs::remove_file(checkpoint).unwrap();
    eprintln!("native MLS: remote queue, durable checkpoint and exact consume accepted");
}

async fn install_received_roster(
    recipient: &Fixture,
    accepted: &arkret_wire::CommittedEventFullView,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadOutcome,
    };
    let request = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: accepted.event.realm_id.clone(),
        effective_scope: accepted.event.scope_ref.clone(),
        mls_group_id: accepted.event.scope_ref.canonical_mls_group_id().unwrap(),
        target_commit_event_ref: accepted.event.event_id.clone(),
        target_epoch: group.epoch(),
        caller_actor_id: ActorId::account(recipient.pcr.history.account.clone()),
        cursor: None,
    };
    let mut next = request.clone();
    let mut pages = Vec::new();
    for _ in 0..16 {
        let (status, value) = boxed_step(|| {
            account_request(
                recipient,
                reqwest::Method::POST,
                arkret_wire::peer_operation_paths::PATH_SELF_MLS_ROSTER_AUTHORITY,
                ServiceOperationId::SelfMlsReadRosterAuthorityV1,
                Some(json!(next)),
            )
        })
        .await;
        assert_eq!(status, StatusCode::OK, "recipient roster: {value}");
        let page: MlsSelfRosterAuthorityReadOutcome = serde_json::from_value(value).unwrap();
        next.cursor = page.roster.next_cursor.clone();
        pages.push(page);
        if next.cursor.is_none() {
            break;
        }
    }
    assert!(next.cursor.is_none(), "roster pagination must terminate");
    let peer = arkret::verify_mls_member_roster_authority_pages(&pages, &request).unwrap();
    let material_request =
        arkret::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let (status, material) = boxed_step(|| {
        account_request(
            recipient,
            reqwest::Method::POST,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_GROUP_STATE_MATERIAL,
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            Some(json!(material_request)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recipient Genesis public material: {material}"
    );
    let material = serde_json::from_value(material).unwrap();
    arkret::install_verified_mls_self_roster_bindings(group, &pages, &request, &material).unwrap();
}

/// A real ordinary member admits the runtime Device through the same MLS
/// membership flow as any other admitted member; no Bot-only permission exists.
pub(super) async fn human_admits_runtime(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
) -> Box<arkret_mls::ArkretMlsGroup> {
    human_admits_runtime_in_authority(fixture, device, None).await
}

pub(super) async fn human_admits_runtime_after_handoff(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    next: &Fixture,
) -> Box<arkret_mls::ArkretMlsGroup> {
    human_admits_runtime_in_authority(fixture, device, Some(next)).await
}

async fn human_admits_runtime_in_authority(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    next: Option<&Fixture>,
) -> Box<arkret_mls::ArkretMlsGroup> {
    let history = &fixture.pcr.history;
    let scope = device.effective_scope().clone();
    let actor = ActorId::account(history.account.clone());
    if let ScopeRef::Circle { circle_id, .. } = &scope {
        let snapshot = fixture
            .state
            .test_persistence()
            .authority_commits()
            .realm_state_snapshot_material(&fixture.realm)
            .await
            .unwrap()
            .unwrap();
        let parent = snapshot.current_state_entries.iter().find_map(|row| {
            let arkret_wire::TypedCurrentRow::Value { selector, revision, value, .. } = row;
            matches!(selector, arkret_wire::CurrentSelector::MemberState { actor_id } if actor_id == &actor)
                .then_some((revision, value))
        }).expect("the ordinary member has an accepted parent membership");
        assert_eq!(parent.1["membership"], "join");
        let join = fixture.admin_event(
            EventKind::CircleMemberState,
            scope.clone(),
            json!({"circle_id":circle_id,"member_id":actor,"membership":"join",
                "parent_membership_revision":parent.0}),
        );
        boxed_step(|| submit_human_event(fixture, join)).await;
    }
    let key = SigningKey::from_bytes(&history.founding_device_signing_seed);
    let authorization = history
        .events
        .iter()
        .find(|e| e.kind == EventKind::DeviceAuthorize)
        .unwrap()
        .event_id
        .clone();
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        history.founding_device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut group = identity
        .create_group_with_governance_binding(&scope, &binding)
        .unwrap();
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let info = boxed_step(|| public_material(fixture, info)).await;
    let tree = boxed_step(|| public_material(fixture, tree)).await;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let raw = arkret_wire::test_support::raw_event_for_actor_at(EventKind::MlsGenesis.as_str(), scope.clone(), actor.clone(), json!({
        "cipher_suite":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", "group_info_ref":info,"ratchet_tree_ref":tree,
        "creator_leaf_authority":{"leaf_signature_key_b64u":arkret_canonical::base64url_encode(key.verifying_key().as_bytes()),
            "endpoint":{"kind":"device","device_id":history.founding_device_id},"authorization_event_ref":authorization},
        "governance_binding":binding,"created_at":at
    }),at).unwrap();
    let genesis = fixture.sign_admin(raw);
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            Some(json!(SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(genesis)
            ))),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary member creates actual MLS group: {value}"
    );
    group
        .install_local_creator_binding(actor.clone(), Some(authorization.clone()))
        .unwrap();
    human_adds_runtime_to_group_in_authority(fixture, device, Box::new(group), next).await
}

pub(super) async fn human_adds_runtime_to_group(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    group: Box<arkret_mls::ArkretMlsGroup>,
) -> Box<arkret_mls::ArkretMlsGroup> {
    human_adds_runtime_to_group_in_authority(fixture, device, group, None).await
}

async fn human_adds_runtime_to_group_in_authority(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    mut group: Box<arkret_mls::ArkretMlsGroup>,
    next: Option<&Fixture>,
) -> Box<arkret_mls::ArkretMlsGroup> {
    let history = &fixture.pcr.history;
    let scope = device.effective_scope().clone();
    let key = SigningKey::from_bytes(&history.founding_device_signing_seed);
    let authorization = history
        .events
        .iter()
        .find(|e| e.kind == EventKind::DeviceAuthorize)
        .unwrap()
        .event_id
        .clone();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut claim = KeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            rand::random::<[u8; 32]>(),
        ))
        .unwrap(),
        target_account_id: None,
        target_actor_id: Some(device.actor_id.clone()),
        requester_account_id: Some(history.account.clone()),
        requester_actor_id: None,
        intended_realm_id: fixture.realm.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: at + chrono::Duration::minutes(4),
        target_device_ids: vec![device.device_id.clone()],
        target_keypackage_ref: None,
        target_agent_id: None,
        target_agent_verification_method: None,
        target_agent_key_authorize_event_id: None,
        timeout_ms: None,
        strand_id: None,
        pair_key: None,
        last_resort_allowed: None,
        service_binding: KeyPackagesClaimServiceBinding {
            source_id: fixture.state.service_core_id(),
            destination_id: fixture.state.service_core_id(),
        },
        requester_authorization: PeerKeyPackageRequesterAuthorization::Device {
            verification_method: history.device_verification_method.clone(),
            requester_device_id: history.founding_device_id.clone(),
            device_authorize_event_id: authorization,
            signed_at: at,
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                history.device_verification_method.as_str(),
                &[0; 64],
            )
            .unwrap(),
        },
    };
    let input = keypackage_claim_authorization_signing_bytes(
        &claim.unsigned_request(),
        &claim.service_binding,
        &claim.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut claim.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &history.founding_device_signing_seed,
        history.device_verification_method.as_str(),
        &input,
    )
    .unwrap();
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(claim)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary member claims admitted Realm Device: {value}"
    );
    let claim: KeyPackagesClaimOutcome = serde_json::from_value(value).unwrap();
    assert_eq!(claim.claims.len(), 1);
    let original_claim = arkret_canonical::canonical_json_bytes(&claim).unwrap();
    if let Some(next) = next {
        assert_eq!(
            claim.claim_receipt.destination_id,
            fixture.state.service_core_id()
        );
        assert_eq!(
            arkret_identity::verification_method_did(claim.claim_receipt.signature.kid.as_str())
                .unwrap(),
            fixture.state.service_did(),
        );
        eprintln!("native MLS: complete handoff after the original claim receipt");
        boxed_step(|| super::realm_native_fixture::handoff_runtime_realm(fixture, next)).await;
    }
    let governor = next.unwrap_or(fixture);
    let imported_claim = governor
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim_by_claim_id(&claim.claims[0].claim_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        original_claim,
        arkret_canonical::canonical_json_bytes(&imported_claim.outcome.unwrap()).unwrap(),
        "the receiving ledger must retain the original claim including its old Station signature"
    );
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: governor.pool.clone(),
    }
    .current(&scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let added = group
        .add_member_with_governance_binding(
            &arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap(),
            &binding,
        )
        .unwrap();
    let event = fixture.admin_event(
        EventKind::MlsCommit,
        scope.clone(),
        json!(
            MlsCommitPayload::new(
                current.current_mls_commit_event_ref.clone(),
                current.current_key_access_revision,
                &added.commit,
                binding
            )
            .unwrap()
        ),
    );
    let at = event.created_at;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:{}",
            uuid::Uuid::now_v7()
        ))
        .unwrap(),
        realm_id: fixture.realm.clone(),
        effective_scope: scope,
        commit_event_ref: event.event_id.clone(),
        recipient_actor_id: device.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: device.device_id.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_b64: added.welcome.ciphertext_b64,
        producer_proof: arkret_signatures::detached_object::sign_detached_object(
            &Value::Null,
            arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            history.device_verification_method.clone(),
            at,
            &key,
        )
        .unwrap(),
    };
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        history.device_verification_method.clone(),
        at,
        &key,
    )
    .unwrap();
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            Some(json!(submission)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "ordinary member admits runtime with actual Add/Welcome: {value}"
    );
    let accepted = governor
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    if next.is_some() {
        assert_eq!(accepted.commit.governance_generation, 1);
        assert_eq!(
            arkret_identity::verification_method_did(
                accepted.commit.signature.verification_method.as_str()
            )
            .unwrap(),
            governor.state.service_did(),
        );
        if let Some(replica) = fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
        {
            assert_eq!(
                replica.commit, accepted.commit,
                "an old Station replica must retain the actual new governor's original"
            );
        }
    }
    group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event,
                commit: accepted.commit,
            },
            &current,
        )
        .unwrap();
    group
}

/// A real covering Commit removes the old leaf before the next legitimate Add.
/// The RealmActor's Circle membership and Device original remain unchanged.
pub(super) async fn human_rotates_out_runtime(
    fixture: &Fixture,
    device: &arkret_bridge_runtime::managed_device::ManagedDevice,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    let scope = device.effective_scope().clone();
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: fixture.pool.clone(),
    }
    .current(&scope)
    .await
    .unwrap()
    .unwrap()
    .value;
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&current.current_mls_commit_event_ref)
        .await
        .unwrap()
        .unwrap();
    let accepted = arkret_wire::CommittedEventFullView {
        event: accepted.event,
        commit: accepted.commit,
    };
    install_received_roster(fixture, &accepted, group).await;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )
    .unwrap();
    let removed = group
        .remove_members_by_actor_with_governance_binding(&[device.actor_id.clone()], &binding)
        .unwrap();
    assert_eq!(removed.removed_actors, vec![device.actor_id.clone()]);
    let event = fixture.admin_event(
        EventKind::MlsCommit,
        scope,
        json!(
            MlsCommitPayload::new(
                current.current_mls_commit_event_ref.clone(),
                current.current_key_access_revision,
                &removed.commit,
                binding
            )
            .unwrap()
        ),
    );
    let submission = SelfAuthoritySubmitRequest::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            Some(json!(submission)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Remove before fresh Welcome: {value}"
    );
    let accepted = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    group
        .install_accepted_commit(
            &arkret_wire::CommittedEventFullView {
                event: accepted.event,
                commit: accepted.commit,
            },
            &current,
        )
        .unwrap();
}

include!("realm_actor_obligation_fixture.rs");
