// Included in realm_actor_mls_fixture: real RealmDevice obligations, no wire substitutes.

async fn obligation_admin_grant(fixture: &Fixture, body: CapabilityGrantCreateBody) -> GrantId {
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let event = fixture.admin_event(
        EventKind::CapabilityGrant,
        scope,
        json!(CapabilityGrantPayload { grant: body }),
    );
    let id = GrantId::from_event_id(&event.event_id);
    boxed_step(|| submit_human_event(fixture, event)).await;
    id
}

async fn obligation_terminal_child(
    fixture: &Fixture,
    package: &AppletPackage,
    actor: &ActorId,
    parents: &[(GrantId, CapabilityGrantCreateBody)],
) -> GrantId {
    let mut child = parents[0].1.clone();
    child.issuer_id = ActorId::service(package.service_id.clone());
    child.subject = CapabilitySubject::Actor(actor.clone());
    child.actions = parents
        .iter()
        .flat_map(|(_, grant)| grant.actions.clone())
        .collect();
    child.actions.sort();
    child.actions.dedup();
    child.issuer_authority_refs = parents
        .iter()
        .map(|(id, _)| IssuerAuthorityRef::Grant {
            grant_id: id.clone(),
        })
        .collect();
    child
        .issuer_authority_refs
        .sort_by_key(|reference| arkret_canonical::canonical_json_bytes(reference).unwrap());
    child.issued_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    for constraint in &mut child.constraints {
        if constraint.constraint_subkind == Some(GrantConstraintSubkind::AppletAuthority) {
            constraint.executed_by = Some(actor.clone());
        } else if constraint.constraint_kind == GrantConstraintKind::AuthorityControl {
            constraint.authority_regrant_allowed = Some(false);
            constraint.max_authority_depth = Some(0);
            constraint.allowed_managed_actor_roles.clear();
        }
    }
    let signer = Ed25519PayloadSigner::new(
        applet_service_signing_key(&package.webhook_signature_policy.key_ref),
        applet_service_did(package),
        package.webhook_signature_policy.key_ref.clone(),
    );
    let event = signed_event(
        package,
        child.issuer_id.clone(),
        ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        EventKind::CapabilityGrant,
        json!(CapabilityGrantPayload { grant: child }),
        Some(&parents[0].0),
        &signer,
    );
    let id = GrantId::from_event_id(&event.event_id);
    let (status, value) = boxed_step(|| async {
        fixture
            .service_post(
                package,
                "/_arkret/edge/applet/transactions",
                ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1,
                &json!(AppletEventTransactionRequestBody {
                    applet_id: package.applet_id.clone(),
                    source_id: package.service_id.clone(),
                    events: vec![event],
                    committed_events: vec![],
                    signals: vec![]
                }),
                &format!("realm-device-multi-parent-{id}"),
            )
            .await
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real multi-parent terminal child: {value}"
    );
    let outcome: AppletTransactionResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(outcome.status(), AppletTransactionStatus::Accepted);
    id
}

async fn obligation_close_grant(fixture: &Fixture, grant: &GrantId) {
    let rows = fixture
        .state
        .test_persistence()
        .capability_grant_current_states()
        .snapshot_for_realm(&fixture.realm)
        .await
        .unwrap();
    let current = rows.iter().find(|row| &row.grant_id == grant).unwrap();
    let event = fixture.admin_event(EventKind::CapabilityRevoke, ScopeRef::Realm { realm_id: fixture.realm.clone() },
        json!({"grant_id":grant,"expected_revision":current.revision,"reason":"exact native obligation source closed"}));
    boxed_step(|| submit_human_event(fixture, event)).await;
}

async fn realm_device_multi_parent_shared_ancestor_quota(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    eprintln!("RealmDevice multi-parent: actual action-local sources and shared quota");
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let admin = ActorId::account(fixture.pcr.history.account.clone());
    let mut strand = fixture.admin_event(EventKind::StrandCreate, scope.clone(), json!({"object": {
        "schema":"ak.schema.strand.v1","realm_id":fixture.realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"RealmDevice action-local quota"},"state":"active","created_by":admin,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }}));
    strand.payload.get_mut("object").unwrap()["created_at"] = json!(
        arkret_canonical::format_timestamp_canonical(strand.created_at)
    );
    strand = fixture.sign_admin(strand);
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    boxed_step(|| submit_human_event(fixture, strand)).await;
    let quota: GrantConstraint = serde_json::from_value(json!({"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operation_count":2,"period":"P1D","constraint_scope":"per_actor"})).unwrap();
    let mut control = GrantConstraint::new(
        GrantConstraintKind::AuthorityControl,
        GrantConstraintEffect::Allow,
    );
    control.authority_regrant_allowed = Some(true);
    control.max_authority_depth = Some(2);
    control.allowed_managed_actor_roles = vec![ManagedActorRole::Bot, ManagedActorRole::Ghost];
    let ancestor_body = CapabilityGrantCreateBody {
        schema: arkret_wire::SchemaId::CAPABILITY_V1.into(),
        realm_id: Some(fixture.realm.clone()),
        issuer_id: admin.clone(),
        subject: CapabilitySubject::Actor(admin),
        actions: vec!["ak.event.read".into(), "ak.message.create".into()],
        resources: vec![arkret_wire::WireResourceSelector::realm(
            fixture.realm.clone(),
        )],
        constraints: vec![control.clone(), quota.clone()],
        issuer_authority_refs: vec![IssuerAuthorityRef::RealmRoot {
            realm_id: fixture.realm.clone(),
            authority_event_ref: fixture.authority_event_ref.clone().unwrap(),
            authority_generation: 0,
        }],
        issued_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
    };
    let ancestor = boxed_step(|| obligation_admin_grant(fixture, ancestor_body.clone())).await;
    control.max_authority_depth = Some(1);
    let mut parents = Vec::new();
    for (index, action) in ["ak.message.create", "ak.event.read", "ak.message.create"]
        .into_iter()
        .enumerate()
    {
        let mut body = ancestor_body.clone();
        body.subject = CapabilitySubject::Actor(ActorId::service(package.service_id.clone()));
        body.actions = vec![action.into()];
        body.constraints = vec![
            GrantConstraint::applet_authority(
                package.applet_id.clone(),
                ActorId::service(package.service_id.clone()),
                package.registration_epoch.clone(),
            ),
            control.clone(),
            quota.clone(),
        ];
        body.issuer_authority_refs = vec![IssuerAuthorityRef::Grant {
            grant_id: ancestor.clone(),
        }];
        // A different accepted timestamp yields an independent sibling original.
        body.issued_at = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::milliseconds(index as i64),
        );
        let id = boxed_step(|| obligation_admin_grant(fixture, body.clone())).await;
        parents.push((id, body));
    }
    assert_ne!(parents[0].0, parents[2].0);
    let before_issuance =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    let child = boxed_step(|| {
        obligation_terminal_child(fixture, package, &authority.actor_id, &parents[..2])
    })
    .await;
    let sibling = boxed_step(|| {
        obligation_terminal_child(fixture, package, &authority.actor_id, &parents[2..])
    })
    .await;
    let after_issuance =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    for table in [
        "capability_quota_counters",
        "capability_quota_buckets",
        "capability_quota_consumptions",
    ] {
        assert_eq!(
            before_issuance[table], after_issuance[table],
            "grant issuance must not exercise business quota"
        );
    }
    let signer = Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[79; 32]),
        authority.native_did.clone(),
        DidUrl::new(format!("{}#{}", authority.native_did, authority.device_id)).unwrap(),
    );
    let make_message = |grant: &GrantId, text: &str| {
        signed_event(
            package,
            authority.actor_id.clone(),
            scope.clone(),
            EventKind::MessageCreate,
            json!(arkret::MessageCreatePayload::with_content(
                strand_id.clone(),
                "discussion",
                arkret::ContentBlock::text(text)
            )),
            Some(grant),
            &signer,
        )
    };
    let first = make_message(&child, "real RealmDevice split source message");
    let submit = |event: Event| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(SelfAuthoritySubmitRequestBody::Event(
                arkret_wire::EventAdmissionSubmission::new(event)
            )),
        )
    };
    let (status, value) = boxed_step(|| submit(first.clone())).await;
    assert_eq!(status, StatusCode::OK, "real multi-parent message: {value}");
    let first_original = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&first.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_original.event, first);
    let accepted =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    let (status, value) = boxed_step(|| submit(first.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "exact native Message retry: {value}"
    );
    assert_eq!(
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await,
        accepted
    );
    assert_eq!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&first.event_id)
            .await
            .unwrap()
            .unwrap()
            .commit,
        first_original.commit
    );
    boxed_step(|| obligation_close_grant(fixture, &parents[1].0)).await;
    let second = make_message(
        &child,
        "closing only read source cannot close Message action",
    );
    let (status, value) = boxed_step(|| submit(second)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "action-local source after read revocation: {value}"
    );
    let used = boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    let counters = used["capability_quota_counters"].as_array().unwrap();
    for id in [&ancestor, &parents[0].0] {
        assert!(
            counters
                .iter()
                .any(|row| row["grant_id"] == json!(id) && row["consumed"] == 2),
            "exact quota source {id}: {counters:?}"
        );
    }
    assert!(
        !counters
            .iter()
            .any(|row| row["grant_id"] == json!(parents[1].0)
                || row["grant_id"] == json!(parents[2].0)),
        "unrelated action/sibling quota must not be spent"
    );
    let exhausted = make_message(
        &sibling,
        "a sibling terminal child cannot reset the shared ancestor",
    );
    let (status, problem) = boxed_step(|| submit(exhausted.clone())).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "shared ancestor exhausted: {problem}"
    );
    assert_eq!(problem["type"], "https://arkret.org/problems/rate_limited");
    assert_eq!(
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await,
        used
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&exhausted.event_id)
            .await
            .unwrap()
            .is_none()
    );
    for id in [&parents[0].0, &parents[2].0, &ancestor] {
        boxed_step(|| obligation_close_grant(fixture, id)).await;
    }
}

async fn obligation_mls_footprint(fixture: &Fixture) -> Value {
    use diesel::sql_types::Jsonb;
    use diesel_async::RunQueryDsl as _;
    #[derive(diesel::QueryableByName)]
    struct Row {
        #[diesel(sql_type = Jsonb)]
        value: Value,
    }
    let mut result =
        boxed_step(|| super::realm_native_fixture::native_business_footprint(fixture)).await;
    let mut connection = fixture.pool.get().await.unwrap();
    for table in [
        "mls_key_packages",
        "mls_welcome_deliveries",
        "device_message_ack_tokens",
        "mls_group_current_states",
        "mls_consumed_proposal_provenance",
        "mls_welcome_provenance",
        "mls_add_authority_attestations",
        "mls_add_authority_attestation_outbox",
        "device_messages",
        "device_message_txns",
        "device_message_idempotency",
    ] {
        let row = diesel::sql_query(format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) AS value FROM {table} r")).get_result::<Row>(&mut connection).await.unwrap();
        result
            .as_object_mut()
            .unwrap()
            .insert(table.into(), row.value);
    }
    result
}

// A separate real SQL connection owns only the selected writer row or the
// finalization trigger advisory lock. No clock/current/claim value is changed.
// Release the lock and remove the owned trigger before asserting, even on timeout.
#[derive(Clone, Copy)]
enum NativeWriterWaitTarget<'a> {
    RealmAuthority,
    ClaimSource {
        source_id: &'a str,
        claim_request_id: &'a str,
    },
    ConsumePackage {
        keypackage_ref: &'a str,
        actor_id: &'a ActorId,
        device_id: &'a DeviceId,
    },
    ConsumeFinalization {
        source_id: &'a str,
        claim_request_id: &'a str,
        actor_id: &'a ActorId,
        device_id: &'a DeviceId,
        lock_key: i64,
    },
}

async fn obligation_post_through_expiry<F>(
    fixture: &Fixture,
    other: &Fixture,
    deadline: chrono::DateTime<chrono::Utc>,
    post: F,
) -> ((StatusCode, Value), Value, Value)
where
    F: std::future::Future<Output = (StatusCode, Value)>,
{
    boxed_step(|| {
        obligation_post_through_held_cut(
            fixture,
            other,
            deadline,
            NativeWriterWaitTarget::RealmAuthority,
            post,
        )
    })
    .await
}

async fn obligation_post_through_held_cut<F>(
    fixture: &Fixture,
    other: &Fixture,
    deadline: chrono::DateTime<chrono::Utc>,
    target: NativeWriterWaitTarget<'_>,
    post: F,
) -> ((StatusCode, Value), Value, Value)
where
    F: std::future::Future<Output = (StatusCode, Value)>,
{
    use diesel::sql_types::{BigInt, Bool, Integer, Text};
    use diesel_async::{RunQueryDsl as _, SimpleAsyncConnection as _};
    #[derive(diesel::QueryableByName)]
    struct Pid {
        #[diesel(sql_type = Integer)]
        pid: i32,
    }
    #[derive(diesel::QueryableByName)]
    struct Waiting {
        #[diesel(sql_type = Bool)]
        waiting: bool,
    }
    #[derive(diesel::QueryableByName)]
    struct AuthenticatedNonce {
        #[diesel(sql_type = Text)]
        nonce: String,
        #[diesel(sql_type = diesel::sql_types::Timestamptz)]
        consumed_at: chrono::DateTime<chrono::Utc>,
    }
    let initial = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let other_initial = boxed_step(|| obligation_mls_footprint(other)).await;
    let mut holder = fixture.pool.get().await.unwrap();
    if let NativeWriterWaitTarget::ConsumeFinalization {
        source_id,
        claim_request_id,
        lock_key,
        ..
    } = target
    {
        // This test-only AFTER trigger changes no value. It waits only after
        // the actual production writer has verified the initial current cut,
        // signed the real receipt and updated this exact claim's state.
        holder.batch_execute(&format!(
            "CREATE FUNCTION test_native_consume_finalization_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.source_id=TG_ARGV[0] AND NEW.claim_request_id=TG_ARGV[1] AND NEW.state='consumed' THEN PERFORM pg_advisory_xact_lock(TG_ARGV[2]::bigint); END IF; RETURN NEW; END $$; CREATE TRIGGER test_native_consume_finalization_wait AFTER UPDATE OF state ON peer_keypackage_claims FOR EACH ROW EXECUTE FUNCTION test_native_consume_finalization_wait('{}','{}','{}');",
            source_id.replace('\'', "''"), claim_request_id.replace('\'', "''"), lock_key,
        )).await.unwrap();
    }
    holder.batch_execute("BEGIN").await.unwrap();
    let pid = diesel::sql_query("SELECT pg_backend_pid() AS pid")
        .get_result::<Pid>(&mut holder)
        .await
        .unwrap()
        .pid;
    let original_nonces = if let NativeWriterWaitTarget::ConsumePackage {
        actor_id,
        device_id,
        ..
    }
    | NativeWriterWaitTarget::ConsumeFinalization {
        actor_id,
        device_id,
        ..
    } = target
    {
        Some(
            diesel::sql_query("SELECT nonce,consumed_at FROM applet_managed_device_nonces WHERE actor_id=$1 AND device_id=$2")
                .bind::<diesel::sql_types::Jsonb, _>(json!(actor_id))
                .bind::<Text, _>(device_id.as_str())
                .load::<AuthenticatedNonce>(&mut holder)
                .await
                .unwrap(),
        )
    } else {
        None
    };
    match target {
        NativeWriterWaitTarget::ClaimSource {
            source_id,
            claim_request_id,
        } => {
            diesel::sql_query("SELECT source_id FROM realm_keypackage_claim_sources WHERE source_id=$1 AND claim_request_id=$2 FOR UPDATE")
            .bind::<Text, _>(source_id)
            .bind::<Text, _>(claim_request_id)
            .execute(&mut holder)
            .await
            .unwrap();
        }
        NativeWriterWaitTarget::RealmAuthority => {
            diesel::sql_query(
                "SELECT realm_id FROM realm_authorities WHERE realm_id=$1 FOR UPDATE",
            )
            .bind::<Text, _>(fixture.realm.as_str())
            .execute(&mut holder)
            .await
            .unwrap();
        }
        NativeWriterWaitTarget::ConsumePackage { keypackage_ref, .. } => {
            diesel::sql_query(
                "SELECT keypackage_ref FROM mls_key_packages WHERE keypackage_ref=$1 FOR UPDATE",
            )
            .bind::<Text, _>(keypackage_ref)
            .execute(&mut holder)
            .await
            .unwrap();
        }
        NativeWriterWaitTarget::ConsumeFinalization { lock_key, .. } => {
            diesel::sql_query("SELECT pg_advisory_xact_lock($1)")
                .bind::<BigInt, _>(lock_key)
                .execute(&mut holder)
                .await
                .unwrap();
        }
    }
    let gate = async {
        let mut monitor = fixture.pool.get().await.unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let observed = loop {
            let waiting_query = match target {
                NativeWriterWaitTarget::ClaimSource { .. } => {
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query ILIKE '%realm_keypackage_claim_sources%' AND a.query ILIKE '%FOR SHARE%') AS waiting"
                }
                NativeWriterWaitTarget::RealmAuthority => {
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query ILIKE '%realm_authorities%' AND (a.query ILIKE '%FOR UPDATE%' OR a.query ILIKE '%FOR SHARE%')) AS waiting"
                }
                NativeWriterWaitTarget::ConsumePackage { .. } => {
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query ILIKE 'SELECT % FROM mls_key_packages WHERE keypackage_ref=$1 FOR UPDATE') AS waiting"
                }
                NativeWriterWaitTarget::ConsumeFinalization { .. } => {
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.query ILIKE 'UPDATE peer_keypackage_claims SET state=%' AND a.wait_event_type='Lock' AND a.wait_event='advisory') AS waiting"
                }
            };
            let state = diesel::sql_query(waiting_query)
                .bind::<Integer, _>(pid)
                .get_result::<Waiting>(&mut monitor)
                .await
                .unwrap();
            if state.waiting {
                break true;
            }
            if std::time::Instant::now() >= until || chrono::Utc::now() >= deadline {
                break false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let observed_at = chrono::Utc::now();
        let authenticated_before_wait = if let NativeWriterWaitTarget::ConsumePackage {
            actor_id,
            device_id,
            ..
        }
        | NativeWriterWaitTarget::ConsumeFinalization {
            actor_id,
            device_id,
            ..
        } = target
        {
            let nonces = diesel::sql_query("SELECT nonce,consumed_at FROM applet_managed_device_nonces WHERE actor_id=$1 AND device_id=$2")
                .bind::<diesel::sql_types::Jsonb, _>(json!(actor_id))
                .bind::<Text, _>(device_id.as_str())
                .load::<AuthenticatedNonce>(&mut monitor)
                .await
                .unwrap();
            let original = original_nonces.as_ref().unwrap();
            let fresh = nonces
                .iter()
                .filter(|row| !original.iter().any(|prior| prior.nonce == row.nonce))
                .collect::<Vec<_>>();
            Some(
                observed
                    && observed_at < deadline
                    && fresh.len() == 1
                    && fresh[0].consumed_at < deadline,
            )
        } else {
            None
        };
        drop(monitor);
        let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
        let other_before = boxed_step(|| obligation_mls_footprint(other)).await;
        if observed {
            tokio::time::sleep(
                (deadline - chrono::Utc::now()).to_std().unwrap_or_default()
                    + std::time::Duration::from_millis(40),
            )
            .await;
        }
        holder.batch_execute("ROLLBACK").await.unwrap();
        (observed, before, other_before, authenticated_before_wait)
    };
    let (response, (observed, before, other_before, authenticated_before_wait)) = tokio::join!(
        tokio::time::timeout(std::time::Duration::from_secs(75), post),
        gate
    );
    if matches!(target, NativeWriterWaitTarget::ConsumeFinalization { .. }) {
        holder.batch_execute("DROP TRIGGER test_native_consume_finalization_wait ON peer_keypackage_claims; DROP FUNCTION test_native_consume_finalization_wait();").await.unwrap();
    }
    // A legitimate remote Add may retain an immutable attestation while
    // preparing. It may not leave queued Events, Commits, MLS state, queue,
    // claim use, quota, or native current before the held writer cut.
    for (mut initial, mut prepared) in [
        (initial, before.clone()),
        (other_initial, other_before.clone()),
    ] {
        for table in [
            "mls_add_authority_attestations",
            "mls_add_authority_attestation_outbox",
        ] {
            initial.as_object_mut().unwrap().remove(table);
            prepared.as_object_mut().unwrap().remove(table);
        }
        assert_eq!(
            initial, prepared,
            "preparation must not leave business writes before the real writer lock"
        );
    }
    assert!(
        observed,
        "the real HTTP operation must reach the selected actual writer row before its signed deadline"
    );
    assert!(
        authenticated_before_wait.unwrap_or(true),
        "the consume request must commit one fresh exact Device authentication nonce and reach its selected writer stage while the Device is still live",
    );
    assert!(
        chrono::Utc::now() >= deadline,
        "release must cross the actual wall-clock deadline"
    );
    (
        response.expect("native writer must terminate after release"),
        before,
        other_before,
    )
}

async fn realm_device_claim_writer_wait_crosses_deadline(
    fixture: &Fixture,
    target: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    original: &KeyPackagesClaimRequestBody,
) {
    let mut command = original.clone();
    command.claim_request_id =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(rand::random::<
            [u8; 32],
        >()))
        .unwrap();
    command.expires_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(15),
    );
    let method = match &command.requester_authorization {
        PeerKeyPackageRequesterAuthorization::RealmDevice {
            verification_method,
            ..
        } => verification_method.clone(),
        _ => unreachable!(),
    };
    let input = keypackage_claim_authorization_signing_bytes(
        &command.unsigned_request(),
        &command.service_binding,
        &command.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::RealmDevice { signature, .. } =
        &mut command.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        method.as_str(),
        &input,
    )
    .unwrap();
    command.validate_shape().unwrap();
    assert!(chrono::Utc::now() < command.expires_at);
    let (reply, before, target_before) = boxed_step(|| {
        obligation_post_through_expiry(
            fixture,
            target,
            command.expires_at,
            device_post(
                fixture,
                authority,
                "/_arkret/self/keys/keypackages/claim",
                ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
                json!(command),
            ),
        )
    })
    .await;
    assert_eq!(
        reply.0,
        StatusCode::BAD_REQUEST,
        "signed claim expired at actual writer: {}",
        reply.1
    );
    assert_eq!(reply.1["type"], "https://arkret.org/problems/claim_failed");
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(target)).await,
        target_before
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .mls_key_packages()
            .realm_claim_source(
                command.service_binding.source_id.as_str(),
                command.claim_request_id.as_str()
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[allow(clippy::too_many_arguments, reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit.")]
async fn realm_device_prepared_add_writer_wait_crosses_claim_deadline(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    recipient: &Fixture,
    original_group: &arkret_mls::ArkretMlsGroup,
) -> (
    super::realm_native_fixture::NetworkStation,
    coland_storage_postgres::test_database::TestDatabase,
) {
    let before_private = original_group.export_state_record().unwrap();
    let mut restored =
        arkret_mls::ArkretMlsGroup::restore_from_state_record(&before_private).unwrap();
    let group = &mut restored;
    let other_database =
        boxed_step(coland_storage_postgres::test_database::TestDatabase::lease).await;
    let (other_recipient, other_server) = boxed_step(|| {
        super::realm_native_fixture::network_fixture_with_device_seed(
            other_database.pool(),
            [83; 32],
        )
    })
    .await;
    boxed_step(|| foreign_member(fixture, &other_recipient)).await;
    assert_ne!(
        recipient.pcr.history.founding_device_signing_seed,
        other_recipient.pcr.history.founding_device_signing_seed,
        "two independent recipients must not reuse a leaf signing key",
    );
    assert_ne!(
        recipient.pcr.history.account,
        other_recipient.pcr.history.account
    );
    let (_other_identity, other_claim) = boxed_step(|| {
        claim_remote_with_lifetime(
            fixture,
            &other_recipient,
            authority,
            chrono::Duration::seconds(60),
            false,
        )
    })
    .await;
    let (_recipient_identity, claim) = boxed_step(|| {
        claim_remote_with_lifetime(
            fixture,
            recipient,
            authority,
            chrono::Duration::seconds(15),
            false,
        )
    })
    .await;
    let deadline = claim.claim_receipt.expires_at;
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
    let package_records = [
        arkret_mls::mls_key_package_record_from_claim(&claim.claims[0]).unwrap(),
        arkret_mls::mls_key_package_record_from_claim(&other_claim.claims[0]).unwrap(),
    ];
    let added = group
        .add_members_with_governance_binding(&package_records, &binding)
        .unwrap();
    assert_eq!(added.welcomes.len(), 2);
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
        Some(child),
        &signer,
    );
    let at = event.created_at;
    let mut welcomes = Vec::new();
    for (recipient, claim) in [(recipient, &claim), (&other_recipient, &other_claim)] {
        let draft = added
            .welcomes
            .iter()
            .find(|draft| draft.keypackage_claim_ref.as_str() == claim.claims[0].claim_id)
            .expect("each actual Add must have its original claim's Welcome");
        let mut welcome = arkret_wire::MlsWelcomeDelivery {
            welcome_id: arkret_wire::MlsWelcomeDeliveryId::new(format!(
                "ak:mls_welcome_delivery:{}",
                uuid::Uuid::now_v7(),
            ))
            .unwrap(),
            realm_id: fixture.realm.clone(),
            effective_scope: scope.clone(),
            commit_event_ref: event.event_id.clone(),
            recipient_actor_id: ActorId::account(recipient.pcr.history.account.clone()),
            recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: recipient.pcr.history.founding_device_id.clone(),
            },
            keypackage_claim_ref: draft.keypackage_claim_ref.clone(),
            ciphertext_base64url: draft.ciphertext_base64url.clone(),
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
        welcomes.push(welcome);
    }
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes,
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });

    assert!(
        chrono::Utc::now() < deadline,
        "the exact signed Add must be fully prepared while its real claim is live"
    );
    let other_before = boxed_step(|| obligation_mls_footprint(&other_recipient)).await;
    let (reply, before, recipient_before) = boxed_step(|| {
        obligation_post_through_held_cut(
            fixture,
            recipient,
            deadline,
            NativeWriterWaitTarget::ClaimSource {
                source_id: other_claim.claim_receipt.source_id.as_str(),
                claim_request_id: other_claim.claim_request_id.as_str(),
            },
            device_post(
                fixture,
                authority,
                "/_arkret/self/events",
                ServiceOperationId::SelfEventsCommandSubmitV1,
                json!(submission),
            ),
        )
    })
    .await;
    assert!(
        chrono::Utc::now() < other_claim.claim_receipt.expires_at,
        "the second original reservation must still be live after its own row wait"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(&other_recipient)).await,
        other_before,
        "the second recipient must also have no partial Welcome, claim use, or queue writes",
    );
    assert_eq!(
        reply.0,
        StatusCode::CONFLICT,
        "prepared Add after actual writer wait: {}",
        reply.1
    );
    assert_eq!(
        reply.1["type"],
        "https://arkret.org/problems/failed_precondition"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(recipient)).await,
        recipient_before
    );
    assert!(
        fixture
            .state
            .test_persistence()
            .authority_commits()
            .committed_event(&event.event_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        original_group
            .export_state_record()
            .unwrap()
            .serialized_state,
        before_private.serialized_state,
        "an unaccepted candidate Add must not replace the accepted local MLS private state"
    );
    eprintln!(
        "RealmDevice actual claim deadline: blocked Add refused with no Event/Commit/queue/claim consumption"
    );
    // The accepted ordinary membership still owes real fanout to this Station
    // during the rest of the driver's valid Add/consume and replay sequence.
    (other_server, other_database)
}

async fn realm_device_prepared_claim_guard_crosses_actual_deadline(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    // Local genuine Human target avoids inventing remote-device proof. The
    // requester remains the accepted native RealmDevice, with its real PoP.
    let (_identity, outcome) = boxed_step(|| {
        claim_remote_with_lifetime(
            fixture,
            fixture,
            authority,
            chrono::Duration::seconds(15),
            false,
        )
    })
    .await;
    let original = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .peer_claim_original(
            outcome.claim_request_id.as_str(),
            outcome.claim_receipt.request_digest.as_str(),
        )
        .await
        .unwrap()
        .expect("durable exact native signed command");
    assert_eq!(
        original.requester_actor_id.as_ref(),
        Some(&authority.actor_id)
    );
    assert!(matches!(&original.requester_authorization,
        PeerKeyPackageRequesterAuthorization::RealmDevice {requester_device_id, device_authorize_event_id, ..}
        if requester_device_id == &authority.device_id && device_authorize_event_id == &authority.authorization_ref.event_id));
    let endpoint = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        },
        service_did_document: applet_service_id_document(package),
    };
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![fixture.realm.clone()],
        keypackage_claims: vec![coland_storage::MlsKeyPackageClaimDelivery {
            operation: ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            outcome: PeerKeyPackagesClaimResponseBody {
                claim_request_id: outcome.claim_request_id.clone(),
                claims: outcome.claims.clone(),
                claim_receipt: outcome.claim_receipt.clone(),
            },
            endpoints: vec![endpoint.clone()],
            command: Some(original),
            remote_devices: vec![],
        }],
        applet_endpoint: Some(endpoint),
        credential_expires_at: Some(authority.expires_at),
        ..Default::default()
    };
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let guard = fixture
        .state
        .test_persistence()
        .authority_commits()
        .acquire_realm_actor_content_delivery(
            &authority.actor_id,
            &fixture.state.service_core_id(),
            &input,
        )
        .await
        .unwrap()
        .expect("actual accepted native claim has a real disclosure cut");
    assert!(
        guard.permits_handoff(),
        "actual current cut must authorize before signed claim expiry"
    );
    let deadline = outcome.claim_receipt.expires_at;
    assert!(chrono::Utc::now() < deadline);
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(40),
    )
    .await;
    assert!(
        !guard.permits_handoff(),
        "a prepared claim response must lose its physical handoff deadline"
    );
    drop(guard);
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
    eprintln!(
        "actual native prepared claim disclosure guard expired before handing off original material"
    );
}

async fn realm_device_owned_query_prepared_guard_crosses_deadline(
    fixture: &Fixture,
    package: &AppletPackage,
    authority: &coland_storage::AppletManagedDeviceAuthority,
) {
    let history = &fixture.pcr.history;
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let method = format!("{}#{}", authority.native_did, authority.device_id);
    let native_identity = arkret_mls::ArkretMlsIdentity::new_realm_device(
        authority.actor_id.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(&[79; 32])),
    )
    .unwrap();
    let record = native_identity.key_package_record().unwrap();
    let mut upload = native_identity
        .signed_key_packages_upload_request(&[record], &method)
        .unwrap()
        .unsigned();
    upload.mls_group_id = Some(scope.canonical_mls_group_id().unwrap());
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        &method,
        &keypackages_upload_signing_input(&upload).unwrap(),
    )
    .unwrap();
    let upload = upload.into_signed(signature);
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(upload),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native recipient publication: {value}"
    );
    assert_eq!(value["accepted"], 1);
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut request = KeyPackagesClaimRequestBody {
        claim_request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            rand::random::<[u8; 32]>(),
        ))
        .unwrap(),
        target_account_id: None,
        target_actor_id: Some(authority.actor_id.clone()),
        requester_account_id: Some(history.account.clone()),
        requester_actor_id: None,
        intended_realm_id: fixture.realm.clone(),
        mls_group_id: scope.canonical_mls_group_id().unwrap(),
        claim_purpose: PeerKeyPackageClaimPurpose::RealmMembership,
        required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
        expires_at: at + chrono::Duration::seconds(15),
        target_device_ids: vec![authority.device_id.clone()],
        target_keypackage_ref: Some(
            arkret_wire::KeyPackageRef::new(upload.keypackages[0].keypackage_ref.as_str()).unwrap(),
        ),
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
            device_authorize_event_id: history
                .events
                .iter()
                .find(|event| event.kind == EventKind::DeviceAuthorize)
                .unwrap()
                .event_id
                .clone(),
            signed_at: at,
            signature: arkret_signatures::keypackages::keypackage_signature_from_bytes(
                history.device_verification_method.as_str(),
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
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &history.founding_device_signing_seed,
        history.device_verification_method.as_str(),
        &input,
    )
    .unwrap();
    request.validate_shape().unwrap();
    let (status, value) = boxed_step(|| {
        account_request(
            fixture,
            reqwest::Method::POST,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            Some(json!(request)),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Human claims the native recipient, no source/recipient substitution: {value}"
    );
    let outcome: PeerKeyPackagesClaimResponseBody = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(outcome.claims.len(), 1);
    assert_eq!(outcome.claims[0].actor_id, authority.actor_id);
    assert_eq!(
        outcome.claims[0].device_id.as_ref(),
        Some(&authority.device_id)
    );
    assert_eq!(
        outcome.claims[0].device_authorize_event_id.as_ref(),
        Some(&authority.authorization_ref.event_id)
    );
    let query = KeyPackagesClaimQueryRequestBody {
        claim_id: arkret_wire::KeypackageClaimId::new(outcome.claims[0].claim_id.as_str()).unwrap(),
    };
    let (status, queried) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/claims/query",
            ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
            json!(query),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native owner reads its original claim: {queried}"
    );
    assert_eq!(queried, value);
    let endpoint = coland_storage::AppletManagedDeviceScopeGuard {
        authority: authority.clone(),
        effective_scope: scope,
        service_did_document: applet_service_id_document(package),
    };
    let input = coland_storage::AccountContentDeliveryInput {
        realms: vec![fixture.realm.clone()],
        applet_endpoint: Some(endpoint.clone()),
        credential_expires_at: Some(authority.expires_at),
        keypackage_claims: vec![coland_storage::MlsKeyPackageClaimDelivery {
            operation: ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
            outcome: outcome.clone(),
            endpoints: vec![endpoint],
            command: None,
            remote_devices: vec![],
        }],
        ..Default::default()
    };
    let before = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let guard = fixture
        .state
        .test_persistence()
        .authority_commits()
        .acquire_realm_actor_content_delivery(
            &authority.actor_id,
            &fixture.state.service_core_id(),
            &input,
        )
        .await
        .unwrap()
        .expect("real native recipient query has a prepared original material cut");
    assert!(guard.permits_handoff());
    let deadline = outcome.claim_receipt.expires_at;
    assert!(chrono::Utc::now() < deadline);
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap() + std::time::Duration::from_millis(40),
    )
    .await;
    assert!(
        !guard.permits_handoff(),
        "prepared native owned query must refuse material after its actual claim deadline"
    );
    drop(guard);
    let (status, problem) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/claims/query",
            ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
            json!(query),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "expired native owned query: {problem}"
    );
    assert_eq!(
        problem["type"],
        "https://arkret.org/problems/keypackage_unknown"
    );
    assert_eq!(
        boxed_step(|| obligation_mls_footprint(fixture)).await,
        before
    );
}

async fn obligation_recipient_post(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
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
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key);
    super::realm_native_fixture::managed_device_post(
        fixture,
        &metadata,
        &DidUrl::new(format!("did:key:{fingerprint}#{fingerprint}")).unwrap(),
        path,
        operation,
        &body,
        seed,
    )
    .await
}

async fn obligation_install_native_roster(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    seed: &[u8; 32],
    accepted: &arkret_wire::CommittedEventFullView,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsMemberRosterAuthorityReadRequestBody, MlsSelfRosterAuthorityReadResponseBody,
    };
    let request = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: accepted.event.realm_id.clone(),
        effective_scope: accepted.event.scope_ref.clone(),
        mls_group_id: accepted.event.scope_ref.canonical_mls_group_id().unwrap(),
        target_commit_event_ref: accepted.event.event_id.clone(),
        target_epoch: group.epoch(),
        caller_actor_id: authority.actor_id.clone(),
        cursor: None,
    };
    let mut next = request.clone();
    let mut pages = Vec::new();
    for _ in 0..16 {
        let (status, value) = boxed_step(|| {
            obligation_recipient_post(
                fixture,
                authority,
                seed,
                arkret_wire::peer_operation_paths::PATH_SELF_MLS_ROSTER_AUTHORITY,
                ServiceOperationId::SelfMlsReadRosterAuthorityV1,
                json!(next),
            )
        })
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "actual native recipient roster: {value}"
        );
        let page: MlsSelfRosterAuthorityReadResponseBody = serde_json::from_value(value).unwrap();
        next.cursor = page.roster.next_cursor.clone();
        pages.push(page);
        if next.cursor.is_none() {
            break;
        }
    }
    assert!(next.cursor.is_none());
    let peer = arkret::verify_mls_member_roster_authority_pages(&pages, &request).unwrap();
    let material_request =
        arkret::mls_roster_genesis_material_request(&peer, &pages[0].roster.manifest);
    let (status, material) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            authority,
            seed,
            arkret_wire::peer_operation_paths::PATH_SELF_MLS_GROUP_STATE_MATERIAL,
            ServiceOperationId::SelfMlsReadGroupStateMaterialV1,
            json!(material_request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual native recipient genesis material: {material}"
    );
    let material = serde_json::from_value(material).unwrap();
    arkret::install_verified_mls_self_roster_bindings(group, &pages, &request, &material).unwrap();
}

#[derive(Clone, Copy, Debug)]
enum NativeConsumeExpiryBoundary {
    InitialCurrent,
    Finalization,
}

async fn realm_device_consume_writer_wait_crosses_physical_device_expiry(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    for boundary in [
        NativeConsumeExpiryBoundary::InitialCurrent,
        NativeConsumeExpiryBoundary::Finalization,
    ] {
        boxed_step(|| {
            realm_device_consume_writer_wait_crosses_device_expiry_at(
                fixture, package, candidate, device, authority, child, group, boundary,
            )
        })
        .await;
    }
}

#[allow(clippy::too_many_arguments, reason = "The fixture keeps independent signed originals, accepted references and source-time coordinates explicit.")]
async fn realm_device_consume_writer_wait_crosses_device_expiry_at(
    fixture: &Fixture,
    package: &AppletPackage,
    candidate: &RealmActorCreatePayload,
    device: &DeviceId,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    child: &GrantId,
    group: &mut arkret_mls::ArkretMlsGroup,
    boundary: NativeConsumeExpiryBoundary,
) {
    let recipient_seed = match boundary {
        NativeConsumeExpiryBoundary::InitialCurrent => 82,
        NativeConsumeExpiryBoundary::Finalization => 84,
    };
    let recipient_signing_seed = [recipient_seed; 32];
    let creation = fixture
        .state
        .test_persistence()
        .authority_commits()
        .applet_realm_actor_creations(&fixture.realm, &candidate.applet_id, None)
        .await
        .unwrap()
        .into_iter()
        .find(|original| original.event.payload.get("actor_id") == Some(&json!(candidate.actor_id)))
        .expect("the actual accepted native actor creation");
    // Legal producer-declared Device lifetime, no mutation of an accepted row.
    // Its own expiry is earlier than the original four-minute claim intent.
    let expires_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(45),
    );
    let recipient_device = boxed_step(|| {
        super::realm_native_fixture::authorize_obligation_device(
            fixture,
            candidate,
            &creation.commit,
            recipient_seed,
            expires_at,
        )
    })
    .await;
    assert_ne!(&recipient_device, device);
    let recipient_authority = fixture
        .state
        .test_persistence()
        .device_revocations()
        .applet_managed_device_authority(&candidate.actor_id, &recipient_device, chrono::Utc::now())
        .await
        .unwrap()
        .expect("the second independently authorized Device is actually current");
    assert_eq!(recipient_authority.expires_at, expires_at);
    assert_ne!(recipient_authority.public_key, authority.public_key);
    assert_ne!(
        recipient_authority.public_key,
        SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes(),
        "the independent native endpoint must differ from the already accepted foreign Human leaf",
    );
    let recipient_method = DidUrl::new(format!(
        "{}#{}",
        recipient_authority.native_did, recipient_device
    ))
    .unwrap();
    let identity = Box::new(
        arkret_mls::ArkretMlsIdentity::new_realm_device(
            recipient_authority.actor_id.clone(),
            recipient_device.clone(),
            arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(SigningKey::from_bytes(
                &recipient_signing_seed,
            )),
        )
        .unwrap(),
    );
    let record = identity.key_package_record().unwrap();
    let mut upload = identity
        .signed_key_packages_upload_request(&[record], recipient_method.as_str())
        .unwrap()
        .unsigned();
    upload.mls_group_id = Some(candidate.creation_scope.canonical_mls_group_id().unwrap());
    let signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &recipient_signing_seed,
        recipient_method.as_str(),
        &keypackages_upload_signing_input(&upload).unwrap(),
    )
    .unwrap();
    let upload = upload.into_signed(signature);
    let (status, value) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient_authority,
            &recipient_signing_seed,
            "/_arkret/self/keys/keypackages/upload",
            ServiceOperationId::SelfKeysKeypackagesUploadCreateV1,
            json!(upload),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual independent recipient publishes its own scoped KeyPackage: {value}"
    );
    assert_eq!(value["accepted"], 1);
    let mut request = claim_request_with_lifetime(
        authority,
        fixture,
        upload.keypackages[0].keypackage_ref.as_str(),
        chrono::Duration::minutes(4),
    );
    request.target_account_id = None;
    request.target_actor_id = Some(recipient_authority.actor_id.clone());
    request.target_device_ids = vec![recipient_device.clone()];
    let input = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )
    .unwrap();
    let PeerKeyPackageRequesterAuthorization::RealmDevice {
        verification_method,
        signature,
        ..
    } = &mut request.requester_authorization
    else {
        unreachable!()
    };
    *signature = arkret_signatures::keypackages::sign_keypackage_signing_input(
        &[79; 32],
        verification_method.as_str(),
        &input,
    )
    .unwrap();
    request.validate_shape().unwrap();
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/keys/keypackages/claim",
            ServiceOperationId::SelfKeysKeypackagesCommandClaimV1,
            json!(request),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual source Device claims the independent native recipient: {value}"
    );
    let claim: KeyPackagesClaimResponseBody = serde_json::from_value(value).unwrap();
    assert_eq!(claim.claims.len(), 1);
    assert_eq!(claim.claims[0].actor_id, recipient_authority.actor_id);
    assert_eq!(claim.claims[0].device_id.as_ref(), Some(&recipient_device));
    assert_eq!(
        claim.claims[0].device_authorize_event_id.as_ref(),
        Some(&recipient_authority.authorization_ref.event_id)
    );
    assert!(
        claim.claim_receipt.expires_at > expires_at + chrono::Duration::minutes(2),
        "the claim itself remains alive through Device expiry"
    );
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
        Some(child),
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
        recipient_actor_id: recipient_authority.actor_id.clone(),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: recipient_device.clone(),
        },
        keypackage_claim_ref: added.welcome.keypackage_claim_ref,
        ciphertext_base64url: added.welcome.ciphertext_base64url,
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
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(arkret_wire::MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    });
    assert!(
        chrono::Utc::now() < expires_at,
        "the real Add/Welcome must be authored while the independent recipient is current"
    );
    let (status, value) = boxed_step(|| {
        device_post(
            fixture,
            authority,
            "/_arkret/self/events",
            ServiceOperationId::SelfEventsCommandSubmitV1,
            json!(submission),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "actual Add/Welcome for independent native recipient: {value}"
    );
    let record = fixture
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.event, event);
    let accepted = arkret_wire::CommittedEventFullView {
        event: record.event,
        commit: record.commit,
    };
    group.install_accepted_commit(&accepted, &current).unwrap();
    let actual_queue = boxed_step(|| obligation_mls_footprint(fixture)).await;
    let queue = actual_queue["mls_welcome_deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["welcome_id"] == json!(welcome.welcome_id))
        .expect("the accepted Add really queued the exact Welcome");
    assert_eq!(queue["delivery_json"], json!(welcome));
    assert_eq!(queue["recipient_device_id"], json!(recipient_device));
    assert_eq!(
        queue["recipient_authorization_event_ref"],
        json!(recipient_authority.authorization_ref.event_id)
    );
    assert_eq!(queue["state"], "queued");
    let producer_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(&authority.public_key),
    };
    arkret_signatures::detached_object::verify_detached_object_signature(
        &welcome.producer_proof,
        &arkret_canonical::unsigned_value(&welcome, &["producer_proof"]).unwrap(),
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        &producer_key,
    )
    .unwrap();
    let mut joined = Box::new(
        arkret_mls::ArkretMlsGroup::join_from_verified_welcome_delivery(
            *identity, &welcome, &accepted,
        )
        .unwrap(),
    );
    boxed_step(|| {
        obligation_install_native_roster(
            fixture,
            &recipient_authority,
            &recipient_signing_seed,
            &accepted,
            &mut joined,
        )
    })
    .await;
    let private = joined.export_state_record().unwrap();
    let path = std::env::temp_dir().join(format!(
        "arkret-native-consume-expiry-{}.json",
        uuid::Uuid::now_v7()
    ));
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(&private).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
    let restored = Box::new(
        arkret_mls::ArkretMlsGroup::restore_from_state_record(
            &serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(restored.epoch(), current.epoch + 1);
    assert_eq!(
        restored.export_state_record().unwrap().serialized_state,
        private.serialized_state
    );
    std::fs::remove_file(path).unwrap();
    let receipt = RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .unwrap(),
        claim_request_id: claim.claim_request_id.clone(),
        key_package_ref: arkret_wire::NonEmptyString::new(claim.claims[0].keypackage_ref.clone())
            .unwrap(),
        recipient: RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: recipient_authority.actor_id.clone(),
            recipient_device_id: recipient_device.clone(),
            device_verification_method: recipient_method.clone(),
        },
        recipient_id: fixture.state.service_core_id(),
        realm_id: welcome.realm_id.clone(),
        mls_group_id: welcome.effective_scope.canonical_mls_group_id().unwrap(),
        mls_epoch: restored.epoch(),
        welcome_ref: welcome.welcome_id.clone(),
        welcome_digest: welcome.durable_receipt_digest().unwrap(),
        durable_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        signature: KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(recipient_method.to_string()).unwrap(),
            signature_algorithm: None,
            signature: arkret_wire::Base64UrlString::new("AA").unwrap(),
        },
    };
    let command = restored
        .identity()
        .signed_key_packages_consume_request(
            welcome.keypackage_claim_ref.clone(),
            restored
                .identity()
                .sign_recipient_mls_durable_receipt(receipt)
                .unwrap(),
        )
        .unwrap();
    command.validate_shape().unwrap();
    for (signature, input) in [
        (
            &command.signature,
            keypackages_consume_signing_input(&command.unsigned()).unwrap(),
        ),
        (
            &command.recipient_durable_receipt.signature,
            command
                .recipient_durable_receipt
                .canonical_signing_bytes()
                .unwrap(),
        ),
    ] {
        arkret_signatures::keypackages::verify_keypackage_signing_input(
            &recipient_authority.public_key,
            recipient_method.as_str(),
            &input,
            signature,
        )
        .unwrap();
    }
    let frozen = arkret_canonical::canonical_json_bytes(&command).unwrap();
    let query = KeyPackagesClaimQueryRequestBody {
        claim_id: command.claim_id.clone(),
    };
    let (status, read) = boxed_step(|| {
        obligation_recipient_post(
            fixture,
            &recipient_authority,
            &recipient_signing_seed,
            "/_arkret/self/keys/keypackages/claims/query",
            ServiceOperationId::SelfKeysKeypackagesReadClaimV1,
            json!(query),
        )
    })
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "before-expiry actual recipient Body+HTTP and original read: {read}"
    );
    assert_eq!(read, json!(claim));
    assert!(
        chrono::Utc::now() + chrono::Duration::seconds(5) < expires_at,
        "the valid body+transport must enter writer wait while the Device is genuinely live"
    );
    let (reply, before, other_before) = boxed_step(|| {
        obligation_post_through_held_cut(
            fixture,
            fixture,
            expires_at,
            match boundary {
                NativeConsumeExpiryBoundary::InitialCurrent => {
                    NativeWriterWaitTarget::ConsumePackage {
                        keypackage_ref: command.recipient_durable_receipt.key_package_ref.as_str(),
                        actor_id: &recipient_authority.actor_id,
                        device_id: &recipient_authority.device_id,
                    }
                }
                NativeConsumeExpiryBoundary::Finalization => {
                    NativeWriterWaitTarget::ConsumeFinalization {
                        source_id: claim.claim_receipt.source_id.as_str(),
                        claim_request_id: claim.claim_request_id.as_str(),
                        actor_id: &recipient_authority.actor_id,
                        device_id: &recipient_authority.device_id,
                        lock_key: rand::random::<i64>(),
                    }
                }
            },
            obligation_recipient_post(
                fixture,
                &recipient_authority,
                &recipient_signing_seed,
                "/_arkret/self/keys/keypackages/consume",
                ServiceOperationId::SelfKeysKeypackagesCommandConsumeV1,
                json!(command),
            ),
        )
    })
    .await;
    assert_eq!(
        reply.0,
        StatusCode::FORBIDDEN,
        "native consume Device expires at {boundary:?} behind its actual writer wait: {}",
        reply.1
    );
    assert_eq!(
        reply.1["type"],
        "https://arkret.org/problems/device_unauthorized"
    );
    assert_eq!(
        reply.1["detail"], "native consume current Device is unavailable",
        "the authenticated request must be refused by the actual consume writer after its wait",
    );
    assert!(
        reply.1.get("consume_receipt").is_none(),
        "the receipt signed before the finalization wait must never become observable",
    );
    assert!(
        chrono::Utc::now() < claim.claim_receipt.expires_at,
        "the failure must not be caused by the claim deadline"
    );
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&command).unwrap(),
        frozen
    );
    let after = boxed_step(|| obligation_mls_footprint(fixture)).await;
    assert_eq!(after, before);
    assert_eq!(after, other_before);
    let ledger = fixture
        .state
        .test_persistence()
        .mls_key_packages()
        .get_peer_claim(
            claim.claim_receipt.source_id.as_str(),
            claim.claim_request_id.as_str(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ledger.state, "claimed");
    assert!(ledger.consume_receipt.is_none());
    assert!(
        after["mls_key_packages"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |row| row["keypackage_ref"] == json!(claim.claims[0].keypackage_ref)
                    && row["consumed_at"].is_null()
            )
    );
    let still_queued = after["mls_welcome_deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["welcome_id"] == json!(welcome.welcome_id))
        .unwrap();
    assert_eq!(
        still_queued, queue,
        "no ACK or Welcome replacement can escape the refused consume"
    );
    assert_eq!(
        group.epoch(),
        current.epoch + 1,
        "the earlier real accepted Add is retained unchanged"
    );
    eprintln!(
        "actual independent native recipient at {boundary:?}: valid signed durable consume reached the real writer then lost its own physical lifetime; claim still live, no consumption/ACK/new Commit"
    );
}
