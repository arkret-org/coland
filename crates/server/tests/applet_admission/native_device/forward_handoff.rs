//! Real native creation and Device pairs precede a planned business-Realm handoff.
use arkret_models_collaboration::authority_commit::{
    AuthorityHandoffRequest, HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
};
use coland_storage::MlsGroupCurrentStore as _;
use diesel_async::AsyncConnection as _;

use super::*;

pub(super) struct Ready {
    pub context: Box<NativeSourcesContext>,
    pub state: AppState,
    pub pool: PgPool,
    pub group: Box<arkret_mls::ArkretMlsGroup>,
    pub mls_child: arkret_wire::GrantId,
    pub _origin: PublicStation,
    pub _governor: PublicStation,
}

#[derive(diesel::QueryableByName)]
struct JsonRow {
    #[diesel(sql_type=diesel::sql_types::Jsonb)]
    value: Value,
}

/// Handoff activation consumes a pre-imported frozen database, not member replication.
/// Transfer only this accepted business Realm and its actual installation; private PCRs stay home.
async fn import_frozen(source: &PgPool, destination: &PgPool, realm: &RealmId, applet: &AppletId) {
    use diesel::sql_types::{Jsonb, Text};
    let mut from = source.get().await.unwrap();
    let mut to = destination.get().await.unwrap();
    let names=diesel::sql_query("SELECT jsonb_agg(table_name ORDER BY CASE table_name WHEN 'canonical_events' THEN 0 WHEN 'realm_commits' THEN 1 ELSE 2 END,table_name) AS value FROM information_schema.columns WHERE table_schema=current_schema() AND column_name='realm_id' AND data_type='text'")
        .get_result::<JsonRow>(&mut from).await.unwrap().value;
    let mut tables = vec![(
        "canonical_realms".to_owned(),
        "wire_id=$1".to_owned(),
        realm.to_string(),
    )];
    tables.extend(names.as_array().unwrap().iter().map(|name| {
        (
            name.as_str().unwrap().to_owned(),
            "realm_id=$1".to_owned(),
            realm.to_string(),
        )
    }));
    tables.push((
        "agent_producer_signer_keys".into(),
        "commit_id IN (SELECT commit_id FROM realm_commits WHERE realm_id=$1)".into(),
        realm.to_string(),
    ));
    tables.push((
        "applet_managed_identities".into(),
        "applet_id=$1".into(),
        applet.to_string(),
    ));
    tables.push((
        "applet_installations".into(),
        "record#>>'{effective_scope,realm_id}'=$1".into(),
        realm.to_string(),
    ));
    tables.push((
        "applet_authoring_units".into(),
        "operation_id='ak.self.applet.command.install' AND request_body#>>'{authoring_request_basis,effective_scope,realm_id}'=$1".into(),
        realm.to_string(),
    ));
    let mut captured = Vec::new();
    for (table, predicate, id) in tables {
        let query = format!(
            "SELECT coalesce(jsonb_agg(to_jsonb(r)),'[]'::jsonb) AS value FROM {table} r WHERE {predicate}"
        );
        let rows = diesel::sql_query(query)
            .bind::<Text, _>(id)
            .get_result::<JsonRow>(&mut from)
            .await
            .unwrap()
            .value;
        if rows.as_array().unwrap().is_empty() {
            continue;
        }
        let columns=diesel::sql_query("SELECT jsonb_agg(jsonb_build_object('name',column_name,'json_null',data_type='jsonb' AND is_nullable='NO') ORDER BY ordinal_position) AS value FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND is_generated='NEVER'")
            .bind::<Text,_>(&table).get_result::<JsonRow>(&mut from).await.unwrap().value;
        let projection = columns
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let name = format!("\"{}\"", v["name"].as_str().unwrap());
                // Record population interprets JSON null as SQL NULL; preserve non-null JSONB
                // values.
                if v["json_null"] == true {
                    format!("coalesce({name},'null'::jsonb)")
                } else {
                    name
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let columns = columns
            .as_array()
            .unwrap()
            .iter()
            .map(|v| format!("\"{}\"", v["name"].as_str().unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        captured.push((table, columns, projection, rows));
    }
    to.transaction::<_,diesel::result::Error,_>(async |conn| {
        for (table,columns,projection,rows) in &captured {
            let query=format!("INSERT INTO {table} ({columns}) OVERRIDING SYSTEM VALUE SELECT {projection} FROM jsonb_populate_recordset(NULL::{table},$1) ON CONFLICT DO NOTHING");
            diesel::sql_query(query).bind::<Jsonb,_>(rows).execute(&mut *conn).await?;
        }
        for table in ["canonical_realms","canonical_events"] {
            diesel::sql_query(format!("SELECT setval(pg_get_serial_sequence('{table}','pk'),coalesce((SELECT max(pk) FROM {table}),1),true)"))
                .execute(&mut *conn).await?;
        }
        Ok(())
    }).await.unwrap();
}

fn random_source_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes
}

async fn public_bundle(
    public: &PublicStation,
    realm: &RealmId,
) -> arkret_wire::RealmAuthorityBundle {
    let client = reqwest::Client::builder()
        .tls_backend_rustls()
        .no_proxy()
        .tls_certs_only([reqwest::Certificate::from_pem(include_bytes!(
            "../../fixtures/outbox-test-ca.pem"
        ))
        .unwrap()])
        .build()
        .unwrap();
    let request = arkret_wire::AuthorityBundleRequest {
        realm_id: realm.clone(),
        nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            random_source_bytes(),
        ))
        .unwrap(),
    };
    let response = client
        .post(format!(
            "{}{}_arkret/open/realm-authority/bundle",
            public.url,
            if public.url.ends_with('/') { "" } else { "/" }
        ))
        .header(
            "Arkret-Operation",
            ServiceOperationId::OpenRealmAuthorityReadBundleV1.as_str(),
        )
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&request).unwrap())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.bytes().await.unwrap();
    assert!(
        status.is_success(),
        "real authority bundle: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

async fn genesis(
    context: &NativeSourcesContext,
    creator: usize,
    child: &arkret_wire::GrantId,
) -> Box<arkret_mls::ArkretMlsGroup> {
    use arkret_models_collaboration::events_payloads::{
        MlsGenesisCreatorLeafAuthority, MlsGenesisPayload,
    };
    use arkret_models_crypto::MlsGovernanceBindingPayload;
    let fixture = &context.fixture;
    let (authority, key, _) = &context.actors[creator];
    let scope = ScopeRef::Realm {
        realm_id: fixture.realm.clone(),
    };
    let actor = ActorId::account(authority.account_id.clone());
    let identity = arkret_mls::ArkretMlsIdentity::new_human_device(
        actor.clone(),
        authority.device_id.clone(),
        arkret_mls::ArkretMlsSigner::from_ed25519_signing_key(key.clone()),
    )
    .unwrap();
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0).unwrap();
    let mut group = Box::new(
        identity
            .create_group_with_governance_binding(&scope, &binding)
            .unwrap(),
    );
    let (info, tree) = group.public_group_state_bytes().unwrap();
    let mut refs = Vec::new();
    for bytes in [info, tree] {
        let digest = arkret_canonical::sha256_digest(&bytes);
        let sha = digest.strip_prefix("sha256:").unwrap();
        let reference = arkret_wire::BlobRef::new(format!("ak:blob:{digest}")).unwrap();
        let storage = fixture.state.test_object_key_for_sha256(sha);
        let record = coland_storage::BlobRecord {
            sha256: sha.into(),
            size_bytes: bytes.len() as i64,
            storage_backend: "memory".into(),
            storage_key: storage.clone(),
            media_type: "application/octet-stream".into(),
            filename: None,
            realm_id: Some(fixture.realm.to_string()),
            encryption: None,
            legal_hold: false,
            redacted: false,
            visibility: arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
            uploaded_by: authority.account_id.principal_id.to_string(),
            created_at: chrono::Utc::now(),
        };
        fixture
            .state
            .test_put_object(&storage, bytes)
            .await
            .unwrap();
        fixture
            .state
            .test_persistence()
            .blobs()
            .put(reference.as_str(), &record)
            .await
            .unwrap();
        refs.push(reference);
    }
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let payload = MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        group_info_ref: refs[0].clone(),
        ratchet_tree_ref: refs[1].clone(),
        creator_leaf_authority: MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: arkret_wire::Base64UrlString::new(
                arkret_canonical::base64url_encode(key.verifying_key().as_bytes()),
            )
            .unwrap(),
            endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: authority.device_id.clone(),
            },
            authorization_event_ref: authority.selector.authorization_ref.event_id.clone(),
        },
        governance_binding: binding,
        created_at: at,
    };
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MlsGenesis.as_str(),
        scope,
        actor.clone(),
        json!(payload),
        at,
    )
    .unwrap();
    event.applet_id = Some(context.install.package.applet_id.clone());
    event.authorization_ref = Some(child.clone().into());
    let event = sign_managed_device_event(event, authority, key, at);
    let (status, outcome) = native_phase(|| post(fixture, authority, key, &event, vec![])).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "real native Genesis before migration: {outcome}"
    );
    group
        .install_local_creator_binding(
            actor,
            Some(authority.selector.authorization_ref.event_id.clone()),
        )
        .unwrap();
    group
}

pub(super) async fn prepare(creator: usize) -> Ready {
    eprintln!("[managed forward] constructing independent origin");
    let origin = PublicStation::new();
    let fixture = Box::new(
        governor_phase("origin fixture", || {
            Fixture::new_inner_with_public_base_url(false, Some(origin.url.clone()))
        })
        .await,
    );
    *origin.state.lock().unwrap() = Some(fixture.state.clone());
    origin
        .publish_original_history(&fixture.state, &fixture.pool)
        .await;
    let mut context = governor_phase("accepted native sources", || {
        native_sources_setup_at_with_e2ee(fixture, true)
    })
    .await;
    eprintln!("[managed forward] original creation and Device sources accepted");
    let creation_realm = context.fixture.realm.clone();
    native_phase(|| context.fixture.new_realm()).await;
    assert_ne!(
        creation_realm, context.fixture.realm,
        "business migration does not move the original creation realm"
    );
    let scope = ScopeRef::Realm {
        realm_id: context.fixture.realm.clone(),
    };
    let (package, outcome, body, key) = native_phase(|| {
        context.fixture.install_service_with_constraints(
            true,
            context.native.package.clone(),
            scope.clone(),
            BTreeMap::new(),
        )
    })
    .await;
    let old = &context.install;
    let install = Box::new(Installed {
        package,
        outcome,
        body,
        key,
        bot_outcome: old.bot_outcome.clone(),
        bot_body: old.bot_body.clone(),
    });
    context.install = install;
    context.strand = native_phase(|| native_strand(&context.fixture)).await;
    let parent = native_phase(|| {
        native_business_parent(
            &context.fixture,
            &context.install,
            vec![],
            vec!["ak.mls.genesis".into(), "ak.mls.commit".into()],
            None,
        )
    })
    .await;
    let mut actors = Vec::new();
    let mut mls_children = Vec::new();
    for (index, (old, key, _)) in context.actors.iter().enumerate() {
        let bundle = if index == 0 {
            &context.ghost_bundle
        } else {
            &context.install.bot_body["managed_actor_bundle"]
        };
        let authority=native_phase(||authorize_scopes(&context.fixture,&context.install,bundle,&context.namespace,key,old.device_id.clone(),json!([{"effective_scope":scope,"actions":["ak.applet.join","ak.applet.publish","ak.event.read","ak.mls.commit","ak.mls.genesis"]}]))).await;
        let join = join_event(
            &context.fixture,
            &context.install,
            &authority,
            key,
            &context.install.outcome.capability_grant_refs[0],
        );
        let (status, outcome) =
            native_phase(|| post(&context.fixture, &authority, key, &join, vec![])).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "actual membership before migration: {outcome}"
        );
        let actor = ActorId::account(authority.account_id.clone());
        let child = native_phase(|| {
            native_message_child(&context.fixture, &context.install, &actor, &parent)
        })
        .await;
        mls_children.push(child.clone());
        actors.push((authority, key.clone(), child));
    }
    context.actors = actors;
    eprintln!("[managed forward] independent business installation and membership accepted");
    let group = native_phase(|| genesis(&context, creator, &mls_children[creator])).await;
    let governor = PublicStation::new();
    let mut config = context.fixture.state.config().clone();
    config.public_base_url = governor.url.clone();
    let (state, pool) = coland_test_support::app_state_with_pool(config);
    *governor.state.lock().unwrap() = Some(state.clone());
    governor.publish_original_history(&state, &pool).await;
    assert_ne!(
        state.service_core_id(),
        context.fixture.state.service_core_id()
    );
    let store = PgAuthorityCommitStore {
        pool: context.fixture.pool.clone(),
    };
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: context.fixture.realm.clone(),
    };
    let head = store.stream_head(&stream).await.unwrap().unwrap();
    let change=context.fixture.admin_event(EventKind::RealmGovernanceStationChange,scope,json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":head.commit_id,"new_governance_station_id":state.service_core_id()}));
    native_phase(|| accepted_admin_domain_event(&context.fixture, change.clone())).await;
    let accepted = store
        .committed_event(&change.event_id)
        .await
        .unwrap()
        .unwrap();
    let material = store
        .realm_state_snapshot_material(&context.fixture.realm)
        .await
        .unwrap()
        .unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        context
            .fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        context.fixture.state.notary_signing_key().as_ref(),
        at,
    )
    .unwrap();
    let mut inventory = Vec::new();
    for full in store
        .handoff_originals(&context.fixture.realm)
        .await
        .unwrap()
    {
        if full.commit.producer_signer_fact_digest.is_some() {
            inventory.push(HistoricalProducerSignerFactEntry {
                target: arkret_wire::CommittedEventRef {
                    event_id: full.event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: store
                    .producer_signer_fact(&full.event, &full.commit)
                    .await
                    .unwrap()
                    .unwrap(),
            });
        }
    }
    inventory.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    let mut handoff = arkret_wire::RealmAuthorityHandoff {
        handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest(random_source_bytes()),
        realm_id: context.fixture.realm.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: context.fixture.state.service_core_id(),
        to_service_id: state.service_core_id(),
        change_event_ref: change.event_id,
        change_commit_id: accepted.commit.commit_id,
        final_stream_heads_digest: arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&material.visible_stream_heads).unwrap(),
        )
        .unwrap(),
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&inventory).unwrap()),
        snapshot_ref: snapshot.snapshot_id.clone(),
        pcr_private_state_digest: None,
        old_authority_signature: snapshot.signature.clone(),
        new_authority_acceptance_signature: snapshot.signature.clone(),
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )
    .unwrap();
    handoff.old_authority_signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffOld,
        context
            .fixture
            .state
            .service_verification_method("notary-key")
            .unwrap(),
        at,
        context.fixture.state.notary_signing_key().as_ref(),
    )
    .unwrap();
    handoff.new_authority_acceptance_signature =
        arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            state.service_verification_method("notary-key").unwrap(),
            at,
            state.notary_signing_key().as_ref(),
        )
        .unwrap();
    import_frozen(
        &context.fixture.pool,
        &pool,
        &context.fixture.realm,
        &context.install.package.applet_id,
    )
    .await;
    let next = PgAuthorityCommitStore { pool: pool.clone() };
    next.install_handoff(&handoff, &material.visible_stream_heads, &snapshot)
        .await
        .unwrap();
    store
        .install_handoff(&handoff, &material.visible_stream_heads, &snapshot)
        .await
        .unwrap();
    let bundle = public_bundle(&governor, &context.fixture.realm).await;
    let route: arkret_models_identity::AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record.clone()).unwrap();
    let carrier = arkret_models_identity::ServiceResolutionCarrier::Inline { inline: route };
    let route_resolver = context.fixture.state.service_route_resolver().unwrap();
    let governor_id = state.service_core_id();
    native_phase(|| {
        route_resolver.resolve_carrier(&carrier, &governor_id, "station", chrono::Utc::now())
    })
    .await
    .unwrap();
    let request = AuthorityHandoffRequest {
        handoff,
        final_stream_heads: material.visible_stream_heads,
        snapshot,
        authority_bundle: bundle,
        historical_signer_facts: Some(inventory),
        pcr_private_state: None,
    };
    let peer = coland_services::authority_commit::AuthenticatedPeerContext {
        source_service_id: context.fixture.state.service_core_id(),
        replay_receipt: None,
    };
    native_phase(|| coland_http::test_install_planned_handoff(&state, &peer, request))
        .await
        .unwrap();
    eprintln!("[managed forward] frozen business Realm and signed handoff verified");
    Ready {
        context,
        state,
        pool,
        group,
        mls_child: mls_children[creator].clone(),
        _origin: origin,
        _governor: governor,
    }
}

pub(super) async fn commit(ready: &mut Ready, creator: usize) -> arkret_wire::MlsCommitSubmission {
    commit_with_revision_offset(ready, creator, 0).await
}

pub(super) async fn commit_with_revision_offset(
    ready: &mut Ready,
    creator: usize,
    offset: u64,
) -> arkret_wire::MlsCommitSubmission {
    use arkret_models_crypto::{MlsCommitPayload, MlsGovernanceBindingPayload};
    let scope = ScopeRef::Realm {
        realm_id: ready.context.fixture.realm.clone(),
    };
    let current = coland_storage_postgres::PgMlsGroupCurrentStore {
        pool: ready.pool.clone(),
    }
    .current(&scope)
    .await
    .unwrap()
    .unwrap();
    let revision = current
        .value
        .current_key_access_revision
        .checked_add(offset)
        .unwrap();
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(current.value.current_mls_commit_event_ref.clone()),
        current.value.epoch,
        current.value.epoch + 1,
        revision,
    )
    .unwrap();
    let envelope = ready
        .group
        .self_update_commit_with_governance_binding(&binding)
        .unwrap();
    let payload = MlsCommitPayload::new(
        current.value.current_mls_commit_event_ref,
        revision,
        &envelope,
        binding,
    )
    .unwrap();
    let (authority, key, _) = &ready.context.actors[creator];
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut event = arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MlsCommit.as_str(),
        scope,
        ActorId::account(authority.account_id.clone()),
        json!(payload),
        at,
    )
    .unwrap();
    event.applet_id = Some(ready.context.install.package.applet_id.clone());
    event.authorization_ref = Some(ready.mls_child.clone().into());
    arkret_wire::MlsCommitSubmission {
        commit_event: sign_managed_device_event(event, authority, key, at),
        welcomes: vec![],
        idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7()).unwrap(),
    }
}
