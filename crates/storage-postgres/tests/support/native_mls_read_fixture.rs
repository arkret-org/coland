pub(super) async fn peer_mls_reads(
    governor: &Fixture,
    recipient: &Fixture,
    accepted: &arkret_wire::CommittedEventFullView,
    group: &mut arkret_mls::ArkretMlsGroup,
) {
    use arkret_models_collaboration::mls_roster_authority::{
        MlsMemberRosterAuthorityReadRequestBody, MlsRosterAuthorityReadResponseBody,
        MlsSelfRosterAuthorityReadResponseBody,
    };
    use arkret_wire::ServiceOperationId as Op;
    if !recording() {
        return;
    }
    let request = MlsMemberRosterAuthorityReadRequestBody {
        realm_id: accepted.event.realm_id.clone(),
        effective_scope: accepted.event.scope_ref.clone(),
        mls_group_id: accepted.event.scope_ref.canonical_mls_group_id().unwrap(),
        target_commit_event_ref: accepted.event.event_id.clone(),
        target_epoch: group.epoch(),
        caller_actor_id: ActorId::account(recipient.pcr.history.account.clone()),
        cursor: None,
    };
    let value = account_read(
        recipient,
        reqwest::Method::POST,
        arkret_wire::peer_operation_paths::PATH_SELF_MLS_ROSTER_AUTHORITY,
        Op::SelfMlsReadRosterAuthorityV1,
        Some(json!(request)),
    )
    .await;
    let own: MlsSelfRosterAuthorityReadResponseBody = serde_json::from_value(value).unwrap();
    let peer_request = request.with_accepted_genesis(own.roster.manifest.genesis_event_ref.clone());
    let mut next = peer_request.clone();
    let mut pages: Vec<MlsRosterAuthorityReadResponseBody> = Vec::new();
    for _ in 0..16 {
        let value = peer_read(
            recipient,
            governor,
            arkret_wire::peer_operation_paths::PATH_PEER_MLS_ROSTER_AUTHORITY,
            Op::PeerMlsReadRosterAuthorityV1,
            &json!(next),
        )
        .await;
        let page: MlsRosterAuthorityReadResponseBody = serde_json::from_value(value).unwrap();
        next.cursor = page.next_cursor.clone();
        pages.push(page);
        if next.cursor.is_none() {
            break;
        }
    }
    assert!(next.cursor.is_none());
    assert!(
        pages
            .iter()
            .any(|page| page.records.iter().any(|record| matches!(
                record,
                arkret_models_collaboration::mls_roster_authority::MlsRosterRecord::Add { .. }
            ))),
        "real accepted Add closure required"
    );
    let client = realm_native_fixture::native_http_client(std::time::Duration::from_secs(30));
    let resolution: arkret_models_identity::AuthenticatedServiceResolution = client
        .get(format!(
            "{}{}",
            governor
                .state
                .config()
                .public_base_url
                .trim_end_matches('/'),
            arkret_models_identity::canonical_service_resolution_path(
                &governor.state.service_core_id()
            )
        ))
        .header("arkret-operation", Op::OpenServiceReadResolutionV1.as_str())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let material_request =
        arkret::mls_roster_genesis_material_request(&peer_request, &pages[0].manifest)
            .as_peer_request();
    let value = peer_read(
        recipient,
        governor,
        arkret_wire::peer_operation_paths::PATH_PEER_MLS_GROUP_STATE_MATERIAL,
        Op::PeerMlsReadGroupStateMaterialV1,
        &json!(material_request),
    )
    .await;
    let material: arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialResponseBody = serde_json::from_value(value.clone()).unwrap();
    material.validate_for_request(&material_request).unwrap();
    arkret::install_verified_mls_roster_bindings(
        group,
        &pages,
        &peer_request,
        &governor.state.service_core_id(),
        &accepted.event.event_id,
        &resolution,
        &material,
    )
    .unwrap();
    let genesis = governor
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&peer_request.genesis_event_ref)
        .await
        .unwrap()
        .unwrap();
    let target = governor
        .state
        .test_persistence()
        .authority_commits()
        .committed_event(&accepted.event.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.event, accepted.event);
    assert_eq!(target.commit, accepted.commit);
    let originals = json!({"genesis":accepted_original(&genesis),"target":accepted_original(&target),"pages":pages,"governance_resolution":resolution});
    capture(
        Op::PeerMlsReadRosterAuthorityV1,
        "POST",
        arkret_wire::peer_operation_paths::PATH_PEER_MLS_ROSTER_AUTHORITY,
        Some(json!(peer_request)),
        json!(pages[0]),
        originals.clone(),
    );
    capture(
        Op::PeerMlsReadGroupStateMaterialV1,
        "POST",
        arkret_wire::peer_operation_paths::PATH_PEER_MLS_GROUP_STATE_MATERIAL,
        Some(json!(material_request)),
        value,
        originals,
    );
    let mut changed = pages.clone();
    changed[0].manifest.records_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    assert!(
        arkret::verify_mls_roster_authority_pages(
            &changed,
            &peer_request,
            &governor.state.service_core_id(),
            &accepted.event.event_id,
            &resolution
        )
        .is_err()
    );
}
