//! Native current metadata remains readable below the Full Event history floor.
use arkret_models_collaboration::exact_current_results::{
    CalendarScheduleSourceExactSelector, CalendarScheduleSourceExactSelectorKind,
    ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
    ExactCurrentResultsReadRequestBody,
};
use coland_storage::AuthorityCommitStore as _;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bot_and_ghost_read_actual_exact_current_below_history_floor_without_session() {
    for ghost in [false, true] {
        for circle in [false, true] {
            tokio::spawn(native_phase(|| {
                originate(ghost, Case::ExactCurrentReads, circle)
            }))
            .await
            .unwrap();
        }
    }
}

pub(super) async fn prepare_source(
    fixture: &Fixture,
    scope: &ScopeRef,
) -> (arkret_wire::StrandId, EventId) {
    let mut object = json!({"schema":"ak.schema.strand.v1","realm_id":fixture.realm,
        "schema_refs":["ak.schema.calendar_event.v1"],
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Current metadata before native membership","fields":{"calendar":{
            "start":"2026-10-19","end":"2026-10-20","timezone":"Etc/UTC","tzdb_version":"2025a",
            "all_day":true,"status":"confirmed"}}},
        "state":"active","created_by":ActorId::account(fixture.pcr.history.account.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())});
    if let ScopeRef::Circle { circle_id, .. } = scope {
        object["scope_circle_id"] = json!(circle_id);
    }
    let event = fixture.admin_event(
        EventKind::StrandCreate,
        scope.clone(),
        json!({"object":object}),
    );
    let strand = arkret_wire::StrandId::from_event_id(&event.event_id);
    let id = event.event_id.clone();
    native_phase(|| accepted_admin_domain_event(fixture, event)).await;
    (strand, id)
}

async fn read(
    state: &AppState,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &Value,
) -> salvo::Response {
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    managed_device_http_request_body(
        state,
        authority,
        &metadata,
        ServiceOperationId::SelfCurrentResultsReadExactV1,
        key,
        Some(arkret_canonical::canonical_json_bytes(body).unwrap()),
    )
    .add_header("content-type", "application/json", true)
    .send(&service(state.clone()))
    .await
}

async fn refused(
    fixture: &Fixture,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    body: &Value,
) {
    let before = native_phase(|| business(fixture)).await;
    let mut response = native_phase(|| read(&fixture.state, authority, key, scope, body)).await;
    assert!(!response.status_code.unwrap().is_success());
    let result: Value = response.take_json().await.unwrap();
    assert!(
        result.get("entry").is_none(),
        "current disclosure: {result}"
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
}

pub(super) async fn exercise(
    fixture: &Fixture,
    install: &Installed,
    authority: &coland_storage::AppletManagedDeviceAuthority,
    key: &SigningKey,
    scope: &ScopeRef,
    (strand, source): (arkret_wire::StrandId, EventId),
) {
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: fixture.realm.clone(),
        selector: ExactCurrentResultSelector::CalendarScheduleSource(
            CalendarScheduleSourceExactSelector {
                kind: CalendarScheduleSourceExactSelectorKind::CalendarScheduleSource,
                strand_id: strand,
            },
        ),
    };
    request.validate().unwrap();
    let body = json!(request);
    native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    let parent = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    // The source predates the real join. Its Full Event remains unavailable;
    // current metadata is an independent authorized, minimal projection.
    let store = coland_storage_postgres::PgAuthorityCommitStore {
        pool: fixture.pool.clone(),
    };
    let station = fixture.state.service_core_id();
    let direct = native_phase(|| {
        store.exact_current_result_for_account(&request, &authority.account_id, &station)
    })
    .await
    .expect("actual native current snapshot must read without writer locks");
    assert!(
        matches!(direct, coland_storage::SelfExactCurrentRead::Answer(_)),
        "actual current cut: {direct:?}"
    );
    let before = native_phase(|| business(fixture)).await;
    let mut metadata = managed_device_metadata(authority);
    metadata.effective_scope = scope.clone();
    let path = format!("/_arkret/self/committed-events/{source}");
    let mut historical = managed_device_http_request_at(
        &fixture.state,
        authority,
        &metadata,
        ServiceOperationId::SelfCommittedEventResourceGetV1,
        key,
        None,
        Some(&path),
    )
    .send(&service(fixture.state.clone()))
    .await;
    let status = historical.status_code;
    let row: Value = historical.take_json().await.unwrap();
    if status == Some(StatusCode::OK) {
        let historical: arkret_wire::CommittedEventView = serde_json::from_value(row).unwrap();
        assert!(
            !matches!(historical, arkret_wire::CommittedEventView::Full(_)),
            "prejoin source became Full"
        );
    }
    let mut response = native_phase(|| read(&fixture.state, authority, key, scope, &body)).await;
    let status = response.status_code;
    let value: Value = response.take_json().await.unwrap();
    assert_eq!(
        status,
        Some(StatusCode::OK),
        "actual native current metadata: {value}"
    );
    let outcome: ExactCurrentResultsReadOutcome = serde_json::from_value(value).unwrap();
    let ExactCurrentResultsReadOutcome::Present {
        governance_generation,
        entry: ExactCurrentResultEntry::CalendarScheduleSource(row),
        ..
    } = &outcome
    else {
        panic!("current source missing");
    };
    outcome
        .validate_for_request(&request, *governance_generation)
        .unwrap();
    assert_eq!(&row.value.effective_scope, scope);
    assert_eq!(row.value.source.as_ref().unwrap().event_id, source);
    assert!(row.value.metadata_context.is_none());
    assert_eq!(before, native_phase(|| business(fixture)).await);
    let reopened = native_phase(|| {
        coland_test_support::app_state_with_persistence(
            fixture.state.config().clone(),
            std::sync::Arc::new(coland_storage_postgres::PgPersistenceStore::new(
                fixture.pool.clone(),
            )),
        )
    })
    .await;
    native_phase(|| reopened.hydrate()).await.unwrap();
    let mut response = native_phase(|| read(&reopened, authority, key, scope, &body)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let cold: ExactCurrentResultsReadOutcome = response.take_json().await.unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&outcome).unwrap(),
        arkret_canonical::canonical_json_bytes(&cold).unwrap()
    );
    if matches!(scope, ScopeRef::Circle { .. }) {
        let realm = ScopeRef::Realm {
            realm_id: fixture.realm.clone(),
        };
        native_phase(|| refused(fixture, authority, key, &realm, &body)).await;
    }
    let mut unknown = body.clone();
    unknown["selector"]["strand_id"] = json!(arkret_wire::StrandId::from_event_id(
        &EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [98; 32])
    ));
    native_phase(|| refused(fixture, authority, key, scope, &unknown)).await;
    let mut extra = body.clone();
    extra["caller_actor_id"] = json!(ActorId::account(fixture.pcr.history.account.clone()));
    native_phase(|| refused(fixture, authority, key, scope, &extra)).await;
    let grant =
        json!({"realm_id":fixture.realm,"selector":{"kind":"capability_grant","grant_id":parent}});
    native_phase(|| refused(fixture, authority, key, scope, &grant)).await;
    native_phase(|| native_current_revoke(fixture, &parent)).await;
    native_phase(|| refused(fixture, authority, key, scope, &body)).await;
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraintEffect, GrantConstraintKind,
    };
    let deadline = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::seconds(15),
    );
    let mut temporal =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    temporal.expires_at = Some(deadline);
    let _finite = native_phase(|| {
        native_business_parent_in_scope(
            fixture,
            install,
            vec![temporal],
            vec!["ak.event.read".into()],
            None,
            scope.clone(),
        )
    })
    .await;
    let mut response = native_phase(|| read(&fixture.state, authority, key, scope, &body)).await;
    assert_eq!(response.status_code, Some(StatusCode::OK));
    let before = native_phase(|| business(fixture)).await;
    tokio::time::sleep(
        (deadline - chrono::Utc::now()).to_std().unwrap_or_default()
            + std::time::Duration::from_millis(100),
    )
    .await;
    assert!(
        response.take_json::<Value>().await.is_err(),
        "expired source handed off prepared current metadata"
    );
    assert_eq!(before, native_phase(|| business(fixture)).await);
    native_phase(|| refused(fixture, authority, key, scope, &body)).await;
}
