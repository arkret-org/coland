//! Actor Profile self-service writes and resolution at a durable PCR authority
//! cut (`zh/discovery/profiles-presence.md` section 2.3).
//!
//! Every profile here is a holder-signed Event admitted by the Actor Profile
//! PCR unit: the Station signs the covering RealmCommit and writes the
//! `actor_profile` typed current in the same transaction. Nothing is inserted
//! as accepted state behind the admission path.

use arkret_identifiers::RealmId;
use arkret_models_collaboration::events_payloads::ActorProfileUpdatePayload;
use arkret_models_identity::actor_profile::ActorProfile;
use arkret_wire::{ActorProfileId, EventKind, ScopeRef};
use coland_http::config::AppConfig;
use coland_http::service;
use coland_http::state::AppState;
use coland_test_support::AppStateTestExt as _;
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

fn test_config() -> AppConfig {
    AppConfig {
        development_mode: true,
        embedded_webvh_registration_bearer: Some("fixture-registration".to_owned()),
        ..coland_test_support::app_config()
    }
}

fn problem_code(body: &Value) -> &str {
    body["type"]
        .as_str()
        .and_then(|problem_type| problem_type.rsplit('/').next())
        .unwrap_or_default()
}

/// Admit the PCR genesis, project the account and open a session for it.
async fn account_session(state: &AppState, fixture: &PcrGenesisFixture) -> String {
    fixture.admit(state).await.expect("durable PCR genesis");
    let app = service(state.clone());
    let mut registration = TestClient::post("http://server/_coland/gate/account/project")
        .add_header("authorization", "Bearer fixture-registration", true)
        .json(&json!({
            "principal_id": fixture.history.account.principal_id,
            "did": fixture.history.did,
            "display_name": "Actor Profile fixture",
        }))
        .send(&app)
        .await;
    let status = registration.status_code;
    let body = registration.take_string().await;
    assert!(
        matches!(status, Some(StatusCode::OK | StatusCode::CONFLICT)),
        "account projection: {body:?}"
    );
    let mut login = TestClient::post("http://server/_coland/gate/auth/dev-login")
        .json(&json!({
            "actor": fixture.history.account.principal_id,
            "device_id": fixture.history.founding_device_id,
            "display_name": "Actor Profile fixture",
        }))
        .send(&app)
        .await;
    assert_eq!(login.status_code, Some(StatusCode::OK));
    let body: Value = login.take_json().await.expect("dev-login JSON");
    body["session_credential"]
        .as_str()
        .expect("session credential")
        .to_owned()
}

fn pcr_of(fixture: &PcrGenesisFixture) -> RealmId {
    fixture.unit.transactions[0].event.realm_id.clone()
}

/// One profile Event of `fixture`'s account in its PCR, signed by the
/// founding device.
fn profile_event(
    state: &AppState,
    fixture: &PcrGenesisFixture,
    kind: EventKind,
    payload: Value,
) -> arkret_wire::Event {
    let event = arkret_wire::test_support::raw_event_at(
        kind.as_str(),
        ScopeRef::Realm {
            realm_id: pcr_of(fixture),
        },
        fixture.history.account.principal_id.clone(),
        state.service_core_id(),
        payload,
        chrono::Utc::now(),
    )
    .expect("typed profile Event");
    coland_test_support::signed_event::sign_fixture_event(
        event,
        fixture.history.did.as_str(),
        fixture.history.founding_device_id.as_str(),
        fixture.history.founding_device_signing_seed,
    )
}

fn create_event(state: &AppState, fixture: &PcrGenesisFixture, name: &str) -> arkret_wire::Event {
    profile_event(
        state,
        fixture,
        EventKind::ProfileCreate,
        json!({"object": {
            "principal_id": fixture.history.account.principal_id,
            "actor_kind": "user",
            "display_name": name,
            "profile_fields": {"bio": "ships the reducer"}
        }}),
    )
}

async fn post_profile_event(
    state: &AppState,
    token: &str,
    event: &arkret_wire::Event,
) -> (StatusCode, Value) {
    let mut response = TestClient::post("http://server/_arkret/self/account/profile")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE_V1,
            true,
        )
        .json(&json!({"profile_event": {"event": event}}))
        .send(&service(state.clone()))
        .await;
    let status = response.status_code.expect("profile POST status");
    let body = response.take_json().await.expect("profile POST JSON");
    (status, body)
}

async fn viewer(state: &AppState, token: &str) -> (StatusCode, Value) {
    let mut response = TestClient::get("http://server/_arkret/self/account/viewer")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACCOUNT_READ_VIEWER_V1,
            true,
        )
        .send(&service(state.clone()))
        .await;
    let status = response.status_code.expect("viewer status");
    let body = response.take_json().await.expect("viewer JSON");
    (status, body)
}

#[tokio::test]
async fn create_and_update_share_one_profile_and_a_patch_is_a_delta() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;

    let create = create_event(&state, &fixture, "Alice");
    let (status, created) = post_profile_event(&state, &token, &create).await;
    assert_eq!(status, StatusCode::OK, "profile create: {created}");
    let profile_id = ActorProfileId::from_event_id(&create.event_id);
    assert_eq!(
        created["profile"]["id"],
        json!(profile_id),
        "the materialized id is the retyped create Event id"
    );
    assert_eq!(created["profile"]["realm_id"], json!(pcr_of(&fixture)));
    assert_eq!(created["commit"]["event_ref"], json!(create.event_id));

    let (status, view) = viewer(&state, &token).await;
    assert_eq!(status, StatusCode::OK, "viewer: {view}");
    assert_eq!(view["profile"]["display_name"], "Alice");

    let update = profile_event(
        &state,
        &fixture,
        EventKind::ProfileUpdate,
        json!({"target_ref": profile_id, "patch": {"display_name": "Alice C."}}),
    );
    let (status, updated) = post_profile_event(&state, &token, &update).await;
    assert_eq!(status, StatusCode::OK, "profile update: {updated}");
    assert_eq!(updated["profile"]["id"], json!(profile_id));
    assert_eq!(updated["profile"]["display_name"], "Alice C.");
    assert_eq!(
        updated["profile"]["profile_fields"]["bio"], "ships the reducer",
        "a patch is a delta: untouched members survive"
    );
    assert_eq!(updated["profile"]["updated_by"], json!(update.actor_id));
    assert_eq!(updated["commit"]["event_ref"], json!(update.event_id));

    // An exact retry of the create returns its stored outcome and Commit.
    let (status, replayed) = post_profile_event(&state, &token, &create).await;
    assert_eq!(status, StatusCode::OK, "exact replay: {replayed}");
    assert_eq!(replayed["commit"], created["commit"]);
    assert_eq!(replayed["profile"], created["profile"]);

    // A second create against the accepted lineage is refused.
    let second = create_event(&state, &fixture, "Alice again");
    let (status, body) = post_profile_event(&state, &token, &second).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(problem_code(&body), "failed_precondition", "{body}");

    // Self-service patch paths are limited to display, avatar and fields.
    for patch in [
        json!({"actor_kind": "agent"}),
        json!({"handle": "alice:example.com"}),
    ] {
        let forbidden = profile_event(
            &state,
            &fixture,
            EventKind::ProfileUpdate,
            json!({"target_ref": profile_id, "patch": patch}),
        );
        let (status, body) = post_profile_event(&state, &token, &forbidden).await;
        assert!(status.is_client_error(), "{body}");
        assert_eq!(
            problem_code(&body),
            "unsupported_profile_patch_path",
            "{patch}: {body}"
        );
    }
    let (_, view) = viewer(&state, &token).await;
    assert_eq!(view["profile"]["display_name"], "Alice C.");
}

#[tokio::test]
async fn a_stale_expected_state_digest_refuses_the_profile_update() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let create = create_event(&state, &fixture, "Bob");
    let (status, created) = post_profile_event(&state, &token, &create).await;
    assert_eq!(status, StatusCode::OK, "profile create: {created}");
    let current: ActorProfile =
        serde_json::from_value(created["profile"].clone()).expect("materialized profile");
    let profile_id = current.id.clone().expect("profile id");

    let stale = profile_event(
        &state,
        &fixture,
        EventKind::ProfileUpdate,
        json!({
            "target_ref": profile_id,
            "patch": {"display_name": "Bob B."},
            "expected_state_digest": format!("sha256:{}", "0".repeat(64))
        }),
    );
    let (status, body) = post_profile_event(&state, &token, &stale).await;
    assert!(status.is_client_error(), "{body}");
    assert_eq!(problem_code(&body), "failed_precondition", "{body}");
    let (_, view) = viewer(&state, &token).await;
    assert_eq!(
        view["profile"]["display_name"], "Bob",
        "a refused update writes nothing"
    );

    let guarded = profile_event(
        &state,
        &fixture,
        EventKind::ProfileUpdate,
        json!({
            "target_ref": profile_id,
            "patch": {"display_name": "Bob B."},
            "expected_state_digest": ActorProfileUpdatePayload::state_digest(&current).unwrap()
        }),
    );
    let (status, body) = post_profile_event(&state, &token, &guarded).await;
    assert_eq!(status, StatusCode::OK, "guarded update: {body}");
    assert_eq!(body["profile"]["display_name"], "Bob B.");
}

#[tokio::test]
async fn an_authorized_co_member_resolves_the_exact_signed_profile_event() {
    let state = coland_test_support::app_state(test_config());
    let owner = PcrGenesisFixture::new(state.service_did());
    let reader = PcrGenesisFixture::new(state.service_did());
    let owner_token = account_session(&state, &owner).await;
    let reader_token = account_session(&state, &reader).await;
    let create = create_event(&state, &owner, "Owner");
    let (status, created) = post_profile_event(&state, &owner_token, &create).await;
    assert_eq!(status, StatusCode::OK, "profile create: {created}");

    // Both accounts are joined members of one shared Collaboration Realm.
    let shared = RealmId::new("ak:realm:AcDBmaLJmexYp8de9kbZez_sjHqo3WTTKGdS8F_Tamb6").unwrap();
    let owner_actor = arkret_wire::ActorId::account(owner.history.account.clone());
    let reader_actor = arkret_wire::ActorId::account(reader.history.account.clone());
    {
        let mut projection = state.test_projection().lock();
        let now = chrono::Utc::now();
        for actor in [&owner_actor, &reader_actor] {
            projection.members.insert(
                (shared.to_string(), actor.to_string()),
                coland_domain::reducer::ColandMembershipState {
                    member: actor.to_string(),
                    realm_id: shared.to_string(),
                    state: "join".to_owned(),
                    role: "member".to_owned(),
                    membership_event_ref: None,
                    invited_at: None,
                    joined_at: now,
                    updated_at: now,
                    reason: None,
                },
            );
        }
    }

    let request = arkret_models_identity::actor_profile_operations::ActorProfileResolveRequest::new(
        shared,
        vec![owner_actor.clone()],
    );
    let mut response = TestClient::post("http://server/_arkret/self/actor-profiles/query")
        .add_header("authorization", format!("Bearer {reader_token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&request).expect("canonical resolve body"))
        .send(&service(state.clone()))
        .await;
    let status = response.status_code;
    let outcome: arkret_models_identity::actor_profile_operations::ActorProfileResolveOutcome =
        response.take_json().await.expect("resolve outcome");
    assert_eq!(status, Some(StatusCode::OK));
    arkret_models_collaboration::actor_profile_resolution::validate_actor_profile_resolve_outcome(
        &outcome,
        std::slice::from_ref(&owner_actor),
    )
    .expect("the row binds projection, Event and covering Commit");
    let row = &outcome.profiles[0];
    assert_eq!(row.actor_id, owner_actor);
    assert_eq!(row.profile_event, create);
    assert_eq!(row.profile_commit.event_ref, create.event_id);
    assert_eq!(json!(row.profile_commit), created["commit"]);
    assert_eq!(row.actor_profile.display_name, "Owner");
    assert!(outcome.failures.is_none());
}

#[tokio::test]
async fn pcr_cannot_be_used_as_actor_profile_relationship_selector() {
    let state = coland_test_support::app_state(test_config());
    let fixture = PcrGenesisFixture::new(state.service_did());
    let token = account_session(&state, &fixture).await;
    let actor = arkret_wire::ActorId::account(fixture.history.account.clone());
    let request = arkret_models_identity::actor_profile_operations::ActorProfileResolveRequest::new(
        pcr_of(&fixture),
        vec![actor],
    );
    let mut response = TestClient::post("http://server/_arkret/self/actor-profiles/query")
        .add_header("authorization", format!("Bearer {token}"), true)
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SELF_ACTOR_PROFILE_READ_RESOLVE_V1,
            true,
        )
        .add_header("content-type", "application/json", true)
        .body(arkret_canonical::canonical_json_bytes(&request).expect("canonical resolve body"))
        .send(&service(state.clone()))
        .await;
    let status = response.status_code;
    let body = response.take_string().await;
    assert_eq!(
        status,
        Some(StatusCode::NOT_FOUND),
        "a PCR must not become a relationship selector: {body:?}"
    );
}
