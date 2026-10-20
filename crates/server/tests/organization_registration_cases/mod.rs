//! Real SDK / DPoP / TCP / PostgreSQL organization registration lifecycle.
use std::sync::Arc;

use arkret_models_identity::{
    OrganizationRegistrationChallengeRequestBody, OrganizationRegistrationEnsureRequestBody,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationScope, OrganizationRegistrationStatus,
};
use coland_services::organization_registration::OrganizationRegistrationService;
use parking_lot::RwLock;

use super::*;

#[path = "../support/organization_registration.rs"]
mod fixture;
use fixture::{StaticOrganizationResolver, organization_fixture, signed_control_proof};

fn admin(session: &GrantSession, enabled: bool, principal: &arkret_wire::DidCoreId) {
    let mut settings = (*session.state.settings()).clone();
    settings.admin_principal_ids = if enabled {
        vec![principal.clone()]
    } else {
        vec![]
    };
    session.state.replace_settings(settings);
}

#[tokio::test]
async fn organization_registration_sdk_uses_delegate_core_and_durable_generation_cas() {
    use salvo::conn::Listener;
    let acceptor = salvo::conn::TcpListener::new("127.0.0.1:0")
        .try_bind()
        .await
        .unwrap();
    let base = format!("http://{}", acceptor.local_addr().unwrap());
    let mut config = test_config();
    config.public_base_url = base.clone();
    let pcr = PcrGenesisFixture::new(
        coland_test_support::fixture_service_identity(&config)
            .identity()
            .unwrap()
            .did
            .clone(),
    );
    let mut session = account_grant_session_at(&pcr, Some(base.clone())).await;
    let principal = pcr.history.account.principal_id.clone();
    admin(&session, true, &principal);
    let (organization, did, _, pinned, key) = organization_fixture();
    let registrations = OrganizationRegistrationService::with_resolver(
        session.state.test_persistence(),
        Arc::new(StaticOrganizationResolver {
            state: RwLock::new(pinned.clone()),
        }),
    );
    session
        .state
        .test_set_organization_registration_service(registrations.clone());
    let state = session.state.clone();
    let server = tokio::spawn(async move {
        salvo::Server::new(acceptor).serve(service(state)).await;
    });
    let dpop_key = session.holder_key.clone();
    let sdk = arkret_http_client::Client::builder(url::Url::parse(&base).unwrap())
        .allow_insecure_localhost()
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token(session.token.clone(), move |request| {
                arkret_signatures::dpop::build_dpop_proof(&request, &dpop_key)
                    .map(|proof| proof.header_value)
                    .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
            }),
        ))
        .build()
        .unwrap();
    let mut prepare = OrganizationRegistrationChallengeRequestBody {
        organization_id: organization.clone(),
        organization_did: did.clone(),
        local_admin_subject_id: principal.clone(),
        requested_scopes: vec![OrganizationRegistrationScope::OrganizationProfileManage],
    };
    let challenge = sdk
        .organization_registration_prepare(&prepare)
        .await
        .unwrap();
    let ensure = OrganizationRegistrationEnsureRequestBody {
        organization_id: organization.clone(),
        organization_did: did.clone(),
        challenge_id: challenge.challenge_id.clone(),
        version_id: pinned.version_id.clone(),
        log_head_digest: pinned.log_head_digest.clone(),
        control_proof: signed_control_proof(&challenge, &pinned, &key),
        local_admin_subject_id: principal.clone(),
        requested_scopes: prepare.requested_scopes.clone(),
        handle_attestation: None,
    };
    let first = sdk.organization_registration_ensure(&ensure).await.unwrap();
    assert!(first.created);
    let replay = sdk.organization_registration_ensure(&ensure).await.unwrap();
    assert!(!replay.created);
    assert_eq!(replay.registration_receipt, first.registration_receipt);
    let mut altered = ensure.clone();
    altered.local_admin_subject_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap();
    assert!(
        sdk.organization_registration_ensure(&altered)
            .await
            .is_err()
    );
    let refresh_challenge = sdk
        .organization_registration_prepare(&prepare)
        .await
        .unwrap();
    let refresh = OrganizationRegistrationRefreshRequestBody {
        organization_id: organization.clone(),
        organization_did: did.clone(),
        challenge_id: refresh_challenge.challenge_id.clone(),
        version_id: pinned.version_id.clone(),
        log_head_digest: pinned.log_head_digest.clone(),
        control_proof: signed_control_proof(&refresh_challenge, &pinned, &key),
    };
    admin(&session, false, &principal);
    assert!(!session.state.is_admin_principal(principal.as_str()));
    assert_eq!(
        sdk.organization_registration_get(&organization)
            .await
            .unwrap()
            .registration_generation(),
        1
    );
    assert!(
        sdk.organization_registration_prepare(&prepare)
            .await
            .is_err()
    );
    let refreshed = sdk
        .organization_registration_refresh(&refresh)
        .await
        .unwrap();
    assert_eq!(refreshed.registration_generation(), 1);
    assert_eq!(
        sdk.organization_registration_refresh(&refresh)
            .await
            .unwrap(),
        refreshed
    );
    let old_current = registrations.current(&organization).await.unwrap().unwrap();
    let revoke = OrganizationRegistrationRevokeRequestBody {
        organization_id: organization.clone(),
        reason_code: None,
    };
    let revoked = sdk.organization_registration_revoke(&revoke).await.unwrap();
    assert_eq!(
        revoked.registration_receipt.status,
        OrganizationRegistrationStatus::Revoked
    );
    assert_eq!(
        sdk.organization_registration_revoke(&revoke).await.unwrap(),
        revoked
    );
    assert!(
        sdk.organization_registration_refresh(&refresh)
            .await
            .is_err()
    );
    // A new accepted delegation retires the old administrator and generation.
    admin(&session, true, &principal);
    prepare.local_admin_subject_id = altered.local_admin_subject_id.clone();
    let next_challenge = sdk
        .organization_registration_prepare(&prepare)
        .await
        .unwrap();
    let next = OrganizationRegistrationEnsureRequestBody {
        challenge_id: next_challenge.challenge_id.clone(),
        local_admin_subject_id: prepare.local_admin_subject_id.clone(),
        control_proof: signed_control_proof(&next_challenge, &pinned, &key),
        ..ensure.clone()
    };
    let second = sdk.organization_registration_ensure(&next).await.unwrap();
    assert_eq!(second.registration_generation(), 2);
    admin(&session, false, &principal);
    let forbidden = sdk
        .organization_registration_get(&organization)
        .await
        .unwrap_err();
    let absent = sdk
        .organization_registration_get(
            &arkret_wire::DidCoreId::new("ak:did_core:web:absent.example").unwrap(),
        )
        .await
        .unwrap_err();
    match (forbidden, absent) {
        (
            arkret_http_client::Error::Api {
                status: a,
                error: x,
            },
            arkret_http_client::Error::Api {
                status: b,
                error: y,
            },
        ) => {
            assert_eq!((a, b), (404, 404));
            assert_eq!(x.problem_type, y.problem_type);
            assert_eq!(x.detail, y.detail);
        }
        other => panic!("expected indistinguishable 404: {other:?}"),
    }
    assert!(sdk.organization_registration_revoke(&revoke).await.is_err());
    assert!(
        sdk.organization_registration_refresh(&refresh)
            .await
            .is_err()
    );
    assert_eq!(
        registrations
            .current(&organization)
            .await
            .unwrap()
            .unwrap()
            .outcome,
        second
    );
    assert_eq!(old_current.generation.registration_generation, 1);
    let identity = coland_test_support::fixture_service_identity(session.state.config());
    let signer = ReceiptSigner {
        issuer: session.state.service_core_id(),
        key: arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
            coland_test_support::fixture_signing_seed(session.state.config(), &identity),
            format!("{}#notary-key", session.state.service_did()),
        ),
        method: arkret_wire::DidUrl::new(format!("{}#notary-key", session.state.service_did()))
            .unwrap(),
    };
    assert!(
        registrations
            .revoke(revoke.clone(), &old_current, &signer, chrono::Utc::now())
            .await
            .is_err()
    );
    assert!(
        registrations
            .refresh(refresh.clone(), &old_current, &signer, chrono::Utc::now())
            .await
            .is_err()
    );
    assert_eq!(
        registrations
            .current(&organization)
            .await
            .unwrap()
            .unwrap()
            .outcome,
        second
    );
    // A terminal successor must not bypass the old generation's CAS either.
    admin(&session, true, &principal);
    let terminal = sdk.organization_registration_revoke(&revoke).await.unwrap();
    assert_eq!(terminal.registration_generation(), 2);
    assert!(
        registrations
            .revoke(revoke, &old_current, &signer, chrono::Utc::now())
            .await
            .is_err()
    );
    assert_eq!(
        registrations
            .current(&organization)
            .await
            .unwrap()
            .unwrap()
            .outcome,
        terminal
    );
    server.abort();
}

struct ReceiptSigner {
    issuer: arkret_wire::DidCoreId,
    method: arkret_wire::DidUrl,
    key: arkret_signatures::Ed25519DetachedJwsSigner,
}
impl coland_services::organization_registration::OrganizationRegistrationReceiptSigner
    for ReceiptSigner
{
    fn issuer_id(&self) -> &arkret_wire::DidCoreId {
        &self.issuer
    }
    fn verification_method(&self) -> &arkret_wire::DidUrl {
        &self.method
    }
    fn sign_detached_jws(&self, bytes: &[u8]) -> Result<String, String> {
        Ok(self.key.sign_detached_jws(bytes))
    }
}
