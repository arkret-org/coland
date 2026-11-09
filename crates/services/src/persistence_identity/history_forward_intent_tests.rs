//! Origin source publication cannot outrun its discoverable original intent.

use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, MlsGroupStateMaterial, PeerAuthorityForwardEventRequestBody,
    PeerAuthoritySubmitRequestBody, authority_forward_body_digest,
};
use arkret_models_identity::ForwardAccountDeviceSignerEvidence;
use arkret_wire::{Did, DidUrl, EventAdmissionSubmission};
use coland_storage::AccountDeviceSignerEvidenceStore as _;
use coland_storage_postgres::PgAccountDeviceSignerEvidenceArchive;
use diesel::sql_types::{Binary, Text};
use serde_json::json;

use super::*;

async fn source(
    pool: &PgPool,
    prepared: &PreparedGroup,
    inception: &arkret_signatures::webvh::PreparedInception,
) -> PeerAuthorityForwardEventRequestBody {
    let event = &prepared.request.authority_commit.event;
    let (info, tree) = prepared.group.public_group_state_bytes().unwrap();
    let mut request = PeerAuthorityForwardEventRequestBody {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(event.clone()),
        mls_group_state_material: Some(MlsGroupStateMaterial {
            group_info_base64url: arkret_canonical::base64url_encode(info),
            ratchet_tree_base64url: arkret_canonical::base64url_encode(tree),
        }),
        producer_device_evidence: None,
        producer_agent_evidence: None,
    };
    let account = event.actual_signer().as_account_id().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&inception.did_key_seed);
    let method = DidUrl::new(inception.did_key_id.clone()).unwrap();
    let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
        account.station_id.clone(),
        "station".into(),
        serde_json::from_value(inception.log_entry["state"].clone()).unwrap(),
        vec![inception.log_entry.clone()],
        vec![],
        chrono::Utc::now(),
    )
    .unwrap();
    let archive = PgAccountDeviceSignerEvidenceArchive::new(pool.clone());
    let core = archive
        .prepare_non_managed_forward_current(
            event,
            &account.station_id,
            &authority_forward_body_digest(&request).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    request.producer_device_evidence = Some(ForwardAccountDeviceSignerEvidence {
        device_projection_attestation:
            arkret_signatures::device_projection::sign_forward_device_projection_attestation(
                core, method, &key,
            )
            .unwrap(),
        service_resolution: resolution,
    });
    request.validate().unwrap();
    request
}

async fn queued(pool: &PgPool, event: &arkret_wire::Event) -> Option<Value> {
    let mut conn = pool.get().await.unwrap();
    use horme::OptionalExtension as _;
    diesel::sql_query("SELECT jsonb_build_object('state',e.state,'original',e.envelope,'source_count',(SELECT count(*) FROM account_device_signer_evidence s WHERE s.forward_event_pk=e.pk),'attempt_count',(SELECT count(*) FROM authority_forward_attempts f WHERE f.event_pk=e.pk)) AS payload FROM canonical_events e WHERE e.id=$1")
        .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
        .get_result::<BindingRow>(&mut *conn).await.optional().unwrap().map(|row| row.payload)
}

#[tokio::test]
async fn signed_forward_source_retains_exact_unaccepted_original_atomically() {
    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception,
    };
    let registration = ServiceRegistrationKey::new(
        arkret_wire::ServiceKind::Station,
        CanonicalServiceUrl::new("https://forward-intent.example/").unwrap(),
    )
    .unwrap();
    let inception = prepare_service_registration_inception(
        &mut rand::rng(),
        &ServiceRegistrationInceptionInput {
            provider_endpoint: &"https://identity.example/".parse().unwrap(),
            registration_key: &registration,
            also_known_as: &[],
            version_created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
            did_key_fragment: None,
        },
    )
    .unwrap();
    let did = Did::new(inception.did.clone()).unwrap();
    let station = arkret_wire::project_did_to_core_id(&did).unwrap();
    let database = TestDatabase::lease().await;
    database.bind_device_inventory_station(station.as_str());
    let pool = database.pool();
    let archive = PgAccountDeviceSignerEvidenceArchive::new(pool.clone());
    for full_request in [false, true] {
        let discussion = Box::pin(ordinary_realm::open_discussion_for_station(
            &pool,
            &format!("source-intent-{full_request}"),
            &station,
            &did,
        ))
        .await;
        let prepared = Box::pin(prepared_group_from_discussion(&pool, discussion, false)).await;
        let event = &prepared.request.authority_commit.event;
        let request = Box::pin(source(&pool, &prepared, &inception)).await;
        let evidence = request.producer_device_evidence.as_ref().unwrap();
        assert_eq!(queued(&pool, event).await, None);

        let mut bad = evidence.clone();
        bad.device_projection_attestation
            .attestation
            .event_authorization
            .forward_body_digest =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"changed-body")).unwrap();
        assert!(archive.retain_forward_current(event, &bad).await.is_err());
        assert_eq!(
            queued(&pool, event).await,
            None,
            "invalid source leaves no intent"
        );

        // No caller queue/transport write occurs: a crash immediately after
        // source publication still leaves the actual target discoverable.
        let reference = if full_request {
            archive
                .retain_forward_request(&PeerAuthoritySubmitRequestBody::AuthorityForwardEvent(
                    request.clone(),
                ))
                .await
                .unwrap()
        } else {
            archive
                .retain_forward_current(event, evidence)
                .await
                .unwrap()
        };
        let retained = queued(&pool, event).await.unwrap();
        assert_eq!(retained["original"], serde_json::to_value(event).unwrap());
        assert_eq!(retained["state"], "queued");
        assert_eq!(retained["source_count"], 1);
        assert_eq!(retained["attempt_count"], 0);
        assert_eq!(
            archive
                .retain_forward_current(event, evidence)
                .await
                .unwrap(),
            reference
        );
        assert_eq!(queued(&pool, event).await.unwrap(), retained);

        // The source FK prevents GC of an unresolved original. No current
        // membership, accepted Commit or current MLS binding was fabricated.
        let mut conn = pool.get().await.unwrap();
        let error = diesel::sql_query("DELETE FROM canonical_events WHERE id=$1")
            .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
            .execute(&mut *conn)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("foreign key"), "{error}");
        let sources = diesel::sql_query("SELECT jsonb_build_object('commits',(SELECT count(*) FROM realm_commits c WHERE c.event_pk=e.pk),'bindings',(SELECT count(*) FROM mls_endpoint_current_bindings b WHERE b.current_event_ref=$2)) AS payload FROM canonical_events e WHERE e.id=$1")
            .bind::<Binary, _>(event.event_id.token_bytes().to_vec())
            .bind::<Text, _>(event.event_id.as_str())
            .get_result::<BindingRow>(&mut *conn).await.unwrap();
        assert_eq!(sources.payload, json!({"commits":0,"bindings":0}));
    }
}
