//! Real HTTP keys/query over an admitted PCR genesis and retained signer root.
#[path = "http_api/current_common.rs"]
mod common;

use arkret_models_crypto::{KeysQueryRequestBody, QueryAccountDeviceSelector};
use coland_test_support::pcr_genesis::PcrGenesisFixture;
use common::*;

#[test]
fn accepted_device_has_retained_signed_projection() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = coland_test_support::app_state_with_postgres_governance(test_config());
        let fixture = PcrGenesisFixture::new(state.service_did());
        fixture.admit(&state).await.expect("accepted PCR genesis");
        let account = fixture.history.account.clone();
        let device = fixture.history.founding_device_id.clone();
        let token = dev_token_for_device(
            state.clone(),
            fixture.history.did.as_str(),
            device.as_str(),
            "PCR device",
        )
        .await;
        let request = KeysQueryRequestBody {
            device_keys: vec![QueryAccountDeviceSelector {
                account_id: account.clone(),
                device_ids: vec![device.clone()],
            }],
            timeout_ms: None,
        };
        let response: Value = TestClient::post("http://server/_arkret/self/keys/query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&request)
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert_eq!(
            response["device_keys"][0]["account_id"]["principal_id"],
            account.principal_id.as_str()
        );
        let row = &response["device_keys"][0]["device_keys"][device.as_str()];
        assert!(row.is_object(), "expected current device row: {response}");
        let reference: arkret_wire::SignerEvidenceRef =
            serde_json::from_value(row["signer_evidence_ref"].clone()).unwrap();
        let stored = state
            .test_persistence()
            .account_device_signer_evidence()
            .get(&account, &device, &reference)
            .await
            .unwrap()
            .expect("complete signer evidence was retained");
        assert_eq!(stored.signer_evidence_ref().unwrap(), reference);
        assert_eq!(
            row["device_projection"]["device_signing_key_did"],
            stored
                .device_projection_attestation
                .attestation
                .device_signing_key_did
                .as_str(),
        );
        assert!(row.get("device_projection_attestation").is_none());

        let unrelated = arkret_wire::AccountId::new(
            arkret_wire::project_did_to_core_id(
                &arkret_wire::Did::new("did:web:unrelated.example").unwrap(),
            )
            .unwrap(),
            account.station_id.clone(),
        );
        let hidden: Value = TestClient::post("http://server/_arkret/self/keys/query")
            .add_header("authorization", format!("Bearer {token}"), true)
            .json(&KeysQueryRequestBody {
                device_keys: vec![QueryAccountDeviceSelector {
                    account_id: unrelated,
                    device_ids: vec![device.clone()],
                }],
                timeout_ms: None,
            })
            .send(&app_from_state(state.clone()))
            .await
            .take_json()
            .await
            .unwrap();
        assert!(
            hidden["device_keys"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| {
                    entry["device_keys"]
                        .as_object()
                        .is_none_or(serde_json::Map::is_empty)
                }),
            "unrelated account must not disclose a device row: {hidden}"
        );
    });
}
