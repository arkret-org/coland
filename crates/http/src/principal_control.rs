//! Direct identity ownership uses native history, never a PCR device key.
use arkret_identity::principal_control::{DirectIdentityControlPurpose, NativeIdentityControlKey};
use arkret_wire::{Did, DidCoreId, DidUrl};

use crate::state::AppState;

pub(crate) async fn resolve_native_identity_control(
    state: &AppState,
    principal_did: &Did,
    expected_core: &DidCoreId,
    method: &DidUrl,
    at: chrono::DateTime<chrono::Utc>,
    purpose: DirectIdentityControlPurpose,
) -> Result<
    (
        NativeIdentityControlKey,
        coland_services::identity::PinnedDidDocumentState,
    ),
    String,
> {
    if arkret_wire::project_did_to_core_id(principal_did).map_err(|e| e.to_string())?
        != *expected_core
    {
        return Err("identity locator does not bind expected principal".to_owned());
    }
    let selected = state
        .dids()
        .resolve_webvh_state_at(principal_did, at)
        .await
        .map_err(|e| e.to_string())?;
    let key =
        arkret_identity::principal_control::native_identity_control_key_from_verified_selection(
            &selected.did,
            expected_core,
            &selected.update_keys,
            method,
            purpose,
        )
        .map_err(|e| e.to_string())?;
    Ok((key, selected))
}

#[cfg(test)]
mod tests {
    use arkret_signatures::webvh::{
        PrincipalInceptionInput, PrincipalRotationInput, prepare_principal_inception,
        prepare_principal_rotation,
    };
    use chrono::{DateTime, Utc};
    use ed25519_dalek::SigningKey;

    use super::*;

    fn public_key(seed: &[u8; 32]) -> String {
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            SigningKey::from_bytes(seed).verifying_key().as_bytes(),
        )
    }

    fn method(seed: &[u8; 32]) -> DidUrl {
        let key = public_key(seed);
        DidUrl::new(format!("did:key:{key}#{key}")).unwrap()
    }

    async fn append(state: &AppState, did: &Did, seq: u64, entry: serde_json::Value) {
        let at = entry["versionTime"].as_str().unwrap().parse().unwrap();
        state
            .dids()
            .append_log_event(coland_services::identity::DidLogEvent {
                event_digest: arkret_canonical::canonical_sha256(&entry).unwrap(),
                did: did.to_string(),
                seq,
                operation: entry,
                created_at: at,
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn invite_subject_native_history_selects_exact_root_across_rotation() {
        let state = AppState::new(
            crate::config::AppConfig::test_default(),
            coland_storage_postgres::Db { pool: None },
        );
        let inception_at: DateTime<Utc> = "2026-07-01T00:00:00Z".parse().unwrap();
        let claim_at = inception_at + chrono::TimeDelta::hours(12);
        let rotation_at = inception_at + chrono::TimeDelta::days(1);
        let endpoint = "https://claim-subject.example/".parse().unwrap();
        let old_seed = [0x31; 32];
        let rotated_seed = [0x32; 32];
        let next_key = public_key(&[0x33; 32]);
        let inception = prepare_principal_inception(&PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: "claim-subject",
            also_known_as: &[],
            version_time: inception_at,
            root_seed: &old_seed,
            next_root_public_key_multibase: &public_key(&rotated_seed),
            witness_policy: None,
        })
        .unwrap();
        let did = Did::new(&inception.did).unwrap();
        let principal = arkret_wire::project_did_to_core_id(&did).unwrap();
        let purpose = DirectIdentityControlPurpose::InviteClaimSubject;
        append(&state, &did, 1, inception.log_entry.clone()).await;
        let (original, original_history) = resolve_native_identity_control(
            &state,
            &did,
            &principal,
            &method(&old_seed),
            claim_at,
            purpose,
        )
        .await
        .unwrap();
        assert_eq!(
            original.public_key(),
            &SigningKey::from_bytes(&old_seed).verifying_key().to_bytes()
        );
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &principal,
                &method(&rotated_seed),
                claim_at,
                purpose,
            )
            .await
            .is_err(),
            "a precommitted future root is not active yet"
        );
        let rotation = prepare_principal_rotation(&PrincipalRotationInput {
            did: did.as_str(),
            local_id: "claim-subject",
            previous_entries: std::slice::from_ref(&inception.log_entry),
            version_time: rotation_at,
            current_root_seed: &rotated_seed,
            next_root_public_key_multibase: &next_key,
            state: &inception.log_entry["state"],
        })
        .unwrap();
        append(&state, &did, 2, rotation.log_entry.clone()).await;
        let (historical, historical_state) = resolve_native_identity_control(
            &state,
            &did,
            &principal,
            &method(&old_seed),
            claim_at,
            purpose,
        )
        .await
        .unwrap();
        assert_eq!(historical.public_key(), original.public_key());
        assert_eq!(historical_state.version_id, original_history.version_id);
        assert_eq!(
            historical_state.log_head_digest,
            original_history.log_head_digest
        );
        assert_eq!(
            historical_state.status,
            coland_services::identity::PinnedDidVersionStatus::Rotated
        );
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &principal,
                &method(&old_seed),
                rotation_at,
                purpose,
            )
            .await
            .is_err(),
            "the old root cannot authorize a new claim at the rotation cut"
        );
        let (current, current_state) = resolve_native_identity_control(
            &state,
            &did,
            &principal,
            &method(&rotated_seed),
            rotation_at,
            purpose,
        )
        .await
        .unwrap();
        assert_eq!(
            current.public_key(),
            &SigningKey::from_bytes(&rotated_seed)
                .verifying_key()
                .to_bytes()
        );
        assert_eq!(current_state.version_id, rotation.version_id);
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &principal,
                &method(&old_seed),
                inception_at - chrono::TimeDelta::milliseconds(1),
                purpose,
            )
            .await
            .is_err()
        );
        let other = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &other,
                &method(&rotated_seed),
                rotation_at,
                purpose,
            )
            .await
            .is_err()
        );
        let device_method = DidUrl::new(format!(
            "{did}#ak:device:01904100-0000-7000-8000-000000002162"
        ))
        .unwrap();
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &principal,
                &device_method,
                rotation_at,
                purpose,
            )
            .await
            .is_err()
        );
        // A later unauthenticated head invalidates the complete history, even
        // when the requested cut precedes it. Never fall back to a cached key.
        let mut corrupted = rotation.log_entry;
        corrupted["state"]["alsoKnownAs"] = serde_json::json!(["https://forged.example/"]);
        append(&state, &did, 3, corrupted).await;
        assert!(
            resolve_native_identity_control(
                &state,
                &did,
                &principal,
                &method(&old_seed),
                claim_at,
                purpose,
            )
            .await
            .is_err()
        );
    }
}
