use super::*;

fn key_backup_untrusted_signature() -> AppError {
    crate::app_error!(
        SignatureInvalid,
        "key backup auth_data.signature is not anchored to the actor device trust root",
    )
    .with_reason_code("untrusted_backup_signature")
}

/// key-management.md §7.4.1 (normative): a device signature alone cannot defend
/// against a malicious/compromised server injecting or substituting a backup
/// envelope signed by a revoked old device key. Before a receiver trusts an
/// envelope, it anchors `auth_data.signature` to the accepted
/// `ak.device.authorize` event for the device.
pub(super) async fn anchor_key_backup_auth_data_trust_root(
    state: &AppState,
    actor_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let auth = backup
        .get("auth_data")
        .and_then(Value::as_object)
        .ok_or_else(key_backup_untrusted_signature)?;
    let device_id = auth
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let signature_b64 = auth
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let verification_method = auth
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    let claimed_device_authorize_event_id = auth
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .filter(|event_id| !event_id.trim().is_empty())
        .ok_or_else(key_backup_untrusted_signature)?;
    EventId::new(claimed_device_authorize_event_id.to_owned())
        .map_err(|_| key_backup_untrusted_signature())?;
    let record = state
        .identities()
        .find_device(coland_services::identity::FindDeviceQuery {
            actor_id: actor_id.to_owned(),
            device_id: device_id.to_owned(),
        })
        .await
        .map_err(|error| AppError::internal(format!("device lookup failed: {error}")))?
        .ok_or_else(key_backup_untrusted_signature)?;
    if record.revoked_at.is_some() || record.verification_state != "verified" {
        return Err(key_backup_untrusted_signature());
    }
    let projected_event_id = record
        .payload
        .get("device_authorize_event_id")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    if projected_event_id != claimed_device_authorize_event_id {
        return Err(key_backup_untrusted_signature());
    }
    let device_public_key = record
        .payload
        .get("device_public_key_did")
        .and_then(Value::as_str)
        .ok_or_else(key_backup_untrusted_signature)?;
    if !key_backup_envelope_method_matches_actor_device(actor_id, device_id, verification_method) {
        return Err(crate::app_error!(
            SignatureInvalid,
            "key backup verification method does not match the authorized device key",
        )
        .with_reason_code("untrusted_backup_signature"));
    }
    verify_key_backup_auth_data_signature(backup, device_public_key, signature_b64)
}

fn key_backup_envelope_method_matches_actor_device(
    principal_id: &str,
    device_id: &str,
    verification_method: &str,
) -> bool {
    let Ok(method) = arkret_wire::DidUrl::new(verification_method.to_owned()) else {
        return false;
    };
    let Some((did_text, fragment)) = method.as_str().split_once('#') else {
        return false;
    };
    arkret_wire::Did::new(did_text.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .is_ok_and(|core| core.as_str() == principal_id && fragment == device_id)
}

fn verify_key_backup_auth_data_signature(
    backup: &Value,
    device_public_key: &str,
    signature_b64: &str,
) -> Result<(), AppError> {
    let verifying_key = crate::routing::identity::device_signing::decode_ed25519_key(
        device_public_key,
        "multibase",
    )
    .map_err(|_| key_backup_untrusted_signature())?;
    let backup: KeyBackup = serde_json::from_value(backup.clone())
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    let canonical = backup.signing_payload_bytes().map_err(|error| {
        AppError::internal(format!(
            "key backup signature transcript is invalid: {error}"
        ))
    })?;
    let raw = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .or_else(|_| STANDARD.decode(signature_b64.as_bytes()))
        .map_err(|_| key_backup_untrusted_signature())?;
    let signature = Signature::from_slice(&raw).map_err(|_| key_backup_untrusted_signature())?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| key_backup_untrusted_signature())
}

fn key_backup_verification_method_matches_device_key(
    principal_id: &str,
    device_id: &str,
    device_public_key: &str,
    verification_method: &str,
) -> bool {
    // `did-usage-and-verification.md` §2.2: a proof `verification_method` MUST
    // be a DID URL with a `#fragment`; a DID without URL components never names a concrete
    // verification method.
    let did_key = device_public_key
        .strip_prefix("did:key:")
        .map_or_else(|| format!("did:key:{device_public_key}"), str::to_owned);
    let fragment = did_key
        .strip_prefix("did:key:")
        .unwrap_or(device_public_key);
    if verification_method == format!("{did_key}#{fragment}")
        || verification_method == format!("{did_key}#device")
    {
        return true;
    }
    let Ok(method) = arkret_wire::DidUrl::new(verification_method.to_owned()) else {
        return false;
    };
    let Some((did_text, fragment)) = method.as_str().split_once('#') else {
        return false;
    };
    arkret_wire::Did::new(did_text.to_owned())
        .and_then(|did| arkret_wire::project_did_to_core_id(&did))
        .is_ok_and(|core| core.as_str() == principal_id && fragment == device_id)
}

pub(super) fn key_backup_canonical_digest_without_signature(
    backup: &Value,
) -> Result<String, AppError> {
    let backup: KeyBackup = serde_json::from_value(backup.clone())
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    let bytes = backup
        .signing_payload_bytes()
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    Ok(arkret_canonical::sha256_digest(bytes))
}

pub(super) fn validate_key_backup_unlock_proof_shape(
    proof: &Value,
    account_id: &arkret_wire::AccountId,
    session_device_id: &str,
    backup: &Value,
) -> Result<(), AppError> {
    let proof = serde_json::from_value::<KeyBackupUnlockProof>(proof.clone())
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    proof
        .validate()
        .map_err(|error| schema_error(format!("invalid key backup unlock proof: {error}")))?;
    let backup = serde_json::from_value::<KeyBackup>(backup.clone())
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    backup
        .validate()
        .map_err(|error| schema_error(format!("invalid key backup envelope: {error}")))?;
    if &proof.account_id != account_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof account_id must match authenticated account",
        ));
    }
    if proof.requesting_device_id.as_str() != session_device_id {
        return Err(AppError::capability_denied(
            "key backup unlock proof requesting_device_id must match authenticated session device",
        ));
    }
    if proof.backup_id != backup.backup_id
        || proof.backup_kind != backup.backup_kind
        || proof.series_id != backup.series_id
        || proof.ciphertext_digest != backup.ciphertext_digest
    {
        return Err(AppError::capability_denied(
            "key backup unlock proof does not match backup metadata",
        ));
    }
    Ok(())
}

fn unlock_audience(state: &AppState) -> Result<String, AppError> {
    let url = reqwest::Url::parse(&state.config().public_base_url)
        .map_err(|error| AppError::internal(error.to_string()))?;
    Ok(url.origin().ascii_serialization())
}

fn enforce_unlock_signer_admission(
    key: &ed25519_dalek::VerifyingKey,
    method: &str,
) -> Result<(), AppError> {
    let verification_method = arkret_wire::DidUrl::new(method.to_owned())
        .map_err(|_| AppError::capability_denied("unlock verification method is invalid"))?;
    let did = arkret_identity::verification_method_did(method)
        .map_err(|_| AppError::capability_denied("unlock signer DID is invalid"))?;
    crate::test_material_admission::enforce_ed25519_admission(key, &did, &verification_method, None)
        .map_err(|_| {
            AppError::capability_denied("unlock signer uses formal test material")
                .with_reason_code(arkret_wire::ReasonCode::TEST_SIGNING_MATERIAL_DENIED)
        })
}

pub(super) async fn verify_key_backup_unlock_proof(
    state: &AppState,
    proof: &Value,
    session: &coland_services::identity::SessionIdentityState,
    backup: &Value,
) -> Result<(), AppError> {
    use arkret_models_crypto::KeyBackupUnlockAuthority;
    let account_id = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(session.actor.clone())
            .map_err(|error| AppError::capability_denied(error.to_string()))?,
        state.service_core_id(),
    );
    validate_key_backup_unlock_proof_shape(
        proof,
        &account_id,
        session.require_human_device_id(),
        backup,
    )?;
    let typed: KeyBackupUnlockProof =
        serde_json::from_value(proof.clone()).map_err(|error| schema_error(error.to_string()))?;
    let now = Utc::now();
    if typed.service_id != state.service_core_id()
        || typed.audience.as_str() != unlock_audience(state)?
        || typed.issued_at > now
    {
        return Err(AppError::capability_denied(
            "unlock service, audience or issuance mismatch",
        ));
    }
    let method = typed.auth_data.verification_method.as_str();
    let key = match &typed.authority {
        KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id,
            nonce,
        } => {
            if session.session_grant.as_ref().is_some_and(|grant| {
                grant.credential_class
                    == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
            }) {
                return Err(AppError::capability_denied(
                    "recovery grant cannot select current_device unlock",
                ));
            }
            crate::routing::identity::session_actor::validated_session_actor(state, session)
                .await?;
            crate::routing::identity::device_generation::active_device_revocation_gate_selector(
                state,
                &session.actor,
                session.require_human_device_id(),
            )
            .await
            .map_err(|error| AppError::capability_denied(error.to_string()))?;
            let stored = state
                .key_backups()
                .unlock_challenge(challenge_id.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::capability_denied("server unlock challenge is missing"))?;
            let challenge: arkret_models_crypto::KeysBackupsUnlockChallenge =
                serde_json::from_value(stored)
                    .map_err(|error| AppError::internal(error.to_string()))?;
            if challenge.account_id != typed.account_id
                || challenge.requesting_device_id != typed.requesting_device_id
                || challenge.backup_id != typed.backup_id
                || challenge.series_id != typed.series_id
                || challenge.ciphertext_digest != typed.ciphertext_digest
                || challenge.challenge != typed.challenge
                || &challenge.nonce != nonce
                || challenge.service_id != typed.service_id
                || challenge.audience != typed.audience
                || typed.issued_at < challenge.issued_at
                || typed.issued_at >= challenge.expires_at
                || typed.expires_at != challenge.expires_at
            {
                return Err(AppError::capability_denied(
                    "unlock proof does not match exact server challenge",
                ));
            }
            // Consumption enforces first-use expiry; an exact durable retry may outlive this
            // challenge.
            let device = state
                .identities()
                .find_device(coland_services::identity::FindDeviceQuery {
                    actor_id: session.actor.clone(),
                    device_id: session.require_human_device_id().clone(),
                })
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::capability_denied("current device missing"))?;
            let key = device
                .payload
                .get("device_public_key_did")
                .and_then(Value::as_str)
                .ok_or_else(|| AppError::capability_denied("current device key missing"))?;
            if !key_backup_verification_method_matches_device_key(
                &session.actor,
                session.require_human_device_id(),
                key,
                method,
            ) {
                return Err(AppError::capability_denied(
                    "unlock signer differs from current device",
                ));
            }
            crate::routing::identity::device_signing::decode_ed25519_key(key, "multibase")
                .map_err(|_| AppError::capability_denied("invalid current device key"))?
        }
        KeyBackupUnlockAuthority::RecoverySession {
            recovery_session_id,
        } => {
            let record = state
                .recovery_sessions()
                .session(recovery_session_id.as_str())
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::capability_denied("recovery_evidence_unbound"))?;
            let grant = session
                .session_grant
                .as_ref()
                .ok_or_else(|| AppError::capability_denied("recovery grant required"))?;
            if grant.credential_class
                != arkret_models_identity::SessionGrantCredentialClass::RecoverySession
                || grant.grant_id.as_str() != record.session_grant_id
                || grant.cnf_jkt != record.session_grant_cnf_jkt
                || record.state != coland_storage::RecoverySessionLifecycle::Verified
                || record.expires_at <= now
                || record.expires_at != typed.expires_at
                || record.principal_id != typed.account_id.principal_id
                || record.station_id != typed.account_id.station_id
                || record.requesting_device_id != typed.requesting_device_id.as_str()
                || record.challenge != typed.challenge.as_str()
                || typed.issued_at < record.created_at
            {
                return Err(AppError::capability_denied("recovery_evidence_unbound"));
            }
            let generation =
                crate::routing::identity::device_generation::current_device_generation(
                    state,
                    &session.actor,
                )
                .await
                .map_err(|error| AppError::internal(error.to_string()))?
                .ok_or_else(|| AppError::capability_denied("recovery generation missing"))?;
            if generation.current_ref != record.current_device_generation_ref {
                return Err(AppError::capability_denied("recovery generation changed"));
            }
            let key = &record.requesting_device_public_key_did;
            let fragment = key.strip_prefix("did:key:").ok_or_else(|| {
                AppError::capability_denied("frozen replacement key is not did:key")
            })?;
            if method != format!("{key}#{fragment}") {
                return Err(AppError::capability_denied(
                    "unlock must be signed by frozen replacement identity key",
                ));
            }
            crate::routing::identity::device_signing::decode_ed25519_key(key, "multibase")
                .map_err(|_| AppError::capability_denied("invalid frozen replacement key"))?
        }
    };
    // The method and key have been bound to the selected device or frozen
    // replacement identity. Published fixture keys and reserved identifiers
    // cannot become an unlock authority even when their signature is valid.
    enforce_unlock_signer_admission(&key, method)?;
    let signature = URL_SAFE_NO_PAD
        .decode(typed.auth_data.signature.as_str())
        .map_err(|_| AppError::capability_denied("invalid unlock signature"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| AppError::capability_denied("invalid unlock signature"))?;
    let bytes = typed
        .signing_payload_bytes()
        .map_err(|error| schema_error(error.to_string()))?;
    key.verify(&bytes, &signature)
        .map_err(|_| AppError::capability_denied("unlock signature verification failed"))
}

#[salvo::oapi::endpoint(
    operation_id = "ak.self.keys.backups.command.issue_unlock_challenge",
    tags("identity")
)]
pub(super) async fn issue_key_backup_unlock_challenge(
    aa: AuthArgs,
    backup_id: PathParam<String>,
    body: JsonBody<arkret_models_crypto::KeysBackupsIssueUnlockChallengeRequestBody>,
    depot: &mut Depot,
    req: &mut Request,
) -> JsonResult<arkret_models_crypto::KeysBackupsUnlockChallenge> {
    use rand::RngExt as _;
    let state = depot.get_typed::<AppState>().expect("state injected");
    let session = aa.authenticated_session(state, req).await?;
    if session.session_grant.as_ref().is_some_and(|grant| {
        grant.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession
    }) {
        return Err(AppError::capability_denied(
            "recovery session reuses its frozen challenge",
        ));
    }
    crate::routing::identity::session_actor::validated_session_actor(state, &session).await?;
    crate::routing::identity::device_generation::active_device_revocation_gate_selector(
        state,
        &session.actor,
        session.require_human_device_id(),
    )
    .await
    .map_err(|error| AppError::capability_denied(error.to_string()))?;
    let backup_id = backup_id.into_inner();
    let backup = state
        .key_backups()
        .backup(&backup_id)
        .await
        .map_err(|error| AppError::internal(error.to_string()))?
        .ok_or_else(|| AppError::not_found("key backup not found"))?;
    if !backup_actor_matches(&backup, &local_backup_actor(state, &session.actor)?) {
        return Err(AppError::not_found("key backup not found"));
    }
    let typed: KeyBackup =
        serde_json::from_value(backup).map_err(|error| AppError::internal(error.to_string()))?;
    let random = |size: usize| {
        let mut bytes = vec![0u8; size];
        rand::rng().fill(bytes.as_mut_slice());
        arkret_wire::Base64UrlString::new(URL_SAFE_NO_PAD.encode(bytes)).expect("base64url")
    };
    let now = Utc::now();
    let request_id = body.into_inner().request_id;
    if !(22..=128).contains(&request_id.as_str().len()) {
        return Err(AppError::param_invalid("invalid unlock request_id"));
    }
    let challenge = arkret_models_crypto::KeysBackupsUnlockChallenge {
        challenge_id: random(16),
        challenge: random(32),
        nonce: random(16),
        operation: "ak.self.keys.backups.command.unlock.v1".to_owned(),
        account_id: arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(session.actor.clone())
                .map_err(|error| AppError::internal(error.to_string()))?,
            state.service_core_id(),
        ),
        requesting_device_id: arkret_wire::DeviceId::new(session.require_human_device_id())
            .map_err(|error| AppError::internal(error.to_string()))?,
        backup_id: typed.backup_id,
        series_id: typed.series_id,
        ciphertext_digest: typed.ciphertext_digest,
        audience: arkret_wire::NonEmptyString::new(unlock_audience(state)?)
            .map_err(|error| AppError::internal(error.to_string()))?,
        service_id: state.service_core_id(),
        request_id,
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(300),
    };
    let stored = state
        .key_backups()
        .issue_unlock_challenge(
            serde_json::to_value(challenge)
                .map_err(|error| AppError::internal(error.to_string()))?,
            now,
        )
        .await
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(serde_json::from_value(stored).map_err(|error| AppError::internal(error.to_string()))?)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

    use super::{
        enforce_unlock_signer_admission, key_backup_envelope_method_matches_actor_device,
        key_backup_verification_method_matches_device_key,
    };

    #[test]
    fn published_unlock_signer_is_denied_even_with_a_valid_signature() {
        let fixture_seed = std::array::from_fn(|index| index as u8);
        let published = SigningKey::from_bytes(&fixture_seed);
        let transcript = b"key backup unlock proof transcript";
        let signature = published.sign(transcript);
        published
            .verifying_key()
            .verify(transcript, &signature)
            .unwrap();

        let published_error = enforce_unlock_signer_admission(
            &published.verifying_key(),
            "did:web:keys.example#runtime-1",
        )
        .expect_err("the published conformance key must not authorize an unlock");
        assert_eq!(
            published_error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::TEST_SIGNING_MATERIAL_DENIED)
        );

        let ordinary = SigningKey::from_bytes(&[42; 32]);
        assert!(
            enforce_unlock_signer_admission(
                &ordinary.verifying_key(),
                "did:web:keys.example#runtime-1",
            )
            .is_ok()
        );
        let reserved_id_error = enforce_unlock_signer_admission(
            &ordinary.verifying_key(),
            "did:web:keys.example#device-fixture",
        )
        .expect_err("a reserved test key id must not authorize an unlock");
        assert_eq!(
            reserved_id_error.reason_code.as_deref(),
            Some(arkret_wire::ReasonCode::TEST_SIGNING_MATERIAL_DENIED)
        );
    }

    // did-usage-and-verification.md §2.2 — a proof `verification_method` MUST
    // be a DID URL with a `#fragment`. A bare `did:key:<mb>` names no concrete
    // verification method and must not satisfy the key-backup device binding.
    #[test]
    fn key_backup_verification_method_rejects_did_without_fragment() {
        let did = arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let principal = arkret_wire::project_did_to_core_id(&did).unwrap();
        let device = "ak:device:primary";
        let key = "z6MkBackup";

        for accepted in [
            format!("{did}#{device}"),
            format!("did:key:{key}#{key}"),
            format!("did:key:{key}#device"),
        ] {
            assert!(key_backup_verification_method_matches_device_key(
                principal.as_str(),
                device,
                key,
                &accepted
            ));
        }
        assert!(!key_backup_verification_method_matches_device_key(
            principal.as_str(),
            device,
            key,
            &format!("did:key:{key}"),
        ));
        assert!(!key_backup_verification_method_matches_device_key(
            principal.as_str(),
            device,
            key,
            did.as_str()
        ));
    }

    #[test]
    fn backup_envelope_method_requires_principal_and_exact_device_fragment() {
        let did = arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let principal = arkret_wire::project_did_to_core_id(&did).unwrap();
        let device = "ak:device:primary";
        assert!(key_backup_envelope_method_matches_actor_device(
            principal.as_str(),
            device,
            &format!("{did}#{device}")
        ));
        assert!(!key_backup_envelope_method_matches_actor_device(
            principal.as_str(),
            device,
            "did:key:z6MkBackup#device"
        ));
        assert!(!key_backup_envelope_method_matches_actor_device(
            principal.as_str(),
            device,
            &format!("{did}#other")
        ));
    }
}

/// The confirmed pointer a current-device unlock is authorized against: the
/// released envelope must belong to the active `secret_storage` series and
/// must not have expired. The consuming transaction rereads this pointer at
/// its own PCR cut.
pub(super) async fn unlock_active_basis(
    state: &AppState,
    account: &arkret_wire::AccountId,
    backup: &Value,
) -> Result<coland_storage::KeyBackupPointerBasis, AppError> {
    use arkret_models_crypto::BackupActiveSeriesPointer;
    let pointers = super::listing::active_pointers(state, account).await?;
    let typed: KeyBackup = serde_json::from_value(backup.clone())
        .map_err(|error| AppError::internal(error.to_string()))?;
    let pointer = &pointers.secret_storage;
    if !matches!(pointer,BackupActiveSeriesPointer::Active{active_series_id,..} if active_series_id==&typed.series_id)
        || typed
            .expires_at
            .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return Err(backup_revision_stale(
            "the envelope is not in the active series or has expired",
        ));
    }
    Ok(coland_storage::KeyBackupPointerBasis {
        account_id: pointers.account_id,
        secret_storage: pointers.secret_storage,
    })
}

pub(super) fn backup_revision_stale(detail: &str) -> AppError {
    crate::app_error!(FailedPrecondition, detail)
        .with_reason_code(arkret_wire::ReasonCode::BACKUP_REVISION_STALE)
}
