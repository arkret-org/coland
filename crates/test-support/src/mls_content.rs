//! Crypto-only fixtures and explicit retained-backup inputs. None of these
//! helpers manufactures a native backup PUT acknowledgement or authorization.

use anyhow::{Context as _, Result, ensure};
use arkret::{ArkretMlsGroup, Event, EventId};
use arkret_models_crypto::*;

/// Opaque shape/gate tests only. Changing these coordinates does not claim a
/// valid ciphertext, native epoch installation, root custody, or producer.
pub fn envelope_shape(epoch: u64, reference: &EventId) -> EncryptedEnvelope {
    let fixture =
        arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
            .unwrap();
    let mut envelope: EncryptedEnvelope =
        serde_json::from_value(fixture["kat"]["envelope"].clone()).unwrap();
    let EncryptedEnvelopeEncryptionContext::EpochContent {
        epoch: stored,
        group_state_ref,
        ..
    } = &mut envelope.encryption_context;
    *stored = epoch;
    *group_state_ref = reference.clone();
    envelope
}

pub fn original_material(
    group: &ArkretMlsGroup,
    event: &Event,
    envelope: &EncryptedEnvelope,
    backups: &[KeyBackup],
) -> Result<EventContentMaterial> {
    let EncryptedEnvelopeEncryptionContext::EpochContent {
        root_ref,
        group_state_ref,
        ..
    } = &envelope.encryption_context;
    let context = backups
        .iter()
        .filter(|b| b.actor_id == event.actor_id)
        .flat_map(|b| &b.contents)
        .find(|item| item.root_ref.as_ref() == Some(root_ref))
        .and_then(|i| i.root_context.clone())
        .context("original content waits for its retained root context")?;
    ensure!(
        context.group_state_ref == *group_state_ref,
        "original root reference changed"
    );
    Ok(EventContentMaterial::from_original(
        event,
        envelope,
        context,
        group.original_content_endpoint(event)?,
    )?)
}

pub fn pending_public_refs(
    group: &ArkretMlsGroup,
    commit: &MlsCommitEnvelope,
    binding: &MlsGovernanceBindingPayload,
) -> Result<(arkret::BlobRef, arkret::BlobRef)> {
    let (info, tree) = group.pending_public_group_state_bytes(commit, binding)?;
    let reference = |bytes: &[u8]| {
        arkret::BlobRef::new(format!(
            "ak:blob:{}",
            arkret_canonical::sha256_digest(bytes)
        ))
    };
    Ok((reference(&info)?, reference(&tree)?))
}

pub fn commit_payload(
    group: &ArkretMlsGroup,
    base: EventId,
    revision: u64,
    commit: &MlsCommitEnvelope,
    binding: MlsGovernanceBindingPayload,
) -> Result<MlsCommitPayload> {
    let (info, tree) = pending_public_refs(group, commit, &binding)?;
    Ok(MlsCommitPayload::new(
        base, revision, commit, binding, info, tree,
    )?)
}

pub fn retained_material(
    group: &ArkretMlsGroup,
    event: &Event,
    reference: &EventId,
    backups: &[KeyBackup],
) -> Result<EventContentMaterial> {
    let mut matches = Vec::new();
    for backup in backups {
        backup.validate()?;
        if backup.actor_id != event.actor_id {
            continue;
        }
        for item in &backup.contents {
            let (Some(context), Some(root_ref)) = (&item.root_context, &item.root_ref) else {
                continue;
            };
            if context.effective_scope != *group.scope()
                || context.epoch != group.epoch()
                || context.group_state_ref != *reference
            {
                continue;
            }
            let root = group.export_content_root(context)?;
            ensure!(
                arkret::crypto::content_history::content_root_ref(&root, context)? == *root_ref,
                "retained backup index differs from actual epoch root"
            );
            matches.push((context.clone(), root_ref.clone(), backup.backup_id.clone()));
        }
    }
    let (context, root_ref, _) = matches
        .first()
        .context("content waits for its native retained root backup")?;
    ensure!(
        matches
            .iter()
            .all(|(ctx, r, _)| ctx == context && r == root_ref),
        "conflicting retained root contexts"
    );
    let mut refs: Vec<_> = matches.iter().map(|(_, _, id)| id.clone()).collect();
    refs.sort();
    refs.dedup();
    material(
        group,
        event,
        context.clone(),
        ContentProtection {
            root_refs: vec![root_ref.clone()],
            blob_refs: vec![],
            backup_refs: refs,
        },
    )
}

pub fn material(
    group: &ArkretMlsGroup,
    event: &Event,
    context: ContentRootContext,
    protection: ContentProtection,
) -> Result<EventContentMaterial> {
    ensure!(
        event.scope_ref == *group.scope() && event.actual_signer() == group.local_actor_id(),
        "content fixture differs from actual producer"
    );
    let root = group.export_content_root(&context)?;
    let root_ref = arkret::crypto::content_history::content_root_ref(&root, &context)?;
    ensure!(
        protection.root_refs.contains(&root_ref) && !protection.backup_refs.is_empty(),
        "content fixture lacks its explicit backup dependency"
    );
    let content_context = ContentContext {
        root_context: context,
        root_ref,
        purpose: ContentPurpose::EventBody,
        encryption_scheme: arkret::EncryptedPayloadScheme::EpochContentAead,
        encryption_algorithm: ContentEncryptionAlgorithm::Aes128Gcm,
        producer: group.local_content_endpoint()?,
        content_key_salt: arkret::crypto::content_history::fresh_content_key_salt()?,
    };
    let key = arkret::crypto::content_history::derive_content_key(&root, &content_context)?;
    Ok(EventContentMaterial {
        key_commitment: arkret::crypto::content_history::content_key_commitment(
            &content_context,
            &key,
        )?,
        content_context,
        outer_event: EventContentMaterial::outer_event_for(event)?,
        protection,
    })
}

/// Standalone AEAD tests only; its local backup selector is not a server receipt.
pub fn local_material(
    group: &ArkretMlsGroup,
    kind: &str,
    reference: &EventId,
) -> Result<EventContentMaterial> {
    let realm = group.scope().realm_id();
    let context = ContentRootContext {
        effective_scope: group.scope().clone(),
        genesis_event_ref: reference.clone(),
        epoch: group.epoch(),
        group_state_ref: reference.clone(),
        cipher_suite: group.group_ciphersuite_canonical_id()?.to_owned(),
        encryption_backup_strategy: arkret::EncryptionBackupStrategy::EpochContentRoots,
        backup_strategy_ref: EventId::from_digest(
            realm.digest_suite_code().digest_suite(),
            realm.digest_bytes(),
        ),
    };
    let root = group.export_content_root(&context)?;
    let root_ref = arkret::crypto::content_history::content_root_ref(&root, &context)?;
    let event = arkret_wire::test_support::raw_event_for_actor_at(
        kind,
        group.scope().clone(),
        group.local_actor_id().clone(),
        serde_json::json!({}),
        "2026-11-09T00:00:00.000Z".parse()?,
    )?;
    material(
        group,
        &event,
        context,
        ContentProtection {
            root_refs: vec![root_ref],
            blob_refs: vec![],
            backup_refs: vec![arkret::BackupId::new(arkret::new_prefixed_uuid7(
                "ak:backup:",
            ))?],
        },
    )
}

pub fn resign(event: &mut Event, seed: [u8; 32]) -> Result<()> {
    let method = event
        .producer_proof
        .as_ref()
        .context("original signer absent")?
        .verification_method
        .clone();
    let did = method
        .as_str()
        .split_once('#')
        .context("original signer controller absent")?
        .0;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        arkret::Did::new(did)?,
        method,
    );
    event.producer_proof = None;
    let mut authored = arkret::AuthoredEvent::finalize_with_digest_suite(
        event.clone(),
        event.event_id.digest_suite_code().digest_suite(),
    )?;
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(event.created_at),
    )?;
    *event = authored.into_event();
    Ok(())
}
