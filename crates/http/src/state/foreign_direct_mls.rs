//! Read-only MLS facts for a hosted participant in a foreign Direct Realm.
//! Replays public RFC 9420 material; never installs governing admission state.
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody;
use arkret_models_crypto::MlsCommitPayload;
use arkret_wire::{ActorId, EventKind, MlsGroupCurrent, RealmId, ScopeRef, TypedCurrentRow};
use coland_storage::ForeignDirectMlsInput;

use super::AppState;

pub(crate) async fn refresh(
    state: &AppState,
    realm: &RealmId,
    caller: &ActorId,
) -> Result<bool, String> {
    let Some(account) = caller.as_account_id() else {
        return Ok(false);
    };
    // Reuse locally verified cuts and public prefixes before asking the origin.
    // Tail MLS transitions clear the authorization cut and require a new snapshot.
    let mut next_input = state
        .event_queries()
        .foreign_direct_mls_input(realm, caller)
        .await
        .map_err(|error| error.to_string())?;
    if next_input.is_none() {
        super::refresh_account_snapshot(state, realm, account).await?;
    }
    let started = std::time::Instant::now();
    let mut pages = 0;
    loop {
        if pages >= 8 || (pages > 0 && started.elapsed() > std::time::Duration::from_secs(8)) {
            return Ok(false);
        }
        pages += 1;
        let selected = if let Some(input) = next_input.take() {
            Some(input)
        } else {
            state
                .event_queries()
                .foreign_direct_mls_input(realm, caller)
                .await
                .map_err(|error| error.to_string())?
        };
        let Some(input) = selected else {
            return Ok(false);
        };
        let TypedCurrentRow::Value { value, .. } = &input.current;
        let current: MlsGroupCurrent =
            serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
        let (group_info, tree) = if input.base.is_none() {
            let Some((_, genesis)) = input.history.first() else {
                return Ok(false);
            };
            if genesis.kind != EventKind::MlsGenesis
                || genesis.event_id != current.genesis_event_ref
            {
                return Ok(false);
            }
            let payload: MlsGenesisPayload = serde_json::from_value(
                serde_json::to_value(&genesis.payload).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let request = MlsMemberGroupStateMaterialReadRequestBody {
                realm_id: realm.clone(),
                effective_scope: ScopeRef::Realm {
                    realm_id: realm.clone(),
                },
                mls_group_id: payload.mls_group_id().map_err(|error| error.to_string())?,
                epoch: arkret_models_collaboration::events_payloads::mls::MlsGenesisEpoch,
                group_state_event_id: genesis.event_id.clone(),
                caller_actor_id: caller.clone(),
                target_commit_event_ref: current.current_mls_commit_event_ref.clone(),
                target_epoch: current.epoch,
                group_info_ref: payload.group_info_ref.clone(),
                ratchet_tree_ref: payload.ratchet_tree_ref.clone(),
                max_response_bytes: None,
            };
            request
                .as_peer_request()
                .validate()
                .map_err(|error| error.to_string())?;
            public_genesis_material(state, &request).await?
        } else {
            (vec![], vec![])
        };
        let (result, exact) = replay(&input, &group_info, &tree)?;
        if input.base.is_none() {
            let (commit, genesis) = &input.history[0];
            let payload: MlsGenesisPayload = serde_json::from_value(
                serde_json::to_value(&genesis.payload).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            cache_public_genesis_material(
                state,
                &input.realm_id,
                commit,
                genesis,
                [
                    (&payload.group_info_ref, group_info),
                    (&payload.ratchet_tree_ref, tree),
                ],
            )
            .await?;
        }
        if !state
            .event_queries()
            .install_foreign_direct_mls_public_state(&input, &result, exact)
            .await
            .map_err(|error| error.to_string())?
        {
            return Ok(false);
        }
        if input.complete {
            return Ok(true);
        }
        // Each accepted page persists a public-only prefix. The next page starts
        // there, so ordinary messages and long epoch lineages have no hard limit.
    }
}

async fn public_genesis_material(
    state: &AppState,
    request: &MlsMemberGroupStateMaterialReadRequestBody,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let info_row = state
        .deliveries()
        .blob(request.group_info_ref.as_str())
        .await
        .map_err(|error| error.to_string())?;
    let tree_row = state
        .deliveries()
        .blob(request.ratchet_tree_ref.as_str())
        .await
        .map_err(|error| error.to_string())?;
    if info_row.as_ref().is_some_and(|row| row.redacted)
        || tree_row.as_ref().is_some_and(|row| row.redacted)
    {
        return Err("public Genesis material is redacted".into());
    }
    let limit = arkret_models_collaboration::mls_group_state_material::MLS_GROUP_STATE_MATERIAL_MAX_RESPONSE_BYTES as usize;
    if info_row.is_some() && tree_row.is_some() {
        let info = crate::routing::mls::load_mls_public_blob(
            state,
            request.group_info_ref.as_str(),
            limit,
        )
        .await
        .map_err(|error| error.to_string())?;
        let tree = crate::routing::mls::load_mls_public_blob(
            state,
            request.ratchet_tree_ref.as_str(),
            limit.saturating_sub(info.len()),
        )
        .await
        .map_err(|error| error.to_string())?;
        Ok((info, tree))
    } else {
        let outcome = crate::routing::mls::read_member_group_state_material(state, request)
            .await
            .map_err(|error| error.to_string())?;
        let bytes = outcome
            .validate_for_request(&request.as_peer_request())
            .map_err(|error| error.to_string())?;
        Ok((bytes.group_info_bytes, bytes.ratchet_tree_bytes))
    }
}

async fn cache_public_genesis_material(
    state: &AppState,
    realm: &RealmId,
    commit: &arkret_wire::RealmCommit,
    genesis: &arkret_wire::Event,
    material: [(&arkret_wire::BlobRef, Vec<u8>); 2],
) -> Result<(), String> {
    // Only RFC-validated public Genesis bytes reach this create-only cache.
    // Existing redaction, retention and ownership metadata always win.
    for (reference, bytes) in material {
        if state
            .deliveries()
            .blob(reference.as_str())
            .await
            .map_err(|error| error.to_string())?
            .is_none()
        {
            let sha256 = arkret_canonical::sha256_digest(&bytes)
                .trim_start_matches("sha256:")
                .to_owned();
            let key = state.deliveries().object_key_for_sha256(&sha256);
            let size_bytes = bytes.len() as i64;
            state.deliveries().put_object(&key, bytes).await?;
            state
                .deliveries()
                .store_blob_if_absent(
                    reference.as_str(),
                    coland_storage::BlobRecord {
                        sha256,
                        size_bytes,
                        storage_backend: state.deliveries().object_storage_backend_name(),
                        storage_key: key,
                        media_type: "application/octet-stream".into(),
                        filename: None,
                        realm_id: Some(realm.to_string()),
                        encryption: None,
                        legal_hold: false,
                        redacted: false,
                        visibility:
                            arkret_models_collaboration::objects::blob::BlobVisibility::RealmBound,
                        uploaded_by: genesis.actor_id.signing_principal_id().to_string(),
                        created_at: commit.committed_at,
                    },
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        if state
            .deliveries()
            .blob(reference.as_str())
            .await
            .map_err(|error| error.to_string())?
            .is_none_or(|row| row.redacted)
        {
            return Err("cached Genesis material disappeared or was redacted".into());
        }
    }
    Ok(())
}

fn replay(
    input: &ForeignDirectMlsInput,
    group_info: &[u8],
    tree: &[u8],
) -> Result<(coland_storage::ForeignDirectMlsBase, bool), String> {
    let fail = |error: &dyn std::fmt::Display| error.to_string();
    let scope = ScopeRef::Realm {
        realm_id: input.realm_id.clone(),
    };
    let TypedCurrentRow::Value {
        selector,
        source_stream_ref,
        revision,
        value,
    } = &input.current;
    if selector
        != &(arkret_wire::CurrentSelector::MlsGroup {
            scope_ref: scope.clone(),
        })
        || source_stream_ref != &input.head.stream_ref
        || revision.stream_position > input.head.stream_position
        || (revision.stream_position == input.head.stream_position
            && revision.commit_id != input.head.commit_id)
    {
        return Err("MLS current source differs from verified cut".into());
    }
    let current: MlsGroupCurrent =
        serde_json::from_value(value.clone()).map_err(|error| fail(&error))?;
    if current.effective_scope != scope
        || input.participants.len() != 2
        || !input.participants.contains(&input.caller)
    {
        return Err("Direct current scope or participant identity differs".into());
    }
    for (commit, event) in &input.history {
        if commit.realm_id != input.realm_id
            || commit.stream_ref != input.head.stream_ref
            || event.realm_id != input.realm_id
            || event.event_id != commit.event_ref
            || commit.governance_generation > input.generation
            || event.scope_ref != scope
        {
            return Err("MLS accepted source binding differs".into());
        }
    }
    let group_id = scope
        .canonical_mls_group_id()
        .map_err(|error| fail(&error))?;
    let (mut tracker, mut reference, mut covered, mut initial, start) = if let Some(base) =
        &input.base
    {
        (
            arkret_mls::MlsPublicGroupTracker::restore(
                &base.public_state,
                group_id.as_str(),
                base.epoch,
            )
            .map_err(|error| fail(&error))?,
            base.current_event_ref.clone(),
            base.covered_revision,
            base.initial_pair_ref.clone(),
            0,
        )
    } else {
        let Some((_, genesis)) = input.history.first() else {
            return Err("MLS Genesis lineage unavailable".into());
        };
        if genesis.kind != EventKind::MlsGenesis
            || genesis.event_id != current.genesis_event_ref
            || genesis.scope_ref != scope
        {
            return Err("MLS lineage does not start at accepted Genesis".into());
        }
        let payload: MlsGenesisPayload = serde_json::from_value(
            serde_json::to_value(&genesis.payload).map_err(|error| fail(&error))?,
        )
        .map_err(|error| fail(&error))?;
        payload.validate().map_err(|error| fail(&error))?;
        for (reference, bytes) in [
            (&payload.group_info_ref, group_info),
            (&payload.ratchet_tree_ref, tree),
        ] {
            let digest = reference
                .as_str()
                .strip_prefix("ak:blob:")
                .ok_or("Genesis material ref is invalid")?;
            arkret_canonical::verify_digest(bytes, digest).map_err(|error| fail(&error))?;
        }
        let tracker = arkret_mls::MlsPublicGroupTracker::from_external(
            group_info,
            tree,
            group_id.as_str(),
            0,
        )
        .map_err(|error| fail(&error))?;
        if tracker.governance_binding().map_err(|error| fail(&error))? != payload.governance_binding
            || tracker
                .ciphersuite_canonical_id()
                .map_err(|error| fail(&error))?
                != payload.cipher_suite.as_str()
        {
            return Err("Genesis public context differs from accepted payload".into());
        }
        let leaves = tracker.leaves().map_err(|error| fail(&error))?;
        if leaves.len() != 1
            || leaves[0].actor_id != genesis.actor_id
            || leaves[0].signature_key != payload.creator_leaf_authority.leaf_signature_key_b64u
        {
            return Err("Genesis creator public leaf differs".into());
        }
        (
            tracker,
            genesis.event_id.clone(),
            payload.governance_binding.key_access_revision(),
            None,
            1,
        )
    };
    for (_, event) in input.history.iter().skip(start) {
        if event.kind == EventKind::MlsGenesis && event.scope_ref == scope {
            return Err("MLS lineage contains another Genesis".into());
        }
        if event.kind != EventKind::MlsCommit || event.scope_ref != scope {
            continue;
        }
        let payload: MlsCommitPayload = serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(|error| fail(&error))?,
        )
        .map_err(|error| fail(&error))?;
        payload.validate().map_err(|error| fail(&error))?;
        if payload.base_group_state_ref() != &reference
            || payload.base_epoch() != tracker.epoch()
            || payload.governance_binding().effective_scope() != &scope
        {
            return Err("MLS accepted epoch lineage is discontinuous".into());
        }
        let wire = arkret_canonical::base64url_decode(payload.commit_bytes_b64())
            .map_err(|error| fail(&error))?;
        let transition = tracker
            .process_public_handshake(&wire)
            .map_err(|error| fail(&error))?;
        let arkret_mls::MlsPublicHandshakeTransition::Commit {
            sender_class,
            sender_leaf,
            previous_epoch,
            epoch,
            ..
        } = transition
        else {
            return Err("MLS Event contains a proposal".into());
        };
        if sender_class!=arkret_models_collaboration::events_payloads::mls_proposal_admission::MlsProposalSenderClass::Member || sender_leaf.is_none_or(|leaf|leaf.actor_id!=event.actor_id) || previous_epoch!=payload.base_epoch() || epoch!=payload.next_epoch() || tracker.governance_binding().map_err(|error|fail(&error))? != *payload.governance_binding() { return Err("MLS public transition differs from accepted Event".into()) }
        reference = event.event_id.clone();
        covered = payload.covers_key_access_revision();
        if initial.is_none()
            && exact_pair(
                &tracker.leaves().map_err(|error| fail(&error))?,
                &input.participants,
            )
        {
            initial = Some(reference.clone())
        }
    }
    if input.complete {
        if reference != current.current_mls_commit_event_ref
            || tracker.epoch() != current.epoch
            || covered != current.covered_key_access_revision
            || covered > current.current_key_access_revision
            || tracker
                .ciphersuite_canonical_id()
                .map_err(|error| fail(&error))?
                != current.cipher_suite.as_str()
            || initial.as_ref() != Some(&input.expected_initial_pair_ref)
        {
            return Err(
                "MLS replay does not reach signed winning current and initial exact-pair binding"
                    .into(),
            );
        }
        let tree = tracker.ratchet_tree_bytes().map_err(|error| fail(&error))?;
        let digest = current
            .public_tree_ref
            .as_str()
            .strip_prefix("ak:blob:")
            .ok_or("MLS current tree ref is invalid")?;
        arkret_canonical::verify_digest(&tree, digest).map_err(|error| fail(&error))?;
    }
    let exact = exact_pair(
        &tracker.leaves().map_err(|error| fail(&error))?,
        &input.participants,
    );
    Ok((
        coland_storage::ForeignDirectMlsBase {
            head: input.replay_head.clone(),
            current_event_ref: reference,
            epoch: tracker.epoch(),
            covered_revision: covered,
            initial_pair_ref: initial,
            public_state: tracker.export_state().map_err(|error| fail(&error))?,
        },
        exact,
    ))
}

fn exact_pair(
    leaves: &[arkret_mls::MlsPublicEndpointLeaf],
    pair: &std::collections::BTreeSet<ActorId>,
) -> bool {
    leaves
        .iter()
        .map(|leaf| leaf.actor_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
        == *pair
}

#[cfg(test)]
mod tests {
    use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity, MlsPublicGroupTracker};
    use arkret_models_crypto::{MlsGovernanceBindingPayload, MlsKeyPackageState};
    use arkret_wire::{
        AccountId, CommitStreamHead, CommitStreamRef, CurrentRevision, DeviceId, DidCoreId, Event,
        EventId, RealmCommit, RealmCommitId,
    };

    use super::*;
    fn actor(name: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
            DidCoreId::new("ak:did_core:web:member-station.example").unwrap(),
        ))
    }
    fn identity(name: &str, index: u8) -> ArkretMlsIdentity {
        ArkretMlsIdentity::new_test_human_device(
            actor(name),
            DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{:012}", index)).unwrap(),
        )
        .unwrap()
    }
    fn id(seed: u8) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
    }
    fn commit(event: &Event, position: u64) -> RealmCommit {
        let at = event.created_at;
        RealmCommit {
            producer_signer_fact_digest: None,
            commit_id: RealmCommitId::from_digest([position as u8 + 1; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            stream_position: position,
            previous_commit_ref: (position > 0)
                .then(|| RealmCommitId::from_digest([position as u8; 32])),
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(id(99)),
            committed_at: at,
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new("did:web:governor.example#authority")
                    .unwrap(),
                signed_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                    b"accepted fixture",
                ))
                .unwrap(),
                created_at: at,
                sig: arkret_wire::Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            },
        }
    }
    // Commits model the already-verified storage boundary. MLS bytes below
    // are real RFC 9420 Genesis/Add transitions, never hand-made roster facts.
    fn fixture(additions: &[(&str, u8)]) -> (ForeignDirectMlsInput, Vec<u8>, Vec<u8>) {
        let realm = RealmId::from_event_id(&id(98));
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let genesis_binding =
            MlsGovernanceBindingPayload::realm(realm.clone(), None, 0, 0, 0).unwrap();
        let mut group: ArkretMlsGroup = identity("alice", 1)
            .create_group_with_governance_binding(&scope, &genesis_binding)
            .unwrap();
        let (group_info, tree) = group.public_group_state_bytes().unwrap();
        let mut tracker =
            MlsPublicGroupTracker::from_external(&group_info, &tree, group.group_id().as_str(), 0)
                .unwrap();
        let payload = MlsGenesisPayload {
            cipher_suite: arkret_wire::NonEmptyString::new(
                tracker.ciphersuite_canonical_id().unwrap(),
            )
            .unwrap(),
            group_info_ref: arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(&group_info)
            ))
            .unwrap(),
            ratchet_tree_ref: arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(&tree)
            ))
            .unwrap(),
            creator_leaf_authority:
                arkret_models_collaboration::events_payloads::mls::MlsGenesisCreatorLeafAuthority {
                    leaf_signature_key_b64u: tracker.leaves().unwrap()[0].signature_key.clone(),
                    endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                            .unwrap(),
                    },
                    authorization_event_ref: id(97),
                },
            governance_binding: genesis_binding,
            created_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        };
        let genesis = arkret_wire::test_support::raw_event_for_actor_at(
            "ak.mls.genesis",
            scope.clone(),
            actor("alice"),
            serde_json::to_value(payload).unwrap(),
            chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        let mut history = vec![(commit(&genesis, 0), genesis.clone())];
        let mut value = MlsGroupCurrent {
            effective_scope: scope.clone(),
            genesis_event_ref: genesis.event_id.clone(),
            cipher_suite: arkret_wire::NonEmptyString::new(
                tracker.ciphersuite_canonical_id().unwrap(),
            )
            .unwrap(),
            current_mls_commit_event_ref: genesis.event_id.clone(),
            epoch: 0,
            current_key_access_revision: 0,
            covered_key_access_revision: 0,
            public_tree_ref: arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(&tree)
            ))
            .unwrap(),
        };
        let mut initial = None;
        for (name, device) in additions {
            let base = value.current_mls_commit_event_ref.clone();
            let binding = MlsGovernanceBindingPayload::realm(
                realm.clone(),
                Some(base.clone()),
                value.epoch,
                value.epoch + 1,
                0,
            )
            .unwrap();
            let mut package = identity(name, *device).key_package_record().unwrap();
            package.state = MlsKeyPackageState::Claimed;
            package.claim_id = Some(format!(
                "ak:keypackage_claim:01904100-0000-7000-8000-{:012}",
                device
            ));
            let add = group
                .add_member_with_governance_binding(&package, &binding)
                .unwrap();
            let payload = MlsCommitPayload::new(base, 0, &add.commit, binding).unwrap();
            let event = arkret_wire::test_support::raw_event_for_actor_at(
                "ak.mls.commit",
                scope.clone(),
                actor("alice"),
                serde_json::to_value(&payload).unwrap(),
                chrono::DateTime::from_timestamp(1_800_000_000 + value.epoch as i64 + 1, 0)
                    .unwrap(),
            )
            .unwrap();
            let committed = commit(&event, history.len() as u64);
            group
                .install_accepted_commit(
                    &arkret_wire::CommittedEventFullView {
                        commit: committed.clone(),
                        event: event.clone(),
                    },
                    &value,
                )
                .unwrap();
            tracker
                .process_public_handshake(
                    &arkret_canonical::base64url_decode(payload.commit_bytes_b64()).unwrap(),
                )
                .unwrap();
            if initial.is_none()
                && exact_pair(
                    &tracker.leaves().unwrap(),
                    &[actor("alice"), actor("bob")].into_iter().collect(),
                )
            {
                initial = Some(event.event_id.clone())
            }
            value.current_mls_commit_event_ref = event.event_id.clone();
            value.epoch += 1;
            value.public_tree_ref = arkret_wire::BlobRef::new(format!(
                "ak:blob:{}",
                arkret_canonical::sha256_digest(tracker.ratchet_tree_bytes().unwrap())
            ))
            .unwrap();
            history.push((committed, event));
        }
        let final_commit = &history.last().unwrap().0;
        let head = CommitStreamHead {
            stream_ref: final_commit.stream_ref.clone(),
            commit_id: final_commit.commit_id.clone(),
            stream_position: final_commit.stream_position,
        };
        (
            ForeignDirectMlsInput {
                realm_id: realm,
                caller: actor("alice"),
                service_id: DidCoreId::new("ak:did_core:web:governor.example").unwrap(),
                generation: 0,
                head: head.clone(),
                current: TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref: scope },
                    source_stream_ref: head.stream_ref.clone(),
                    revision: CurrentRevision {
                        commit_id: head.commit_id.clone(),
                        stream_position: head.stream_position,
                    },
                    value: serde_json::to_value(value).unwrap(),
                },
                current_state_entries: vec![],
                participants: [actor("alice"), actor("bob")].into_iter().collect(),
                history,
                base: None,
                replay_head: head,
                complete: true,
                expected_initial_pair_ref: initial.unwrap(),
            },
            group_info,
            tree,
        )
    }
    #[test]
    fn foreign_direct_public_replay_accepts_pair_and_multiple_devices_but_rejects_third_actor() {
        for additions in [
            vec![("bob", 2)],
            vec![("bob", 2), ("bob", 3)],
            vec![("bob", 2), ("charlie", 3)],
        ] {
            let (input, info, tree) = fixture(&additions);
            let (base, exact) = replay(&input, &info, &tree).unwrap();
            assert_eq!(exact, additions.last().unwrap().0 != "charlie");
            let restored = MlsPublicGroupTracker::restore(
                &base.public_state,
                (ScopeRef::Realm {
                    realm_id: input.realm_id.clone(),
                })
                .canonical_mls_group_id()
                .unwrap()
                .as_str(),
                base.epoch,
            );
            assert!(restored.is_ok());
        }
    }
    #[test]
    fn foreign_direct_public_replay_rejects_wrong_current_material_source_sender_and_identity() {
        let (input, info, tree) = fixture(&[("bob", 2)]);
        for mutation in 0..8 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.history.remove(0),
                1 => {
                    bad.history[1].1.actor_id = actor("bob");
                    bad.history[1].0.event_ref = bad.history[1].1.event_id.clone();
                    (bad.history[0].0.clone(), bad.history[0].1.clone())
                }
                2 => {
                    bad.generation = 0;
                    bad.history[1].0.governance_generation = 1;
                    (bad.history[0].0.clone(), bad.history[0].1.clone())
                }
                3 => {
                    bad.caller = ActorId::account(AccountId::new(
                        actor("alice").signing_principal_id().clone(),
                        DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
                    ));
                    (bad.history[0].0.clone(), bad.history[0].1.clone())
                }
                _ => {
                    let TypedCurrentRow::Value {
                        value,
                        source_stream_ref,
                        revision,
                        ..
                    } = &mut bad.current;
                    match mutation {
                        4 => {
                            value["public_tree_ref"] = serde_json::json!(format!(
                                "ak:blob:{}",
                                arkret_canonical::sha256_digest(b"wrong")
                            ))
                        }
                        5 => value["epoch"] = serde_json::json!(2),
                        6 => {
                            *source_stream_ref = CommitStreamRef::Realm {
                                realm_id: RealmId::from_event_id(&id(96)),
                            }
                        }
                        _ => revision.stream_position += 1,
                    };
                    (bad.history[0].0.clone(), bad.history[0].1.clone())
                }
            };
            assert!(replay(&bad, &info, &tree).is_err(), "mutation {mutation}");
        }
        let mut changed = tree.clone();
        changed[0] ^= 1;
        assert!(replay(&input, &info, &changed).is_err());
    }
    #[test]
    fn foreign_direct_public_replay_resumes_verified_prefix_and_rebinds_long_ordinary_tail() {
        let (input, info, tree) = fixture(&[("bob", 2), ("bob", 3)]);
        let mut prefix = input.clone();
        prefix.history.truncate(2);
        prefix.complete = false;
        let commit = &prefix.history.last().unwrap().0;
        prefix.replay_head = CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_position: commit.stream_position,
        };
        let (base, _) = replay(&prefix, &info, &tree).unwrap();
        let mut resumed = input.clone();
        resumed.history.remove(0);
        resumed.history.remove(0);
        resumed.base = Some(base);
        let (base, exact) = replay(&resumed, &[], &[]).unwrap();
        assert!(exact);
        let mut tail = input.clone();
        tail.history.clear();
        tail.base = Some(base);
        tail.head.stream_position = 1_000_000;
        tail.head.commit_id = RealmCommitId::from_digest([55; 32]);
        tail.replay_head = tail.head.clone();
        assert!(replay(&tail, &[], &[]).unwrap().1);
    }
    async fn seed_pg(
        input: &mut ForeignDirectMlsInput,
    ) -> (
        coland_storage_postgres::TestDatabase,
        coland_storage_postgres::PgEventStore,
    ) {
        use diesel::sql_types::{BigInt, Binary, Jsonb, SmallInt, Text};
        use diesel_async::RunQueryDsl;
        let database = coland_storage_postgres::TestDatabase::lease().await;
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        // Post-verification storage fixture: the opening join precedes every
        // actual RFC MLS transition. Producer admission is tested elsewhere.
        for (commit, _) in &mut input.history {
            commit.stream_position += 1;
            commit.commit_id = RealmCommitId::from_digest([commit.stream_position as u8 + 1; 32]);
            commit.previous_commit_ref = Some(RealmCommitId::from_digest(
                [commit.stream_position as u8; 32],
            ));
        }
        let mut join = input.history[0].1.clone();
        join.kind = EventKind::MemberState;
        join.event_id = id(90);
        join.payload = serde_json::json!({"membership":"join","joined_at":arkret_canonical::format_timestamp_canonical(join.created_at)})
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let opening = commit(&join, 0);
        let last = &input.history.last().unwrap().0;
        input.head = CommitStreamHead {
            stream_ref: last.stream_ref.clone(),
            commit_id: last.commit_id.clone(),
            stream_position: last.stream_position,
        };
        input.replay_head = input.head.clone();
        let TypedCurrentRow::Value { revision, .. } = &mut input.current;
        *revision = CurrentRevision {
            commit_id: last.commit_id.clone(),
            stream_position: last.stream_position,
        };
        let stream_key = String::from_utf8(
            arkret_canonical::canonical_json_bytes(&input.head.stream_ref).unwrap(),
        )
        .unwrap();
        for (commit, event) in
            std::iter::once((&opening, &join)).chain(input.history.iter().map(|(c, e)| (c, e)))
        {
            let bytes = arkret_canonical::base64url_decode(
                event.event_id.as_str().strip_prefix("ak:event:").unwrap(),
            )
            .unwrap();
            #[derive(diesel::QueryableByName)]
            struct Pk {
                #[diesel(sql_type=BigInt)]
                pk: i64,
            }
            let row=diesel::sql_query("INSERT INTO canonical_events(id,digest_suite,digest,actor_id,realm_id,scope_ref,kind,canonical_bytes,envelope,state,committed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'committed',now()) RETURNING pk")
                .bind::<Binary,_>(&bytes).bind::<SmallInt,_>(bytes[0] as i16).bind::<Binary,_>(&bytes[1..]).bind::<Text,_>(event.actor_id.to_string()).bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&event.scope_ref).unwrap()).bind::<Text,_>(event.kind.as_str()).bind::<Binary,_>(arkret_canonical::canonical_json_bytes(event).unwrap()).bind::<Jsonb,_>(serde_json::to_value(event).unwrap()).get_result::<Pk>(&mut conn).await.unwrap();
            diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,now())")
                .bind::<Text,_>(commit.commit_id.as_str()).bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(&stream_key).bind::<Jsonb,_>(serde_json::to_value(&commit.stream_ref).unwrap()).bind::<BigInt,_>(commit.stream_position as i64).bind::<diesel::sql_types::Nullable<Text>,_>(commit.previous_commit_ref.as_ref().map(|id|id.as_str())).bind::<BigInt,_>(row.pk).bind::<Jsonb,_>(serde_json::to_value(commit).unwrap()).execute(&mut conn).await.unwrap();
        }
        diesel::sql_query("INSERT INTO realm_authorities(realm_id,generation,service_id,authority_ref) VALUES($1,0,$2,'{}')").bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(input.service_id.as_str()).execute(&mut conn).await.unwrap();
        diesel::sql_query("INSERT INTO replica_stream_anchors(stream_key,realm_id,join_commit_id,member_account_id,anchor_commit_id,anchor_stream_position,anchored_at) VALUES($1,$2,$3,$4,$5,$6,now())")
            .bind::<Text,_>(&stream_key).bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(opening.commit_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(input.caller.as_account_id().unwrap()).unwrap()).bind::<Text,_>(input.head.commit_id.as_str()).bind::<BigInt,_>(input.head.stream_position as i64).execute(&mut conn).await.unwrap();
        diesel::sql_query("INSERT INTO replica_authorization_cuts(realm_id,source_stream_ref,head_commit_id,head_stream_position,verified_at) VALUES($1,$2,$3,$4,now())")
            .bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&input.head.stream_ref).unwrap()).bind::<Text,_>(input.head.commit_id.as_str()).bind::<BigInt,_>(input.head.stream_position as i64).execute(&mut conn).await.unwrap();
        let TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = &input.current;
        diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,now())")
            .bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(selector).unwrap()).bind::<Jsonb,_>(serde_json::to_value(source_stream_ref).unwrap()).bind::<Text,_>(revision.commit_id.as_str()).bind::<BigInt,_>(revision.stream_position as i64).bind::<Jsonb,_>(value).execute(&mut conn).await.unwrap();
        for actor in &input.participants {
            let member_value = serde_json::json!({"membership":"join","joined_at":arkret_canonical::format_timestamp_canonical(join.created_at)});
            diesel::sql_query("INSERT INTO member_state_current_results(realm_id,member_id,membership,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,'join',$3,0,$4,now())")
                .bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(actor.to_string()).bind::<Text,_>(opening.commit_id.as_str()).bind::<Jsonb,_>(&member_value).execute(&mut conn).await.unwrap();
            diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,0,$5,now())")
                .bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::MemberState{actor_id:actor.clone()}).unwrap()).bind::<Jsonb,_>(serde_json::to_value(source_stream_ref).unwrap()).bind::<Text,_>(opening.commit_id.as_str()).bind::<Jsonb,_>(&member_value).execute(&mut conn).await.unwrap();
        }
        diesel::sql_query("INSERT INTO realm_bootstrap_current_results(realm_id,result_family,current_commit_id,current_stream_position,value,updated_at) VALUES($1,'realm_history_access',$2,0,'\"since_join\"',now())")
            .bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(opening.commit_id.as_str()).execute(&mut conn).await.unwrap();
        let payload:arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBoundPayload=serde_json::from_value(serde_json::json!({"pair_key":arkret_canonical::sha256_digest(b"pair"),"unordered_participant_ids":input.participants,"realm_id":input.realm_id,"main_strand_id":arkret_wire::StrandId::from_event_id(&id(89)),"founding_unit_digest":arkret_canonical::sha256_digest(b"founding"),"authorization_basis":{"kind":"accepted_contact","event_refs":[id(88),id(87)]},"initial_exact_pair_group_state_ref":input.expected_initial_pair_ref,"created_at":arkret_canonical::format_timestamp_canonical(join.created_at)})).unwrap();
        diesel::sql_query("INSERT INTO direct_conversation_founding_slots(founder_id,trust_domain_id,pair_key,peer_id,founding_unit_digest,realm_id,main_strand_id,authorization_basis,event_ids,commits_json,idempotency_key,accepted_at) VALUES($1,'ak:trust_domain:foreign-direct-fixture',$2,$3,$4,$5,$6,$7,$8,$9,'verified-read-fixture',now())")
            .bind::<Text,_>(input.caller.to_string()).bind::<Text,_>(payload.pair_key.as_str()).bind::<Text,_>(actor("bob").to_string()).bind::<Text,_>(payload.founding_unit_digest.as_str()).bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(payload.main_strand_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&payload.authorization_basis).unwrap()).bind::<Jsonb,_>(serde_json::json!([id(83),id(84),id(85),id(86)])).bind::<Jsonb,_>(serde_json::json!([opening,opening,opening,opening])).execute(&mut conn).await.unwrap();
        let binding=arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue{endorsements:vec![arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingEndorsementEntry{tag_id:arkret_models_collaboration::exact_current_results::CanonicalEventDot::new(id(86),0).unwrap(),value:payload}]};
        diesel::sql_query("INSERT INTO direct_conversation_binding_current_results(realm_id,pair_key,binding_digest,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,now())")
            .bind::<Text,_>(input.realm_id.as_str()).bind::<Text,_>(arkret_canonical::sha256_digest(b"pair")).bind::<Text,_>(binding.binding_digest().unwrap().as_str()).bind::<Text,_>(input.head.commit_id.as_str()).bind::<BigInt,_>(input.head.stream_position as i64).bind::<Jsonb,_>(serde_json::to_value(&binding).unwrap()).execute(&mut conn).await.unwrap();
        diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) VALUES($1,$2,$3,$4,$5,$6,now())")
            .bind::<Text,_>(input.realm_id.as_str())
            .bind::<Jsonb,_>(serde_json::to_value(arkret_wire::CurrentSelector::DirectConversationBinding { pair_key: binding.endorsements[0].value.pair_key.clone() }).unwrap())
            .bind::<Jsonb,_>(serde_json::to_value(&input.head.stream_ref).unwrap())
            .bind::<Text,_>(input.head.commit_id.as_str()).bind::<BigInt,_>(input.head.stream_position as i64)
            .bind::<Jsonb,_>(serde_json::to_value(&binding).unwrap()).execute(&mut conn).await.unwrap();
        // Unrelated selectors are deliberately malformed; production must use
        // bounded Direct point reads rather than deserialize the whole Realm.
        diesel::sql_query("INSERT INTO replica_authorization_rows(realm_id,selector,source_stream_ref,current_commit_id,current_stream_position,value,updated_at) SELECT $1,jsonb_build_object('unrelated',n),$2,$3,0,'null'::jsonb,now() FROM generate_series(1,1000) n")
            .bind::<Text,_>(input.realm_id.as_str()).bind::<Jsonb,_>(serde_json::to_value(&input.head.stream_ref).unwrap())
            .bind::<Text,_>(opening.commit_id.as_str()).execute(&mut conn).await.unwrap();
        drop(conn);
        (database, coland_storage_postgres::PgEventStore { pool })
    }
    #[tokio::test]
    async fn foreign_direct_pg_public_cache_rejects_missing_stale_forked_cut_and_caller_floor() {
        use coland_storage::EventStore;
        use diesel::sql_types::{BigInt, Text};
        use diesel_async::RunQueryDsl;
        let (mut fixture, info, tree) = fixture(&[("bob", 2)]);
        let (database, store) = seed_pg(&mut fixture).await;
        let input = store
            .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
            .await
            .unwrap()
            .unwrap();
        let (base, exact) = replay(&input, &info, &tree).unwrap();
        assert!(exact);
        assert!(
            store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        // Both durable read entry points run RR READ ONLY, including the
        // public-cache cut lookup. They must not call admission lock readers.
        let durable = store
            .direct_conversation_durable_state(
                "ak:trust_domain:foreign-direct-fixture",
                &arkret_canonical::sha256_digest(b"pair"),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(durable.group_current_exact_pair, Some(true));
        assert_eq!(
            durable.group_state_ref.as_ref(),
            Some(&base.current_event_ref)
        );
        let by_realm = store
            .direct_conversation_durable_state_for_realm(fixture.realm_id.as_str())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_realm.group_current_exact_pair, Some(true));
        assert_eq!(by_realm.group_state_ref, durable.group_state_ref);
        let cached = store
            .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
            .await
            .unwrap()
            .unwrap();
        assert!(cached.history.is_empty());
        assert!(cached.base.is_some());
        let pool = database.pool();
        let mut conn = pool.get().await.unwrap();
        // A held binding table cannot replace the governing signed typed row.
        diesel::sql_query("UPDATE replica_authorization_rows SET value='null'::jsonb WHERE selector->>'kind'='direct_conversation_binding'")
            .execute(&mut conn).await.unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        diesel::sql_query("UPDATE replica_authorization_rows r SET value=b.value FROM direct_conversation_binding_current_results b WHERE r.realm_id=b.realm_id AND r.selector->>'kind'='direct_conversation_binding'")
            .execute(&mut conn).await.unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_some()
        );
        // More than one replay page of ordinary accepted continuity nodes
        // does not invalidate a cache whose signed winning MLS row is unchanged.
        let mut last = input.head.clone();
        let stream_key =
            String::from_utf8(arkret_canonical::canonical_json_bytes(&last.stream_ref).unwrap())
                .unwrap();
        for offset in 1..=300u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(offset + 1000).to_le_bytes());
            let mut node = fixture.history.last().unwrap().0.clone();
            node.commit_id = RealmCommitId::from_digest(bytes);
            node.previous_commit_ref = Some(last.commit_id.clone());
            node.stream_position = input.head.stream_position + offset;
            node.event_ref = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, bytes);
            diesel::sql_query("INSERT INTO realm_commits(commit_id,realm_id,stream_key,stream_ref,stream_position,previous_commit_ref,event_pk,governance_generation,commit_json,committed_at) VALUES($1,$2,$3,$4,$5,$6,NULL,0,$7,now())")
                .bind::<Text,_>(node.commit_id.as_str()).bind::<Text,_>(fixture.realm_id.as_str()).bind::<Text,_>(&stream_key).bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&node.stream_ref).unwrap()).bind::<BigInt,_>(node.stream_position as i64).bind::<Text,_>(last.commit_id.as_str()).bind::<diesel::sql_types::Jsonb,_>(serde_json::to_value(&node).unwrap()).execute(&mut conn).await.unwrap();
            last = CommitStreamHead {
                stream_ref: node.stream_ref,
                commit_id: node.commit_id,
                stream_position: node.stream_position,
            };
        }
        diesel::sql_query(
            "UPDATE replica_stream_anchors SET anchor_commit_id=$1,anchor_stream_position=$2",
        )
        .bind::<Text, _>(last.commit_id.as_str())
        .bind::<BigInt, _>(last.stream_position as i64)
        .execute(&mut conn)
        .await
        .unwrap();
        diesel::sql_query(
            "UPDATE replica_authorization_cuts SET head_commit_id=$1,head_stream_position=$2",
        )
        .bind::<Text, _>(last.commit_id.as_str())
        .bind::<BigInt, _>(last.stream_position as i64)
        .execute(&mut conn)
        .await
        .unwrap();
        let rebound = store
            .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
            .await
            .unwrap()
            .unwrap();
        assert!(rebound.history.is_empty());
        assert_eq!(rebound.head, last);
        let (rebound_base, rebound_exact) = replay(&rebound, &[], &[]).unwrap();
        assert!(
            store
                .install_foreign_direct_mls_public_state(&rebound, &rebound_base, rebound_exact)
                .await
                .unwrap()
        );
        diesel::sql_query("DELETE FROM realm_commits WHERE stream_position>$1")
            .bind::<BigInt, _>(input.head.stream_position as i64)
            .execute(&mut conn)
            .await
            .unwrap();
        diesel::sql_query(
            "UPDATE replica_stream_anchors SET anchor_commit_id=$1,anchor_stream_position=$2",
        )
        .bind::<Text, _>(input.head.commit_id.as_str())
        .bind::<BigInt, _>(input.head.stream_position as i64)
        .execute(&mut conn)
        .await
        .unwrap();
        diesel::sql_query(
            "UPDATE replica_authorization_cuts SET head_commit_id=$1,head_stream_position=$2",
        )
        .bind::<Text, _>(input.head.commit_id.as_str())
        .bind::<BigInt, _>(input.head.stream_position as i64)
        .execute(&mut conn)
        .await
        .unwrap();
        diesel::sql_query("DELETE FROM replica_direct_mls_public_states")
            .execute(&mut conn)
            .await
            .unwrap();
        diesel::sql_query("UPDATE replica_authorization_cuts SET head_commit_id=$1")
            .bind::<Text, _>(RealmCommitId::from_digest([99; 32]).as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            !store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        diesel::sql_query(
            "UPDATE replica_authorization_cuts SET head_commit_id=$1,head_stream_position=$2",
        )
        .bind::<Text, _>(input.head.commit_id.as_str())
        .bind::<BigInt, _>(input.head.stream_position as i64 - 1)
        .execute(&mut conn)
        .await
        .unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_none()
        );
        diesel::sql_query("UPDATE replica_authorization_cuts SET head_stream_position=$1")
            .bind::<BigInt, _>(input.head.stream_position as i64)
            .execute(&mut conn)
            .await
            .unwrap();
        diesel::sql_query("UPDATE member_state_current_results SET current_commit_id=$1,current_stream_position=$2 WHERE member_id=$3").bind::<Text,_>(input.head.commit_id.as_str()).bind::<BigInt,_>(input.head.stream_position as i64).bind::<Text,_>(fixture.caller.to_string()).execute(&mut conn).await.unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_none()
        );
        diesel::sql_query("UPDATE member_state_current_results SET current_commit_id=$1,current_stream_position=0 WHERE member_id=$2").bind::<Text,_>(RealmCommitId::from_digest([1;32]).as_str()).bind::<Text,_>(fixture.caller.to_string()).execute(&mut conn).await.unwrap();
        diesel::sql_query("UPDATE realm_authorities SET service_id=$1")
            .bind::<Text, _>(fixture.caller.as_account_id().unwrap().station_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            !store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        diesel::sql_query("UPDATE realm_authorities SET service_id=$1")
            .bind::<Text, _>(input.service_id.as_str())
            .execute(&mut conn)
            .await
            .unwrap();
        diesel::sql_query("UPDATE member_state_current_results SET membership='leave',value=jsonb_set(value,'{membership}','\"leave\"') WHERE member_id=$1").bind::<Text,_>(fixture.caller.to_string()).execute(&mut conn).await.unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_none()
        );
        diesel::sql_query("UPDATE member_state_current_results SET membership='join',value=jsonb_set(value,'{membership}','\"join\"') WHERE member_id=$1").bind::<Text,_>(fixture.caller.to_string()).execute(&mut conn).await.unwrap();
        diesel::sql_query(
            "UPDATE realm_authorities SET generation=1,last_handoff_ref='accepted-fixture-handoff'",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        assert!(
            !store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        diesel::sql_query("UPDATE realm_authorities SET generation=0,last_handoff_ref=NULL")
            .execute(&mut conn)
            .await
            .unwrap();
        diesel::sql_query("UPDATE realm_commits SET event_pk=NULL WHERE stream_position=1")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            store
                .foreign_direct_mls_input(&fixture.realm_id, &fixture.caller)
                .await
                .unwrap()
                .is_none()
        );
        diesel::sql_query("UPDATE realm_commits c SET event_pk=e.pk FROM canonical_events e WHERE e.envelope->>'event_id'=c.commit_json->>'event_ref' AND c.event_pk IS NULL").execute(&mut conn).await.unwrap();
        diesel::sql_query("DELETE FROM replica_authorization_cuts")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            !store
                .install_foreign_direct_mls_public_state(&input, &base, exact)
                .await
                .unwrap()
        );
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=BigInt)]
            count: i64,
        }
        assert_eq!(
            diesel::sql_query(
                "SELECT COUNT(*)::bigint AS count FROM replica_direct_mls_public_states"
            )
            .get_result::<Count>(&mut conn)
            .await
            .unwrap()
            .count,
            0
        );
    }
}
