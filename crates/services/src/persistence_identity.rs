use std::sync::Arc;

use chrono::Utc;
use coland_storage::*;
use serde_json::Value;

use crate::identity::*;

struct PersistenceAccountLookup(Arc<dyn PersistenceStore>);
struct PersistenceAccountData(Arc<dyn PersistenceStore>);
struct PersistenceDeviceKeys(Arc<dyn PersistenceStore>);
struct PersistenceOneTimeKeys(Arc<dyn PersistenceStore>);
struct PersistenceMimiConsentCorrelations(Arc<dyn PersistenceStore>);
struct PersistenceContacts(Arc<dyn PersistenceStore>);
struct PersistenceInviteReceivePolicies(Arc<dyn PersistenceStore>);
struct PersistenceDeviceDirectory(Arc<dyn PersistenceStore>);
struct PersistenceAgentDirectory(Arc<dyn PersistenceStore>);
struct PersistenceAgentPairing(Arc<dyn PersistenceStore>);
struct PersistenceSidecars(Arc<dyn PersistenceStore>);
struct PersistenceAgentParticipation(Arc<dyn PersistenceStore>);
struct PersistenceKeyBackups(Arc<dyn PersistenceStore>);
struct PersistenceSessions(Arc<dyn PersistenceStore>);
struct PersistenceRecoveryPolicies(Arc<dyn PersistenceStore>);
struct PersistenceRecoverySessions(Arc<dyn PersistenceStore>);
struct PersistenceSecurityTransactions(Arc<dyn PersistenceStore>);
struct PersistenceDidDocuments(Arc<dyn PersistenceStore>);
#[async_trait::async_trait]
impl crate::identity::AccountLookupPort for PersistenceAccountLookup {
    async fn find_account_by_actor(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::AccountIdentity>> {
        Ok(self.0.accounts().get(account_id).await?.map(|account| {
            crate::identity::AccountIdentity {
                account_pk: account.pk,
                account_id: arkret_wire::AccountId::new(account.principal_id, account.station_id),
            }
        }))
    }

    async fn account_by_id(
        &self,
        account_pk: AccountPk,
    ) -> crate::ServiceResult<Option<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .get_by_pk(account_pk)
            .await?
            .map(application_account_profile))
    }

    async fn register_account(
        &self,
        command: crate::identity::RegisterAccountCommand,
    ) -> crate::ServiceResult<crate::identity::AccountIdentity> {
        let account = coland_storage::AccountRecord {
            pk: AccountPk(0),
            principal_id: command.account_id.principal_id.clone(),
            station_id: command.account_id.station_id.clone(),
            localpart: command.localpart.clone(),
            display_name: command.display_name,
            bio: None,
            avatar_blob_ref: None,
            created_at: command.created_at,
        };
        let account_pk = self.0.accounts().put(&account).await?;
        Ok(crate::identity::AccountIdentity {
            account_pk,
            account_id: command.account_id,
        })
    }

    async fn account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .get(account_id)
            .await?
            .map(application_account_profile))
    }

    async fn accounts(&self) -> crate::ServiceResult<Vec<crate::identity::AccountProfileState>> {
        Ok(self
            .0
            .accounts()
            .list()
            .await?
            .into_iter()
            .map(application_account_profile)
            .collect())
    }

    async fn save_account(
        &self,
        account: crate::identity::AccountProfileState,
    ) -> crate::ServiceResult<()> {
        self.0
            .accounts()
            .put(&persistence_account_profile(account))
            .await?;
        Ok(())
    }

    async fn delete_account(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<()> {
        self.0.accounts().delete(account_id).await?;
        Ok(())
    }

    async fn account_localparts(
        &self,
        account_pk: AccountPk,
    ) -> crate::ServiceResult<Vec<crate::identity::AccountLocalpartState>> {
        Ok(self
            .0
            .account_localparts()
            .list_for_account(account_pk)
            .await?)
    }

    async fn localpart_owner(
        &self,
        localpart: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AccountLocalpartState>> {
        Ok(self.0.account_localparts().owner_of(localpart).await?)
    }

    async fn add_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
        primary: bool,
    ) -> crate::ServiceResult<crate::identity::AccountLocalpartState> {
        Ok(self
            .0
            .account_localparts()
            .add(account_pk, localpart, primary)
            .await?)
    }

    async fn remove_localpart(
        &self,
        account_pk: AccountPk,
        localpart: &str,
    ) -> crate::ServiceResult<()> {
        self.0
            .account_localparts()
            .remove(account_pk, localpart)
            .await?;
        Ok(())
    }

    async fn clear_localparts(&self, account_pk: AccountPk) -> crate::ServiceResult<()> {
        self.0
            .account_localparts()
            .clear_for_account(account_pk)
            .await?;
        Ok(())
    }

    async fn record_handle_release(
        &self,
        localpart: &str,
        released_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<()> {
        self.0.handle_releases().put(localpart, released_at).await?;
        Ok(())
    }

    async fn save_account_lifecycle(
        &self,
        account_pk: AccountPk,
        _actor_id: &str,
        lifecycle: crate::identity::AccountLifecycleState,
    ) -> crate::ServiceResult<()> {
        self.0
            .account_lifecycle()
            .put(account_pk, &lifecycle)
            .await?;
        Ok(())
    }

    async fn delete_account_lifecycle(
        &self,
        account_pk: AccountPk,
        _actor_id: &str,
    ) -> crate::ServiceResult<()> {
        self.0.account_lifecycle().delete(account_pk).await?;
        Ok(())
    }

    async fn account_lifecycles(
        &self,
    ) -> crate::ServiceResult<
        Vec<(
            arkret_wire::AccountId,
            crate::identity::AccountLifecycleState,
        )>,
    > {
        Ok(self.0.account_lifecycle().snapshot_all().await?)
    }
}

fn application_account_profile(
    account: coland_storage::AccountRecord,
) -> crate::identity::AccountProfileState {
    crate::identity::AccountProfileState {
        pk: account.pk,
        account_id: arkret_wire::AccountId::new(
            account.principal_id.clone(),
            account.station_id.clone(),
        ),
        principal_id: account.principal_id,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

fn persistence_account_profile(
    account: crate::identity::AccountProfileState,
) -> coland_storage::AccountRecord {
    coland_storage::AccountRecord {
        pk: account.pk,
        principal_id: account.principal_id,
        station_id: account.account_id.station_id,
        localpart: account.localpart,
        display_name: account.display_name,
        bio: account.bio,
        avatar_blob_ref: account.avatar_blob_ref,
        created_at: account.created_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::AccountDataPort for PersistenceAccountData {
    async fn entry(
        &self,
        actor_id: &str,
        account_data_key: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AccountDataState>> {
        Ok(self
            .0
            .account_data()
            .get(actor_id, account_data_key)
            .await?
            .map(application_account_data))
    }

    async fn entries_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::AccountDataState>> {
        Ok(self
            .0
            .account_data()
            .list_for_actor(actor_id)
            .await?
            .into_iter()
            .map(application_account_data)
            .collect())
    }

    async fn changes_after(
        &self,
        actor_id: &str,
        position: u64,
    ) -> crate::ServiceResult<Vec<crate::identity::AccountDataChangeState>> {
        Ok(self
            .0
            .account_data()
            .changes_after(actor_id, position)
            .await?
            .into_iter()
            .map(|change| crate::identity::AccountDataChangeState {
                position: change.position,
                entry: application_account_data(change.record),
            })
            .collect())
    }

    async fn latest_change_position(&self, actor_id: &str) -> crate::ServiceResult<u64> {
        Ok(self
            .0
            .account_data()
            .latest_change_position(actor_id)
            .await?)
    }

    async fn change_position_is_replayable(
        &self,
        actor_id: &str,
        position: u64,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .account_data()
            .change_position_is_replayable(actor_id, position)
            .await?)
    }

    async fn prune_changes_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<u64> {
        Ok(self.0.account_data().prune_changes_before(cutoff).await?)
    }

    async fn snapshot_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<(Vec<crate::identity::AccountDataState>, u64)> {
        let (entries, position) = self.0.account_data().snapshot_for_actor(actor_id).await?;
        Ok((
            entries.into_iter().map(application_account_data).collect(),
            position,
        ))
    }

    async fn compare_and_set(
        &self,
        entry: crate::identity::AccountDataState,
        expected_revision: u64,
    ) -> crate::ServiceResult<crate::identity::AccountDataCasOutcome> {
        let outcome = self
            .0
            .account_data()
            .compare_and_set(
                &coland_storage::AccountDataRecord {
                    actor: entry.actor_id,
                    account_data_key: entry.account_data_key,
                    revision: entry.revision,
                    payload: entry.payload,
                    tombstone: entry.tombstone,
                    updated_at: entry.updated_at,
                },
                expected_revision,
            )
            .await?;
        Ok(match outcome {
            coland_storage::AccountDataCasResult::Applied(record) => {
                crate::identity::AccountDataCasOutcome::Applied(application_account_data(record))
            }
            coland_storage::AccountDataCasResult::Conflict(record) => {
                crate::identity::AccountDataCasOutcome::Conflict(
                    record.map(application_account_data),
                )
            }
        })
    }
}

fn application_account_data(
    record: coland_storage::AccountDataRecord,
) -> crate::identity::AccountDataState {
    crate::identity::AccountDataState {
        actor_id: record.actor,
        account_data_key: record.account_data_key,
        revision: record.revision,
        payload: record.payload,
        tombstone: record.tombstone,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::MimiConsentCorrelationPort for PersistenceMimiConsentCorrelations {
    async fn save_correlation(
        &self,
        correlation: crate::identity::MimiConsentCorrelation,
    ) -> crate::ServiceResult<()> {
        self.0.mimi_consent_correlations().put(&correlation).await?;
        Ok(())
    }

    async fn correlation(
        &self,
        consent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::MimiConsentCorrelation>> {
        Ok(self.0.mimi_consent_correlations().get(consent_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::ContactPort for PersistenceContacts {
    async fn contact_any(
        &self,
        requester_id: &arkret_wire::ActorId,
        target_id: &arkret_wire::ActorId,
    ) -> crate::ServiceResult<Option<crate::identity::ContactRecord>> {
        // The durable row retains request direction; pair consumers may query
        // from either participant without changing that signed direction.
        let contacts = self.0.contacts();
        if let Some(record) = contacts.get(requester_id, target_id).await? {
            return Ok(Some(record));
        }
        Ok(contacts.get(target_id, requester_id).await?)
    }

    async fn contacts_for_actor(
        &self,
        actor_id: &arkret_wire::ActorId,
    ) -> crate::ServiceResult<Vec<crate::identity::ContactRecord>> {
        Ok(self.0.contacts().list_for_actor(actor_id).await?)
    }

    async fn save_contact(
        &self,
        contact: crate::identity::ContactRecord,
    ) -> crate::ServiceResult<()> {
        self.0.contacts().put(&contact).await?;
        Ok(())
    }

    async fn save_contact_if_updated_at(
        &self,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
        contact: crate::identity::ContactRecord,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .contacts()
            .put_if_updated_at(expected_updated_at, &contact)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::InviteReceivePolicyPort for PersistenceInviteReceivePolicies {
    async fn save_policy(
        &self,
        account_id: &arkret_wire::AccountId,
        policy: arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
    ) -> crate::ServiceResult<()> {
        self.0
            .invite_receive_policies()
            .put(account_id, &policy)
            .await?;
        Ok(())
    }

    async fn policies(
        &self,
    ) -> crate::ServiceResult<
        Vec<(
            arkret_wire::AccountId,
            arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy,
        )>,
    > {
        Ok(self.0.invite_receive_policies().snapshot_all().await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::DeviceKeyPort for PersistenceDeviceKeys {
    async fn save_bundle(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        payload: Value,
    ) -> crate::ServiceResult<()> {
        self.0.device_keys().put(authorization, payload).await?;
        Ok(())
    }

    async fn bundle(&self, actor_id: &str, device_id: &str) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.device_keys().get(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::OneTimeKeyPort for PersistenceOneTimeKeys {
    async fn save_keys(
        &self,
        authorization: &coland_storage::DeviceRevocationGateSelector,
        keys: Vec<Value>,
    ) -> crate::ServiceResult<()> {
        self.0.one_time_keys().put(authorization, keys).await?;
        Ok(())
    }

    async fn claim_key(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.one_time_keys().claim(actor_id, device_id).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::DeviceDirectoryPort for PersistenceDeviceDirectory {
    async fn list_active_device_actors(&self) -> crate::ServiceResult<Vec<String>> {
        Ok(self
            .0
            .devices()
            .list()
            .await?
            .into_iter()
            .filter(|device| device.revoked_at.is_none())
            .map(|device| device.actor)
            .collect())
    }

    async fn devices(&self) -> crate::ServiceResult<Vec<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .list()
            .await?
            .into_iter()
            .map(application_device_identity)
            .collect())
    }

    async fn find_device(
        &self,
        actor_id: &str,
        device_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .get(actor_id, device_id)
            .await?
            .map(application_device_identity))
    }

    async fn save_device(
        &self,
        command: crate::identity::SaveDeviceCommand,
    ) -> crate::ServiceResult<()> {
        self.0
            .devices()
            .put_metadata(&coland_storage::DeviceInventoryMetadata {
                actor: command.actor_id,
                device_id: command.device_id,
                display_name: command.display_name,
                last_seen_at: command
                    .device
                    .payload
                    .get("last_seen_at")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|e| {
                        crate::ServiceError::SchemaViolation(format!(
                            "invalid device last_seen_at: {e}"
                        ))
                    })?,
                last_key_upload_at: command
                    .device
                    .payload
                    .get("last_key_upload_at")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|e| {
                        crate::ServiceError::SchemaViolation(format!(
                            "invalid device last_key_upload_at: {e}"
                        ))
                    })?,
                updated_at: command.device.updated_at,
            })
            .await?;
        Ok(())
    }

    async fn save_device_if_absent(
        &self,
        device: crate::identity::DeviceIdentity,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .devices()
            .put_if_absent(&persistence_device_identity(device))
            .await?)
    }

    async fn devices_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::DeviceIdentity>> {
        Ok(self
            .0
            .devices()
            .list_for_actor_including_revoked(actor_id)
            .await?
            .into_iter()
            .map(application_device_identity)
            .collect())
    }
}

fn application_device_identity(
    device: coland_storage::DeviceInventoryRecord,
) -> crate::identity::DeviceIdentity {
    crate::identity::DeviceIdentity {
        actor_id: device.actor,
        device_id: device.device_id,
        display_name: device.display_name,
        verification_state: device.verification_state,
        payload: device.payload,
        created_at: device.created_at,
        updated_at: device.updated_at,
        revoked_at: device.revoked_at,
    }
}

fn persistence_device_identity(
    device: crate::identity::DeviceIdentity,
) -> coland_storage::DeviceInventoryRecord {
    coland_storage::DeviceInventoryRecord {
        actor: device.actor_id,
        device_id: device.device_id,
        display_name: device.display_name,
        verification_state: device.verification_state,
        payload: device.payload,
        created_at: device.created_at,
        updated_at: device.updated_at,
        revoked_at: device.revoked_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentDirectoryPort for PersistenceAgentDirectory {
    async fn find_agent_controller(
        &self,
        agent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentController>> {
        Ok(self
            .0
            .agents()
            .get(agent_id)
            .await?
            .map(|agent| crate::identity::AgentController {
                controller_principal_id: agent.controller_principal_id,
            }))
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentPairingPort for PersistenceAgentPairing {
    async fn pairing_receipt(
        &self,
        event_id: &str,
    ) -> crate::ServiceResult<Option<coland_storage::AgentPairingReceipt>> {
        Ok(self.0.agents().pairing_receipt(event_id).await?)
    }
    async fn qualified_scope_receipt_for_pairing(
        &self,
        agent_id: &str,
        pairing_request_id: &str,
    ) -> crate::ServiceResult<Option<coland_storage::AgentPairingReceipt>> {
        Ok(self
            .0
            .agents()
            .qualified_scope_receipt_for_pairing(agent_id, pairing_request_id)
            .await?)
    }
    async fn pending_pairings_after(
        &self,
        after_id: &str,
        limit: usize,
    ) -> crate::ServiceResult<Vec<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .pending_pairings_after(after_id, limit)
            .await?
            .into_iter()
            .map(application_agent_pairing)
            .collect())
    }

    async fn pairing_record(
        &self,
        pairing_request_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .get_by_pairing_request_id(pairing_request_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agent(
        &self,
        agent_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .get(agent_id)
            .await?
            .map(application_agent_pairing))
    }

    async fn agents_for_controller(
        &self,
        controller_principal_id: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::AgentPairingState>> {
        Ok(self
            .0
            .agents()
            .list_for_controller(controller_principal_id)
            .await?
            .into_iter()
            .map(application_agent_pairing)
            .collect())
    }

    async fn save_agent(
        &self,
        agent: crate::identity::AgentPairingState,
    ) -> crate::ServiceResult<()> {
        self.0
            .agents()
            .put(persistence_agent_pairing(agent))
            .await?;
        Ok(())
    }

    async fn store_runtime_approval(
        &self,
        command: &crate::identity::StoreAgentRuntimeApprovalCommand,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        let write = coland_storage::AgentRuntimeApprovalWrite {
            agent_id: command.agent_id.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            approval_notification_id: command.approval_notification_id.clone(),
            approval_requested_at: command.approval_requested_at,
            proof_verified_at: command.proof_verified_at,
            controller_account_pk: command.controller_account_pk,
            recipient_id: command.recipient_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            runtime_public_key_digest: command.runtime_public_key_digest.clone(),
            runtime_attestation_digest: command.runtime_attestation_digest.clone(),
            runtime_key_request: command.runtime_key_request.clone(),
        };
        Ok(self
            .0
            .agents()
            .put_runtime_approval_if_compatible(&write)
            .await?
            .map(application_agent_pairing))
    }

    async fn activate_runtime_if_current(
        &self,
        command: &crate::identity::ActivateAgentRuntimeCommand,
    ) -> crate::ServiceResult<bool> {
        let activation = coland_storage::AgentRuntimeActivation {
            agent_id: command.agent_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            paired_request_digest: command.paired_request_digest.clone(),
            authorized_event_ref: command.authorized_event_ref.clone(),
            authorized_verification_method: command.authorized_verification_method.clone(),
            authorized_public_key_digest: command.authorized_public_key_digest.clone(),
            signer_resolution_evidence_ref: command.signer_resolution_evidence_ref.clone(),
            current_signer_evidence: command.current_signer_evidence.clone(),
            frozen_authorize_event: command.frozen_authorize_event.clone(),
            scope_custody_ref: command.scope_custody_ref.clone(),
            authorize_ref: command.authorize_ref.clone(),
            status: command.status,
            authorized_key_event: command.authorized_key_event.clone(),
            authorized_at: command.authorized_at,
        };
        Ok(self
            .0
            .agents()
            .activate_runtime_if_current(&activation)
            .await?)
    }

    async fn record_pairing_commit_intent(
        &self,
        command: &crate::identity::RecordAgentPairingCommitIntentCommand,
    ) -> crate::ServiceResult<Option<crate::identity::AgentPairingState>> {
        let intent = coland_storage::AgentPairingCommitIntent {
            agent_id: command.agent_id.clone(),
            approval_request_id: command.approval_request_id.clone(),
            runtime_key_binding_digest: command.runtime_key_binding_digest.clone(),
            pairing_request_id: command.pairing_request_id.clone(),
            request_digest: command.request_digest.clone(),
            authorize_event_id: command.authorize_event_id.clone(),
            key_authorization_event: command.key_authorization_event.clone(),
            scope_custody_ref: command.scope_custody_ref.clone(),
        };
        Ok(self
            .0
            .agents()
            .put_pairing_commit_intent_if_compatible(&intent)
            .await?
            .map(application_agent_pairing))
    }

    async fn clear_approval_notification_if_current(
        &self,
        agent_id: &str,
        approval_request_id: &str,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .agents()
            .clear_runtime_approval_notification_if_current(agent_id, approval_request_id)
            .await?)
    }

    async fn enqueue_runtime_message_if_current(
        &self,
        command: &EnqueueAgentRuntimeMessage,
    ) -> crate::ServiceResult<AgentRuntimeEnqueueOutcome> {
        Ok(self
            .0
            .agents()
            .enqueue_runtime_message_if_current(command)
            .await?)
    }
}

fn application_agent_pairing(
    record: coland_storage::AgentPrincipalRecord,
) -> crate::identity::AgentPairingState {
    crate::identity::AgentPairingState {
        id: record.id,
        controller_principal_id: record.controller_principal_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pending_pairing_commit_intent: record.pending_pairing_commit_intent,
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_pk: record.controller_account_pk,
        recipient_id: record.recipient_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        runtime_proof_verified_at: record.runtime_proof_verified_at,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        authorized_key_event: record.authorized_key_event,
        signer_resolution_evidence_ref: record.signer_resolution_evidence_ref,
        current_signer_evidence: record.current_signer_evidence,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

fn persistence_agent_pairing(
    record: crate::identity::AgentPairingState,
) -> coland_storage::AgentPrincipalRecord {
    coland_storage::AgentPrincipalRecord {
        id: record.id,
        controller_principal_id: record.controller_principal_id,
        principal_control_realm_id: record.principal_control_realm_id,
        controller_authorization_ref: record.controller_authorization_ref,
        display_name: record.display_name,
        agent_slug: record.agent_slug,
        avatar_blob_ref: record.avatar_blob_ref,
        state: record.state,
        requested_scope: record.requested_scope,
        accountability: record.accountability,
        provision_event_refs: record.provision_event_refs,
        pairing_request_id: record.pairing_request_id,
        paired_pairing_request_id: record.paired_pairing_request_id,
        paired_request_digest: record.paired_request_digest,
        pending_pairing_commit_intent: record.pending_pairing_commit_intent,
        pairing_code: record.pairing_code,
        pairing_expires_at: record.pairing_expires_at,
        approval_request_id: record.approval_request_id,
        controller_account_pk: record.controller_account_pk,
        recipient_id: record.recipient_id,
        runtime_key_binding_digest: record.runtime_key_binding_digest,
        runtime_public_key_digest: record.runtime_public_key_digest,
        runtime_attestation_digest: record.runtime_attestation_digest,
        runtime_proof_verified_at: record.runtime_proof_verified_at,
        approval_notification_id: record.approval_notification_id,
        runtime_key_request: record.runtime_key_request,
        approval_requested_at: record.approval_requested_at,
        authorized_event_ref: record.authorized_event_ref,
        authorized_verification_method: record.authorized_verification_method,
        authorized_public_key_digest: record.authorized_public_key_digest,
        authorized_key_event: record.authorized_key_event,
        signer_resolution_evidence_ref: record.signer_resolution_evidence_ref,
        current_signer_evidence: record.current_signer_evidence,
        state_changed_at: record.state_changed_at,
        created_at: record.created_at,
        updated_at: record.updated_at,
    }
}

#[async_trait::async_trait]
impl crate::identity::SidecarPort for PersistenceSidecars {
    async fn ensure_sidecar(
        &self,
        sidecar: crate::identity::AgentSidecarState,
    ) -> crate::ServiceResult<crate::identity::AgentSidecarState> {
        Ok(self.0.sidecars().insert_or_get(sidecar).await?)
    }
    async fn sidecar(
        &self,
        sidecar_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarState>> {
        Ok(self.0.sidecars().get(sidecar_id).await?)
    }
    async fn sidecar_for_realm_controller(
        &self,
        realm_id: &str,
        controller_account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarState>> {
        Ok(self
            .0
            .sidecars()
            .get_for_realm_controller(realm_id, controller_account_id)
            .await?)
    }
    async fn sidecars_for_controller(
        &self,
        controller_account_id: &arkret_wire::AccountId,
        realm_id: Option<&str>,
    ) -> crate::ServiceResult<Vec<crate::identity::AgentSidecarState>> {
        Ok(self
            .0
            .sidecars()
            .list_for_controller(controller_account_id, realm_id)
            .await?)
    }
    async fn ensure_context(
        &self,
        context: crate::identity::AgentSidecarContextState,
    ) -> crate::ServiceResult<crate::identity::AgentSidecarContextState> {
        Ok(self.0.sidecars().insert_or_get_context(context).await?)
    }
    async fn context(
        &self,
        sidecar_id: &str,
        digest: &str,
    ) -> crate::ServiceResult<Option<crate::identity::AgentSidecarContextState>> {
        Ok(self.0.sidecars().get_context(sidecar_id, digest).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::AgentParticipationPort for PersistenceAgentParticipation {
    async fn compare_and_swap_selection(
        &self,
        selection: serde_json::Value,
        expected_version: u64,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .agent_participation()
            .compare_and_swap_selection(selection, expected_version)
            .await?)
    }

    async fn selections(&self, agent_id: &str) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self
            .0
            .agent_participation()
            .list_selections(agent_id)
            .await?)
    }

    async fn ceilings(
        &self,
        scope_keys: &[String],
    ) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self
            .0
            .agent_participation()
            .ceilings_for_scope_keys(scope_keys)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::KeyBackupPort for PersistenceKeyBackups {
    async fn confirmed_list_page_for_account(
        &self,
        account_id: &arkret_wire::AccountId,
        query: &crate::identity::KeyBackupListQuery,
    ) -> crate::ServiceResult<coland_storage::ConfirmedKeyBackupListPage> {
        Ok(self
            .0
            .key_backups()
            .confirmed_list_page_for_account(account_id, query)
            .await?)
    }

    async fn confirmed_list_page_for_device(
        &self,
        account_id: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<Utc>,
        query: &crate::identity::KeyBackupListQuery,
    ) -> crate::ServiceResult<coland_storage::ConfirmedKeyBackupListPage> {
        Ok(self
            .0
            .key_backups()
            .confirmed_list_page_for_device(account_id, device_id, now, query)
            .await?)
    }

    async fn confirmed_active_series_for_device(
        &self,
        account_id: &arkret_wire::AccountId,
        device_id: &arkret_wire::DeviceId,
        now: chrono::DateTime<Utc>,
    ) -> crate::ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        Ok(self
            .0
            .key_backups()
            .confirmed_active_series_for_device(account_id, device_id, now)
            .await?)
    }

    async fn commit_active_series_pointer(
        &self,
        write: coland_storage::KeyBackupActiveSeriesCommitWrite,
    ) -> crate::ServiceResult<coland_storage::KeyBackupActiveSeriesCommitOutcome> {
        Ok(self
            .0
            .key_backups()
            .commit_active_series_pointer(write)
            .await?)
    }

    async fn confirmed_active_series(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<arkret_models_crypto::BackupActiveSeriesState>> {
        Ok(self
            .0
            .key_backups()
            .confirmed_active_series(account_id)
            .await?)
    }
    async fn confirmed_active_series_basis(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::ConfirmedKeyBackupAuthorityBasis>> {
        Ok(self
            .0
            .key_backups()
            .confirmed_active_series_basis(account_id)
            .await?)
    }
    async fn issue_unlock_challenge(
        &self,
        challenge: Value,
        now: chrono::DateTime<Utc>,
    ) -> crate::ServiceResult<Value> {
        Ok(self
            .0
            .key_backups()
            .issue_unlock_challenge(challenge, now)
            .await?)
    }
    async fn reserve_recovery_unlock_attempt(
        &self,
        authority_id: &str,
        holder: &str,
        request_digest: &str,
        now: chrono::DateTime<Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .key_backups()
            .reserve_recovery_unlock_attempt(authority_id, holder, request_digest, now)
            .await?)
    }
    async fn unlock_challenge(&self, authority_id: &str) -> crate::ServiceResult<Option<Value>> {
        Ok(self.0.key_backups().unlock_challenge(authority_id).await?)
    }
    async fn consume_unlock(
        &self,
        command: coland_storage::KeyBackupUnlockCommand<'_>,
    ) -> crate::ServiceResult<Value> {
        Ok(self.0.key_backups().consume_unlock(command).await?)
    }
    async fn backup(&self, backup_id: &str) -> crate::ServiceResult<Option<serde_json::Value>> {
        Ok(self.0.key_backups().get(backup_id).await?)
    }

    async fn backups_for_actor(
        &self,
        actor_id: &str,
    ) -> crate::ServiceResult<Vec<serde_json::Value>> {
        Ok(self.0.key_backups().list_for_actor(actor_id).await?)
    }

    async fn list_page(
        &self,
        query: &coland_storage::KeyBackupListQuery,
    ) -> crate::ServiceResult<coland_storage::KeyBackupListPage> {
        Ok(self.0.key_backups().list_page(query).await?)
    }

    async fn store_backup(
        &self,
        backup_id: String,
        payload: serde_json::Value,
    ) -> crate::ServiceResult<()> {
        self.0.key_backups().put(backup_id, payload).await?;
        Ok(())
    }

    async fn delete_backup(&self, backup_id: &str) -> crate::ServiceResult<bool> {
        Ok(self.0.key_backups().delete(backup_id).await?)
    }

    async fn issue_delete_challenge(
        &self,
        record: coland_storage::KeyBackupDeleteChallengeRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<coland_storage::KeyBackupDeleteChallengeRecord> {
        Ok(self
            .0
            .key_backups()
            .issue_delete_challenge(record, now)
            .await?)
    }

    async fn delete_challenge(
        &self,
        challenge_id: &str,
    ) -> crate::ServiceResult<Option<coland_storage::KeyBackupDeleteChallengeRecord>> {
        Ok(self.0.key_backups().delete_challenge(challenge_id).await?)
    }

    async fn consume_delete_challenge(
        &self,
        gate: &coland_storage::KeyBackupDeleteGate,
        challenge_id: &str,
        backup: Value,
        recovery_session_id: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<bool> {
        Ok(self
            .0
            .key_backups()
            .consume_delete_challenge(gate, challenge_id, backup, recovery_session_id, now)
            .await?)
    }

    async fn prune_expired_delete_challenges(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        Ok(self
            .0
            .key_backups()
            .prune_expired_delete_challenges(now)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::SessionIdentityPort for PersistenceSessions {
    async fn session(
        &self,
        token_hash: &str,
    ) -> crate::ServiceResult<Option<crate::identity::SessionIdentityState>> {
        self.0
            .sessions()
            .get(token_hash)
            .await?
            .map(application_session_identity)
            .transpose()
    }

    async fn sessions(&self) -> crate::ServiceResult<Vec<crate::identity::SessionIdentityState>> {
        self.0
            .sessions()
            .snapshot_all()
            .await?
            .into_iter()
            .map(application_session_identity)
            .collect()
    }

    async fn save_session(
        &self,
        session: crate::identity::SessionIdentityState,
    ) -> crate::ServiceResult<()> {
        self.0
            .sessions()
            .put(&persistence_session_identity(session)?)
            .await?;
        Ok(())
    }

    async fn revoke_session(
        &self,
        token_hash: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<Option<crate::identity::SessionIdentityState>> {
        let Some(mut session) = self.0.sessions().get(token_hash).await? else {
            return Ok(None);
        };
        if session.revoked_at.is_some() {
            return Ok(None);
        }
        session.revoked_at = Some(revoked_at);
        self.0.sessions().put(&session).await?;
        Ok(Some(application_session_identity(session)?))
    }

    async fn revoke_actor_sessions(
        &self,
        actor_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        self.revoke_matching_sessions(actor_id, None, revoked_at)
            .await
    }

    async fn revoke_actor_device_sessions(
        &self,
        actor_id: &str,
        device_id: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        self.revoke_matching_sessions(actor_id, Some(device_id), revoked_at)
            .await
    }
}

impl PersistenceSessions {
    async fn revoke_matching_sessions(
        &self,
        actor_id: &str,
        device_id: Option<&str>,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::ServiceResult<usize> {
        let sessions = self.0.sessions().snapshot_all().await?;
        let mut count = 0;
        for mut session in sessions.into_iter().filter(|session| {
            session.actor == actor_id
                && session.revoked_at.is_none()
                && device_id.is_none_or(|device_id| session.device_id == device_id)
        }) {
            session.revoked_at = Some(revoked_at);
            self.0.sessions().put(&session).await?;
            count += 1;
        }
        Ok(count)
    }
}

fn application_session_identity(
    session: coland_storage::SessionRecord,
) -> crate::ServiceResult<crate::identity::SessionIdentityState> {
    // Local bearers are Human device sessions. Agent sessions are accepted
    // only as request-scoped SessionGrants; a legacy empty DeviceId must not
    // become a synthetic authenticated endpoint.
    if session.agent_session.is_some() || session.device_id.is_empty() {
        return Err(crate::ServiceError::SchemaViolation(
            "stored local session has no Human device binding".to_owned(),
        ));
    }
    Ok(crate::identity::SessionIdentityState {
        token_hash: session.token_hash,
        account_pk: Some(session.account_pk),
        actor: session.actor,
        endpoint: crate::identity::SessionEndpointState::HumanDevice {
            device_id: session.device_id,
        },
        audience: session.audience,
        session_public_key: session.session_public_key,
        session_grant: None,
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    })
}

fn persistence_session_identity(
    session: crate::identity::SessionIdentityState,
) -> crate::ServiceResult<coland_storage::SessionRecord> {
    debug_assert!(
        session.session_grant.is_none(),
        "request-scoped session grants must never be persisted"
    );
    let crate::identity::SessionEndpointState::HumanDevice { device_id } = session.endpoint else {
        return Err(crate::ServiceError::SchemaViolation(
            "only Human device sessions may be stored as local bearers".to_owned(),
        ));
    };
    Ok(coland_storage::SessionRecord {
        token_hash: session.token_hash,
        account_pk: session
            .account_pk
            .expect("only account-bound sessions may be persisted"),
        actor: session.actor,
        device_id,
        audience: session.audience,
        session_public_key: session.session_public_key,
        agent_session: None,
        expires_at: session.expires_at,
        created_at: session.created_at,
        revoked_at: session.revoked_at,
    })
}

#[async_trait::async_trait]
impl crate::identity::RecoveryPolicyPort for PersistenceRecoveryPolicies {
    async fn active_policy(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Option<crate::identity::RecoveryPolicyState>> {
        Ok(self
            .0
            .recovery_policies()
            .get_active_for_account(account_id)
            .await?)
    }

    async fn policy_history(
        &self,
        account_id: &arkret_wire::AccountId,
    ) -> crate::ServiceResult<Vec<crate::identity::RecoveryPolicyState>> {
        Ok(self
            .0
            .recovery_policies()
            .list_for_account(account_id)
            .await?)
    }

    async fn commit_publication(
        &self,
        write: coland_storage::RecoveryPolicyPublicationWrite,
    ) -> crate::ServiceResult<coland_storage::RecoveryPolicyPublicationOutcome> {
        Ok(self.0.recovery_policies().commit_publication(write).await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::RecoverySessionPort for PersistenceRecoverySessions {
    async fn session(
        &self,
        recovery_session_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self.0.recovery_sessions().get(recovery_session_id).await?)
    }

    async fn session_for_grant(
        &self,
        session_grant_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self
            .0
            .recovery_sessions()
            .get_by_grant_id(session_grant_id)
            .await?)
    }

    async fn session_for_request(
        &self,
        session_grant_id: &str,
        request_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::RecoverySessionState>> {
        Ok(self
            .0
            .recovery_sessions()
            .get_by_grant_request(session_grant_id, request_id)
            .await?)
    }

    async fn insert_session(
        &self,
        session: crate::identity::RecoverySessionState,
    ) -> crate::ServiceResult<()> {
        self.0.recovery_sessions().insert(session).await?;
        Ok(())
    }

    async fn save_verified_with_unlock_manifest(
        &self,
        session: crate::identity::RecoverySessionState,
        manifest: Value,
    ) -> crate::ServiceResult<()> {
        Ok(self
            .0
            .recovery_sessions()
            .save_verified_with_unlock_manifest(session, manifest)
            .await?)
    }
    async fn update_session(
        &self,
        session: crate::identity::RecoverySessionState,
    ) -> crate::ServiceResult<()> {
        self.0.recovery_sessions().update(session).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl crate::identity::SecurityTransactionPort for PersistenceSecurityTransactions {
    async fn commit_revoke_proposal(
        &self,
        write: crate::identity::RevokeProposalCommitWrite,
    ) -> crate::ServiceResult<arkret_wire::RealmCommit> {
        Ok(self
            .0
            .security_transactions()
            .commit_revoke_proposal(write)
            .await?)
    }

    async fn commit_revoke_command_terminal(
        &self,
        write: crate::identity::RevokeCommandTerminalWrite,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(self
            .0
            .security_transactions()
            .commit_revoke_command_terminal(write)
            .await?)
    }
    async fn create(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(self.0.security_transactions().create(transaction).await?)
    }

    async fn transaction(
        &self,
        transaction_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionRecord>> {
        Ok(self.0.security_transactions().get(transaction_id).await?)
    }

    async fn save(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
    ) -> crate::ServiceResult<()> {
        self.0.security_transactions().update(transaction).await?;
        Ok(())
    }

    async fn rotations_awaiting_worker(&self, limit: u32) -> crate::ServiceResult<Vec<String>> {
        Ok(self
            .0
            .security_transactions()
            .rotations_awaiting_worker(limit)
            .await?)
    }

    async fn commit_rotation_upload(
        &self,
        write: crate::identity::RotationUploadCommitWrite,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(self
            .0
            .security_transactions()
            .commit_rotation_upload(write)
            .await?)
    }

    async fn commit_rotation_pointer_switch(
        &self,
        write: crate::identity::RotationPointerSwitchWrite,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(self
            .0
            .security_transactions()
            .commit_rotation_pointer_switch(write)
            .await?)
    }

    async fn commit_rotation_local_commit(
        &self,
        write: crate::identity::RotationLocalCommitWrite,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionRecord> {
        Ok(self
            .0
            .security_transactions()
            .commit_rotation_local_commit(write)
            .await?)
    }

    async fn step_outcome(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionStepOutcomeState>> {
        Ok(self
            .0
            .security_transactions()
            .step_outcome(transaction_id, step)
            .await?)
    }

    async fn step_attempt(
        &self,
        transaction_id: &str,
        step: arkret_models_crypto::security_transaction::SecurityTransactionStep,
    ) -> crate::ServiceResult<Option<crate::identity::SecurityTransactionStepAttemptState>> {
        Ok(self
            .0
            .security_transactions()
            .step_attempt(transaction_id, step)
            .await?)
    }

    async fn begin_step(
        &self,
        attempt: crate::identity::SecurityTransactionStepAttemptState,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionStepAttemptState> {
        Ok(self.0.security_transactions().begin_step(attempt).await?)
    }

    async fn accept_step(
        &self,
        transaction: crate::identity::SecurityTransactionRecord,
        outcome: crate::identity::SecurityTransactionStepOutcomeState,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionStepOutcomeState> {
        Ok(self
            .0
            .security_transactions()
            .accept_step(transaction, outcome)
            .await?)
    }

    async fn commit_recovery_unit(
        &self,
        write: crate::identity::RecoveryUnitCommitWrite,
    ) -> crate::ServiceResult<crate::identity::SecurityTransactionStepOutcomeState> {
        Ok(self
            .0
            .security_transactions()
            .commit_recovery_unit(write)
            .await?)
    }

    async fn backup_erase_progress(
        &self,
        transaction_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::BackupSeriesEraseProgressState>> {
        Ok(self
            .0
            .security_transactions()
            .backup_erase_progress(transaction_id)
            .await?)
    }

    async fn begin_backup_erase(
        &self,
        progress: crate::identity::BackupSeriesEraseProgressState,
    ) -> crate::ServiceResult<crate::identity::BackupSeriesEraseProgressState> {
        Ok(self
            .0
            .security_transactions()
            .begin_backup_erase(progress)
            .await?)
    }

    async fn update_backup_erase(
        &self,
        progress: crate::identity::BackupSeriesEraseProgressState,
    ) -> crate::ServiceResult<crate::identity::BackupSeriesEraseProgressState> {
        Ok(self
            .0
            .security_transactions()
            .update_backup_erase(progress)
            .await?)
    }
}

#[async_trait::async_trait]
impl crate::identity::DidDocumentPort for PersistenceDidDocuments {
    async fn document(
        &self,
        did: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DidDocumentState>> {
        Ok(self.0.webvh().get_document(did).await?)
    }

    async fn embedded_document(
        &self,
        local_id: &str,
    ) -> crate::ServiceResult<Option<crate::identity::DidDocumentState>> {
        Ok(self
            .0
            .webvh()
            .get_embedded_webvh_document_by_local_id(local_id)
            .await?)
    }

    async fn log_events(
        &self,
        did: &str,
    ) -> crate::ServiceResult<Vec<crate::identity::DidLogEvent>> {
        Ok(self.0.webvh().list_log_events(did).await?)
    }

    async fn store_document(
        &self,
        document: crate::identity::DidDocumentState,
    ) -> crate::ServiceResult<()> {
        self.0.webvh().put_document(document).await?;
        Ok(())
    }

    async fn append_log_event(
        &self,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<()> {
        self.0.webvh().append_log_event(event).await?;
        Ok(())
    }

    async fn service_registration(
        &self,
        key: &arkret_models_identity::service_identity::ServiceRegistrationKey,
    ) -> crate::ServiceResult<
        Option<arkret_models_identity::service_identity::ServiceRegistrationOutcome>,
    > {
        Ok(self.0.webvh().get_service_registration(key).await?)
    }

    async fn commit_service_registration(
        &self,
        key: arkret_models_identity::service_identity::ServiceRegistrationKey,
        outcome: arkret_models_identity::service_identity::ServiceRegistrationOutcome,
        document: crate::identity::DidDocumentState,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<crate::identity::ServiceRegistrationCommitResult> {
        Ok(
            match self
                .0
                .webvh()
                .commit_service_registration(key, outcome, document, event)
                .await?
            {
                coland_storage::ServiceRegistrationCommitOutcome::Created(outcome) => {
                    crate::identity::ServiceRegistrationCommitResult::Created(outcome)
                }
                coland_storage::ServiceRegistrationCommitOutcome::Existing(outcome) => {
                    crate::identity::ServiceRegistrationCommitResult::Existing(outcome)
                }
                coland_storage::ServiceRegistrationCommitOutcome::Conflict => {
                    crate::identity::ServiceRegistrationCommitResult::Conflict
                }
            },
        )
    }

    async fn commit_log_operation(
        &self,
        expected_current_head: Option<String>,
        document: crate::identity::DidDocumentState,
        event: crate::identity::DidLogEvent,
    ) -> crate::ServiceResult<crate::identity::DidLogCommitResult> {
        Ok(
            match self
                .0
                .webvh()
                .commit_log_operation(expected_current_head, document, event, None)
                .await?
            {
                coland_storage::WebvhLogCommitOutcome::Accepted => {
                    crate::identity::DidLogCommitResult::Accepted
                }
                coland_storage::WebvhLogCommitOutcome::Duplicate => {
                    crate::identity::DidLogCommitResult::Duplicate
                }
                coland_storage::WebvhLogCommitOutcome::Conflict => {
                    crate::identity::DidLogCommitResult::Conflict
                }
            },
        )
    }
}

#[derive(Clone)]
pub struct PersistenceIdentityServices {
    pub identity: IdentityService,
    pub account_data: AccountDataService,
    pub key_material: KeyMaterialService,
    pub consent: ConsentService,
    pub contact: ContactService,
    pub agent_pairing: AgentPairingService,
    pub agent_participation: AgentParticipationService,
    pub key_backup: KeyBackupService,
    pub session: SessionService,
    pub recovery_policy: RecoveryPolicyService,
    pub recovery_session: RecoverySessionService,
    pub security_transaction: SecurityTransactionService,
    pub did: DidService,
    pub organization_registration:
        crate::organization_registration::OrganizationRegistrationService,
}

pub fn build_persistence_identity_services(
    persistence: Arc<dyn PersistenceStore>,
    did_resolver: Arc<dyn DidResolverPort>,
) -> PersistenceIdentityServices {
    let did = DidService::new(
        Arc::new(PersistenceDidDocuments(persistence.clone())),
        did_resolver,
    );
    PersistenceIdentityServices {
        identity: IdentityService::new(
            Arc::new(PersistenceAccountLookup(persistence.clone())),
            Arc::new(PersistenceDeviceDirectory(persistence.clone())),
            Arc::new(PersistenceAgentDirectory(persistence.clone())),
        ),
        account_data: AccountDataService::new(Arc::new(PersistenceAccountData(
            persistence.clone(),
        ))),
        key_material: KeyMaterialService::new(
            Arc::new(PersistenceDeviceKeys(persistence.clone())),
            Arc::new(PersistenceOneTimeKeys(persistence.clone())),
        ),
        consent: ConsentService::new(Arc::new(PersistenceMimiConsentCorrelations(
            persistence.clone(),
        ))),
        contact: ContactService::new(
            Arc::new(PersistenceContacts(persistence.clone())),
            Arc::new(PersistenceInviteReceivePolicies(persistence.clone())),
        ),
        agent_pairing: AgentPairingService::new(
            Arc::new(PersistenceAgentPairing(persistence.clone())),
            Arc::new(PersistenceSidecars(persistence.clone())),
        ),
        agent_participation: AgentParticipationService::new(Arc::new(
            PersistenceAgentParticipation(persistence.clone()),
        )),
        key_backup: KeyBackupService::new(Arc::new(PersistenceKeyBackups(persistence.clone()))),
        session: SessionService::new(Arc::new(PersistenceSessions(persistence.clone()))),
        recovery_policy: RecoveryPolicyService::new(Arc::new(PersistenceRecoveryPolicies(
            persistence.clone(),
        ))),
        recovery_session: RecoverySessionService::new(Arc::new(PersistenceRecoverySessions(
            persistence.clone(),
        ))),
        security_transaction: SecurityTransactionService::new(Arc::new(
            PersistenceSecurityTransactions(persistence.clone()),
        )),
        organization_registration:
            crate::organization_registration::OrganizationRegistrationService::new(
                persistence,
                did.clone(),
            ),
        did,
    }
}
