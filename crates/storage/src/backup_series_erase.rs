//! Private durable carrier for the SecurityRotation erase worker.
//!
//! These records are persisted with the worker's canonical request for crash
//! recovery. They are not Arkret operations or public request/response DTOs.

use std::collections::BTreeSet;

use arkret_models_crypto::{
    BackupObjectRef, BackupRotationBinding, BackupRotationKind, BackupSeriesEraseConfirmation,
    security_rotation_erase_confirmation_digest,
};
use arkret_wire::{BackupSeriesId, Hash, RealmCommitId, ReasonCode, TransactionId};
use serde::{Deserialize, Serialize};

use crate::{PersistenceError, PersistenceResult};

fn invalid(reason: impl Into<String>) -> PersistenceError {
    PersistenceError::SchemaViolation(reason.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseStatus {
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSeriesEraseRowStatus {
    Pending,
    FailedRetryable,
    Erased,
}

/// Canonical erase request the worker derives from the saved plan; its bytes
/// define `request_digest` for exact-retry and `duplicate_conflict` checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseWorkerRequest {
    pub transaction_id: TransactionId,
    pub transaction_request_digest: Hash,
    pub prepared_plan_digest: Hash,
    pub erase_confirmation_digest: Hash,
    pub series: Vec<BackupRotationBinding>,
    pub authority_commit_id: RealmCommitId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseRow {
    pub backup_kind: BackupRotationKind,
    pub previous_series_id: BackupSeriesId,
    pub new_series_id: BackupSeriesId,
    pub status: BackupSeriesEraseRowStatus,
    pub erased_backups: Vec<BackupObjectRef>,
    pub remaining_backups: Vec<BackupObjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ReasonCode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSeriesEraseOutcome {
    pub transaction_id: TransactionId,
    pub request_digest: Hash,
    pub status: BackupSeriesEraseStatus,
    pub series_records: Vec<BackupSeriesEraseRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<BackupSeriesEraseConfirmation>,
}

fn validate_refs(refs: &[BackupObjectRef], label: &str) -> PersistenceResult<()> {
    if refs.len() > 512 {
        return Err(invalid(format!(
            "{label} exceeds 512 backup object references"
        )));
    }
    let mut ids = BTreeSet::new();
    if refs.iter().any(|item| !ids.insert(&item.backup_id)) {
        return Err(invalid(format!(
            "{label} backup object references must be unique"
        )));
    }
    Ok(())
}

fn validate_canonical_refs(refs: &[BackupObjectRef], label: &str) -> PersistenceResult<()> {
    validate_refs(refs, label)?;
    if refs
        .windows(2)
        .any(|pair| pair[0].backup_id.as_str() >= pair[1].backup_id.as_str())
    {
        return Err(invalid(format!(
            "{label} must be canonical backup-id sorted"
        )));
    }
    Ok(())
}

fn validate_binding(series: &[BackupRotationBinding]) -> PersistenceResult<&BackupRotationBinding> {
    let [binding] = series else {
        return Err(invalid(
            "backup erase requires exactly one secret_storage series",
        ));
    };
    if binding.backup_kind != BackupRotationKind::SecretStorage
        || binding.previous_series_id == binding.new_series_id
        || binding.new_backups.is_empty()
        || binding.old_backups.is_empty()
    {
        return Err(invalid(
            "backup erase requires one changed series with non-empty backup sets",
        ));
    }
    validate_refs(&binding.new_backups, "new_backups")?;
    validate_refs(&binding.old_backups, "old_backups")?;
    Ok(binding)
}

impl BackupSeriesEraseWorkerRequest {
    pub fn validate_structural(&self) -> PersistenceResult<()> {
        validate_binding(&self.series)?;
        let expected =
            security_rotation_erase_confirmation_digest(&self.transaction_id, &self.series)
                .map_err(|error| invalid(error.to_string()))?;
        if self.erase_confirmation_digest != expected {
            return Err(invalid(
                "backup erase confirmation digest changed its fixed projection",
            ));
        }
        Ok(())
    }
}

impl BackupSeriesEraseOutcome {
    pub fn validate_structural(&self) -> PersistenceResult<()> {
        let [record] = self.series_records.as_slice() else {
            return Err(invalid(
                "backup erase outcome requires one secret_storage record",
            ));
        };
        if record.backup_kind != BackupRotationKind::SecretStorage
            || record.previous_series_id == record.new_series_id
        {
            return Err(invalid("backup erase record has an invalid series binding"));
        }
        validate_canonical_refs(&record.erased_backups, "erased_backups")?;
        validate_canonical_refs(&record.remaining_backups, "remaining_backups")?;
        match record.status {
            BackupSeriesEraseRowStatus::Erased
                if !record.remaining_backups.is_empty() || record.reason_code.is_some() =>
            {
                return Err(invalid(
                    "erased backup series requires no remaining backups or reason",
                ));
            }
            BackupSeriesEraseRowStatus::Pending if record.reason_code.is_some() => {
                return Err(invalid("pending backup series cannot carry a reason"));
            }
            BackupSeriesEraseRowStatus::FailedRetryable if record.reason_code.is_none() => {
                return Err(invalid("failed-retryable backup series requires a reason"));
            }
            _ => {}
        }
        match (self.status, self.confirmation.as_ref()) {
            (BackupSeriesEraseStatus::Complete, Some(confirmation)) => confirmation
                .validate_structural()
                .map_err(|error| invalid(error.to_string())),
            (BackupSeriesEraseStatus::Partial, None) => Ok(()),
            _ => Err(invalid(
                "only a complete erase outcome carries confirmation",
            )),
        }
    }

    pub fn validate_for_request(
        &self,
        request: &BackupSeriesEraseWorkerRequest,
    ) -> PersistenceResult<()> {
        self.validate_structural()?;
        request.validate_structural()?;
        let digest = arkret_canonical::canonical::canonical_sha256(request)
            .map_err(|error| invalid(error.to_string()))?;
        let record = &self.series_records[0];
        let binding = validate_binding(&request.series)?;
        let mut reported = record.erased_backups.clone();
        reported.extend(record.remaining_backups.clone());
        reported.sort_by(|a, b| a.backup_id.as_str().cmp(b.backup_id.as_str()));
        let mut planned = binding.old_backups.clone();
        planned.sort_by(|a, b| a.backup_id.as_str().cmp(b.backup_id.as_str()));
        if self.transaction_id != request.transaction_id
            || self.request_digest.as_str() != digest
            || record.backup_kind != binding.backup_kind
            || record.previous_series_id != binding.previous_series_id
            || record.new_series_id != binding.new_series_id
            || reported != planned
        {
            return Err(invalid(
                "backup erase outcome changed transaction, request, or target",
            ));
        }
        if let Some(confirmation) = &self.confirmation
            && (confirmation.transaction_id != request.transaction_id
                || confirmation.transaction_request_digest != request.transaction_request_digest
                || confirmation.prepared_plan_digest != request.prepared_plan_digest
                || confirmation.series != request.series
                || request.erase_confirmation_digest
                    != security_rotation_erase_confirmation_digest(
                        &confirmation.transaction_id,
                        &confirmation.series,
                    )
                    .map_err(|error| invalid(error.to_string()))?)
        {
            return Err(invalid(
                "backup erase confirmation changed the reserved plan",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{BackupId, EventId, SchemaId};

    use super::*;

    fn fixture() -> (
        BackupSeriesEraseWorkerRequest,
        crate::BackupSeriesEraseProgressRecord,
    ) {
        let transaction_id =
            TransactionId::new(format!("ak:transaction:{}", uuid::Uuid::now_v7())).unwrap();
        let object = BackupObjectRef {
            backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap(),
            ciphertext_digest: Hash::new(arkret_canonical::sha256_digest(b"old")).unwrap(),
        };
        let binding = BackupRotationBinding {
            backup_kind: BackupRotationKind::SecretStorage,
            previous_series_id: BackupSeriesId::new(format!(
                "ak:backup_series:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
            new_series_id: BackupSeriesId::new(format!(
                "ak:backup_series:{}",
                uuid::Uuid::now_v7()
            ))
            .unwrap(),
            new_backups: vec![BackupObjectRef {
                backup_id: BackupId::new(format!("ak:backup:{}", uuid::Uuid::now_v7())).unwrap(),
                ciphertext_digest: Hash::new(arkret_canonical::sha256_digest(b"new")).unwrap(),
            }],
            active_series_event_id: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7; 32],
            ),
            old_backups: vec![object.clone()],
        };
        let request = BackupSeriesEraseWorkerRequest {
            transaction_id: transaction_id.clone(),
            transaction_request_digest: Hash::new(arkret_canonical::sha256_digest(b"request"))
                .unwrap(),
            prepared_plan_digest: Hash::new(arkret_canonical::sha256_digest(b"plan")).unwrap(),
            erase_confirmation_digest: security_rotation_erase_confirmation_digest(
                &transaction_id,
                std::slice::from_ref(&binding),
            )
            .unwrap(),
            series: vec![binding.clone()],
            authority_commit_id: RealmCommitId::from_digest([9; 32]),
        };
        let canonical_request = arkret_canonical::canonical_json_bytes(&request).unwrap();
        let progress = crate::BackupSeriesEraseProgressRecord {
            transaction_id: transaction_id.to_string(),
            canonical_request,
            outcome: BackupSeriesEraseOutcome {
                transaction_id,
                request_digest: Hash::new(arkret_canonical::canonical_sha256(&request).unwrap())
                    .unwrap(),
                status: BackupSeriesEraseStatus::Partial,
                series_records: vec![BackupSeriesEraseRow {
                    backup_kind: BackupRotationKind::SecretStorage,
                    previous_series_id: binding.previous_series_id,
                    new_series_id: binding.new_series_id,
                    status: BackupSeriesEraseRowStatus::Pending,
                    erased_backups: vec![],
                    remaining_backups: vec![object],
                    reason_code: None,
                }],
                confirmation: None,
            },
        };
        (request, progress)
    }

    #[test]
    fn progress_roundtrip_and_monotonic_completion() {
        let (request, initial) = fixture();
        crate::validate_backup_erase_progress_initial(&initial).unwrap();
        let stored: crate::BackupSeriesEraseProgressRecord =
            serde_json::from_value(serde_json::to_value(&initial).unwrap()).unwrap();
        assert_eq!(stored.outcome, initial.outcome);
        let mut completed = stored.clone();
        let object = completed.outcome.series_records[0]
            .remaining_backups
            .remove(0);
        completed.outcome.series_records[0]
            .erased_backups
            .push(object);
        completed.outcome.series_records[0].status = BackupSeriesEraseRowStatus::Erased;
        completed.outcome.status = BackupSeriesEraseStatus::Complete;
        completed.outcome.confirmation = Some(BackupSeriesEraseConfirmation {
            schema: SchemaId::BackupSeriesEraseConfirmationV1,
            transaction_id: request.transaction_id,
            transaction_request_digest: request.transaction_request_digest,
            prepared_plan_digest: request.prepared_plan_digest,
            series: request.series,
        });
        crate::validate_backup_erase_progress_update(&stored, &completed).unwrap();
        assert!(crate::validate_backup_erase_progress_update(&completed, &stored).is_err());
        assert!(crate::validate_backup_erase_progress_update(&completed, &completed).is_ok());
    }

    #[test]
    fn progress_rejects_changed_canonical_request() {
        let (_, progress) = fixture();
        let outcome = serde_json::to_value(&progress.outcome).unwrap();
        assert_eq!(
            serde_json::from_value::<BackupSeriesEraseOutcome>(outcome.clone()).unwrap(),
            progress.outcome,
        );
        let mut unknown = outcome;
        unknown["unexpected"] = serde_json::json!(true);
        let error = serde_json::from_value::<BackupSeriesEraseOutcome>(unknown).unwrap_err();
        assert!(error.to_string().contains("unknown field `unexpected`"));
        let mut changed = progress.clone();
        changed.canonical_request.push(b' ');
        assert!(crate::validate_backup_erase_progress_initial(&changed).is_err());
        assert!(crate::validate_backup_erase_progress_update(&progress, &changed).is_err());
    }
}
