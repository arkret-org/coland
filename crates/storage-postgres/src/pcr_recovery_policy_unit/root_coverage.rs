//! A normal recipient rotation cannot strand Human roots from their first PUT.
//! Explicitly disabling recovery remains the separate policy-revocation path.

use std::collections::BTreeMap;

use arkret_models_crypto::{RecoveryMethod, RecoveryPolicy};
use coland_storage::PersistenceError;
use diesel::sql_query;
use diesel::sql_types::{Jsonb, Text};
use horme::RunQueryDsl as _;

use crate::{AsyncPgConnection, PgTransactionError};

#[derive(diesel::QueryableByName)]
struct Root {
    #[diesel(sql_type=Text)]
    root_ref: String,
    #[diesel(sql_type=Jsonb)]
    root_context: serde_json::Value,
}

#[derive(diesel::QueryableByName)]
struct Candidate {
    #[diesel(sql_type=diesel::sql_types::Uuid)]
    id: uuid::Uuid,
}

fn active_factor(policy: &RecoveryPolicy, key_ref: Option<&str>) -> bool {
    let at = chrono::Utc::now();
    policy.methods.iter().any(|method| matches!(method, RecoveryMethod::RecoveryUnlock { keys }
        if keys.iter().any(|key| key_ref.is_none_or(|reference| key.backup_hpke.key_agreement_ref.as_str() == reference)
            && key.not_before <= at && at < key.expires_at && key.revoked_at.is_none_or(|revoked| at < revoked))))
}

/// Called after the accepted PCR/current-policy lock and before any Event is
/// queued. Agent custody joins this boundary with its own native role adapter;
/// this function deliberately qualifies only the Human subject's own roots.
pub(super) async fn require_human_coverage(
    conn: &mut AsyncPgConnection,
    policy: &RecoveryPolicy,
) -> Result<(), PgTransactionError> {
    if !active_factor(policy, None) {
        return Ok(());
    }
    let actor = arkret_wire::ActorId::account(policy.account_id.clone());
    crate::key_backup::lock_backup_series_in_connection(conn, &actor).await?;
    let roots = sql_query("SELECT DISTINCT item->>'root_ref' AS root_ref,item->'root_context' AS root_context FROM key_backup_identities i CROSS JOIN LATERAL jsonb_array_elements(i.content_index) item WHERE i.actor_id=$1 AND item->>'item_kind'='content_epoch_root' ORDER BY root_ref")
        .bind::<Text,_>(actor.to_string()).get_results::<Root>(&mut *conn).await?;
    if roots.is_empty() {
        return Ok(());
    }
    let mut verified = BTreeMap::new();
    for root in roots {
        let selector = serde_json::json!([{"item_kind":"content_epoch_root","root_ref":root.root_ref,"root_context":root.root_context}]);
        let mut after = uuid::Uuid::nil();
        let mut covered = false;
        loop {
            let page = sql_query("SELECT b.id FROM key_backups b JOIN key_backup_identities i USING(id) WHERE b.actor_id=$1 AND i.actor_id=b.actor_id AND i.deleted_at IS NULL AND b.id>$2 AND i.content_index @> $3 ORDER BY b.id LIMIT 64 FOR SHARE OF b,i")
                .bind::<Text,_>(actor.to_string()).bind::<diesel::sql_types::Uuid,_>(after).bind::<Jsonb,_>(&selector)
                .get_results::<Candidate>(&mut *conn).await?;
            let last = page.len() < 64;
            for candidate in page {
                after = candidate.id;
                let eligible = if let Some(eligible) = verified.get(&candidate.id) {
                    *eligible
                } else {
                    let id = arkret_wire::BackupId::new(format!("ak:backup:{}", candidate.id))
                        .map_err(PersistenceError::database)?;
                    let backup =
                        crate::content_root_packages::read_retained_envelope(conn, &id).await?;
                    let eligible = match crate::key_backup_history::recipient_for_policy(
                        conn, &backup, policy,
                    )
                    .await
                    {
                        Ok(_) => {
                            active_factor(policy, backup.encryption.recipient_key_ref.as_deref())
                        }
                        Err(PersistenceError::Conflict(_)) => false,
                        Err(error) => return Err(error.into()),
                    };
                    verified.insert(candidate.id, eligible);
                    eligible
                };
                if eligible {
                    covered = true;
                    break;
                }
            }
            if covered || last {
                break;
            }
        }
        if !covered {
            return Err(PersistenceError::Conflict("failed_precondition: recovery policy would strand a retained PCR content root; complete recipient rewrap coverage first".into()).into());
        }
    }
    Ok(())
}
