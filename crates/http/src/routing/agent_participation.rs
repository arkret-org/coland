use arkret_models_collaboration::governance::agent_participation::{
    ParticipationBits, effective_participation,
};
use serde_json::Value;

use crate::state::AppState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedAgentParticipation {
    pub(crate) effective: ParticipationBits,
    /// True when a required policy layer (deployment/Realm/Circle/Strand
    /// ceiling) could not be resolved and was folded to all-false; the wire
    /// reason for the resulting rejection is
    /// `agent_participation_ceiling_unresolved`, distinct from a resolved
    /// policy whose bit is false.
    pub(crate) ceiling_unresolved: bool,
}

pub(crate) fn realm_scope_key(realm_id: &str) -> String {
    format!("realm:{realm_id}")
}

pub(crate) fn circle_scope_key(realm_id: &str, circle_id: &str) -> String {
    format!("circle:{realm_id}:{circle_id}")
}

pub(crate) fn strand_scope_key(realm_id: &str, strand_id: &str) -> String {
    format!("strand:{realm_id}:{strand_id}")
}

pub(crate) fn participation_from_value(row: &Value) -> ParticipationBits {
    let mut bits = serde_json::Map::new();
    for field in [
        "message_creation_allowed",
        "reaction_addition_allowed",
        "reaction_removal_allowed",
        "third_party_mention_delivery_allowed",
        "acting_on_behalf_allowed",
    ] {
        let Some(value) = row.get(field).filter(|value| value.is_boolean()) else {
            return ParticipationBits::NONE;
        };
        bits.insert(field.to_owned(), value.clone());
    }
    serde_json::from_value(Value::Object(bits)).unwrap_or(ParticipationBits::NONE)
}

#[cfg(test)]
fn projected_strand_circle_id(state: &AppState, strand_id: &str) -> Option<Option<String>> {
    {
        let projection = state.projections().snapshot();
        {
            projection.strands.get(strand_id).map(|strand| {
                strand
                    .scope_circle_id
                    .clone()
                    .filter(|scope| scope.starts_with("ak:circle:"))
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn scope_keys_for_message(
    state: &AppState,
    realm_id: &str,
    strand_id: Option<&str>,
) -> Option<Vec<String>> {
    let mut keys = vec![realm_scope_key(realm_id)];
    let Some(strand_id) = strand_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return Some(keys);
    };
    if !strand_id.starts_with("ak:strand:") {
        return Some(keys);
    }
    if let Some(circle_id) = projected_strand_circle_id(state, strand_id)? {
        keys.push(circle_scope_key(realm_id, &circle_id));
    }
    keys.push(strand_scope_key(realm_id, strand_id));
    Some(keys)
}

pub(crate) async fn resolve_effective_ceiling_for_scope_keys(
    state: &AppState,
    scope_keys: &[String],
) -> Option<ParticipationBits> {
    let Ok(rows) = state.agent_participations().ceilings(scope_keys).await else {
        return None;
    };
    if scope_keys.is_empty()
        || !scope_keys.iter().all(|key| {
            rows.iter()
                .filter(|row| row.get("scope_key").and_then(Value::as_str) == Some(key.as_str()))
                .count()
                == 1
        })
    {
        return None;
    }
    Some(
        rows.iter()
            .map(participation_from_value)
            .fold(state.config().agent_participation_ceiling, |acc, row| {
                acc.intersect(row)
            }),
    )
}

fn selection_for_scope_keys<'a>(
    selections: &'a [Value],
    scope_keys: &[String],
) -> Option<&'a Value> {
    scope_keys.iter().rev().find_map(|scope_key| {
        selections
            .iter()
            .find(|row| row.get("scope_key").and_then(Value::as_str) == Some(scope_key.as_str()))
    })
}

pub(crate) async fn resolve_agent_participation_for_scope_keys(
    state: &AppState,
    agent_id: &str,
    scope_keys: &[String],
) -> Option<ResolvedAgentParticipation> {
    let selections = state
        .agent_participations()
        .selections(agent_id)
        .await
        .ok()?;
    let record = state.agent_pairings().agent(agent_id).await.ok()??;
    crate::routing::identity::agent_pcr::validate_agent_controller_binding(
        state,
        &record,
        chrono::Utc::now(),
    )
    .await
    .ok()?;
    crate::routing::identity::agent_pcr::agent_controller_account(state, &record)
        .await
        .ok()?;
    let selection = participation_from_value(selection_for_scope_keys(&selections, scope_keys)?);
    let ceiling = resolve_effective_ceiling_for_scope_keys(state, scope_keys).await;
    Some(ResolvedAgentParticipation {
        effective: effective_participation(ceiling.unwrap_or(ParticipationBits::NONE), selection),
        ceiling_unresolved: ceiling.is_none(),
    })
}

#[cfg(test)]
mod tests {
    use super::{circle_scope_key, realm_scope_key, strand_scope_key};

    const REALM_ID: &str = "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO";
    const CIRCLE_ID: &str = "ak:circle:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS";
    const STRAND_ID: &str = "ak:strand:AYbepLWCNKm2SxJt1JgbGtBjKrwf_iGhnjreRy4TZj09";

    #[test]
    fn scope_keys_preserve_complete_event_derived_tokens() {
        assert_eq!(realm_scope_key(REALM_ID), format!("realm:{REALM_ID}"));
        assert_eq!(
            circle_scope_key(REALM_ID, CIRCLE_ID),
            format!("circle:{REALM_ID}:{CIRCLE_ID}")
        );
        assert_eq!(
            strand_scope_key(REALM_ID, STRAND_ID),
            format!("strand:{REALM_ID}:{STRAND_ID}")
        );
    }
}
