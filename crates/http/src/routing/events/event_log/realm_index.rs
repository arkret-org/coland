use super::*;

#[cfg(test)]
pub(super) fn event_string_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}
