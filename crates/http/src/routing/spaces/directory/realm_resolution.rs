use salvo::oapi::extract::JsonBody;

use super::*;

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.search_realms", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.search_realms.v1"))]
pub(super) async fn search_realms(
    body: JsonBody<DirectorySearchRealmsRequestBody>,
    depot: &mut Depot,
) -> JsonResult<DirectoryRealmSearchResponseBody> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    body.validate()
        .map_err(|error| AppError::param_invalid(error.to_string()))?;
    let requested_limit = usize::from(body.limit.unwrap_or(20).clamp(1, 100));
    if body.cursor.is_some() {
        return Err(AppError::not_found("directory cursor is not available"));
    }
    let query = body.query.as_deref().map(str::to_lowercase);
    let now = Utc::now();
    let mut results = {
        let realms = state.realm_directory().snapshot();
        realms
            .entries_iter()
            .filter_map(|(_, entry)| public_directory_entry(entry, now))
            .filter(|entry| {
                query.as_ref().is_none_or(|query| {
                    entry
                        .public_metadata
                        .display_name
                        .to_lowercase()
                        .contains(query)
                        || entry
                            .public_metadata
                            .summary
                            .as_deref()
                            .unwrap_or_default()
                            .to_lowercase()
                            .contains(query)
                })
            })
            .collect::<Vec<_>>()
    };
    results.sort_by(|left, right| {
        left.public_metadata
            .display_name
            .cmp(&right.public_metadata.display_name)
            .then_with(|| left.realm_id.cmp(&right.realm_id))
    });
    let has_more = results.len() > requested_limit;
    if has_more {
        results.truncate(requested_limit);
    }
    let outcome = DirectoryRealmSearchResponseBody {
        realms: results,
        next_cursor: None,
        has_more,
    };
    outcome
        .validate()
        .map_err(|error| AppError::internal(error.to_string()))?;
    json_ok(outcome)
}

#[salvo::oapi::endpoint(operation_id = "ak.find.directory.read.resolve_realm", tags("spaces"))]
#[tracing::instrument(skip_all, fields(op = "ak.find.directory.read.resolve_realm.v1"))]
pub(super) async fn resolve_realm(
    body: JsonBody<DirectoryResolveRealmRequestBody>,
    depot: &mut Depot,
) -> JsonResult<PublicRealmDirectoryEntry> {
    let state = depot.get_typed::<AppState>().expect("state injected");
    let body = body.into_inner();
    let entry = {
        let realms = state.realm_directory().snapshot();
        realms.get(&body.realm_id).cloned()
    };
    let resolved = entry
        .as_ref()
        .and_then(|entry| public_directory_entry(entry, Utc::now()))
        .ok_or_else(|| AppError::not_found("not found"))?;
    json_ok(resolved)
}
