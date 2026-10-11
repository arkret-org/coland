use salvo::prelude::*;

mod authz;
pub(super) mod policy;

use super::{now, query_param, validate_canonical_json_value};

/// Protocol surface mounted under `/_arkret/self/...`.
pub fn router() -> Router {
    Router::new().push(authz::protocol_router())
}

/// Product surface mounted under `/_coland/self/...`: owner-scoped policy
/// document storage CRUD (deployment-local management, not a v1 protocol
/// operation).
pub fn product_router() -> Router {
    Router::new().push(policy::product_router())
}
