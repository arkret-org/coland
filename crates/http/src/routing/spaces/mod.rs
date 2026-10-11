use salvo::prelude::*;

mod actor_private_events;
pub(super) mod directory;
mod read_cursor;
pub(super) mod space;

use super::AuthArgs;

/// `self`-segment spaces surface. The directory surface is split out into
/// [`find_router`] because directory discovery belongs to the `find` trust
/// segment, not `self`.
pub fn router() -> Router {
    protocol_router()
}

pub fn protocol_router() -> Router {
    Router::new()
        // Spec `realm_read` group (`ak.self.realm.*`).
        .push(space::protocol_router())
        // Spec `read_cursor` group (`ak.self.read_cursor.*`), canonical path
        // `/_arkret/self/read-cursors`.
        .push(
            Router::with_path("read-cursors")
                .post(read_cursor::set_read_cursor)
                .get(read_cursor::get_read_cursors),
        )
        // `ak.self.actor_private_events.command.submit.v1`.
        .push(
            Router::with_path("actor-private-events")
                .post(actor_private_events::submit_actor_private_event),
        )
}

pub fn local_router() -> Router {
    Router::new().push(space::local_router())
}

/// `find`-segment directory discovery surface (`/_arkret/find/directory/*`).
///
/// The historical `/_coland/find/directory/*` mirror has been retired;
/// directory discovery is served only from the canonical `/_arkret/find/...`
/// protocol tree.
pub fn find_router() -> Router {
    directory::protocol_router()
}
