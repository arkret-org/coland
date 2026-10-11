# Storage port boundary

`coland-storage` is a permanent backend-neutral port and contract crate. It is
not a temporary indirection around PostgreSQL.

## Ownership

- `coland-storage` owns persistence records, capability-oriented traits,
  cross-adapter result/error semantics, exact-replay outcomes, unit-of-work
  inputs, and reusable adapter contract tests.
- `coland-storage-postgres` owns Diesel, SQL, migrations, PostgreSQL locking,
  transaction implementation, row codecs, pooling, and database lifecycle.
- `coland-services` and `coland-http` depend on storage ports. They must not
  downcast an adapter or import database client, row, query, or transaction
  types.
- A future SQLite or other durable adapter is a sibling of
  `coland-storage-postgres` and implements the same ports and contract suite.

## Interface rules

1. A port is capability-oriented; it describes the atomic operation required
   by domain/services code rather than mirroring SQL tables or a repository
   implementation.
2. Public records use Arkret/standard Rust types. Diesel, PostgreSQL, SQLx,
   rusqlite, pool, connection, query, and row types are forbidden.
3. Backend-specific transaction semantics remain inside adapter unit-of-work
   implementations. HTTP and services do not assemble partial transactions.
4. A method with no current production caller is not deleted solely by
   reference count. It must be classified as a required adapter contract,
   an explicitly owned not-yet-wired capability, or a confirmed orphan.
5. Every durable adapter runs the shared contract tests plus its own restart,
   migration, locking, and failure-boundary tests.

## Automated guard

`cargo run -p xtask --bin check_layering --locked` rejects direct backend
dependencies from `coland-storage` and rejects adapter dependencies from the
HTTP/services/domain layers. This deliberately bans both current PostgreSQL
libraries and likely future SQLite/SQLx libraries from the port crate; an
adapter adds them in its own crate instead.

## Low-reference capability audit (2026-09-04)

Reference count is only a discovery signal. The following low-reference ports
were reviewed against their protocol role before changing the interface:

| Capability | Classification | Owner and disposition |
| --- | --- | --- |
| `AccountLocalpartStore::primary_for_account` | confirmed orphan | Removed from the port and PostgreSQL adapter; account registration and lookup use the account record/list operations. |
| `HistoryAuthorityViewCas::{bind_authority_view_cas, with_current_release_authority}` | unwired safety capability | Retained; governance-history response publication owns the release-authority CAS. The PostgreSQL adapter must fail closed once this validation hook is wired rather than inventing adapter-local policy. |
| `HistoryResponseStreamStore::expire_requests` | unwired worker capability | Retained; governance-history request lifecycle owns expiry scheduling. |
| `HistoryResponseStreamStore::replace_response_with_lost_exact` | unwired protocol branch | Retained; governance-history response lifecycle owns exact lost-response replacement. |
| `HistoryTraversalRetentionStore::resolve_retained_object` | unwired protocol branch | Retained; governance-history traversal/retention owns retained-object resolution. |

The retained entries are intentionally not folded into PostgreSQL-only APIs:
they are part of the persistence contract a future SQLite adapter must either
implement with equivalent atomicity or explicitly reject as unsupported at
adapter construction time.
