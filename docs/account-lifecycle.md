# Account lifecycle (coland)

Reference for the coland implementation of the Arkret account lifecycle
state machine. The wire surface is `/_arkret/self/account/*`; this document
covers the coland-side behaviours: the lifecycle states, the audit
contract, and the GDPR erasure cascade.

## States

| State          | Set by                                  | Auth side-effect              |
|----------------|-----------------------------------------|-------------------------------|
| `active`       | default                                 | normal session issuance       |
| `locked`       | `set_account_lifecycle_record`           | 403 `account_locked`          |
| `suspended`    | `set_account_lifecycle_record`           | 403 `account_suspended`       |
| `deactivated`  | `POST /_coland/admin/accounts/{did}/deactivate` | 403 `account_deactivated`     |
| `erased`       | `POST /_arkret/local/account/erase`           | 401 `account_erased`          |

Lifecycle records are durable through `AccountLifecycleStore`. The identity
application hydrates its bounded read projection during startup and persists a
change before publishing it to request handlers. Credential-failure throttling
belongs to the Account Authority because Coland does not verify account
credentials; the former unwired local failed-login counter has been removed.

## GDPR erasure cascade

`POST /_arkret/local/account/erase` is the Arkret exit-point for an erased
principal. Coland performs the following actions atomically per
request, using durable application/storage ports:

1. Append a `org.arkret.coland.audit.erasure_initiated` audit row.
2. Pseudonymize the account record — replace `display_name` with
   `"[user erased]"`, null `bio` and `avatar_url`, and rotate `handle`
   to `@erased-<short-tag>`. The previous handle enters the release
   ledger so foreign references resolve gracefully.
3. Revoke every device record owned by the actor (`revoked_at` stamped
   on each row); count returned as `devices_revoked`.
4. Revoke every active session (`revoke_sessions_for_actor`); count
   returned as `sessions_revoked`.
5. Remove the actor from every Realm membership projection through the Realm
   directory application; count
   returned as `memberships_removed`.
6. Persist the actor's lifecycle state as `erased` so future authenticated
   requests resolve to 401 `account_erased`.
7. Append an `org.arkret.coland.account.state_change` audit row.
8. Append a single `org.arkret.coland.audit.actor_audit_redacted` row that catalogues
   every prior audit entry by `audit_id` + `created_at` only, marking
   each body as `redacted: true`. The append-only audit store still
   carries the historical rows so chain-of-custody is preserved.
   Downstream consumers honour this marker when rendering the actor's
   audit trail.
9. Mint a `ak.schema.erasure_receipt.v1` proof, sign it with the
   notary signing key, and append `ak.audit.erasure_receipt`.
10. Mint a per-realm `ak.schema.erasure_receipt.realm.v1` proof for
    every realm the actor was active in (`affected_erasure_realms_for_actor`)
    and emit each as a realm-scoped operation (best-effort fanout —
    failures are audited under `org.arkret.coland.audit.erasure_receipt.fanout_failed`).
11. Return the response envelope:

    ```json
    {
      "did": "did:web:alice.example",
      "state": "erased",
      "erased_at": "2026-05-26T12:34:56.789Z",
      "erasure_receipt": { ... },
      "realm_erasure_receipts": [ ... ],
      "audit_log": [ ... ],
      "memberships_removed": <count>,
      "sessions_revoked": <count>,
      "devices_revoked": <count>
    }
    ```

After the response is returned, every authenticated request bearing
the actor's bearer token resolves to 401 `account_erased`. The
`audit_log` field in the response is the canonical last-known-good
view of the actor's audit trail; subsequent reads will 401.

## Audit redaction marker contract

The `org.arkret.coland.audit.actor_audit_redacted` row written during erasure carries:

```json
{
  "action": "org.arkret.coland.audit.actor_audit_redacted",
  "outcome": "accepted",
  "payload": {
    "actor": "did:web:alice.example",
    "redacted_entry_count": 12,
    "entries": [
      { "audit_id": "...", "created_at": "...", "action": "auth.dev_login", "redacted": true },
      ...
    ]
  }
}
```

Renderers MUST treat any audit entry whose `audit_id` appears in a
later `org.arkret.coland.audit.actor_audit_redacted` row as redacted — replace the
body with `[redacted]` while preserving `audit_id`, `created_at`, and
`action` for forensic reconstruction.
