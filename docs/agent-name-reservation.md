# Agent name reservation

Coland rejects a second Agent with the same canonical `agent_slug` for the
same controller principal in its locally observed accepted provisioning
history. Display names remain presentation text; Agent IDs remain distinct
identities. This local policy does not establish global uniqueness across
unobserved remote Stations.

An accepted provision reserves the slug even before Agent PCR genesis and DID
binding finish. Once the Agent exists, both `active` and `paused` reserve it.
Missing runtime keys, runtime unbinding, pairing expiry and cancelled approvals
do not release the name: the controller can still recover that same identity
through renewed pairing. Renewal must not depend on sibling slug availability.

Only accepted terminal `deactivated` lifecycle releases the slug. Retained old
keys, handles, approvals and audit history do not reserve it or select a new
Agent by name. A replacement has a different Agent ID and independent pairing
handles; old requests remain bound to the old, terminal identity and cannot
revive it or replace the new selector owner.

HTTP provisioning checks provide an early error for visible Agent records.
The accepting PostgreSQL transaction also checks original accepted provisions
and their exact Agent PCR lifecycle current. The controller's selector namespace
is serialized, so concurrent provisions and direct source admission cannot
bypass the policy. No cleanup of historical Events or pairing records is needed
to free a terminal name.

See `key-management.md` sections 3.6.1 and 3.6.3 and `actor.md` section 3.3 in
the Arkret v1 specification. Regressions live in the HTTP Agent lifecycle tests
and `crates/storage-postgres/tests/agent_origin.rs`.
