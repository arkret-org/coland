#!/usr/bin/env python3
"""Reject known test-only accessors and modules that leak into production builds.

Two shapes:

* `SURFACES` — a `pub fn` that only tests should reach, which must carry
  `#[cfg(any(test, feature = "test-support"))]`.
* `GATED_MODULES` — a whole module that must not be compiled into a default
  build. The development conformance harness is the case this exists for:
  `coland_http::routing::conformance` is the isolated HTTP fixture surface.
  The removed legacy `conformance_basis` module must not return.
  `development_mode` decides whether the namespace is *mounted*; these
  attributes decide whether it is *compiled*, which is what keeps the seed
  constructor out of the release binary.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEST_CFG = '#[cfg(any(test, feature = "test-support"))]'
# `(relative_path, module_declaration): required_attribute`
GATED_MODULES = {
    (
        "crates/http/src/routing/mod.rs",
        "pub(crate) mod conformance;",
    ): '#[cfg(any(test, feature = "conformance-harness"))]',
}

SURFACES = {
    "crates/http/src/config.rs": ("test_default",),
    "crates/services/src/events.rs": ("test_index",),
    "crates/services/src/persistence.rs": ("shared_for_tests",),
    "crates/services/src/projection.rs": ("test_state",),
    "crates/storage/src/records.rs": ("with_coalescing_lane",),
}


def deterministic_http_key_errors(root: Path) -> list[str]:
    source = (root / "crates/http/src/http_signature.rs").read_text(encoding="utf-8")
    if re.search(r"\bdeterministic_development_signing_key\b", source):
        return ["crates/http/src/http_signature.rs: unused deterministic fixture key constructor must remain removed"]
    return []


def removed_basis_errors(root: Path) -> list[str]:
    source = (root / "crates/services/src/lib.rs").read_text(encoding="utf-8")
    if re.search(r"\bmod\s+conformance_basis\b", source) or (
        root / "crates/services/src/conformance_basis.rs"
    ).exists() or (root / "crates/services/src/conformance_basis").exists():
        return ["crates/services/src: removed conformance_basis must not return"]
    return []


HARNESS_CFG = '#[cfg(any(test, feature = "conformance-harness"))]'
HARNESS_ITEMS = {
    "crates/http/src/routing/identity/auth/login.rs": ("dev_login", "initial_session_device_verification_state", "account_new_session_error", "session_device_inventory_record"),
    "crates/http/src/routing/admin/introspect.rs": ("synthetic_dev_admin_scopes", "synthetic_dev_grant"),
    "crates/http/src/routing/identity/auth/logout.rs": ("dev_mode_local_logout",),
}
HARNESS_STATEMENTS = {
    "crates/http/src/routing/identity/auth.rs": r'let router = router\.push\(Router::with_path\("dev-login"\)',
    "crates/http/src/routing/admin/introspect.rs": r'if state\.config\(\)\.development_harness_enabled\(\)',
    "crates/http/src/routing/identity/auth/logout.rs": r'if state\.config\(\)\.development_harness_enabled\(\)',
    "crates/http/src/routing/identity/auth/sessions.rs": r'Err\(error\)\s+if state\.config\(\)\.development_harness_enabled\(\)',
    "crates/http/src/routing/interop/push.rs": r'None if state\.config\(\)\.development_harness_enabled\(\)',
}


def harness_surface_errors(root: Path) -> list[str]:
    failures = []
    for relative, names in HARNESS_ITEMS.items():
        source = (root / relative).read_text(encoding="utf-8")
        for name in names:
            matches = list(re.finditer(rf"(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{name}\b", source))
            if len(matches) != 1:
                failures.append(f"{relative}: expected exactly one harness function {name}")
                continue
            prefix = source[max(0, matches[0].start() - 600):matches[0].start()]
            if HARNESS_CFG not in prefix[prefix.rfind("\n\n") + 2:]:
                failures.append(f"{relative}: {name} lacks {HARNESS_CFG}")
    for relative, pattern in HARNESS_STATEMENTS.items():
        source = (root / relative).read_text(encoding="utf-8")
        match = re.search(pattern, source)
        if match is None or not source[:match.start()].rstrip().endswith(HARNESS_CFG):
            failures.append(f"{relative}: synthetic branch must be directly harness-gated")
    source = (root / "crates/http/src/config.rs").read_text(encoding="utf-8")
    if 'cfg!(any(test, feature = "conformance-harness")) && self.development_mode' not in source:
        failures.append("config.rs: runtime development mode must not enable synthetic trust in a normal build")
    if "jws_replay_window_seconds" in source:
        failures.append("config.rs: removed, unused JWS replay setting must not return")
    bootstrap = (root / "crates/server/src/bootstrap.rs").read_text(encoding="utf-8")
    if "danger_accept_invalid_certs" in bootstrap:
        failures.append("bootstrap.rs: initial Account Authority discovery must validate TLS certificates")
    for name in ("demo.rs", "actors_users.rs", "organization_resolution.rs"):
        if (root / "crates/http/src/routing/spaces/directory" / name).exists():
            failures.append(f"directory/{name}: retired, uncompiled demo directory must not return")
    return failures


def main() -> int:
    failures = deterministic_http_key_errors(ROOT) + removed_basis_errors(ROOT) + harness_surface_errors(ROOT)
    for relative_path, names in SURFACES.items():
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        for name in names:
            definitions = list(
                re.finditer(
                    rf"(?m)^\s*pub(?:\([^)]*\))?\s+(?:async\s+)?fn\s+{re.escape(name)}\b",
                    source,
                )
            )
            for definition in definitions:
                prefix = source[max(0, definition.start() - 320) : definition.start()]
                attribute_block = prefix[prefix.rfind("\n\n") + 2 :]
                if TEST_CFG not in attribute_block:
                    line = source.count("\n", 0, definition.start()) + 1
                    failures.append(f"{relative_path}:{line}: {name} lacks {TEST_CFG}")

    for (relative_path, declaration), attribute in GATED_MODULES.items():
        source = (ROOT / relative_path).read_text(encoding="utf-8")
        if declaration not in source:
            failures.append(
                f"{relative_path}: `{declaration}` is gone — update this gate "
                f"or restore the declaration"
            )
            continue
        if f"{attribute}\n{declaration}" not in source:
            line = source.count("\n", 0, source.index(declaration)) + 1
            failures.append(
                f"{relative_path}:{line}: `{declaration}` is not directly "
                f"preceded by {attribute}"
            )

    if failures:
        print("test-support surface gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(
        f"test-support surface gate passed "
        f"({len(SURFACES)} accessor files, {len(GATED_MODULES)} gated modules, "
        f"{sum(map(len, HARNESS_ITEMS.values()))} isolated functions, {len(HARNESS_STATEMENTS)} isolated branches)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
