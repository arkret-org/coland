#!/usr/bin/env python3
"""Fail when Coland runtime environment literals and deployment docs drift."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATTERN = re.compile(r"\bCOLAND_[A-Z0-9_]+\b")
STRING_ENV_PATTERN = re.compile(r'"(COLAND_[A-Z0-9_]+)"')

def rust_environment_names() -> set[str]:
    names: set[str] = set()
    for path in (ROOT / "crates").rglob("*.rs"):
        # Integration tests read operator-only toggles (e.g. release gates)
        # that must never appear in deployment documentation.
        if "tests" in path.relative_to(ROOT / "crates").parts:
            continue
        names.update(STRING_ENV_PATTERN.findall(path.read_text(encoding="utf-8")))
    return {
        name
        for name in names
        if not name.startswith(("COLAND_TEST_", "COLAND_TEST_CHAOS_"))
    }


def documented_environment_names() -> set[str]:
    text = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (".env.example", "DEPLOYMENT.md")
    )
    return set(ENV_PATTERN.findall(text))


def main() -> int:
    code = rust_environment_names()
    docs = documented_environment_names()
    missing = sorted(code - docs)
    stale = sorted(name for name in docs - code if not name.endswith("_"))
    if missing or stale:
        if missing:
            print("Runtime variables missing from .env.example/DEPLOYMENT.md:")
            print("\n".join(f"  {name}" for name in missing))
        if stale:
            print("Documented variables not read by Rust code:")
            print("\n".join(f"  {name}" for name in stale))
        return 1
    print(f"environment documentation: ok ({len(code)} runtime variables)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
