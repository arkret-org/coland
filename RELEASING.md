# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in `.ci/release-sources.json` define the release source set.
Native releases and tagged Docker builds use this same frozen set; ordinary CI
and main Docker builds check current sibling main branches.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

Artifacts contain Coland, federation outbox, keystore snapshot, and keystore
keygen executables for Linux x64/ARM64, Windows x64 and macOS ARM64.
Linux builds target Ubuntu 24.04 (glibc 2.39 or newer); install the system
OpenSSL runtime if required by your distribution. No macOS x64 build is produced.
