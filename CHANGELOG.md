# Changelog

All notable changes follow Keep a Changelog principles.

## [Unreleased]

### Added

- Add a dependency-free MCP `2026-07-28` stdio service with discovery and a
  deterministic two-tool catalog for transcript simulation and audit
  verification.
- Validate interoperability with the official MCP v2 client while keeping the
  published package's runtime dependency set empty.
- Bound UTF-8 frames, JSON structure, policy work, transcript inputs, and
  response size; apply an aggregate policy-by-transcript work budget; and
  recover cleanly after malformed, invalid-encoding, or oversized lines.

### Changed

- Reject a bare `xn--` ACE prefix explicitly so hostname-policy validation
  remains fail closed across Node URL-parser revisions, including Node 24.20.
- Replace dynamic regular-expression construction for tool-name globs with an
  explicit wildcard state machine while preserving the existing anchored `*`
  behavior.

## [0.1.1] - 2026-08-16

### Changed

- Parse policy patterns into a bounded, non-repeating safe-pattern program and
  evaluate it without dynamically compiling JavaScript regular expressions;
  fail closed on oversized match inputs and reject ambiguous `\\B` surrogate-pair
  semantics.
- Treat valid JSON-RPC requests without an `id` as notifications: their policy decision and audit entry are retained, while the recorded protocol response is `null`.
- Reject trailing CLI operands and option-like positional values instead of silently ignoring them.
- Dispatch CLI commands only through a fixed exhaustive switch.
- Reject sparse or extended policy-rule and authenticated audit arrays instead of accepting non-JSON array structure.
- Publish artifact sets through component-verified staging, directory/target identity rechecks, per-file atomic renames, and set-level backup/rollback. Output-path and target-file symlinks are rejected before any artifact is replaced.
- Serialize cooperative artifact writers with a bounded fail-closed filesystem lock and reconcile rename-then-error outcomes by inode identity, preventing mixed concurrent bundles and restoring the full prior set after ambiguous failures.
- Report generated artifacts as `trustline-mcp@0.1.1`.

These stricter regex, array, and CLI checks can reject policies or invocations that `0.1.0` accepted.

## [0.1.0] - 2026-08-16

### Added

- Deny-overrides tool, argument, path, host, quota, and approval policy engine.
- Offline JSON-RPC transcript simulator with attack fixture.
- Secret redaction, canonical chained hashes, and tamper verification.
- Deterministic JSON, Markdown, and single-file HTML reports.
- Fail-closed path/host allowlists, constructor-time regex validation, and nonblank approval identities.
- Strict runtime policy, JSON-RPC, audit-bundle, audit-entry, and decision validation.
- Policy-digest-bound audit genesis and entries, with controlled nonzero verification for malformed bundles.
- Enforcement of every overlapping quota plus URL credential/query redaction.
- Clean-source npm prepack and installed-package import/CLI smoke coverage.
- An explicitly non-JSONL attack fixture containing the intentional malformed
  protocol record.
