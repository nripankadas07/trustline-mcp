# Limitations

- This is an offline JSON-RPC transcript simulator with an opt-in modern MCP
  stdio service, not a transparent MCP proxy. The service supports
  `server/discover`, `tools/list`, and `tools/call` for `trustline.simulate` and
  `trustline.verify`; it does not forward arbitrary tools.
- The stdio service supports MCP `2026-07-28` only. It intentionally rejects the
  legacy `initialize` handshake and does not yet provide Streamable HTTP.
- Modern MCP applies to the outer service. The inner
  `trustline.transcript/v1` format remains a simplified deterministic replay
  input and is not an MCP conformance trace. `approvedBy` is unverified replay
  data, not an authenticated approval receipt.
- Outer requests are limited to 1 MiB, 64 nesting levels, and 20,000 JSON nodes.
  Simulations are additionally limited to 256 transcript entries, 32 KiB per
  entry, 256 KiB total transcript text, and 1,024 policy rules. Responses are
  capped at 2 MiB. An aggregate 8,000,000-unit policy-weight-by-transcript-size
  budget counts both bytes and entries, preventing callers from combining all
  independent maxima or hiding repeated setup behind empty entries. These are
  deterministic admission controls, not a process sandbox or wall-clock
  guarantee.
- Requests are bounded and synchronous. Notifications are ignored without a
  response or tool invocation; there is no cancellable long-running operation
  in this slice.
- It does not terminate OAuth, inspect encrypted HTTP traffic, enforce operating-system permissions, or isolate commands.
- Host checks are string/URL checks, not DNS-rebinding protection.
- Path checks are lexical and do not resolve symlinks or filesystem mount boundaries.
- Pattern policies use a dedicated interpreter for literals, dot, basic escapes,
  character classes, start/end anchors, and `\\b` word boundaries. The `\\B`
  non-boundary assertion is rejected because JavaScript can evaluate it inside
  a UTF-16 surrogate pair while this interpreter uses Unicode code-point
  boundaries. Grouping,
  alternation, backreferences, lookarounds, and repetition operators are rejected;
  patterns are capped at 256 code points and matched values at 100,000 code
  points. The interpreter does not dynamically compile policy text as a
  JavaScript regular expression. This is not a substitute for typed argument
  validation.
- Artifact publication rejects symlinks in every existing output-path component, rechecks directory identities, stages complete sets, reconciles ambiguous rename failures, and rolls back on a publish failure. Cooperative writers serialize through a bounded five-second `.artifact-write.lock`; a crash or incomplete recovery leaves that lock in place so later writers fail closed. After verifying that no writer is active, an operator must inspect any `.artifact-stage-*` recovery directory before manually removing a stale lock. Non-cooperating processes are not serialized. Node does not expose portable directory-file-descriptor-relative rename APIs, so a process that can concurrently replace trusted ancestor directories may still race between identity checks and filesystem operations; choose an output tree not writable by an attacker.
- Explicit policy, transcript, and audit input paths follow the operating system's normal symlink resolution; the CLI does not claim an input-directory confinement boundary.
- Quotas live in one in-memory engine instance.
- The chain binds entries to the complete declared policy configuration, but an unsigned bundle can still be replaced and rehashed wholesale. SHA-256 chaining does not establish signer identity; add an external signing system if provenance is required.
- Audit request and response fields are redacted, but the complete declared
  policy is embedded unredacted so its digest can be recomputed. Never place
  secrets in policy names, rule IDs, rule values, or other policy metadata.
- Redaction covers configured/standard secret keys, common token shapes, and URL
  userinfo/query credentials, but cannot prove that every secret shape is
  covered. Review generated artifacts before sharing them.
- Only the fixture tool adapter is included. A production integration would require explicit, reviewed transport and identity adapters.
