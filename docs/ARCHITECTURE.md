# Architecture

## Data flow

```text
JSONL line -> JSON-RPC validation -> tools/call extraction -> policy engine
          -> deny / approval / allow -> offline fixture response
          -> redact -> canonical audit payload -> chained SHA-256
          -> JSON + Markdown + self-contained HTML
```

The policy engine is stateful only for quota counters. A new engine starts at zero, making a transcript replay deterministic. Matching rules do not short-circuit; the engine gathers all evidence so that a later deny cannot be hidden by an earlier allow.

The simulator canonicalizes the complete validated policy into `policyDigest`. The audit genesis commits to that digest, and every entry repeats it. Audit entry `N` includes the hash of entry `N-1`; its own hash is SHA-256 over the previous hash, a newline, and canonical JSON for the payload excluding `hash`. Verification strictly validates bundle, policy, decision, and entry schemas before checking the declared policy digest, indexes, links, and content hashes.

All quota rules matching a tool are evaluated and, on an allowed call, incremented together. Any exhausted matching quota contributes a deny, preserving deny-overrides semantics.

The simulator intentionally separates policy behavior from transport behavior. It parses JSON-RPC-shaped lines but does not bind a socket or impersonate an MCP server.

## MCP services

`trustline-mcp serve-stdio` and `trustline-mcp serve-http` add real outer MCP
transports around the existing offline lab:

```text
client stdin -> bounded UTF-8 newline frame -> JSON-RPC + per-request metadata
             -> server/discover | tools/list | tools/call
             -> trustline.simulate -> bounded inner transcript -> simulator
             -> trustline.verify   -> audit verifier
             -> MCP tool result -> stdout JSON-RPC line
```

```text
loopback HTTP POST -> origin/media-type/byte bounds -> routing-header mirror
                   -> shared JSON-RPC + per-request metadata handler
                   -> direct application/json response
```

The outer protocol implements the modern `2026-07-28` stateless request model.
It never caches client identity, capabilities, or protocol version between
requests. The catalog is deterministic and every result identifies the server.
The HTTP service binds only to `127.0.0.1`, uses the same per-request stateless
handler, and accepts direct JSON responses rather than opening an SSE stream.
It verifies the MCP protocol version, method, and method-specific name headers
against the body before dispatch. Browser `Origin` values are restricted to
loopback origins as a DNS-rebinding defense. The official
`@modelcontextprotocol/client` v2 stdio and Streamable HTTP transports are used
as development-only interoperability tests; the shipped package retains zero
runtime dependencies.

The inner `trustline.transcript/v1` payload is deliberately separate. It is a
simplified replay input, not proof that the recorded messages conform to the
current MCP revision. In particular, its `approvedBy` field is unverified replay
data. Quota state begins at zero for each `trustline.simulate` invocation and is
never inferred from a transport or process lifetime.

Requests are handled synchronously after bounded parsing. Valid notifications
produce no JSON-RPC response and do not invoke tools (`202 Accepted` over
HTTP). There is no long-running operation to cancel in this slice; EOF is
honored after the current bounded stdio request, and SIGINT or SIGTERM closes
the HTTP listener after active requests finish.

The independent message, transcript, and rule maxima are backed by an aggregate
8,000,000-unit admission budget. The estimator weights the complete policy
structure—including nested tool patterns, predicates, roots, and hosts—by the
transcript byte count plus its entry count before constructing the policy
engine. Counting entries separately covers per-entry setup even when transcript
strings are empty. This bounds the worst-case product for substring and
safe-pattern scans instead of allowing a caller to multiply every advertised
maximum together. Tool-name globs use an explicit wildcard state machine rather
than a dynamically constructed regular expression.

## Trust boundaries

- Trusted for the demo: checked-in policy, checked-in transcript, local Node runtime.
- Untrusted and redacted: request/response content. JSON-RPC IDs, methods, names, and arguments are runtime-validated before a fixture call.
- Untrusted for both services: every input byte, outer request field, policy,
  inner transcript, and audit bundle. HTTP headers and origins are untrusted as
  well. Byte, structure, and evaluation bounds are applied before the policy
  engine or verifier runs.
- Not provided: process isolation, network isolation, HTTP authentication,
  identity verification, durable quota storage, or multi-process
  synchronization. A loopback listener is reachable by other local processes.
