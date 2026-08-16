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

## Trust boundaries

- Trusted for the demo: checked-in policy, checked-in transcript, local Node runtime.
- Untrusted and redacted: request/response content. JSON-RPC IDs, methods, names, and arguments are runtime-validated before a fixture call.
- Not provided: process isolation, network isolation, identity verification, durable quota storage, multi-process synchronization.
