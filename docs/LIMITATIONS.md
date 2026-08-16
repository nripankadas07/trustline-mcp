# Limitations

- This is an offline JSON-RPC transcript simulator, not a transparent MCP proxy.
- It does not terminate OAuth, inspect encrypted HTTP traffic, enforce operating-system permissions, or isolate commands.
- Host checks are string/URL checks, not DNS-rebinding protection.
- Path checks are lexical and do not resolve symlinks or filesystem mount boundaries.
- Regex policies use a deliberately conservative subset: no grouping, alternation, backreferences, lookarounds, or repetition operators; patterns are capped at 256 code points and matched values at 100,000 code points. This prevents catastrophic backtracking but is not a substitute for typed argument validation.
- Artifact publication rejects symlinks in every existing output-path component, rechecks directory identities, stages complete sets, reconciles ambiguous rename failures, and rolls back on a publish failure. Cooperative writers serialize through a bounded five-second `.artifact-write.lock`; a crash or incomplete recovery leaves that lock in place so later writers fail closed. After verifying that no writer is active, an operator must inspect any `.artifact-stage-*` recovery directory before manually removing a stale lock. Non-cooperating processes are not serialized. Node does not expose portable directory-file-descriptor-relative rename APIs, so a process that can concurrently replace trusted ancestor directories may still race between identity checks and filesystem operations; choose an output tree not writable by an attacker.
- Explicit policy, transcript, and audit input paths follow the operating system's normal symlink resolution; the CLI does not claim an input-directory confinement boundary.
- Quotas live in one in-memory engine instance.
- The chain binds entries to the complete declared policy configuration, but an unsigned bundle can still be replaced and rehashed wholesale. SHA-256 chaining does not establish signer identity; add an external signing system if provenance is required.
- Redaction covers configured/standard secret keys, common token shapes, and URL userinfo/query credentials, but cannot prove that every secret shape is covered. Do not put secrets in policy names, rule IDs, or other metadata.
- Only the fixture tool adapter is included. A production integration would require explicit, reviewed transport and identity adapters.
