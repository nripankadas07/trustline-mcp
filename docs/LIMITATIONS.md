# Limitations

- This is an offline JSON-RPC transcript simulator, not a transparent MCP proxy.
- It does not terminate OAuth, inspect encrypted HTTP traffic, enforce operating-system permissions, or isolate commands.
- Host checks are string/URL checks, not DNS-rebinding protection.
- Path checks are lexical and do not resolve symlinks or filesystem mount boundaries.
- Regex policies can be incomplete and are not a substitute for typed argument validation.
- Quotas live in one in-memory engine instance.
- The chain binds entries to the complete declared policy configuration, but an unsigned bundle can still be replaced and rehashed wholesale. SHA-256 chaining does not establish signer identity; add an external signing system if provenance is required.
- Redaction covers configured/standard secret keys, common token shapes, and URL userinfo/query credentials, but cannot prove that every secret shape is covered. Do not put secrets in policy names, rule IDs, or other metadata.
- Only the fixture tool adapter is included. A production integration would require explicit, reviewed transport and identity adapters.
