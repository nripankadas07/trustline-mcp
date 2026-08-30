# Release process

1. Run `npm ci && npm run package:smoke && npm run check` on Node 22. The smoke test packs from source, installs the tarball, imports the library, executes the installed CLI, and negotiates the installed stdio service with the official MCP v2 client.
2. Compare demo totals/root to `examples/golden/expected.json`.
3. Run `node dist/src/cli.js verify artifacts/demo/audit.json`.
4. Confirm the report contains no fixture secrets.
5. Review policy, policy-digest, audit-bundle, audit-entry, transcript, and report schema versions.
6. Update package version and `CHANGELOG.md` together.
7. Package source plus the demo evidence; do not describe the simulator or its stdio service as a downstream tool proxy, authenticated approval system, or OAuth/HTTP interceptor.
