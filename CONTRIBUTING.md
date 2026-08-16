# Contributing

1. Open an issue describing the policy or artifact behavior to change.
2. Keep runtime dependencies at zero.
3. Add a test that fails before the change and covers deny-overrides behavior where relevant.
4. Run `npm test` and `npm run demo` on Node 22 or newer.
5. Document schema changes and introduce a new artifact version for breaking changes.

Security reports belong in the private process described in `SECURITY.md`, not a public issue.
