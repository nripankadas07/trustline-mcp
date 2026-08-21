# Trustline schemas

Schemas use JSON Schema 2020-12 and are versioned with the artifacts they
describe. Consumers should select a schema by the artifact's exact `version`
field rather than assuming forward compatibility.

## Policy v1

`trustline.policy.v1.schema.json` describes the portable JSON shape accepted by
`trustline.policy/v1`.

When Trustline is installed as a package, resolve the schema through
`trustline-mcp/schemas/trustline.policy.v1.schema.json`. The conformance entry
point is exported separately as
`trustline-mcp/fixtures/conformance/manifest.json`; its case files are relative
to the manifest and are included in the package.

JSON Schema is the adapter edge, not a replacement for `assertPolicy`. The
runtime additionally enforces constraints that JSON Schema cannot express
portably here, including:

- rule IDs are unique across every rule family;
- `redactKeys` are unique without regard to case;
- match patterns use Trustline's bounded safe-regex subset.

The portable schema and runtime both enforce nonnegative JavaScript safe-integer
quota limits, primitive argument-rule values, and host allowlist lexical
constraints. The checks listed above remain runtime-only because JSON Schema
cannot express them portably in this contract.

Use `fixtures/conformance/manifest.json` to test both layers. A case may be
schema-valid and runtime-invalid by design.
