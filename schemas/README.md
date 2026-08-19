# Trustline schemas

Schemas use JSON Schema 2020-12 and are versioned with the artifacts they
describe. Consumers should select a schema by the artifact's exact `version`
field rather than assuming forward compatibility.

## Policy v1

`trustline.policy.v1.schema.json` describes the portable JSON shape accepted by
`trustline.policy/v1`.

JSON Schema is the adapter edge, not a replacement for `assertPolicy`. The
runtime additionally enforces constraints that JSON Schema cannot express
portably here, including:

- rule IDs are unique across every rule family;
- `redactKeys` are unique without regard to case;
- match patterns use Trustline's bounded safe-regex subset;
- host allowlists reject malformed hostnames; and
- quota limits are JavaScript safe integers.

Use `fixtures/conformance/manifest.json` to test both layers. A case may be
schema-valid and runtime-invalid by design.
