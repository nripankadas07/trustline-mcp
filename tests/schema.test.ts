import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import { assertPolicy } from "../src/policy.js";

interface ConformanceCase {
  file: string;
  schemaValid: boolean;
  runtimeValid: boolean;
}

interface ConformanceManifest {
  version: "trustline.conformance/v1";
  schema: string;
  cases: ConformanceCase[];
}

async function readJson(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

function runtimeAccepts(value: unknown): boolean {
  try {
    assertPolicy(value);
    return true;
  } catch {
    return false;
  }
}

test("published policy schema and runtime agree with the conformance manifest", async () => {
  const manifestPath = "fixtures/conformance/manifest.json";
  const manifest = await readJson(manifestPath) as ConformanceManifest;
  assert.equal(manifest.version, "trustline.conformance/v1");

  const schema = await readJson(join(dirname(manifestPath), manifest.schema));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema as AnySchema);

  for (const conformanceCase of manifest.cases) {
    const value = await readJson(join(dirname(manifestPath), conformanceCase.file));
    assert.equal(
      validate(value),
      conformanceCase.schemaValid,
      `${conformanceCase.file}: ${JSON.stringify(validate.errors)}`,
    );
    assert.equal(
      runtimeAccepts(value),
      conformanceCase.runtimeValid,
      `${conformanceCase.file}: unexpected runtime validation result`,
    );
  }
});

test("the checked-in demo policy validates against the public schema", async () => {
  const schema = await readJson("schemas/trustline.policy.v1.schema.json");
  const policy = await readJson("fixtures/policy.json");
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema as AnySchema);

  assert.equal(validate(policy), true, JSON.stringify(validate.errors));
  assert.doesNotThrow(() => assertPolicy(policy));
});
