import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { attackTranscript, demoPolicy } from "../src/demo.js";
import { markdownReport, writeArtifacts } from "../src/report.js";
import { auditBundle, digestPolicy, simulateTranscript, verifyAudit } from "../src/simulator.js";

test("offline attack transcript is redacted, deterministic, and verifiable", async () => {
  const first = simulateTranscript(demoPolicy, attackTranscript);
  const second = simulateTranscript(demoPolicy, attackTranscript);
  assert.deepEqual(first, second);
  assert.deepEqual(first.totals, { lines: 11, allowed: 4, denied: 5, approvalRequired: 1, protocolErrors: 1 });
  assert.equal(verifyAudit(auditBundle(first)).valid, true);
  assert.ok(!JSON.stringify(first).includes("synthetic-demo-token"));
  assert.ok(!JSON.stringify(first).includes("very-secret-token"));

  const tampered = auditBundle(first);
  const entry = tampered.entries[1];
  assert.ok(entry);
  entry.response = { changed: true };
  const tamperedVerification = verifyAudit(tampered);
  assert.equal(tamperedVerification.valid, false);
  assert.equal(tamperedVerification.index, 1);
  assert.equal(tamperedVerification.reason, "entry hash mismatch");
  assert.equal(tamperedVerification.rootHash, tampered.entries[0]?.hash);

  const out = await mkdtemp(join(tmpdir(), "trustline-"));
  await writeArtifacts(out, first);
  const html = await readFile(join(out, "index.html"), "utf8");
  const markdown = await readFile(join(out, "report.md"), "utf8");
  assert.match(html, /<!doctype html>/u);
  assert.match(markdown, /Audit valid: \*\*true\*\*/u);

  const golden = JSON.parse(await readFile("examples/golden/expected.json", "utf8")) as { totals: typeof first.totals; rootHash: string };
  assert.deepEqual(first.totals, golden.totals);
  assert.equal(verifyAudit(auditBundle(first)).rootHash, golden.rootHash);
});

test("Markdown reports collapse untrusted policy labels to one inert line", () => {
  const policy = structuredClone(demoPolicy);
  policy.name = "safe\n\n## Forged section\n- forged";
  const markdown = markdownReport(simulateTranscript(policy, []));
  assert.ok(!markdown.includes("\n## Forged section"));
  assert.ok(!markdown.includes("\n- forged"));
  assert.match(markdown, /Policy: \*\*safe ## Forged section - forged\*\*/u);
});

test("audit verifier rejects malformed schemas and unsupported versions without throwing", () => {
  for (const candidate of [{}, [], null, "", { version: "trustline.audit-bundle/v1", entries: {} }, { version: "trustline.audit-bundle/v999", entries: [] }]) {
    assert.doesNotThrow(() => verifyAudit(candidate));
    assert.equal(verifyAudit(candidate).valid, false);
  }
  const result = simulateTranscript(demoPolicy, attackTranscript.slice(0, 1));
  const bundle = auditBundle(result);
  const entry = bundle.entries[0];
  assert.ok(entry);
  entry.version = "trustline.audit/v999" as typeof entry.version;
  assert.equal(verifyAudit(bundle).reason, "unsupported entry version");

  const nonJson = auditBundle(result);
  const nonJsonEntry = nonJson.entries[0];
  assert.ok(nonJsonEntry);
  nonJsonEntry.request = new Date("2026-01-01T00:00:00.000Z");
  assert.equal(verifyAudit(nonJson).reason, "request and response must be JSON values");
});

test("audit chain commits to the declared policy and CLI exits nonzero on invalid bundles", async () => {
  const result = simulateTranscript(demoPolicy, attackTranscript.slice(0, 1));
  const bundle = auditBundle(result);
  bundle.policy.name = "substituted-policy";
  assert.notEqual(digestPolicy(bundle.policy), bundle.policyDigest);
  assert.equal(verifyAudit(bundle).reason, "policy digest mismatch");

  const out = await mkdtemp(join(tmpdir(), "trustline-invalid-audit-"));
  const path = join(out, "invalid.json");
  await writeFile(path, "{}\n");
  const cli = spawnSync(process.execPath, ["dist/src/cli.js", "verify", path], { encoding: "utf8" });
  assert.equal(cli.status, 1, cli.stderr);
  assert.equal((JSON.parse(cli.stdout) as { valid: boolean }).valid, false);
});

test("malformed JSON-RPC IDs and blank tool names fail closed, and URL credentials are redacted", () => {
  const lines = [
    JSON.stringify({ jsonrpc: "2.0", id: { invalid: true }, method: "tools/call", params: { name: "repo.read", arguments: { path: "/workspace/a" } } }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: " ", arguments: {} } }),
    JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "docs.search", arguments: { url: "https://alice:plain-password@docs.example.test/?token=plain-token#api_key=fragment-secret" } } }),
  ];
  const result = simulateTranscript(demoPolicy, lines);
  assert.deepEqual(result.totals, { lines: 3, allowed: 1, denied: 0, approvalRequired: 0, protocolErrors: 2 });
  const serialized = JSON.stringify(result.entries);
  assert.ok(!serialized.includes("plain-password"));
  assert.ok(!serialized.includes("plain-token"));
  assert.ok(!serialized.includes("fragment-secret"));
  assert.ok(!serialized.includes("alice"));
});
