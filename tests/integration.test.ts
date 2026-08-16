import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rename as fsRename, rmdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { attackTranscript, demoPolicy } from "../src/demo.js";
import { markdownReport, writeArtifacts } from "../src/report.js";
import { writeArtifactSet } from "../src/safe-output.js";
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

test("JSON-RPC notifications retain their audit decision without emitting a response", () => {
  const notification = JSON.stringify({ jsonrpc: "2.0", method: "tools/call", params: { name: "repo.read", arguments: { path: "/workspace/README.md" } } });
  const result = simulateTranscript(demoPolicy, [notification]);
  assert.equal(result.totals.allowed, 1);
  assert.equal(result.entries[0]?.decision?.effect, "allow");
  assert.equal(result.entries[0]?.response, null);
  assert.equal(verifyAudit(auditBundle(result)).valid, true);
});

test("CLI rejects trailing operands and option-like output paths", () => {
  for (const args of [["demo", "out", "extra"], ["demo", "--typo"], ["verify", "audit.json", "extra"]]) {
    const cli = spawnSync(process.execPath, ["dist/src/cli.js", ...args], { encoding: "utf8" });
    assert.equal(cli.status, 1);
    assert.match(cli.stderr, /usage:/u);
  }
});

test("artifact publication rejects symlink and non-directory targets before writing", async () => {
  const root = await mkdtemp(join(tmpdir(), "trustline-safe-output-"));
  const victim = join(root, "victim.txt");
  await writeFile(victim, "unchanged\n");
  const result = simulateTranscript(demoPolicy, attackTranscript);

  const fileTarget = join(root, "file-target");
  await mkdir(fileTarget);
  await symlink(victim, join(fileTarget, "audit.json"));
  await assert.rejects(writeArtifacts(fileTarget, result), /regular file/u);
  assert.equal(await readFile(victim, "utf8"), "unchanged\n");
  assert.deepEqual(await readdir(fileTarget), ["audit.json"]);

  const directoryVictim = join(root, "directory-victim");
  await mkdir(directoryVictim);
  const linkedOutput = join(root, "linked-output");
  await symlink(directoryVictim, linkedOutput);
  await assert.rejects(writeArtifacts(linkedOutput, result), /symbolic-link component/u);
  await assert.rejects(writeArtifacts(join(linkedOutput, "nested"), result), /symbolic-link component/u);
  assert.deepEqual(await readdir(directoryVictim), []);

  const parentFile = join(root, "not-a-directory");
  await writeFile(parentFile, "x");
  await assert.rejects(writeArtifacts(join(parentFile, "child"), result));

  const transactional = join(root, "transactional");
  await mkdir(transactional);
  await writeFile(join(transactional, "one.txt"), "original\n");
  let publishes = 0;
  await assert.rejects(writeArtifactSet(transactional, { "one.txt": "replacement\n", "two.txt": "new\n" }, {
    publishRename: async (source, destination) => {
      publishes += 1;
      if (publishes === 2) throw new Error("injected second publish failure");
      await fsRename(source, destination);
    },
  }), /injected second publish failure/u);
  assert.equal(publishes, 2);
  assert.equal(await readFile(join(transactional, "one.txt"), "utf8"), "original\n");
  assert.deepEqual(await readdir(transactional), ["one.txt"]);

  const ambiguous = join(root, "ambiguous-rename");
  await mkdir(ambiguous);
  await writeFile(join(ambiguous, "one.txt"), "original-one\n");
  await writeFile(join(ambiguous, "two.txt"), "original-two\n");
  let completedRenames = 0;
  await assert.rejects(writeArtifactSet(ambiguous, { "one.txt": "replacement-one\n", "two.txt": "replacement-two\n" }, {
    publishRename: async (source, destination) => {
      await fsRename(source, destination);
      completedRenames += 1;
      if (completedRenames === 2) throw new Error("injected post-rename failure");
    },
  }), /injected post-rename failure/u);
  assert.equal(await readFile(join(ambiguous, "one.txt"), "utf8"), "original-one\n");
  assert.equal(await readFile(join(ambiguous, "two.txt"), "utf8"), "original-two\n");
  assert.deepEqual(await readdir(ambiguous), ["one.txt", "two.txt"]);

  const concurrent = join(root, "concurrent-writers");
  await mkdir(concurrent);
  const pause = async (): Promise<void> => new Promise((resolvePause) => { setTimeout(resolvePause, 20); });
  const writer = async (label: "A" | "B"): Promise<void> => {
    let writerRenames = 0;
    await writeArtifactSet(concurrent, { "one.txt": `${label}\n`, "two.txt": `${label}\n` }, {
      publishRename: async (source, destination) => {
        writerRenames += 1;
        if (label === "A" && writerRenames === 1) await pause();
        await fsRename(source, destination);
        if (label === "B" && writerRenames === 1) await pause();
      },
    });
  };
  await Promise.all([writer("A"), writer("B")]);
  const concurrentContents = await Promise.all(["one.txt", "two.txt"].map(async (name) => readFile(join(concurrent, name), "utf8")));
  assert.equal(concurrentContents[0], concurrentContents[1]);
  assert.ok(concurrentContents[0] === "A\n" || concurrentContents[0] === "B\n");
  assert.deepEqual(await readdir(concurrent), ["one.txt", "two.txt"]);

  const stale = join(root, "stale-lock");
  await mkdir(stale);
  const staleLock = join(stale, ".artifact-write.lock");
  await mkdir(staleLock);
  await assert.rejects(writeArtifactSet(stale, { "one.txt": "unpublished\n" }, { lockTimeoutMs: 0 }), /lock is held or stale/u);
  assert.deepEqual(await readdir(stale), [".artifact-write.lock"]);
  await rmdir(staleLock);
});
