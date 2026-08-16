import assert from "node:assert/strict";
import test from "node:test";
import { demoPolicy } from "../src/demo.js";
import { POLICY_VERSION, PolicyEngine, type Policy } from "../src/policy.js";

test("deny overrides allow and approval", () => {
  const engine = new PolicyEngine(demoPolicy);
  const decision = engine.evaluate({ name: "shell.safe", arguments: { command: "sudo rm -rf build" } }, { approvedBy: "reviewer" });
  assert.equal(decision.effect, "deny");
  assert.ok(decision.reasonCodes.includes("argument-deny"));
});

test("path traversal and hosts are denied", () => {
  const engine = new PolicyEngine(demoPolicy);
  assert.equal(engine.evaluate({ name: "repo.read", arguments: { path: "/workspace/../etc/passwd" } }).effect, "deny");
  assert.equal(engine.evaluate({ name: "docs.search", arguments: { url: "http://169.254.169.254/latest" } }).effect, "deny");
});

test("path and host allowlists fail closed on missing, non-string, and malformed arguments", () => {
  const engine = new PolicyEngine(demoPolicy);
  for (const path of [undefined, 42, "", "bad\0path"]) {
    const args = path === undefined ? {} : { path };
    const decision = engine.evaluate({ name: "repo.read", arguments: args });
    assert.equal(decision.effect, "deny");
    assert.ok(decision.reasonCodes.includes("path-invalid"));
  }
  for (const url of [undefined, 42, "", "http://["]) {
    const args = url === undefined ? {} : { url };
    const decision = engine.evaluate({ name: "docs.search", arguments: args });
    assert.equal(decision.effect, "deny");
    assert.ok(decision.reasonCodes.includes("host-invalid"));
  }
});

test("invalid configured regular expressions are rejected before evaluation", () => {
  const policy: Policy = {
    version: POLICY_VERSION,
    name: "invalid-regex",
    defaultEffect: "deny",
    toolRules: [{ id: "allow", effect: "allow", tools: ["fixture"] }],
    argumentRules: [{ id: "broken", effect: "deny", tool: "fixture", path: "value", operator: "matches", value: "[" }],
  };
  assert.throws(() => new PolicyEngine(policy), /broken contains an invalid regex/u);
});

test("approval identity must be a nonblank string", () => {
  const engine = new PolicyEngine(demoPolicy);
  const call = { name: "shell.safe", arguments: { command: "npm test" } };
  assert.equal(engine.evaluate(call, { approvedBy: "reviewer" }).effect, "allow");
  assert.equal(engine.evaluate(call, { approvedBy: "" }).effect, "approval");
  assert.equal(engine.evaluate(call, { approvedBy: "   " }).effect, "approval");
  assert.equal(engine.evaluate(call, { approvedBy: 7 as unknown as string }).effect, "approval");
});

test("quota counts only allowed calls", () => {
  const engine = new PolicyEngine(demoPolicy);
  const call = { name: "docs.search", arguments: { url: "https://docs.example.test/x" } };
  assert.equal(engine.evaluate(call).effect, "allow");
  assert.equal(engine.evaluate(call).effect, "allow");
  const third = engine.evaluate(call);
  assert.equal(third.effect, "deny");
  assert.ok(third.reasonCodes.includes("quota-exceeded"));
});

test("every overlapping quota is enforced and incremented", () => {
  const policy: Policy = {
    version: POLICY_VERSION,
    name: "overlapping-quotas",
    defaultEffect: "deny",
    toolRules: [{ id: "allow", effect: "allow", tools: ["repo.*"] }],
    quotas: [
      { id: "broad", tool: "repo.*", limit: 10 },
      { id: "strict", tool: "repo.read", limit: 1 },
    ],
  };
  const engine = new PolicyEngine(policy);
  const call = { name: "repo.read", arguments: {} };
  assert.equal(engine.evaluate(call).effect, "allow");
  const denied = engine.evaluate(call);
  assert.equal(denied.effect, "deny");
  assert.deepEqual(denied.matchedRuleIds, ["strict"]);
});

test("runtime policy validation rejects malformed fail-open rules and quotas", () => {
  const base: Policy = {
    version: POLICY_VERSION,
    name: "runtime-validation",
    defaultEffect: "deny",
    toolRules: [{ id: "allow", effect: "allow", tools: ["*"] }],
  };
  assert.throws(() => new PolicyEngine({ ...base, argumentRules: [{ id: "bad", effect: "deny", tool: "*", path: "x", operator: "typo" as "present" }] }), /unsupported operator/u);
  assert.throws(() => new PolicyEngine({ ...base, argumentRules: [{ id: "bad-equals", effect: "deny", tool: "*", path: "x", operator: "equals", value: {} as unknown as string }] }), /primitive value/u);
  assert.throws(() => new PolicyEngine({ ...base, argumentRules: [{ id: "bad-path", effect: "deny", tool: "*", path: "a..b", operator: "present" }] }), /empty segment/u);
  assert.throws(() => new PolicyEngine({ ...base, quotas: [{ id: "q", tool: "*", limit: "unlimited" as unknown as number }] }), /nonnegative safe integer/u);
  assert.throws(() => new PolicyEngine({ ...base, hostRules: [{ id: "h", effect: "allow", tool: "*", argument: "url", hosts: ["*."] }] }), /invalid hostname/u);
  assert.throws(() => new PolicyEngine({ ...base, quotaRules: [{ id: "q", tool: "*", limit: 0 }] } as unknown as Policy), /unsupported field quotaRules/u);
});

test("nested argument matching never reads inherited prototype properties", () => {
  const policy: Policy = {
    version: POLICY_VERSION,
    name: "own-properties",
    defaultEffect: "deny",
    toolRules: [],
    argumentRules: [{ id: "constructor-present", effect: "allow", tool: "fixture", path: "constructor", operator: "present" }],
  };
  assert.equal(new PolicyEngine(policy).evaluate({ name: "fixture", arguments: {} }).effect, "default-deny");
});
