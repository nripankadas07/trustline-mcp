import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { attackTranscript, demoPolicy } from "../src/demo.js";
import {
  MAX_MCP_MESSAGE_BYTES,
  MAX_TRANSCRIPT_LINES,
  MCP_PROTOCOL_VERSION,
  handleMcpMessage,
} from "../src/stdio.js";

const requestMeta = {
  "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
  "io.modelcontextprotocol/clientCapabilities": {},
  "io.modelcontextprotocol/clientInfo": { name: "trustline-test", version: "1.0.0" },
};

function request(id: number, method: string, params: Record<string, unknown> = {}): unknown {
  return { jsonrpc: "2.0", id, method, params: { ...params, _meta: structuredClone(requestMeta) } };
}

function resultOf(response: unknown): Record<string, unknown> {
  assert.ok(response !== null && typeof response === "object" && "result" in response);
  const result = (response as { result: unknown }).result;
  assert.ok(result !== null && typeof result === "object");
  return result as Record<string, unknown>;
}

function errorOf(response: unknown): Record<string, unknown> {
  assert.ok(response !== null && typeof response === "object" && "error" in response);
  const error = (response as { error: unknown }).error;
  assert.ok(error !== null && typeof error === "object");
  return error as Record<string, unknown>;
}

test("modern discovery and tools/list expose a deterministic stateless catalog", () => {
  const discovery = resultOf(handleMcpMessage(request(1, "server/discover")));
  assert.deepEqual(discovery.supportedVersions, [MCP_PROTOCOL_VERSION]);
  assert.deepEqual(discovery.capabilities, { tools: {} });
  assert.equal(discovery.resultType, "complete");

  const listed = resultOf(handleMcpMessage(request(2, "tools/list")));
  assert.equal(listed.resultType, "complete");
  assert.deepEqual(
    (listed.tools as Array<{ name: string; inputSchema: { type: string } }>).map((tool) => tool.name),
    ["trustline.simulate", "trustline.verify"],
  );
  assert.ok((listed.tools as Array<{ inputSchema: { type: string } }>).every((tool) => tool.inputSchema.type === "object"));
  assert.equal(listed.cacheScope, "public");
  assert.equal(listed.ttlMs, 3_600_000);

  const optionalClientInfo = request(3, "tools/list") as { params: { _meta: Record<string, unknown> } };
  delete optionalClientInfo.params._meta["io.modelcontextprotocol/clientInfo"];
  assert.equal(resultOf(handleMcpMessage(optionalClientInfo)).resultType, "complete");
});

test("simulate and verify round-trip redacted, tamper-evident results", () => {
  const simulated = resultOf(handleMcpMessage(request(3, "tools/call", {
    name: "trustline.simulate",
    arguments: { policy: demoPolicy, transcript: attackTranscript },
  })));
  assert.equal(simulated.resultType, "complete");
  assert.equal(simulated.isError, false);
  const structured = simulated.structuredContent as Record<string, unknown>;
  assert.deepEqual(structured.totals, {
    lines: 11,
    allowed: 4,
    denied: 5,
    approvalRequired: 1,
    protocolErrors: 1,
  });
  const encoded = JSON.stringify(simulated);
  assert.ok(!encoded.includes("synthetic-demo-token-123456"));
  assert.ok(!encoded.includes("very-secret-token"));

  const audit = structured.audit;
  const verified = resultOf(handleMcpMessage(request(4, "tools/call", {
    name: "trustline.verify",
    arguments: { audit },
  })));
  assert.equal(verified.isError, false);
  assert.equal((verified.structuredContent as { valid: boolean }).valid, true);

  const tampered = structuredClone(audit) as { entries: Array<{ hash: string }> };
  tampered.entries[0]!.hash = "0".repeat(64);
  const rejected = resultOf(handleMcpMessage(request(5, "tools/call", {
    name: "trustline.verify",
    arguments: { audit: tampered },
  })));
  assert.equal(rejected.isError, true);
  assert.equal((rejected.structuredContent as { valid: boolean }).valid, false);
});

test("metadata, methods, tools, and transcript bounds fail closed", () => {
  assert.equal(errorOf(handleMcpMessage({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} })).code, -32602);

  const unsupported = request(2, "tools/list") as { params: { _meta: Record<string, unknown> } };
  unsupported.params._meta["io.modelcontextprotocol/protocolVersion"] = "1900-01-01";
  const versionError = errorOf(handleMcpMessage(unsupported));
  assert.equal(versionError.code, -32022);
  assert.deepEqual((versionError.data as { supported: string[] }).supported, [MCP_PROTOCOL_VERSION]);

  assert.equal(errorOf(handleMcpMessage(request(3, "unknown/method"))).code, -32601);
  assert.equal(errorOf(handleMcpMessage(request(4, "tools/call", { name: "unknown.tool", arguments: {} }))).code, -32602);
  assert.equal(errorOf(handleMcpMessage(request(41, "tools/list", { cursor: "unexpected" }))).code, -32602);

  for (const id of [null, true, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    const invalidId = request(42, "tools/list") as Record<string, unknown>;
    invalidId.id = id;
    const response = handleMcpMessage(invalidId);
    assert.equal(errorOf(response).code, -32600);
    assert.ok(response !== null && typeof response === "object" && !Object.hasOwn(response, "id"));
  }

  const invalidCapabilities = request(43, "tools/list") as { params: { _meta: Record<string, unknown> } };
  invalidCapabilities.params._meta["io.modelcontextprotocol/clientCapabilities"] = [];
  assert.equal(errorOf(handleMcpMessage(invalidCapabilities)).code, -32602);

  const initialize = errorOf(handleMcpMessage({ jsonrpc: "2.0", id: 44, method: "initialize", params: {} }));
  assert.equal(initialize.code, -32601);
  assert.match(String(initialize.message), /2026-07-28/u);

  const oversizedTranscript = Array.from({ length: MAX_TRANSCRIPT_LINES + 1 }, () => "{}");
  const bounded = resultOf(handleMcpMessage(request(5, "tools/call", {
    name: "trustline.simulate",
    arguments: { policy: demoPolicy, transcript: oversizedTranscript },
  })));
  assert.equal(bounded.isError, true);
  assert.match(JSON.stringify(bounded.content), /transcript.*limit/iu);

  assert.equal(handleMcpMessage({ jsonrpc: "2.0", method: "notifications/cancelled", params: {} }), null);
  assert.equal(handleMcpMessage({ jsonrpc: "1.0", method: "tools/call", params: { name: "trustline.simulate" } }), null);

  let deep: unknown = "leaf";
  for (let index = 0; index < 70; index += 1) deep = { nested: deep };
  const deepRequest = request(6, "tools/call", { name: "trustline.verify", arguments: { audit: deep } });
  const deepResponse = handleMcpMessage(deepRequest);
  assert.equal(errorOf(deepResponse).code, -32600);
  assert.equal((deepResponse as { id: number }).id, 6);
});

test("aggregate simulation work is rejected before costly policy evaluation", () => {
  const expensivePolicy = {
    ...structuredClone(demoPolicy),
    name: "aggregate-work-regression",
    argumentRules: Array.from({ length: 16 }, (_, index) => ({
      id: `expensive-${index}`,
      effect: "deny" as const,
      tool: "fixture.echo",
      path: "text",
      operator: "matches" as const,
      value: `${"a".repeat(255)}b`,
    })),
  };
  const expensiveTranscript = [JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "fixture.echo", arguments: { text: "a".repeat(32_000) } },
  })];
  const rejected = resultOf(handleMcpMessage(request(7, "tools/call", {
    name: "trustline.simulate",
    arguments: { policy: expensivePolicy, transcript: expensiveTranscript },
  })));
  assert.equal(rejected.isError, true);
  assert.match(JSON.stringify(rejected.content), /aggregate policy evaluation work.*limit/iu);

  const repeatedSetupPolicy = {
    ...structuredClone(demoPolicy),
    name: "per-entry-setup-regression",
    redactKeys: Array.from({ length: 10_000 }, (_, index) => `synthetic-key-${index}`),
  };
  const repeatedSetup = resultOf(handleMcpMessage(request(8, "tools/call", {
    name: "trustline.simulate",
    arguments: {
      policy: repeatedSetupPolicy,
      transcript: Array.from({ length: MAX_TRANSCRIPT_LINES }, () => ""),
    },
  })));
  assert.equal(repeatedSetup.isError, true);
  assert.match(JSON.stringify(repeatedSetup.content), /aggregate policy evaluation work.*limit/iu);
});

test("serve-stdio frames only JSON-RPC on stdout and exits at EOF", async () => {
  const child = spawn(process.execPath, ["dist/src/cli.js", "serve-stdio"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });

  child.stdin.write(`${JSON.stringify(request(1, "server/discover"))}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: {} })}\n`);
  child.stdin.write("{not-json}\n");
  child.stdin.write(`${" ".repeat(MAX_MCP_MESSAGE_BYTES + 1)}\n`);
  child.stdin.write(Buffer.from([0xff, 0x0a]));
  child.stdin.write(`${JSON.stringify(request(2, "tools/list"))}\n`);
  child.stdin.end();

  const [exitCode] = await new Promise<[number | null]>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => { resolve([code]); });
  });
  assert.equal(exitCode, 0, stderr);
  assert.equal(stderr, "");
  const messages = stdout.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  assert.equal(messages.length, 5);
  assert.equal((messages[0]!.result as { resultType: string }).resultType, "complete");
  assert.equal((messages[1]!.error as { code: number }).code, -32700);
  assert.equal((messages[2]!.error as { code: number }).code, -32600);
  assert.equal((messages[3]!.error as { code: number }).code, -32700);
  assert.equal((messages[4]!.result as { resultType: string }).resultType, "complete");
  assert.ok(!Object.hasOwn(messages[1]!, "id"));
  assert.ok(!Object.hasOwn(messages[2]!, "id"));
});

test("the official MCP v2 client negotiates, lists, and calls the stdio service", async () => {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["dist/src/cli.js", "serve-stdio"],
    cwd: process.cwd(),
    stderr: "pipe",
  });
  const client = new Client(
    { name: "trustline-official-client-test", version: "1.0.0" },
    { versionNegotiation: { mode: { pin: MCP_PROTOCOL_VERSION } } },
  );
  try {
    await client.connect(transport);
    assert.equal(client.getProtocolEra(), "modern");
    assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ["trustline.simulate", "trustline.verify"]);
    const result = await client.callTool({
      name: "trustline.simulate",
      arguments: { policy: demoPolicy, transcript: attackTranscript },
    });
    assert.equal(result.isError, false);
    const structured = result.structuredContent as { totals: { lines: number }; verification: { valid: boolean } };
    assert.equal(structured.totals.lines, attackTranscript.length);
    assert.equal(structured.verification.valid, true);
  } finally {
    await client.close();
  }
});
