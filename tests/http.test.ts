import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import test from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { attackTranscript, demoPolicy } from "../src/demo.js";
import { listenStreamableHttp } from "../src/http.js";
import { MAX_MCP_MESSAGE_BYTES, MCP_PROTOCOL_VERSION } from "../src/stdio.js";

const requestMeta = {
  "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
  "io.modelcontextprotocol/clientCapabilities": {},
  "io.modelcontextprotocol/clientInfo": { name: "trustline-http-test", version: "1.0.0" },
};

function rpcRequest(id: number, method: string, params: Record<string, unknown> = {}): Record<string, unknown> {
  return { jsonrpc: "2.0", id, method, params: { ...params, _meta: structuredClone(requestMeta) } };
}

function mcpHeaders(method: string, name?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    "Mcp-Method": method,
  };
  if (name !== undefined) headers["Mcp-Name"] = name;
  return headers;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error === undefined ? resolve() : reject(error));
  });
}

async function responseJson(response: Response): Promise<Record<string, unknown>> {
  const value = await response.json() as unknown;
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}

async function rawPost(url: URL, rawHeaders: string[], body: string): Promise<{ status: number; body: string }> {
  return await new Promise((resolve, reject) => {
    const headers = [...rawHeaders, "Content-Length", String(Buffer.byteLength(body, "utf8"))];
    const request = httpRequest(url, { method: "POST", headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("error", reject);
      response.once("end", () => {
        resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") });
      });
    });
    request.once("error", reject);
    request.end(body);
  });
}

test("the official MCP v2 client negotiates, lists, and calls over Streamable HTTP", async () => {
  const { server, url } = await listenStreamableHttp(0);
  const transport = new StreamableHTTPClientTransport(url);
  const client = new Client(
    { name: "trustline-official-http-client-test", version: "1.0.0" },
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
    await closeServer(server);
  }
});

test("Streamable HTTP validates routing headers and remains stateless", async () => {
  const { server, url } = await listenStreamableHttp(0);
  try {
    const discoveryRequest = rpcRequest(1, "server/discover");
    const discovery = await fetch(url, {
      method: "POST",
      headers: mcpHeaders("server/discover"),
      body: JSON.stringify(discoveryRequest),
    });
    assert.equal(discovery.status, 200);
    assert.equal(((await responseJson(discovery)).result as { resultType: string }).resultType, "complete");

    const missingHeaders = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json, text/event-stream", "Content-Type": "application/json" },
      body: JSON.stringify(rpcRequest(2, "tools/list")),
    });
    assert.equal(missingHeaders.status, 400);
    assert.equal(((await responseJson(missingHeaders)).error as { code: number }).code, -32020);

    const mismatchedMethod = await fetch(url, {
      method: "POST",
      headers: mcpHeaders("tools/call"),
      body: JSON.stringify(rpcRequest(3, "tools/list")),
    });
    assert.equal(mismatchedMethod.status, 400);
    assert.equal(((await responseJson(mismatchedMethod)).error as { code: number }).code, -32020);

    const unicodeName = "trustline.\u2603";
    const encodedName = `=?base64?${Buffer.from(unicodeName, "utf8").toString("base64")}?=`;
    const unknownTool = await fetch(url, {
      method: "POST",
      headers: mcpHeaders("tools/call", encodedName),
      body: JSON.stringify(rpcRequest(4, "tools/call", { name: unicodeName, arguments: {} })),
    });
    assert.equal(unknownTool.status, 200);
    assert.equal(((await responseJson(unknownTool)).error as { code: number }).code, -32602);

    for (const [index, name] of ["__proto__", "constructor", "toString"].entries()) {
      const inheritedName = await fetch(url, {
        method: "POST",
        headers: mcpHeaders("tools/call", name),
        body: JSON.stringify(rpcRequest(40 + index, "tools/call", { name, arguments: {} })),
      });
      assert.equal(inheritedName.status, 200);
      const error = (await responseJson(inheritedName)).error as { code: number; message: string };
      assert.equal(error.code, -32602);
      assert.equal(error.message, `Unknown tool: ${name}`);
    }

    const duplicatedMethod = await rawPost(url, [
      "Accept", "application/json, text/event-stream",
      "Content-Type", "application/json",
      "MCP-Protocol-Version", MCP_PROTOCOL_VERSION,
      "Mcp-Method", "tools/list",
      "Mcp-Method", "tools/call",
    ], JSON.stringify(rpcRequest(5, "tools/list")));
    assert.equal(duplicatedMethod.status, 400);
    if (duplicatedMethod.body !== "") {
      assert.equal((JSON.parse(duplicatedMethod.body) as { error: { code: number } }).error.code, -32020);
    }

    const notification = await fetch(url, {
      method: "POST",
      headers: { Accept: "application/json, text/event-stream", "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: {} }),
    });
    assert.equal(notification.status, 202);
    assert.equal(await notification.text(), "");
  } finally {
    await closeServer(server);
  }
});

test("Streamable HTTP fails closed at its network and parser boundaries", async () => {
  const { server, url } = await listenStreamableHttp(0);
  try {
    const foreignOrigin = await fetch(url, {
      method: "POST",
      headers: { ...mcpHeaders("tools/list"), Origin: "https://example.com" },
      body: JSON.stringify(rpcRequest(1, "tools/list")),
    });
    assert.equal(foreignOrigin.status, 403);

    const localOrigin = "http://localhost:3000";
    const acceptedOrigin = await fetch(url, {
      method: "POST",
      headers: { ...mcpHeaders("tools/list"), Origin: localOrigin },
      body: JSON.stringify(rpcRequest(2, "tools/list")),
    });
    assert.equal(acceptedOrigin.status, 200);
    assert.equal(acceptedOrigin.headers.get("access-control-allow-origin"), localOrigin);

    const wrongMethod = await fetch(url, { method: "GET" });
    assert.equal(wrongMethod.status, 405);
    assert.equal(wrongMethod.headers.get("allow"), "POST");

    const wrongPath = await fetch(new URL("/not-mcp", url), { method: "POST" });
    assert.equal(wrongPath.status, 404);

    const wrongContentType = await fetch(url, {
      method: "POST",
      headers: { ...mcpHeaders("tools/list"), "Content-Type": "text/plain" },
      body: JSON.stringify(rpcRequest(3, "tools/list")),
    });
    assert.equal(wrongContentType.status, 415);

    const wrongAccept = await fetch(url, {
      method: "POST",
      headers: { ...mcpHeaders("tools/list"), Accept: "application/json" },
      body: JSON.stringify(rpcRequest(4, "tools/list")),
    });
    assert.equal(wrongAccept.status, 406);

    const invalidUtf8 = await fetch(url, {
      method: "POST",
      headers: mcpHeaders("tools/list"),
      body: Buffer.from([0xff]),
    });
    assert.equal(invalidUtf8.status, 400);
    assert.equal(((await responseJson(invalidUtf8)).error as { code: number }).code, -32700);

    const oversized = await fetch(url, {
      method: "POST",
      headers: mcpHeaders("tools/list"),
      body: Buffer.alloc(MAX_MCP_MESSAGE_BYTES + 1, 0x20),
    });
    assert.equal(oversized.status, 413);
  } finally {
    await closeServer(server);
  }
});
