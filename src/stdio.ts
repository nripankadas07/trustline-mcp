import { once } from "node:events";
import type { Readable, Writable } from "node:stream";
import type { Policy } from "./policy.js";
import { auditBundle, simulateTranscript, verifyAudit } from "./simulator.js";

export const MCP_PROTOCOL_VERSION = "2026-07-28" as const;
export const MAX_MCP_MESSAGE_BYTES = 1_048_576;
export const MAX_TRANSCRIPT_LINES = 256;
export const MAX_TRANSCRIPT_LINE_BYTES = 32_768;
export const MAX_TRANSCRIPT_BYTES = 262_144;
export const MAX_JSON_NESTING = 64;
export const MAX_JSON_NODES = 20_000;
export const MAX_POLICY_RULES = 1_024;
export const MAX_SIMULATION_WORK_UNITS = 8_000_000;
export const MAX_MCP_RESPONSE_BYTES = 2_097_152;

const SERVER_INFO = { name: "trustline-mcp", version: "0.1.1" } as const;

type RequestId = string | number;

interface JsonRpcResultResponse {
  jsonrpc: "2.0";
  id: RequestId;
  result: Record<string, unknown>;
}

interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id?: RequestId;
  error: { code: number; message: string; data?: unknown };
}

export type McpResponse = JsonRpcResultResponse | JsonRpcErrorResponse;

class SafeInputError extends Error {}

const TOOLS = [
  {
    name: "trustline.simulate",
    title: "Simulate a Trustline policy transcript",
    description: "Evaluate a complete offline JSON-RPC transcript against a Trustline policy and return a redacted, tamper-evident audit bundle. No commands, network calls, or files are accessed.",
    inputSchema: {
      type: "object",
      properties: {
        policy: { type: "object", description: "A trustline.policy/v1 policy." },
        transcript: {
          type: "array",
          description: "Complete JSON-RPC messages encoded as individual strings, evaluated in order.",
          items: { type: "string", maxLength: MAX_TRANSCRIPT_LINE_BYTES },
          maxItems: MAX_TRANSCRIPT_LINES,
        },
      },
      required: ["policy", "transcript"],
      additionalProperties: false,
    },
  },
  {
    name: "trustline.verify",
    title: "Verify a Trustline audit bundle",
    description: "Verify the schema, declared policy digest, indexes, links, and hashes of a trustline.audit-bundle/v1 value.",
    inputSchema: {
      type: "object",
      properties: {
        audit: { type: "object", description: "A trustline.audit-bundle/v1 value." },
      },
      required: ["audit"],
      additionalProperties: false,
    },
  },
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function validId(value: unknown): value is RequestId {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

function errorResponse(id: RequestId | undefined, code: number, message: string, data?: unknown): JsonRpcErrorResponse {
  const error = data === undefined ? { code, message } : { code, message, data };
  return id === undefined ? { jsonrpc: "2.0", error } : { jsonrpc: "2.0", id, error };
}

function resultResponse(id: RequestId, result: Record<string, unknown>): JsonRpcResultResponse {
  return { jsonrpc: "2.0", id, result };
}

function responseMeta(): Record<string, unknown> {
  return { "io.modelcontextprotocol/serverInfo": SERVER_INFO };
}

function assertJsonComplexity(value: unknown, label: string): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const seen = new Set<object>();
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) continue;
    nodes += 1;
    if (nodes > MAX_JSON_NODES) throw new SafeInputError(`${label} exceeds the ${MAX_JSON_NODES}-node limit`);
    if (current.depth > MAX_JSON_NESTING) throw new SafeInputError(`${label} exceeds the ${MAX_JSON_NESTING}-level nesting limit`);
    if (current.value === null || typeof current.value !== "object") continue;
    if (seen.has(current.value)) throw new SafeInputError(`${label} must be acyclic JSON data`);
    seen.add(current.value);
    if (Array.isArray(current.value)) {
      for (const entry of current.value) stack.push({ value: entry, depth: current.depth + 1 });
    } else if (isRecord(current.value)) {
      for (const entry of Object.values(current.value)) stack.push({ value: entry, depth: current.depth + 1 });
    } else {
      throw new SafeInputError(`${label} must contain only plain JSON objects`);
    }
  }
}

function jsonWorkWeight(value: unknown): number {
  const stack: unknown[] = [value];
  let weight = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    weight += 1;
    if (typeof current === "string") {
      weight += Buffer.byteLength(current, "utf8");
    } else if (Array.isArray(current)) {
      for (const entry of current) stack.push(entry);
    } else if (isRecord(current)) {
      for (const entry of Object.values(current)) stack.push(entry);
    }
  }
  return weight;
}

function assertPolicyWorkLimit(value: unknown, transcriptBytes: number, transcriptEntries: number): void {
  if (!isRecord(value)) return;
  let rules = 0;
  for (const key of ["toolRules", "argumentRules", "pathRules", "hostRules", "quotas"] as const) {
    const candidate = value[key];
    if (Array.isArray(candidate)) rules += candidate.length;
  }
  if (rules > MAX_POLICY_RULES) throw new SafeInputError(`policy exceeds the ${MAX_POLICY_RULES}-rule evaluation limit`);
  const policyWeight = jsonWorkWeight(value);
  const workUnits = policyWeight * (transcriptBytes + transcriptEntries + 1) + transcriptBytes;
  if (workUnits > MAX_SIMULATION_WORK_UNITS) {
    throw new SafeInputError(`aggregate policy evaluation work exceeds the ${MAX_SIMULATION_WORK_UNITS}-unit limit`);
  }
}

function toolResult(structuredContent: unknown, summary: unknown, isError: boolean): Record<string, unknown> {
  return {
    resultType: "complete",
    content: [{ type: "text", text: JSON.stringify(summary) }],
    structuredContent,
    isError,
    _meta: responseMeta(),
  };
}

function toolInputError(message: string): Record<string, unknown> {
  return toolResult({ valid: false, reason: message }, { error: message }, true);
}

function validateTranscript(value: unknown): { bytes: number; entries: number } {
  if (!Array.isArray(value)) throw new SafeInputError("transcript must be an array of JSON-RPC message strings");
  if (Object.keys(value).length !== value.length || Object.keys(value).some((key, index) => key !== String(index))) {
    throw new SafeInputError("transcript must be a dense JSON array");
  }
  if (value.length > MAX_TRANSCRIPT_LINES) throw new SafeInputError(`transcript exceeds the ${MAX_TRANSCRIPT_LINES}-line limit`);
  let totalBytes = 0;
  for (const line of value) {
    if (typeof line !== "string") throw new SafeInputError("every transcript entry must be a string");
    const bytes = Buffer.byteLength(line, "utf8");
    if (bytes > MAX_TRANSCRIPT_LINE_BYTES) throw new SafeInputError(`a transcript entry exceeds the ${MAX_TRANSCRIPT_LINE_BYTES}-byte limit`);
    totalBytes += bytes;
    if (totalBytes > MAX_TRANSCRIPT_BYTES) throw new SafeInputError(`transcript exceeds the ${MAX_TRANSCRIPT_BYTES}-byte total limit`);
    try { assertJsonComplexity(JSON.parse(line), "a transcript message"); }
    catch (error: unknown) { if (!(error instanceof SyntaxError)) throw error; }
  }
  return { bytes: totalBytes, entries: value.length };
}

function invokeTool(name: string, argumentsValue: Record<string, unknown>): Record<string, unknown> | JsonRpcErrorResponse {
  if (name === "trustline.simulate") {
    if (!hasExactKeys(argumentsValue, ["policy", "transcript"])) return toolInputError("trustline.simulate requires exactly policy and transcript");
    try {
      const transcript = argumentsValue.transcript;
      const transcriptSize = validateTranscript(transcript);
      assertPolicyWorkLimit(argumentsValue.policy, transcriptSize.bytes, transcriptSize.entries);
      const simulation = simulateTranscript(argumentsValue.policy as Policy, transcript as string[]);
      const audit = auditBundle(simulation);
      const verification = verifyAudit(audit);
      return toolResult(
        {
          version: simulation.version,
          policyName: simulation.policyName,
          policyDigest: simulation.policyDigest,
          totals: simulation.totals,
          audit,
          verification,
        },
        { totals: simulation.totals, policyDigest: simulation.policyDigest, verification },
        false,
      );
    } catch (error: unknown) {
      return toolInputError(error instanceof SafeInputError ? error.message : "policy or transcript input is invalid");
    }
  }

  if (name === "trustline.verify") {
    if (!hasExactKeys(argumentsValue, ["audit"])) return toolInputError("trustline.verify requires exactly audit");
    const verification = verifyAudit(argumentsValue.audit);
    return toolResult(verification, verification, !verification.valid);
  }

  return errorResponse(undefined, -32602, `Unknown tool: ${name}`);
}

function validateMetadata(params: Record<string, unknown>, id: RequestId): JsonRpcErrorResponse | undefined {
  if (!isRecord(params._meta)) return errorResponse(id, -32602, "params._meta is required");
  const requestedVersion = params._meta["io.modelcontextprotocol/protocolVersion"];
  if (typeof requestedVersion !== "string" || requestedVersion.length === 0) {
    return errorResponse(id, -32602, "io.modelcontextprotocol/protocolVersion is required");
  }
  if (requestedVersion !== MCP_PROTOCOL_VERSION) {
    return errorResponse(id, -32022, "Unsupported protocol version", {
      supported: [MCP_PROTOCOL_VERSION],
      requested: requestedVersion,
    });
  }
  if (!isRecord(params._meta["io.modelcontextprotocol/clientCapabilities"])) {
    return errorResponse(id, -32602, "io.modelcontextprotocol/clientCapabilities is required");
  }
  const clientInfo = params._meta["io.modelcontextprotocol/clientInfo"];
  if (clientInfo !== undefined && (!isRecord(clientInfo)
    || typeof clientInfo.name !== "string" || clientInfo.name.trim().length === 0
    || typeof clientInfo.version !== "string" || clientInfo.version.trim().length === 0)) {
    return errorResponse(id, -32602, "io.modelcontextprotocol/clientInfo must contain nonblank name and version strings");
  }
  return undefined;
}

export function handleMcpMessage(value: unknown): McpResponse | null {
  if (isRecord(value) && !Object.hasOwn(value, "id") && typeof value.method === "string") return null;
  try { assertJsonComplexity(value, "request"); }
  catch (error: unknown) {
    const readableId = isRecord(value) && validId(value.id) ? value.id : undefined;
    return errorResponse(readableId, -32600, error instanceof SafeInputError ? error.message : "Invalid Request");
  }
  if (!isRecord(value) || value.jsonrpc !== "2.0" || typeof value.method !== "string" || value.method.length === 0) {
    return errorResponse(undefined, -32600, "Invalid Request");
  }

  const hasId = Object.hasOwn(value, "id");
  if (!hasId) return null;
  if (!validId(value.id)) return errorResponse(undefined, -32600, "Request id must be a string or safe integer");
  const id = value.id;

  if (value.method === "initialize") {
    return errorResponse(id, -32601, `Legacy initialize is unsupported; supported protocol versions: ${MCP_PROTOCOL_VERSION}`, {
      supported: [MCP_PROTOCOL_VERSION],
    });
  }
  if (!isRecord(value.params)) return errorResponse(id, -32602, "params must be an object");
  const metadataError = validateMetadata(value.params, id);
  if (metadataError !== undefined) return metadataError;

  if (value.method === "server/discover") {
    if (!hasExactKeys(value.params, ["_meta"])) return errorResponse(id, -32602, "server/discover accepts only params._meta");
    return resultResponse(id, {
      resultType: "complete",
      supportedVersions: [MCP_PROTOCOL_VERSION],
      capabilities: { tools: {} },
      _meta: responseMeta(),
      instructions: "Use trustline.simulate to evaluate a complete offline transcript and trustline.verify to check an audit bundle. This server never executes the simulated tools.",
      ttlMs: 3_600_000,
      cacheScope: "public",
    });
  }

  if (value.method === "tools/list") {
    const unexpected = Object.keys(value.params).find((key) => !["_meta", "cursor"].includes(key));
    if (unexpected !== undefined) return errorResponse(id, -32602, `tools/list contains unsupported parameter ${unexpected}`);
    if (value.params.cursor !== undefined) return errorResponse(id, -32602, "tools/list pagination is not supported");
    return resultResponse(id, {
      resultType: "complete",
      tools: structuredClone(TOOLS),
      ttlMs: 3_600_000,
      cacheScope: "public",
      _meta: responseMeta(),
    });
  }

  if (value.method === "tools/call") {
    const unexpected = Object.keys(value.params).find((key) => !["_meta", "name", "arguments"].includes(key));
    if (unexpected !== undefined) return errorResponse(id, -32602, `tools/call contains unsupported parameter ${unexpected}`);
    if (typeof value.params.name !== "string" || value.params.name.trim().length === 0 || !isRecord(value.params.arguments)) {
      return errorResponse(id, -32602, "tools/call requires a nonblank name and object arguments");
    }
    let result: ReturnType<typeof invokeTool>;
    try { result = invokeTool(value.params.name, value.params.arguments); }
    catch { return errorResponse(id, -32603, "Internal error while processing tool call"); }
    if ("jsonrpc" in result) {
      const invocationError = result as JsonRpcErrorResponse;
      return errorResponse(id, invocationError.error.code, invocationError.error.message, invocationError.error.data);
    }
    return resultResponse(id, result);
  }

  return errorResponse(id, -32601, "Method not found");
}

async function writeResponse(output: Writable, response: McpResponse): Promise<void> {
  let encoded = JSON.stringify(response);
  if (Buffer.byteLength(encoded, "utf8") > MAX_MCP_RESPONSE_BYTES) {
    const id = "id" in response ? response.id : undefined;
    encoded = JSON.stringify(errorResponse(id, -32603, `Response exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte limit`));
  }
  if (!output.write(`${encoded}\n`, "utf8")) await once(output, "drain");
}

export async function runStdio(input: Readable, output: Writable): Promise<void> {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let segments: Buffer[] = [];
  let bufferedBytes = 0;
  let discardingOversizedLine = false;

  const processLine = async (): Promise<void> => {
    const bytes = Buffer.concat(segments, bufferedBytes);
    segments = [];
    bufferedBytes = 0;
    let line: string;
    try { line = decoder.decode(bytes); }
    catch {
      await writeResponse(output, errorResponse(undefined, -32700, "Message is not valid UTF-8"));
      return;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(line); }
    catch {
      await writeResponse(output, errorResponse(undefined, -32700, "Parse error"));
      return;
    }
    const response = handleMcpMessage(parsed);
    if (response !== null) await writeResponse(output, response);
  };

  for await (const chunkValue of input) {
    const chunk = typeof chunkValue === "string" ? Buffer.from(chunkValue, "utf8") : Buffer.from(chunkValue as Uint8Array);
    let offset = 0;
    while (offset < chunk.length) {
      const newline = chunk.indexOf(0x0a, offset);
      const end = newline === -1 ? chunk.length : newline;
      const piece = chunk.subarray(offset, end);
      if (!discardingOversizedLine) {
        if (bufferedBytes + piece.length > MAX_MCP_MESSAGE_BYTES) {
          segments = [];
          bufferedBytes = 0;
          discardingOversizedLine = true;
          await writeResponse(output, errorResponse(undefined, -32600, `Message exceeds the ${MAX_MCP_MESSAGE_BYTES}-byte limit`));
        } else if (piece.length > 0) {
          segments.push(piece);
          bufferedBytes += piece.length;
        }
      }
      if (newline === -1) break;
      if (discardingOversizedLine) {
        discardingOversizedLine = false;
      } else {
        await processLine();
      }
      offset = newline + 1;
    }
  }

  if (!discardingOversizedLine && bufferedBytes > 0) {
    await writeResponse(output, errorResponse(undefined, -32700, "Unterminated message at end of input"));
  }
}
