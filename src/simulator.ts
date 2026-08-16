import { canonicalJson, redact, sha256 } from "./canonical.js";
import { assertPolicy, type CallContext, type Decision, type Policy, PolicyEngine, type ToolCall } from "./policy.js";

export const AUDIT_VERSION = "trustline.audit/v1" as const;
export const AUDIT_BUNDLE_VERSION = "trustline.audit-bundle/v1" as const;
export const TRANSCRIPT_VERSION = "trustline.transcript/v1" as const;
const GENESIS = "0".repeat(64);
const HEX_SHA256 = /^[a-f0-9]{64}$/u;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface AuditEntryPayload {
  version: typeof AUDIT_VERSION;
  index: number;
  previousHash: string;
  policyDigest: string;
  request: unknown;
  response: unknown;
  decision: Decision | null;
}

export interface AuditEntry extends AuditEntryPayload { hash: string }
export interface AuditBundle {
  version: typeof AUDIT_BUNDLE_VERSION;
  policy: Policy;
  policyDigest: string;
  entries: AuditEntry[];
}

export interface SimulationResult {
  version: typeof TRANSCRIPT_VERSION;
  policy: Policy;
  policyName: string;
  policyDigest: string;
  entries: AuditEntry[];
  totals: { lines: number; allowed: number; denied: number; approvalRequired: number; protocolErrors: number };
}

export interface AuditVerification { valid: boolean; index?: number; reason?: string; rootHash: string; policyDigest?: string }

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === [...expected].sort()[index]);
}

function isDenseArray(value: unknown): value is unknown[] {
  return Array.isArray(value)
    && Object.keys(value).length === value.length
    && Object.keys(value).every((key, index) => key === String(index));
}

function isJsonValue(value: unknown, seen = new Set<object>()): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.keys(value).some((key, index) => key !== String(index))) return false;
    if (seen.has(value)) return false;
    seen.add(value);
    const valid = value.every((entry) => isJsonValue(entry, seen));
    seen.delete(value);
    return valid;
  }
  if (isRecord(value)) {
    if (seen.has(value)) return false;
    seen.add(value);
    const valid = Object.values(value).every((entry) => isJsonValue(entry, seen));
    seen.delete(value);
    return valid;
  }
  return false;
}

function isDecision(value: unknown): value is Decision {
  if (!isRecord(value) || !hasExactKeys(value, ["effect", "tool", "reasonCodes", "matchedRuleIds", "quotaBefore", "quotaAfter"])) return false;
  return ["allow", "approval", "deny", "default-deny"].includes(String(value.effect))
    && typeof value.tool === "string" && value.tool.trim().length > 0
    && isDenseArray(value.reasonCodes) && value.reasonCodes.every((entry) => typeof entry === "string")
    && isDenseArray(value.matchedRuleIds) && value.matchedRuleIds.every((entry) => typeof entry === "string")
    && Number.isSafeInteger(value.quotaBefore) && (value.quotaBefore as number) >= 0
    && Number.isSafeInteger(value.quotaAfter) && (value.quotaAfter as number) >= 0;
}

export function digestPolicy(policy: Policy): string {
  assertPolicy(policy);
  return sha256(`${POLICY_VERSION_TAG}\n${canonicalJson(policy)}`);
}

const POLICY_VERSION_TAG = "trustline.policy-digest/v1";
function auditGenesis(policyDigest: string): string {
  return sha256(`trustline.audit-genesis/v1\n${policyDigest}`);
}

export function auditBundle(result: SimulationResult): AuditBundle {
  return {
    version: AUDIT_BUNDLE_VERSION,
    policy: structuredClone(result.policy),
    policyDigest: result.policyDigest,
    entries: structuredClone(result.entries),
  };
}

function response(id: string | number | null, result?: unknown, error?: JsonRpcResponse["error"]): JsonRpcResponse {
  return error === undefined ? { jsonrpc: "2.0", id, result } : { jsonrpc: "2.0", id, error };
}

function parseCall(request: JsonRpcRequest): { call?: ToolCall; context?: CallContext; error?: JsonRpcResponse["error"] } {
  if (request.method !== "tools/call") return { error: { code: -32601, message: "method not simulated" } };
  if (request.params === null || typeof request.params !== "object") return { error: { code: -32602, message: "params must be an object" } };
  const params = request.params as Record<string, unknown>;
  if (typeof params.name !== "string" || params.name.trim().length === 0 || params.arguments === null || typeof params.arguments !== "object" || Array.isArray(params.arguments)) {
    return { error: { code: -32602, message: "tools/call requires name and object arguments" } };
  }
  const context: CallContext = {};
  if (typeof params.approvedBy === "string") context.approvedBy = params.approvedBy;
  return { call: { name: params.name, arguments: params.arguments as Record<string, unknown> }, context };
}

function invokeFixtureTool(call: ToolCall): unknown {
  if (call.name === "repo.read") return { mimeType: "text/plain", text: `fixture:${String(call.arguments.path ?? "")}` };
  if (call.name === "docs.search") return { hits: [{ title: "Offline policy fixture", score: 1 }] };
  if (call.name === "shell.safe") return { exitCode: 0, stdout: "simulated only; no process executed" };
  return { simulated: true, tool: call.name };
}

function appendAudit(entries: AuditEntry[], requestValue: unknown, responseValue: unknown, decision: Decision | null, redactKeys: readonly string[], policyDigest: string): void {
  const previousHash = entries.at(-1)?.hash ?? auditGenesis(policyDigest);
  const payload: AuditEntryPayload = {
    version: AUDIT_VERSION,
    index: entries.length,
    previousHash,
    policyDigest,
    request: redact(requestValue, redactKeys),
    response: redact(responseValue, redactKeys),
    decision,
  };
  entries.push({ ...payload, hash: sha256(`${previousHash}\n${canonicalJson(payload)}`) });
}

export function simulateTranscript(policy: Policy, lines: readonly string[]): SimulationResult {
  const engine = new PolicyEngine(policy);
  const effectivePolicy = structuredClone(engine.policy);
  const policyDigest = digestPolicy(effectivePolicy);
  const entries: AuditEntry[] = [];
  const totals = { lines: lines.length, allowed: 0, denied: 0, approvalRequired: 0, protocolErrors: 0 };
  for (const line of lines) {
    let parsed: unknown;
    try { parsed = JSON.parse(line); }
    catch {
      const rpcResponse = response(null, undefined, { code: -32700, message: "parse error" });
      totals.protocolErrors += 1;
      appendAudit(entries, { raw: line }, rpcResponse, null, effectivePolicy.redactKeys ?? [], policyDigest);
      continue;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed) || (parsed as Record<string, unknown>).jsonrpc !== "2.0") {
      const rpcResponse = response(null, undefined, { code: -32600, message: "invalid request" });
      totals.protocolErrors += 1;
      appendAudit(entries, parsed, rpcResponse, null, effectivePolicy.redactKeys ?? [], policyDigest);
      continue;
    }
    const request = parsed as JsonRpcRequest;
    if ((request.id !== undefined && request.id !== null && typeof request.id !== "string" && typeof request.id !== "number") || (typeof request.id === "number" && !Number.isFinite(request.id)) || typeof request.method !== "string") {
      const rpcResponse = response(null, undefined, { code: -32600, message: "invalid request" });
      totals.protocolErrors += 1;
      appendAudit(entries, request, rpcResponse, null, effectivePolicy.redactKeys ?? [], policyDigest);
      continue;
    }
    const id = request.id ?? null;
    const notification = !Object.hasOwn(request, "id");
    const callResult = parseCall(request);
    if (callResult.error !== undefined || callResult.call === undefined) {
      const rpcResponse = response(id, undefined, callResult.error ?? { code: -32602, message: "invalid params" });
      totals.protocolErrors += 1;
      appendAudit(entries, request, notification ? null : rpcResponse, null, effectivePolicy.redactKeys ?? [], policyDigest);
      continue;
    }
    const decision = engine.evaluate(callResult.call, callResult.context ?? {});
    let rpcResponse: JsonRpcResponse;
    if (decision.effect === "allow") {
      totals.allowed += 1;
      rpcResponse = response(id, { content: invokeFixtureTool(callResult.call), policy: decision });
    } else if (decision.effect === "approval") {
      totals.approvalRequired += 1;
      rpcResponse = response(id, undefined, { code: -32001, message: "approval required", data: decision });
    } else {
      totals.denied += 1;
      rpcResponse = response(id, undefined, { code: -32000, message: "policy denied", data: decision });
    }
    appendAudit(entries, request, notification ? null : rpcResponse, decision, effectivePolicy.redactKeys ?? [], policyDigest);
  }
  return { version: TRANSCRIPT_VERSION, policy: effectivePolicy, policyName: effectivePolicy.name, policyDigest, entries, totals };
}

export function verifyAudit(value: unknown): AuditVerification {
  if (!isRecord(value) || !hasExactKeys(value, ["version", "policy", "policyDigest", "entries"])) return { valid: false, reason: "invalid audit bundle schema", rootHash: GENESIS };
  if (value.version !== AUDIT_BUNDLE_VERSION) return { valid: false, reason: "unsupported audit bundle version", rootHash: GENESIS };
  try { assertPolicy(value.policy); }
  catch (error: unknown) { return { valid: false, reason: error instanceof Error ? `invalid policy: ${error.message}` : "invalid policy", rootHash: GENESIS }; }
  if (typeof value.policyDigest !== "string" || !HEX_SHA256.test(value.policyDigest)) return { valid: false, reason: "invalid policy digest", rootHash: GENESIS };
  const expectedPolicyDigest = digestPolicy(value.policy);
  if (value.policyDigest !== expectedPolicyDigest) return { valid: false, reason: "policy digest mismatch", rootHash: GENESIS, policyDigest: expectedPolicyDigest };
  let previousHash = auditGenesis(value.policyDigest);
  if (!isDenseArray(value.entries)) return { valid: false, reason: "entries must be a dense array", rootHash: previousHash, policyDigest: value.policyDigest };
  for (let index = 0; index < value.entries.length; index += 1) {
    const candidate = value.entries[index];
    if (!isRecord(candidate) || !hasExactKeys(candidate, ["version", "index", "previousHash", "policyDigest", "request", "response", "decision", "hash"])) {
      return { valid: false, index, reason: "invalid entry schema", rootHash: previousHash, policyDigest: value.policyDigest };
    }
    if (candidate.version !== AUDIT_VERSION) return { valid: false, index, reason: "unsupported entry version", rootHash: previousHash, policyDigest: value.policyDigest };
    if (candidate.index !== index) return { valid: false, index, reason: "non-contiguous index", rootHash: previousHash, policyDigest: value.policyDigest };
    if (candidate.previousHash !== previousHash) return { valid: false, index, reason: "previous hash mismatch", rootHash: previousHash, policyDigest: value.policyDigest };
    if (candidate.policyDigest !== value.policyDigest) return { valid: false, index, reason: "entry policy digest mismatch", rootHash: previousHash, policyDigest: value.policyDigest };
    if (!isJsonValue(candidate.request) || !isJsonValue(candidate.response)) return { valid: false, index, reason: "request and response must be JSON values", rootHash: previousHash, policyDigest: value.policyDigest };
    if (candidate.decision !== null && !isDecision(candidate.decision)) return { valid: false, index, reason: "invalid decision schema", rootHash: previousHash, policyDigest: value.policyDigest };
    if (typeof candidate.hash !== "string" || !HEX_SHA256.test(candidate.hash)) return { valid: false, index, reason: "invalid entry hash", rootHash: previousHash, policyDigest: value.policyDigest };
    const { hash, ...payload } = candidate;
    const expected = sha256(`${previousHash}\n${canonicalJson(payload)}`);
    if (hash !== expected) return { valid: false, index, reason: "entry hash mismatch", rootHash: previousHash, policyDigest: value.policyDigest };
    previousHash = hash;
  }
  return { valid: true, rootHash: previousHash, policyDigest: value.policyDigest };
}
