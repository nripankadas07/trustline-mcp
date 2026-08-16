export const POLICY_VERSION = "trustline.policy/v1" as const;

export type Effect = "allow" | "approval" | "deny";
export type DecisionEffect = Effect | "default-deny";

export interface ToolRule {
  id: string;
  effect: Effect;
  tools: string[];
}

export interface ArgumentRule {
  id: string;
  effect: Effect;
  tool: string;
  path: string;
  operator: "equals" | "contains" | "matches" | "present";
  value?: string | number | boolean;
}

export interface PathRule {
  id: string;
  effect: Effect;
  tool: string;
  argument: string;
  roots?: string[];
}

export interface HostRule {
  id: string;
  effect: Effect;
  tool: string;
  argument: string;
  hosts: string[];
}

export interface QuotaRule {
  id: string;
  tool: string;
  limit: number;
}

export interface Policy {
  version: typeof POLICY_VERSION;
  name: string;
  defaultEffect: "deny";
  toolRules: ToolRule[];
  argumentRules?: ArgumentRule[];
  pathRules?: PathRule[];
  hostRules?: HostRule[];
  quotas?: QuotaRule[];
  redactKeys?: string[];
}

export interface CallContext {
  approvedBy?: string;
}

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
}

export interface Decision {
  effect: DecisionEffect;
  tool: string;
  reasonCodes: string[];
  matchedRuleIds: string[];
  quotaBefore: number;
  quotaAfter: number;
}

const EFFECTS = new Set<unknown>(["allow", "approval", "deny"]);
const ARGUMENT_OPERATORS = new Set<unknown>(["equals", "contains", "matches", "present"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireOnlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const unexpected = Object.keys(value).find((key) => !allowed.includes(key));
  if (unexpected !== undefined) throw new Error(`${label} contains unsupported field ${unexpected}`);
}

function requireNonblank(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${label} must be a nonblank string`);
}

function requireStringArray(value: unknown, label: string, allowEmpty = false): asserts value is string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.some((entry) => typeof entry !== "string" || entry.trim().length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "an" : "a nonempty"} array of nonblank strings`);
  }
}

/** Runtime validation is mandatory because policies normally arrive through JSON, not TypeScript. */
export function assertPolicy(value: unknown): asserts value is Policy {
  if (!isRecord(value)) throw new Error("policy must be an object");
  requireOnlyKeys(value, ["version", "name", "defaultEffect", "toolRules", "argumentRules", "pathRules", "hostRules", "quotas", "redactKeys"], "policy");
  if (value.version !== POLICY_VERSION) throw new Error(`unsupported policy version: ${String(value.version)}`);
  requireNonblank(value.name, "policy name");
  if (value.defaultEffect !== "deny") throw new Error("Trustline v1 requires default deny");
  if (!Array.isArray(value.toolRules)) throw new Error("toolRules must be an array");

  const ids = new Set<string>();
  const claimId = (rule: Record<string, unknown>, label: string): string => {
    requireNonblank(rule.id, `${label} id`);
    if (ids.has(rule.id)) throw new Error(`duplicate rule id: ${rule.id}`);
    ids.add(rule.id);
    return rule.id;
  };
  const requireEffect = (rule: Record<string, unknown>, label: string): void => {
    if (!EFFECTS.has(rule.effect)) throw new Error(`${label} effect must be allow, approval, or deny`);
  };
  const optionalArray = (key: keyof Policy): unknown[] => {
    const candidate = value[key];
    if (candidate === undefined) return [];
    if (!Array.isArray(candidate)) throw new Error(`${key} must be an array`);
    return candidate;
  };

  for (const candidate of value.toolRules) {
    if (!isRecord(candidate)) throw new Error("tool rule must be an object");
    requireOnlyKeys(candidate, ["id", "effect", "tools"], "tool rule");
    const id = claimId(candidate, "tool rule");
    requireEffect(candidate, `tool rule ${id}`);
    requireStringArray(candidate.tools, `tool rule ${id} tools`);
  }
  for (const candidate of optionalArray("argumentRules")) {
    if (!isRecord(candidate)) throw new Error("argument rule must be an object");
    requireOnlyKeys(candidate, ["id", "effect", "tool", "path", "operator", "value"], "argument rule");
    const id = claimId(candidate, "argument rule");
    requireEffect(candidate, `argument rule ${id}`);
    requireNonblank(candidate.tool, `argument rule ${id} tool`);
    requireNonblank(candidate.path, `argument rule ${id} path`);
    if (candidate.path.split(".").some((segment) => segment.length === 0)) throw new Error(`argument rule ${id} path contains an empty segment`);
    if (!ARGUMENT_OPERATORS.has(candidate.operator)) throw new Error(`argument rule ${id} has an unsupported operator`);
    if (["equals", "contains", "matches"].includes(String(candidate.operator)) && candidate.value === undefined) throw new Error(`argument rule ${id} requires a value`);
    if (candidate.operator === "equals" && !["string", "number", "boolean"].includes(typeof candidate.value)) throw new Error(`argument rule ${id} equals requires a primitive value`);
    if (typeof candidate.value === "number" && !Number.isFinite(candidate.value)) throw new Error(`argument rule ${id} value must be finite`);
    if (candidate.operator === "matches") {
      if (typeof candidate.value !== "string") throw new Error(`argument rule ${id} requires a string regex`);
      try { new RegExp(candidate.value, "u"); }
      catch { throw new Error(`argument rule ${id} contains an invalid regex`); }
    }
    if (candidate.operator === "contains" && !["string", "number", "boolean"].includes(typeof candidate.value)) {
      throw new Error(`argument rule ${id} contains requires a string, number, or boolean value`);
    }
  }
  for (const candidate of optionalArray("pathRules")) {
    if (!isRecord(candidate)) throw new Error("path rule must be an object");
    requireOnlyKeys(candidate, ["id", "effect", "tool", "argument", "roots"], "path rule");
    const id = claimId(candidate, "path rule");
    requireEffect(candidate, `path rule ${id}`);
    requireNonblank(candidate.tool, `path rule ${id} tool`);
    requireNonblank(candidate.argument, `path rule ${id} argument`);
    if (candidate.argument.split(".").some((segment) => segment.length === 0)) throw new Error(`path rule ${id} argument contains an empty segment`);
    requireStringArray(candidate.roots, `path rule ${id} roots`);
  }
  for (const candidate of optionalArray("hostRules")) {
    if (!isRecord(candidate)) throw new Error("host rule must be an object");
    requireOnlyKeys(candidate, ["id", "effect", "tool", "argument", "hosts"], "host rule");
    const id = claimId(candidate, "host rule");
    requireEffect(candidate, `host rule ${id}`);
    requireNonblank(candidate.tool, `host rule ${id} tool`);
    requireNonblank(candidate.argument, `host rule ${id} argument`);
    if (candidate.argument.split(".").some((segment) => segment.length === 0)) throw new Error(`host rule ${id} argument contains an empty segment`);
    requireStringArray(candidate.hosts, `host rule ${id} hosts`);
    for (const host of candidate.hosts) {
      if (host === "*." || /[/:?#@]/u.test(host.replace(/^\*\./u, ""))) throw new Error(`host rule ${id} contains an invalid hostname`);
    }
  }
  for (const candidate of optionalArray("quotas")) {
    if (!isRecord(candidate)) throw new Error("quota rule must be an object");
    requireOnlyKeys(candidate, ["id", "tool", "limit"], "quota rule");
    const id = claimId(candidate, "quota rule");
    requireNonblank(candidate.tool, `quota rule ${id} tool`);
    if (!Number.isSafeInteger(candidate.limit) || (candidate.limit as number) < 0) throw new Error(`quota rule ${id} limit must be a nonnegative safe integer`);
  }
  if (value.redactKeys !== undefined) {
    requireStringArray(value.redactKeys, "redactKeys", true);
    if (new Set(value.redactKeys.map((key) => key.toLowerCase())).size !== value.redactKeys.length) throw new Error("redactKeys must be unique ignoring case");
  }
}

function matchTool(pattern: string, tool: string): boolean {
  if (pattern === "*") return true;
  if (!pattern.includes("*")) return pattern === tool;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}$`).test(tool);
}

function readPath(value: unknown, path: string): unknown {
  return path.split(".").filter(Boolean).reduce<unknown>((current, segment) => {
    if (current === null || typeof current !== "object") return undefined;
    return Object.hasOwn(current, segment) ? (current as Record<string, unknown>)[segment] : undefined;
  }, value);
}

function argumentMatches(actual: unknown, rule: ArgumentRule): boolean {
  switch (rule.operator) {
    case "present": return actual !== undefined && actual !== null;
    case "equals": return actual === rule.value;
    case "contains": return typeof actual === "string" && actual.includes(String(rule.value ?? ""));
    case "matches": {
      if (typeof actual !== "string" || typeof rule.value !== "string") return false;
      return new RegExp(rule.value, "u").test(actual);
    }
  }
}

function normalizePathCandidate(value: unknown): { value?: string; invalid: boolean; traversal: boolean } {
  if (typeof value !== "string" || value.trim().length === 0) return { invalid: true, traversal: false };
  const parts = value.replaceAll("\\", "/").split("/");
  const malformed = value.includes("\0");
  return { value, invalid: malformed, traversal: parts.includes("..") || malformed };
}

function extractHost(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try { return new URL(value.includes("://") ? value : `https://${value}`).hostname.toLowerCase(); }
  catch { return undefined; }
}

export class PolicyEngine {
  readonly #counts = new Map<string, number>();
  readonly policy: Policy;

  constructor(policy: Policy) {
    assertPolicy(policy);
    this.policy = structuredClone(policy);
  }

  reset(): void { this.#counts.clear(); }

  evaluate(call: ToolCall, context: CallContext = {}): Decision {
    const matches: Array<{ id: string; effect: Effect; reason: string }> = [];
    for (const rule of this.policy.toolRules) {
      if (rule.tools.some((pattern) => matchTool(pattern, call.name))) {
        matches.push({ id: rule.id, effect: rule.effect, reason: `tool-${rule.effect}` });
      }
    }
    for (const rule of this.policy.argumentRules ?? []) {
      if (matchTool(rule.tool, call.name) && argumentMatches(readPath(call.arguments, rule.path), rule)) {
        matches.push({ id: rule.id, effect: rule.effect, reason: `argument-${rule.effect}` });
      }
    }
    for (const rule of this.policy.pathRules ?? []) {
      if (!matchTool(rule.tool, call.name)) continue;
      const candidate = normalizePathCandidate(readPath(call.arguments, rule.argument));
      if (rule.effect === "allow" && candidate.invalid) {
        matches.push({ id: `${rule.id}:invalid-path`, effect: "deny", reason: "path-invalid" });
        continue;
      }
      if (candidate.traversal) matches.push({ id: `${rule.id}:traversal`, effect: "deny", reason: "path-traversal" });
      if (candidate.value !== undefined && rule.roots !== undefined) {
        const normalized = candidate.value.replaceAll("\\", "/");
        const inRoot = rule.roots.some((root) => normalized === root || normalized.startsWith(`${root.replace(/\/$/, "")}/`));
        if (inRoot) matches.push({ id: rule.id, effect: rule.effect, reason: `path-${rule.effect}` });
        if (rule.effect === "allow" && !inRoot) matches.push({ id: `${rule.id}:outside-root`, effect: "deny", reason: "path-outside-root" });
      }
    }
    for (const rule of this.policy.hostRules ?? []) {
      if (!matchTool(rule.tool, call.name)) continue;
      const host = extractHost(readPath(call.arguments, rule.argument));
      if (host === undefined) {
        if (rule.effect === "allow") matches.push({ id: `${rule.id}:invalid-host`, effect: "deny", reason: "host-invalid" });
        continue;
      }
      const listed = rule.hosts.some((entry) => entry === host || (entry.startsWith("*.") && host.endsWith(entry.slice(1))));
      if (listed) matches.push({ id: rule.id, effect: rule.effect, reason: `host-${rule.effect}` });
      else if (rule.effect === "allow") matches.push({ id: `${rule.id}:unlisted`, effect: "deny", reason: "host-unlisted" });
    }

    const quotas = (this.policy.quotas ?? []).filter((rule) => matchTool(rule.tool, call.name));
    const quotaCounts = quotas.map((quota) => ({ quota, before: this.#counts.get(quota.id) ?? 0 }));
    for (const { quota, before } of quotaCounts) {
      if (before >= quota.limit) matches.push({ id: quota.id, effect: "deny", reason: "quota-exceeded" });
    }
    const quotaBefore = Math.max(0, ...quotaCounts.map(({ before }) => before));

    const denies = matches.filter((match) => match.effect === "deny");
    const approvals = matches.filter((match) => match.effect === "approval");
    const allows = matches.filter((match) => match.effect === "allow");
    const approvalSatisfied = typeof context.approvedBy === "string" && context.approvedBy.trim().length > 0;
    let effect: DecisionEffect;
    if (denies.length > 0) effect = "deny";
    else if (approvals.length > 0 && !approvalSatisfied) effect = "approval";
    else if (allows.length > 0 || (approvals.length > 0 && approvalSatisfied)) effect = "allow";
    else effect = "default-deny";

    if (effect === "allow") {
      for (const { quota, before } of quotaCounts) this.#counts.set(quota.id, before + 1);
    }
    const quotaAfter = Math.max(0, ...quotaCounts.map(({ quota, before }) => effect === "allow" ? before + 1 : (this.#counts.get(quota.id) ?? before)));
    const relevant = effect === "deny" ? denies : effect === "approval" ? approvals : effect === "allow" ? [...allows, ...approvals] : [];
    return {
      effect,
      tool: call.name,
      reasonCodes: relevant.length > 0 ? [...new Set(relevant.map((match) => match.reason))].sort() : ["no-allow-rule"],
      matchedRuleIds: relevant.map((match) => match.id).sort(),
      quotaBefore,
      quotaAfter,
    };
  }
}
