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
export const MAX_REGEX_PATTERN_LENGTH = 256;
export const MAX_REGEX_ARGUMENT_LENGTH = 100_000;

type CharacterMatcher =
  | { kind: "literal"; value: string }
  | { kind: "any" }
  | { kind: "digit" | "word" | "space"; negated: boolean }
  | { kind: "class"; negated: boolean; members: ClassMember[] };
type ClassMember =
  | { kind: "literal"; value: string }
  | { kind: "range"; first: number; last: number }
  | { kind: "digit" | "word" | "space"; negated: boolean };
type PatternAtom =
  | { kind: "character"; matcher: CharacterMatcher }
  | { kind: "start" }
  | { kind: "end" }
  | { kind: "boundary"; negated: boolean };
interface SafePattern { atoms: PatternAtom[] }

function exceedsCodePointLimit(value: string, limit: number): boolean {
  let count = 0;
  for (const _character of value) {
    count += 1;
    if (count > limit) return true;
  }
  return false;
}

function categoryMatches(kind: "digit" | "word" | "space", character: string): boolean {
  if (kind === "digit") return character >= "0" && character <= "9";
  if (kind === "word") return (character >= "A" && character <= "Z")
    || (character >= "a" && character <= "z")
    || (character >= "0" && character <= "9")
    || character === "_";
  return /\s/u.test(character);
}

function classMemberMatches(member: ClassMember, character: string): boolean {
  if (member.kind === "literal") return character === member.value;
  if (member.kind === "range") {
    const codePoint = character.codePointAt(0);
    return codePoint !== undefined && codePoint >= member.first && codePoint <= member.last;
  }
  const matched = categoryMatches(member.kind, character);
  return member.negated ? !matched : matched;
}

function characterMatches(matcher: CharacterMatcher, character: string): boolean {
  if (matcher.kind === "literal") return character === matcher.value;
  if (matcher.kind === "any") return !["\n", "\r", "\u2028", "\u2029"].includes(character);
  if (matcher.kind === "class") {
    const matched = matcher.members.some((member) => classMemberMatches(member, character));
    return matcher.negated ? !matched : matched;
  }
  const matched = categoryMatches(matcher.kind, character);
  return matcher.negated ? !matched : matched;
}

function escapedCharacterMatcher(escape: string, inClass: boolean): CharacterMatcher | undefined {
  if (["d", "D", "w", "W", "s", "S"].includes(escape)) {
    const lower = escape.toLowerCase() as "d" | "w" | "s";
    const kind = lower === "d" ? "digit" : lower === "w" ? "word" : "space";
    return { kind, negated: escape !== lower };
  }
  const controls: Record<string, string> = { n: "\n", r: "\r", t: "\t", f: "\f", v: "\v", "0": "\0" };
  if (Object.hasOwn(controls, escape)) return { kind: "literal", value: controls[escape] as string };
  if (inClass && escape === "b") return { kind: "literal", value: "\b" };
  const identityEscapes = inClass ? "/^$\\.*+?()[]{}|-" : "/^$\\.*+?()[]{}|";
  if (identityEscapes.includes(escape)) return { kind: "literal", value: escape };
  return undefined;
}

function classMemberFromMatcher(matcher: CharacterMatcher): ClassMember {
  if (matcher.kind === "literal") return matcher;
  if (matcher.kind === "digit" || matcher.kind === "word" || matcher.kind === "space") return matcher;
  throw new Error("character class contains an unsupported nested matcher");
}

function parseCharacterClass(pattern: string, start: number, label: string): { atom: PatternAtom; next: number } {
  let index = start + 1;
  let negated = false;
  if (pattern[index] === "^") { negated = true; index += 1; }
  const members: ClassMember[] = [];
  let closed = false;
  while (index < pattern.length) {
    if (pattern[index] === "]") { closed = true; index += 1; break; }
    let matcher: CharacterMatcher;
    let next: number;
    if (pattern[index] === "\\") {
      const escaped = pattern[index + 1];
      if (escaped === undefined) throw new Error(`${label} contains an incomplete character-class escape`);
      if (escaped === "0" && /[0-9]/u.test(pattern[index + 2] ?? "")) throw new Error(`${label} contains an invalid decimal escape`);
      const parsed = escapedCharacterMatcher(escaped, true);
      if (parsed === undefined) throw new Error(`${label} uses an unsupported character-class escape`);
      matcher = parsed;
      next = index + 2;
    } else {
      const codePoint = pattern.codePointAt(index);
      if (codePoint === undefined) throw new Error(`${label} contains an invalid character class`);
      const value = String.fromCodePoint(codePoint);
      if (value === "[") throw new Error(`${label} contains a nested character class`);
      matcher = { kind: "literal", value };
      next = index + value.length;
    }
    const startsRange = pattern[next] === "-" && pattern[next + 1] !== "]" && next + 1 < pattern.length;
    if (startsRange && matcher.kind !== "literal") throw new Error(`${label} range endpoints must be literal characters`);
    if (matcher.kind === "literal" && startsRange) {
      const rangeStart = matcher.value.codePointAt(0) as number;
      const endIndex = next + 1;
      let rangeEndMatcher: CharacterMatcher;
      let rangeNext: number;
      if (pattern[endIndex] === "\\") {
        const escaped = pattern[endIndex + 1];
        if (escaped === "0" && /[0-9]/u.test(pattern[endIndex + 2] ?? "")) throw new Error(`${label} contains an invalid decimal escape`);
        const parsed = escaped === undefined ? undefined : escapedCharacterMatcher(escaped, true);
        if (parsed === undefined || parsed.kind !== "literal") throw new Error(`${label} range endpoints must be literal characters`);
        rangeEndMatcher = parsed;
        rangeNext = endIndex + 2;
      } else {
        const codePoint = pattern.codePointAt(endIndex);
        if (codePoint === undefined) throw new Error(`${label} contains an incomplete character-class range`);
        const value = String.fromCodePoint(codePoint);
        if (value === "[") throw new Error(`${label} range endpoints must be literal characters`);
        rangeEndMatcher = { kind: "literal", value };
        rangeNext = endIndex + value.length;
      }
      const rangeEnd = rangeEndMatcher.value.codePointAt(0) as number;
      if (rangeStart > rangeEnd) throw new Error(`${label} contains a descending character-class range`);
      members.push({ kind: "range", first: rangeStart, last: rangeEnd });
      index = rangeNext;
    } else {
      members.push(classMemberFromMatcher(matcher));
      index = next;
    }
  }
  if (!closed || members.length === 0) throw new Error(`${label} contains an invalid regex (invalid or empty character class)`);
  return { atom: { kind: "character", matcher: { kind: "class", negated, members } }, next: index };
}

function compileSafePattern(pattern: string, label: string): SafePattern {
  if (exceedsCodePointLimit(pattern, MAX_REGEX_PATTERN_LENGTH)) throw new Error(`${label} exceeds the safe regex length limit`);
  const atoms: PatternAtom[] = [];
  for (let index = 0; index < pattern.length;) {
    const codePoint = pattern.codePointAt(index);
    if (codePoint === undefined) break;
    const character = String.fromCodePoint(codePoint);
    if (character === "[") {
      const parsed = parseCharacterClass(pattern, index, label);
      atoms.push(parsed.atom);
      index = parsed.next;
      continue;
    }
    if (character === "]") throw new Error(`${label} contains an unmatched character-class terminator`);
    if (character === "\\") {
      const escaped = pattern[index + 1];
      if (escaped === undefined) throw new Error(`${label} contains an incomplete escape`);
      if (/[1-9]/u.test(escaped) || escaped === "k") throw new Error(`${label} contains an unsupported backreference`);
      if (escaped === "0" && /[0-9]/u.test(pattern[index + 2] ?? "")) throw new Error(`${label} contains an invalid decimal escape`);
      if (escaped === "b" || escaped === "B") atoms.push({ kind: "boundary", negated: escaped === "B" });
      else {
        const matcher = escapedCharacterMatcher(escaped, false);
        if (matcher === undefined) throw new Error(`${label} uses an unsupported escape outside the safe regex subset`);
        atoms.push({ kind: "character", matcher });
      }
      index += 2;
      continue;
    }
    if ("()|*+?{}".includes(character)) throw new Error(`${label} uses grouping, alternation, or repetition outside the safe regex subset`);
    if (character === "^") atoms.push({ kind: "start" });
    else if (character === "$") atoms.push({ kind: "end" });
    else atoms.push({ kind: "character", matcher: character === "." ? { kind: "any" } : { kind: "literal", value: character } });
    index += character.length;
  }
  if (atoms.length === 0) throw new Error(`${label} contains an invalid regex`);
  return { atoms };
}

function safePatternMatches(pattern: SafePattern, value: string): boolean {
  const characters = [...value];
  const anchoredAtStart = pattern.atoms[0]?.kind === "start";
  const maximumStart = anchoredAtStart ? 0 : characters.length;
  for (let start = 0; start <= maximumStart; start += 1) {
    let cursor = start;
    let matched = true;
    for (const atom of pattern.atoms) {
      if (atom.kind === "start") { if (cursor !== 0) { matched = false; break; } continue; }
      if (atom.kind === "end") { if (cursor !== characters.length) { matched = false; break; } continue; }
      if (atom.kind === "boundary") {
        const before = cursor > 0 && categoryMatches("word", characters[cursor - 1] as string);
        const after = cursor < characters.length && categoryMatches("word", characters[cursor] as string);
        if ((before !== after) === atom.negated) { matched = false; break; }
        continue;
      }
      const character = characters[cursor];
      if (character === undefined || !characterMatches(atom.matcher, character)) { matched = false; break; }
      cursor += 1;
    }
    if (matched) return true;
  }
  return false;
}

function assertSafeRegex(pattern: string, label: string): void {
  compileSafePattern(pattern, label);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isDenseArray(value: unknown): value is unknown[] {
  return Array.isArray(value)
    && Object.keys(value).length === value.length
    && Object.keys(value).every((key, index) => key === String(index));
}

function requireOnlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const unexpected = Object.keys(value).find((key) => !allowed.includes(key));
  if (unexpected !== undefined) throw new Error(`${label} contains unsupported field ${unexpected}`);
}

function requireNonblank(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${label} must be a nonblank string`);
}

function requireStringArray(value: unknown, label: string, allowEmpty = false): asserts value is string[] {
  if (!isDenseArray(value) || (!allowEmpty && value.length === 0) || value.some((entry) => typeof entry !== "string" || entry.trim().length === 0)) {
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
  if (!isDenseArray(value.toolRules)) throw new Error("toolRules must be a dense array");

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
    if (!isDenseArray(candidate)) throw new Error(`${key} must be a dense array`);
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
      assertSafeRegex(candidate.value, `argument rule ${id}`);
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

function argumentMatches(actual: unknown, rule: ArgumentRule, compiledPattern?: SafePattern): { matched: boolean; oversized: boolean } {
  switch (rule.operator) {
    case "present": return { matched: actual !== undefined && actual !== null, oversized: false };
    case "equals": return { matched: actual === rule.value, oversized: false };
    case "contains": return { matched: typeof actual === "string" && actual.includes(String(rule.value ?? "")), oversized: false };
    case "matches": {
      if (typeof actual !== "string" || typeof rule.value !== "string") return { matched: false, oversized: false };
      if (exceedsCodePointLimit(actual, MAX_REGEX_ARGUMENT_LENGTH)) return { matched: false, oversized: true };
      if (compiledPattern === undefined) return { matched: false, oversized: false };
      return { matched: safePatternMatches(compiledPattern, actual), oversized: false };
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
  readonly #argumentPatterns = new Map<string, SafePattern>();
  readonly policy: Policy;

  constructor(policy: Policy) {
    assertPolicy(policy);
    this.policy = structuredClone(policy);
    for (const rule of this.policy.argumentRules ?? []) {
      if (rule.operator === "matches" && typeof rule.value === "string") {
        this.#argumentPatterns.set(rule.id, compileSafePattern(rule.value, `argument rule ${rule.id}`));
      }
    }
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
      if (!matchTool(rule.tool, call.name)) continue;
      const evaluation = argumentMatches(readPath(call.arguments, rule.path), rule, this.#argumentPatterns.get(rule.id));
      if (evaluation.oversized) {
        matches.push({ id: `${rule.id}:input-too-large`, effect: "deny", reason: "argument-too-large" });
      } else if (evaluation.matched) {
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
