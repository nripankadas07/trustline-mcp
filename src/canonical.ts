import { createHash } from "node:crypto";

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical JSON rejects non-finite numbers");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.keys(value).some((key, index) => key !== String(index))) throw new TypeError("canonical JSON rejects sparse or extended arrays");
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("canonical JSON rejects non-plain objects");
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

const secretKey = /(authorization|api[-_]?key|password|secret|token|cookie)/i;
const secretValue = /\b(?:sk|gh[opsu]|xox[baprs])[-_][A-Za-z0-9_-]{6,}\b|Bearer\s+[A-Za-z0-9._~+/-]+=*/gi;

export function redact(value: unknown, extraKeys: readonly string[] = []): unknown {
  const extra = new Set(extraKeys.map((key) => key.toLowerCase()));
  const redactString = (text: string): string => {
    let safe = text.replace(secretValue, "[REDACTED]");
    try {
      const url = new URL(safe);
      let changed = false;
      if (url.password.length > 0) { url.password = "[REDACTED]"; changed = true; }
      if (url.username.length > 0) { url.username = "[REDACTED]"; changed = true; }
      for (const key of [...url.searchParams.keys()]) {
        if (secretKey.test(key) || extra.has(key.toLowerCase())) { url.searchParams.set(key, "[REDACTED]"); changed = true; }
      }
      if (url.hash.length > 1) {
        const fragment = new URLSearchParams(url.hash.slice(1));
        let fragmentChanged = false;
        for (const key of [...fragment.keys()]) {
          if (secretKey.test(key) || extra.has(key.toLowerCase())) { fragment.set(key, "[REDACTED]"); fragmentChanged = true; }
        }
        if (fragmentChanged) { url.hash = fragment.toString(); changed = true; }
      }
      if (changed) safe = url.toString();
    } catch {
      // Non-URL strings still receive credential-shape redaction above.
    }
    return safe;
  };
  const walk = (item: unknown, key?: string): unknown => {
    if (key !== undefined && (secretKey.test(key) || extra.has(key.toLowerCase()))) return "[REDACTED]";
    if (typeof item === "string") return redactString(item);
    if (Array.isArray(item)) {
      if (Object.keys(item).length !== item.length || Object.keys(item).some((childKey, index) => childKey !== String(index))) throw new TypeError("redaction rejects sparse or extended arrays");
      return item.map((entry) => walk(entry));
    }
    if (item !== null && typeof item === "object") {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError("redaction rejects non-plain objects");
      return Object.fromEntries(Object.entries(item).map(([childKey, child]) => [childKey, walk(child, childKey)]));
    }
    return item;
  };
  return walk(value);
}
