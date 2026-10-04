import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  MAX_MCP_MESSAGE_BYTES,
  MAX_MCP_RESPONSE_BYTES,
  MCP_PROTOCOL_VERSION,
  handleMcpMessage,
  type McpResponse,
} from "./stdio.js";

export const DEFAULT_MCP_HTTP_HOST = "127.0.0.1" as const;
export const DEFAULT_MCP_HTTP_PORT = 8787;
export const MCP_HTTP_PATH = "/mcp" as const;

type RequestId = string | number;

class BodyTooLargeError extends Error {}
class InvalidUtf8Error extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validId(value: unknown): value is RequestId {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value));
}

function requestId(value: unknown): RequestId | undefined {
  return isRecord(value) && validId(value.id) ? value.id : undefined;
}

function errorResponse(id: RequestId | undefined, code: number, message: string, data?: unknown): McpResponse {
  const error = data === undefined ? { code, message } : { code, message, data };
  return id === undefined
    ? { jsonrpc: "2.0", error }
    : { jsonrpc: "2.0", id, error };
}

function setCommonHeaders(response: ServerResponse): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

function sendEmpty(response: ServerResponse, status: number): void {
  setCommonHeaders(response);
  response.statusCode = status;
  response.end();
}

function sendJson(response: ServerResponse, status: number, value: McpResponse): void {
  let encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded, "utf8") > MAX_MCP_RESPONSE_BYTES) {
    const id = "id" in value ? value.id : undefined;
    encoded = JSON.stringify(errorResponse(id, -32603, `Response exceeds the ${MAX_MCP_RESPONSE_BYTES}-byte limit`));
  }
  setCommonHeaders(response);
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(encoded, "utf8"));
  response.end(encoded);
}

function rawSingletonHeader(request: IncomingMessage, expectedName: string): string | null | undefined {
  const matches: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === expectedName) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) matches.push(value);
    }
  }
  if (matches.length === 0) return undefined;
  return matches.length === 1 ? matches[0] : null;
}

function acceptsRequiredTypes(request: IncomingMessage): boolean {
  const value = request.headers.accept;
  if (typeof value !== "string") return false;
  const mediaTypes = value.split(",").map((entry) => entry.split(";", 1)[0]?.trim().toLowerCase());
  return mediaTypes.includes("application/json") && mediaTypes.includes("text/event-stream");
}

function hasJsonContentType(request: IncomingMessage): boolean {
  const value = rawSingletonHeader(request, "content-type");
  if (value === null || value === undefined) return false;
  return value.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function isLoopbackOrigin(value: string): boolean {
  try {
    const parsed = new URL(value);
    if (!["http:", "https:"].includes(parsed.protocol)) return false;
    if (parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") return false;
    const hostname = parsed.hostname.toLowerCase();
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
  } catch {
    return false;
  }
}

function decodeMirroredHeader(value: string): string | undefined {
  const sentinel = /^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$/u.exec(value);
  if (sentinel !== null) {
    const encoded = sentinel[1];
    if (encoded === undefined || encoded.length % 4 !== 0) return undefined;
    const bytes = Buffer.from(encoded, "base64");
    if (bytes.toString("base64") !== encoded) return undefined;
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      return undefined;
    }
  }
  if (!/^[\x20-\x7e\t]*$/u.test(value) || value.trim() !== value) return undefined;
  if (value.startsWith("=?base64?") || value.endsWith("?=")) return undefined;
  return value;
}

function bodyProtocolVersion(value: Record<string, unknown>): unknown {
  if (!isRecord(value.params) || !isRecord(value.params._meta)) return undefined;
  return value.params._meta["io.modelcontextprotocol/protocolVersion"];
}

function bodyName(value: Record<string, unknown>): unknown {
  if (!isRecord(value.params)) return undefined;
  if (value.method === "resources/read") return value.params.uri;
  if (value.method === "tools/call" || value.method === "prompts/get") return value.params.name;
  return undefined;
}

function validateMirroredHeaders(request: IncomingMessage, value: Record<string, unknown>): string | undefined {
  const protocolHeader = rawSingletonHeader(request, "mcp-protocol-version");
  const methodHeader = rawSingletonHeader(request, "mcp-method");
  const version = bodyProtocolVersion(value);
  if (protocolHeader === null || protocolHeader === undefined || protocolHeader !== version) {
    return "Header mismatch: MCP-Protocol-Version is missing or does not match params._meta";
  }
  if (methodHeader === null || methodHeader === undefined || methodHeader !== value.method) {
    return "Header mismatch: Mcp-Method is missing or does not match method";
  }

  const expectedName = bodyName(value);
  const requiresName = value.method === "tools/call" || value.method === "resources/read" || value.method === "prompts/get";
  const nameHeader = rawSingletonHeader(request, "mcp-name");
  if (requiresName) {
    if (typeof expectedName !== "string" || nameHeader === null || nameHeader === undefined) {
      return "Header mismatch: Mcp-Name is missing or its body source is invalid";
    }
    const decoded = decodeMirroredHeader(nameHeader);
    if (decoded === undefined || decoded !== expectedName) {
      return "Header mismatch: Mcp-Name is malformed or does not match the request body";
    }
  } else if (nameHeader !== undefined) {
    return "Header mismatch: Mcp-Name is not defined for this method";
  }
  return undefined;
}

function readBoundedBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      request.removeAllListeners("data");
      request.resume();
      reject(error);
    };
    request.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > MAX_MCP_MESSAGE_BYTES) {
        fail(new BodyTooLargeError());
        return;
      }
      chunks.push(buffer);
    });
    request.once("aborted", () => fail(new Error("Request body aborted")));
    request.once("error", fail);
    request.once("end", () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks, bytes));
    });
  });
}

function parseUtf8Json(bytes: Buffer): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new InvalidUtf8Error();
  }
  return JSON.parse(text) as unknown;
}

function responseStatus(response: McpResponse): number {
  if (!("error" in response)) return 200;
  if ([-32700, -32600, -32020, -32022].includes(response.error.code)) return 400;
  return 200;
}

async function handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
  let requestUrl: URL;
  try {
    requestUrl = new URL(request.url ?? "/", "http://localhost");
  } catch {
    sendJson(response, 400, errorResponse(undefined, -32600, "Invalid request target"));
    return;
  }
  if (requestUrl.pathname !== MCP_HTTP_PATH) {
    sendJson(response, 404, errorResponse(undefined, -32601, "MCP endpoint not found"));
    return;
  }

  const origin = rawSingletonHeader(request, "origin");
  if (origin === null || (origin !== undefined && !isLoopbackOrigin(origin))) {
    sendJson(response, 403, errorResponse(undefined, -32021, "Forbidden Origin"));
    return;
  }
  if (origin !== undefined) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Vary", "Origin");
  }

  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    sendJson(response, 405, errorResponse(undefined, -32600, "The MCP endpoint accepts POST only"));
    return;
  }
  if (!hasJsonContentType(request)) {
    sendJson(response, 415, errorResponse(undefined, -32600, "Content-Type must be application/json"));
    return;
  }
  if (!acceptsRequiredTypes(request)) {
    sendJson(response, 406, errorResponse(undefined, -32600, "Accept must include application/json and text/event-stream"));
    return;
  }

  const declaredLength = rawSingletonHeader(request, "content-length");
  if (declaredLength === null || (declaredLength !== undefined && !/^(0|[1-9][0-9]*)$/u.test(declaredLength))) {
    request.resume();
    sendJson(response, 400, errorResponse(undefined, -32600, "Content-Length must be one nonnegative decimal integer"));
    return;
  }
  if (declaredLength !== undefined && Number(declaredLength) > MAX_MCP_MESSAGE_BYTES) {
    request.resume();
    sendJson(response, 413, errorResponse(undefined, -32600, `Request exceeds the ${MAX_MCP_MESSAGE_BYTES}-byte limit`));
    return;
  }

  let value: unknown;
  try {
    value = parseUtf8Json(await readBoundedBody(request));
  } catch (error: unknown) {
    if (error instanceof BodyTooLargeError) {
      sendJson(response, 413, errorResponse(undefined, -32600, `Request exceeds the ${MAX_MCP_MESSAGE_BYTES}-byte limit`));
      return;
    }
    const message = error instanceof InvalidUtf8Error ? "Request body must be valid UTF-8 JSON" : "Parse error";
    sendJson(response, 400, errorResponse(undefined, -32700, message));
    return;
  }

  if (!isRecord(value) || Array.isArray(value) || typeof value.method !== "string") {
    sendJson(response, 400, errorResponse(requestId(value), -32600, "Invalid Request"));
    return;
  }

  if (!Object.hasOwn(value, "id")) {
    if (handleMcpMessage(value) === null) {
      sendEmpty(response, 202);
      return;
    }
  } else {
    const mismatch = validateMirroredHeaders(request, value);
    if (mismatch !== undefined) {
      sendJson(response, 400, errorResponse(requestId(value), -32020, mismatch));
      return;
    }
  }

  const handled = handleMcpMessage(value);
  if (handled === null) {
    sendEmpty(response, 202);
    return;
  }
  sendJson(response, responseStatus(handled), handled);
}

export function createStreamableHttpServer(): Server {
  const server = createServer((request, response) => {
    void handleRequest(request, response).catch(() => {
      if (!response.headersSent) sendJson(response, 500, errorResponse(undefined, -32603, "Internal server error"));
      else response.destroy();
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 1_000;
  return server;
}

export async function listenStreamableHttp(port = DEFAULT_MCP_HTTP_PORT): Promise<{ server: Server; url: URL }> {
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("HTTP port must be an integer from 0 to 65535");
  const server = createStreamableHttpServer();
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen(port, DEFAULT_MCP_HTTP_HOST, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address() as AddressInfo | null;
  if (address === null) {
    server.close();
    throw new Error("HTTP server did not expose a listening address");
  }
  return { server, url: new URL(`http://${DEFAULT_MCP_HTTP_HOST}:${address.port}${MCP_HTTP_PATH}`) };
}

export async function runStreamableHttp(port = DEFAULT_MCP_HTTP_PORT): Promise<void> {
  const { server, url } = await listenStreamableHttp(port);
  process.stderr.write(`trustline-mcp listening on ${url.href}\n`);
  await new Promise<void>((resolve, reject) => {
    let shuttingDown = false;
    const shutdown = (): void => {
      if (shuttingDown) return;
      shuttingDown = true;
      server.close((error) => error === undefined ? resolve() : reject(error));
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
    server.once("error", reject);
  });
}
