import { POLICY_VERSION, type Policy } from "./policy.js";

export const demoPolicy: Policy = {
  version: POLICY_VERSION,
  name: "offline-attack-lab",
  defaultEffect: "deny",
  toolRules: [
    { id: "allow-read", effect: "allow", tools: ["repo.read"] },
    { id: "allow-search", effect: "allow", tools: ["docs.search"] },
    { id: "approve-shell", effect: "approval", tools: ["shell.safe"] },
    { id: "deny-system", effect: "deny", tools: ["system.*"] },
  ],
  argumentRules: [
    { id: "deny-destructive-shell", effect: "deny", tool: "shell.safe", path: "command", operator: "matches", value: "(^|\\s)(rm|sudo|curl|wget)(\\s|$)|--force" },
  ],
  pathRules: [
    { id: "workspace-only", effect: "allow", tool: "repo.read", argument: "path", roots: ["/workspace"] },
  ],
  hostRules: [
    { id: "docs-hosts", effect: "allow", tool: "docs.search", argument: "url", hosts: ["docs.example.test"] },
    { id: "deny-link-local", effect: "deny", tool: "*", argument: "url", hosts: ["169.254.169.254", "localhost"] },
  ],
  quotas: [{ id: "search-quota", tool: "docs.search", limit: 2 }],
  redactKeys: ["privateNote"],
};

function call(id: number, name: string, args: Record<string, unknown>, approvedBy?: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args, ...(approvedBy === undefined ? {} : { approvedBy }) } });
}

export const attackTranscript = [
  call(1, "repo.read", { path: "/workspace/README.md", apiKey: "synthetic-demo-token-123456" }),
  call(2, "repo.read", { path: "/workspace/../etc/passwd" }),
  call(3, "docs.search", { url: "https://docs.example.test/agents", query: "policy" }),
  call(4, "docs.search", { url: "https://docs.example.test/evals", query: "audit" }),
  call(5, "docs.search", { url: "https://docs.example.test/extra", query: "quota" }),
  call(6, "docs.search", { url: "http://169.254.169.254/latest/meta-data", query: "credentials" }),
  call(7, "shell.safe", { command: "npm test", privateNote: "Bearer very-secret-token" }),
  call(8, "shell.safe", { command: "rm -rf build --force" }, "reviewer@example.test"),
  call(9, "shell.safe", { command: "npm test" }, "reviewer@example.test"),
  call(10, "unknown.tool", {}),
  "{not-json}",
] as const;
