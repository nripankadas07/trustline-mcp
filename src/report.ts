import { auditBundle, type SimulationResult, verifyAudit } from "./simulator.js";
import { writeArtifactSet } from "./safe-output.js";

export const REPORT_VERSION = "trustline.report/v1" as const;

function escapeHtml(value: unknown): string {
  return normalizeDisplayText(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
}

function normalizeDisplayText(value: unknown): string {
  return String(value).replace(/[\p{Cc}\p{Cf}]+/gu, " ").replace(/\s+/gu, " ").trim();
}

function escapeMarkdown(value: unknown): string {
  return normalizeDisplayText(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replace(/([\\`*_[\]{}|])/gu, "\\$1");
}

export function buildReport(result: SimulationResult) {
  const verification = verifyAudit(auditBundle(result));
  return {
    version: REPORT_VERSION,
    generatedBy: "trustline-mcp@0.1.1",
    deterministic: true,
    policyName: result.policyName,
    policyDigest: result.policyDigest,
    totals: result.totals,
    audit: verification,
    decisions: result.entries.map((entry) => ({ index: entry.index, effect: entry.decision?.effect ?? "protocol-error", reasons: entry.decision?.reasonCodes ?? [], hash: entry.hash })),
  };
}

export function markdownReport(result: SimulationResult): string {
  const report = buildReport(result);
  const rows = report.decisions.map((item) => `| ${item.index} | ${item.effect} | ${item.reasons.join(", ") || "-"} | \`${item.hash.slice(0, 12)}\` |`).join("\n");
  return `# Trustline MCP offline simulation\n\nArtifact: \`${REPORT_VERSION}\`\n\n- Policy: **${escapeMarkdown(report.policyName)}**\n- Policy digest: \`${report.policyDigest}\`\n- Allowed: **${report.totals.allowed}**\n- Denied: **${report.totals.denied}**\n- Approval required: **${report.totals.approvalRequired}**\n- Protocol errors: **${report.totals.protocolErrors}**\n- Audit valid: **${report.audit.valid}**\n- Audit root: \`${report.audit.rootHash}\`\n\n| # | Decision | Reasons | Hash |\n|---:|---|---|---|\n${rows}\n\n> This is an offline JSON-RPC transcript simulator. It does not intercept production OAuth or HTTP traffic.\n`;
}

export function htmlReport(result: SimulationResult): string {
  const report = buildReport(result);
  const rows = report.decisions.map((item) => `<tr><td>${item.index}</td><td><span class="${escapeHtml(item.effect)}">${escapeHtml(item.effect)}</span></td><td>${escapeHtml(item.reasons.join(", ") || "-")}</td><td><code>${escapeHtml(item.hash.slice(0, 16))}</code></td></tr>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Trustline MCP report</title><style>body{font:15px system-ui;margin:0;background:#09111f;color:#e5edf8}.wrap{max-width:980px;margin:auto;padding:40px}.card{background:#111d31;border:1px solid #263754;border-radius:14px;padding:22px;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}.metric{background:#0d1728;padding:14px;border-radius:10px}.metric b{font-size:26px;display:block}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:10px;border-bottom:1px solid #263754}code{color:#9bd4ff}.allow{color:#76e6a4}.deny,.default-deny{color:#ff8f8f}.approval{color:#ffd479}.protocol-error{color:#b3bfd1}.note{color:#aebbd0}</style></head><body><main class="wrap"><h1>Trustline MCP</h1><p class="note">Deterministic offline JSON-RPC policy simulation · ${REPORT_VERSION}</p><section class="grid"><div class="metric"><b>${report.totals.allowed}</b>allowed</div><div class="metric"><b>${report.totals.denied}</b>denied</div><div class="metric"><b>${report.totals.approvalRequired}</b>approval</div><div class="metric"><b>${report.totals.protocolErrors}</b>protocol errors</div></section><section class="card"><h2>Audit chain</h2><p>Valid: <b>${report.audit.valid}</b></p><code>${escapeHtml(report.audit.rootHash)}</code></section><section class="card"><h2>Transcript decisions</h2><table><thead><tr><th>#</th><th>Decision</th><th>Reasons</th><th>Hash</th></tr></thead><tbody>${rows}</tbody></table></section><p class="note">Simulation only: no production OAuth or HTTP interception is claimed.</p></main></body></html>\n`;
}

export async function writeArtifacts(outDir: string, result: SimulationResult): Promise<void> {
  await writeArtifactSet(outDir, {
    "audit.json": `${JSON.stringify(auditBundle(result), null, 2)}\n`,
    "report.json": `${JSON.stringify(buildReport(result), null, 2)}\n`,
    "report.md": markdownReport(result),
    "index.html": htmlReport(result),
  });
}
