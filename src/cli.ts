#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { attackTranscript, demoPolicy } from "./demo.js";
import type { Policy } from "./policy.js";
import { writeArtifacts } from "./report.js";
import { auditBundle, simulateTranscript, verifyAudit } from "./simulator.js";

async function main(args: string[]): Promise<number> {
  const [command = "help", ...rest] = args;
  if (command === "demo") {
    if (rest.length > 1 || rest[0]?.startsWith("-") === true) throw new Error("usage: trustline-mcp demo [OUT]");
    const out = rest[0] ?? "artifacts/demo";
    const result = simulateTranscript(demoPolicy, attackTranscript);
    await writeArtifacts(out, result);
    console.log(JSON.stringify({ out, totals: result.totals, audit: verifyAudit(auditBundle(result)) }));
    return 0;
  }
  if (command === "simulate") {
    if (rest.length < 2 || rest.length > 3 || rest.some((value) => value.startsWith("-"))) throw new Error("usage: trustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]");
    const [policyPath, transcriptPath, out = "artifacts/simulation"] = rest;
    if (policyPath === undefined || transcriptPath === undefined) throw new Error("usage: trustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]");
    const policy = JSON.parse(await readFile(policyPath, "utf8")) as Policy;
    const lines = (await readFile(transcriptPath, "utf8")).split(/\r?\n/u).filter(Boolean);
    const result = simulateTranscript(policy, lines);
    await writeArtifacts(out, result);
    console.log(JSON.stringify({ out, totals: result.totals, audit: verifyAudit(auditBundle(result)) }));
    return 0;
  }
  if (command === "verify") {
    if (rest.length !== 1 || rest[0]?.startsWith("-") === true) throw new Error("usage: trustline-mcp verify AUDIT.json");
    const path = rest[0];
    if (path === undefined) throw new Error("usage: trustline-mcp verify AUDIT.json");
    const parsed = JSON.parse(await readFile(path, "utf8")) as unknown;
    const verification = verifyAudit(parsed);
    console.log(JSON.stringify(verification));
    return verification.valid ? 0 : 1;
  }
  if (["help", "--help", "-h"].includes(command) && rest.length > 0) throw new Error("help does not accept operands");
  console.log("trustline-mcp demo [OUT]\ntrustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]\ntrustline-mcp verify AUDIT.json");
  return command === "help" || command === "--help" || command === "-h" ? 0 : 2;
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
