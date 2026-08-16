#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { attackTranscript, demoPolicy } from "./demo.js";
import type { Policy } from "./policy.js";
import { writeArtifacts } from "./report.js";
import { auditBundle, simulateTranscript, verifyAudit } from "./simulator.js";

const USAGE = "trustline-mcp demo [OUT]\ntrustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]\ntrustline-mcp verify AUDIT.json";
type CommandHandler = (operands: string[]) => Promise<number>;

const demo: CommandHandler = async (operands) => {
  if (operands.length > 1 || operands[0]?.startsWith("-") === true) throw new Error("usage: trustline-mcp demo [OUT]");
  const out = operands[0] ?? "artifacts/demo";
  const result = simulateTranscript(demoPolicy, attackTranscript);
  await writeArtifacts(out, result);
  console.log(JSON.stringify({ out, totals: result.totals, audit: verifyAudit(auditBundle(result)) }));
  return 0;
};

const simulate: CommandHandler = async (operands) => {
  if (operands.length < 2 || operands.length > 3 || operands.some((value) => value.startsWith("-"))) throw new Error("usage: trustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]");
  const [policyPath, transcriptPath, out = "artifacts/simulation"] = operands;
  if (policyPath === undefined || transcriptPath === undefined) throw new Error("usage: trustline-mcp simulate POLICY.json TRANSCRIPT.jsonl [OUT]");
  const policy = JSON.parse(await readFile(policyPath, "utf8")) as Policy;
  const lines = (await readFile(transcriptPath, "utf8")).split(/\r?\n/u).filter(Boolean);
  const result = simulateTranscript(policy, lines);
  await writeArtifacts(out, result);
  console.log(JSON.stringify({ out, totals: result.totals, audit: verifyAudit(auditBundle(result)) }));
  return 0;
};

const verify: CommandHandler = async (operands) => {
  if (operands.length !== 1 || operands[0]?.startsWith("-") === true) throw new Error("usage: trustline-mcp verify AUDIT.json");
  const inputPath = operands[0];
  if (inputPath === undefined) throw new Error("usage: trustline-mcp verify AUDIT.json");
  const parsed = JSON.parse(await readFile(inputPath, "utf8")) as unknown;
  const verification = verifyAudit(parsed);
  console.log(JSON.stringify(verification));
  return verification.valid ? 0 : 1;
};

const help: CommandHandler = async (operands) => {
  if (operands.length > 0) throw new Error("help does not accept operands");
  console.log(USAGE);
  return 0;
};

async function main(args: string[]): Promise<number> {
  const [requestedCommand = "help", ...operands] = args;
  switch (requestedCommand) {
    case "demo": return demo(operands);
    case "simulate": return simulate(operands);
    case "verify": return verify(operands);
    case "help":
    case "--help":
    case "-h": return help(operands);
    default:
      console.log(USAGE);
      return 2;
  }
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
