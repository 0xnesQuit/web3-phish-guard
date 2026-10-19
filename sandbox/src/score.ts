/** Turn the raw observations into a score (0..100), a verdict and short human findings. Mutates the report. */
import type { ScanReport } from "./types.js";

const HELD = new Set(["approve-unlimited", "setApprovalForAll", "permit2", "permit", "permit-batch", "permit-for-all", "seaport-order", "blur-order", "delegation", "delegation-7702", "transfer-auth", "safe-delegatecall", "agent-approval", "eth_sign"]);

export function score(r: ScanReport): void {
  let s = 0;
  const flags: string[] = [];
  const findings: string[] = [];
  const add = (n: number, flag: string, finding: string) => { s += n; if (!flags.includes(flag)) { flags.push(flag); findings.push(finding); } };

  // what the page asked the throwaway wallet to do
  const commits = r.requests.filter((q) => /sign|sendTransaction|sendCalls/i.test(q.method));
  const unprompted = commits.filter((q) => q.unprompted);
  if (unprompted.length) add(40, "auto-request-on-load", `Asked the wallet to act without any click (${unprompted.length} request${unprompted.length > 1 ? "s" : ""})`);
  for (const q of commits) {
    if (q.kind === "eth_sign") add(35, "blind-sign", "Requested a raw eth_sign (can authorize anything)");
    else if (HELD.has(q.kind)) add(25, "dangerous-" + q.kind, `Requested ${q.kind}${q.counterparty ? ` to ${q.counterparty.slice(0, 10)}…` : ""}`);
  }

  // what simulating those requests would have done
  for (const sim of r.simulations) {
    if (!sim.sim) continue;
    const leaves = sim.sim.out.length > 0;
    const comesBack = sim.sim.in.length > 0;
    if (leaves && !comesBack) add(40, "drain", `Simulation: assets leave the wallet with nothing in return (${sim.sim.out.join(", ").slice(0, 80)})`);
    if (sim.sim.approvals.length) add(30, "approval", `Simulation: grants a spending approval (${sim.sim.approvals.join(", ").slice(0, 80)})`);
  }

  if (r.scriptMarkers.length) add(30, "drainer-script", `Page code matches known drainer kits (${r.scriptMarkers.length} marker${r.scriptMarkers.length > 1 ? "s" : ""})`);
  if (r.badHosts.length) add(25, "bad-host", `Contacted a known-bad host (${r.badHosts.join(", ").slice(0, 60)})`);
  if (r.seedForm) add(50, "seed-form", "The page tries to collect a recovery phrase or private key");

  r.score = Math.max(0, Math.min(100, s));
  r.flags = flags;
  r.findings = findings;
  r.verdict = !r.ok ? "unknown" : r.score >= 70 ? "malicious" : r.score >= 35 ? "suspicious" : "clean";
}
