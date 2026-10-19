/** A wallet request the page made while we watched. We never answer it for real; we record and simulate it. */
export interface CapturedRequest {
  method: string;
  /** decoded intent label, e.g. "approve-unlimited", "setApprovalForAll", "permit2", "eth_sign" */
  kind: string;
  /** ms after the page said it was ready */
  atMs: number;
  /** true if it fired without any click from the harness (auto-drain on load / on connect) */
  unprompted: boolean;
  to?: string;
  /** spender / operator / recipient, when the decoder found one */
  counterparty?: string;
  chainId?: string;
  /** the raw params, trimmed, kept for the simulation step */
  params?: unknown;
}

export interface SimLine { out: string[]; in: string[]; approvals: string[]; reverted: boolean }

export interface ScanReport {
  url: string;
  host: string;
  /** did the run complete, or did navigation / the browser fail */
  ok: boolean;
  error?: string;
  startedAt: number;
  durationMs: number;
  /** 0..100, higher = more likely a drainer */
  score: number;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  /** short machine-readable reasons, e.g. "auto-approve-on-connect", "drainer-script", "seed-form" */
  flags: string[];
  /** human lines for the popup, already plain text */
  findings: string[];
  requests: CapturedRequest[];
  /** per-request simulation of what signing it would have done to a wallet on that chain */
  simulations: Array<{ kind: string; chainId?: string; sim?: SimLine }>;
  /** drainer markers found in page scripts */
  scriptMarkers: string[];
  /** outbound hosts the page contacted that are on our known-bad list */
  badHosts: string[];
  /** did the page try to read a seed phrase / private key */
  seedForm: boolean;
}

export interface ScanOptions {
  /** hard ceiling for the whole run */
  timeoutMs?: number;
  /** try clicking obvious connect / claim / mint buttons to make the page reveal its flow */
  interact?: boolean;
}
