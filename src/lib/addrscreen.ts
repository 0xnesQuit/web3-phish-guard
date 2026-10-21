/**
 * Counterparty screening at the wallet gate: is the address a request would approve / pay a known malicious one?
 * Pure helpers here (allowlist, which addresses to screen, flag labels); the network call is the background's
 * `w3pg:addr` handler asking our Worker, which asks GoPlus. Display only: it never decides to hold or release.
 */
import { KNOWN_CONTRACTS } from "./impact";

/**
 * Never screened, never flagged (lowercase). Reuses the gate's KNOWN_CONTRACTS table (Uniswap Permit2 and routers,
 * OpenSea Seaport 1.5 / 1.6 and conduit, Blur, 1inch, 0x, ... the same addresses the gate already names as "known
 * contract") and pins the three that matter most explicitly: Permit2, Seaport 1.6, Seaport 1.5.
 */
export const ADDR_ALLOWLIST: ReadonlySet<string> = new Set([
  "0x000000000022d473030f116ddee9f6b43ac78ba3", // Uniswap Permit2 (same address on every chain)
  "0x0000000000000068f116a894984e2db1123eb395", // OpenSea Seaport 1.6
  "0x00000000000000adc04c56bf30ac9d3c0aaf14dc", // OpenSea Seaport 1.5
  ...Object.keys(KNOWN_CONTRACTS),
]);

const ADDR_RE = /^0x[0-9a-f]{40}$/;
const ZERO = "0x0000000000000000000000000000000000000000";

export interface Counterparty { address: string; role: "spender" | "recipient" }

/** Kinds whose counterparty is a recipient of funds; every other screened kind is a spender / operator. */
const RECIPIENT_KINDS = new Set(["transfer", "transferFrom", "eth-send", "transfer-auth"]);
const SCREEN_KINDS = new Set(["approve", "approve-unlimited", "setApprovalForAll", "permit2", "permit", "permit-batch", "permit-for-all", ...RECIPIENT_KINDS]);

/**
 * Distinct addresses worth screening (at most 3): drops the allowlist, the zero address and the user's own address.
 * `items` are (kind, counterparty) pairs from the decoded intent(s).
 */
export function screenTargets(items: Array<{ kind: string; counterparty?: string }>, user?: string): Counterparty[] {
  const out: Counterparty[] = [];
  const seen = new Set<string>();
  for (const it of items) {
    const a = it.counterparty?.toLowerCase();
    if (!a || !SCREEN_KINDS.has(it.kind) || !ADDR_RE.test(a) || a === ZERO || a === user?.toLowerCase() || ADDR_ALLOWLIST.has(a) || seen.has(a)) continue;
    seen.add(a);
    out.push({ address: a, role: RECIPIENT_KINDS.has(it.kind) ? "recipient" : "spender" });
    if (out.length >= 3) break;
  }
  return out;
}

/** Short i18n label key for the strongest matched GoPlus flag group (display only). */
export function flagLabelKey(flags: string[]): string {
  const has = (...f: string[]) => f.some((x) => flags.includes(x));
  if (has("phishing_activities", "stealing_attack")) return "gate_addr_l_phish";
  if (has("sanctioned")) return "gate_addr_l_sanction";
  if (has("money_laundering")) return "gate_addr_l_launder";
  return "gate_addr_l_crime";
}

/** Shape check of the Worker reply; anything else counts as "not flagged". */
export function parseAddrReply(r: unknown): { bad: boolean; flags: string[] } {
  const o = (r && typeof r === "object" ? r : {}) as { bad?: unknown; flags?: unknown };
  const flags = Array.isArray(o.flags) ? o.flags.filter((f): f is string => typeof f === "string").slice(0, 12) : [];
  return { bad: o.bad === true && flags.length > 0, flags };
}
