/** Static drainer fingerprints and a small set of known-bad hosts. Kept deliberately tight to avoid false positives. */

/** Patterns that show up in wallet-drainer kits but almost never in legitimate dapps. */
export const SCRIPT_MARKERS: RegExp[] = [
  /secureproxy\.php/i,
  /ping_proxy/i,
  /rotatingURL/i,
  /createPrizeTxs/i,
  /claimSolana/i,
  /\bdrainer\b/i,
  /inferno/i,
  /angel[_-]?drainer/i,
  /setApprovalForAll[\s\S]{0,300}(permit|transferFrom)/i,
  /eth_signTypedData_v4[\s\S]{0,300}Permit/i,
  /signAllTransactions[\s\S]{0,200}SystemProgram\.transfer/i,
  /drainerapi|pandora|monkey[_-]?drainer|venom[_-]?drainer/i,
];

/**
 * Hosts a drainer page typically phones home to. This is a seed only; the real list is pulled from the project's
 * blocklist feeds at deploy time (see README). Matching is on the registrable part, case-insensitive.
 */
export const KNOWN_BAD_HOSTS: string[] = [
  // intentionally small; extend from data/bad-hosts.json at deploy time
];

/** Does the page's own source look like it reads a recovery phrase or a private key? */
export const SEED_FORM_HINTS: RegExp[] = [
  /seed\s*phrase|recovery\s*phrase|mnemonic|secret\s*recovery/i,
  /private\s*key|wallet\s*import|import\s*wallet|restore\s*wallet/i,
];

const SIMPLE_TLD = /\.[a-z]{2,24}$/i;
export function registrable(host: string): string {
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  // naive eTLD+1; good enough for list matching (the extension does the precise work with tldts)
  return parts.slice(-2).join(".") || host;
}

/**
 * Is this hostname a private / loopback / link-local / internal target the sandbox must never reach? Used both to
 * vet the scan URL and to abort the page's own sub-requests, so a hostile page cannot pivot to services on the VPS
 * (defence in depth on top of the container's network egress rules). IP-literal based; DNS-rebinding to a private
 * address is caught by the network-level egress block, not here.
 */
export function isPrivateHost(host: string): boolean {
  const h = (host || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan") || h.endsWith(".home") || h.endsWith(".corp")) return true;
  if (!h.includes(".") && !h.includes(":")) return true; // bare single-label name
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = Number(m[1]), b = Number(m[2]);
    if (a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224) return true;
  }
  // any IPv6 literal (loopback ::1, link-local fe80::, ULA fc00::/7, mapped) — we only ever scan public IPv4 hosts
  if (h.includes(":")) return true;
  return false;
}

export function isBadHost(host: string, extra: string[] = []): boolean {
  const r = registrable(host);
  const all = new Set([...KNOWN_BAD_HOSTS, ...extra].map((h) => h.toLowerCase()));
  return all.has(r) || all.has(host.toLowerCase()) || (SIMPLE_TLD.test(r) && all.has(r));
}
