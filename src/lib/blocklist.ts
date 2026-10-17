/**
 * External list sync. Sources are plain JSON data (allowed under MV3's
 * remote-code rules). Everything is stored in chrome.storage.local and held in
 * memory as Sets for O(1) lookup. Parsing is defensive because none of these
 * endpoints publishes a stable schema contract for third parties.
 */

export interface ListSource {
  id: string;
  url: string;
  kind: "blocklist" | "allowlist";
  /** refresh interval in minutes */
  every: number;
}

export const SOURCES: ListSource[] = [
  // MetaMask's own production endpoint (stalelist = full snapshot, refreshed by MetaMask every 30 days)
  { id: "metamask", url: "https://phishing-detection.api.cx.metamask.io/v1/stalelist", kind: "blocklist", every: 60 * 12 },
  // PhishDestroy DestroyList: crypto-focused, keyless, raw JSON
  { id: "phishdestroy", url: "https://gitlab.com/phishdestroy/destroylist/-/raw/main/dns/active_domains.json", kind: "blocklist", every: 60 * 6 },
  // ScamSniffer open database (7-day delayed, GPL-3.0 data; fetched at runtime, not bundled)
  { id: "scamsniffer", url: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json", kind: "blocklist", every: 60 * 24 },
];

const MM_DIFFS = "https://phishing-detection.api.cx.metamask.io/v2/diffsSince/";

interface StoredList {
  domains: string[];
  updatedAt: number;
  /** MetaMask lastUpdated (unix seconds) for diffsSince */
  mmLastUpdated?: number;
}

const mem = new Map<string, Set<string>>();
let allowMem: Set<string> | null = null;

/**
 * Sibling index: scammers rotate the label on a shared host (airdrop-onsolana.netlify.app is listed,
 * drop-onsolana.netlify.app is live). Index listed free-host entries by (freeHost, distinctive token)
 * so a fresh sibling is recognised from the token it shares with a listed one.
 */
export type SiblingIndex = Map<string, Map<string, string>>; // freeHost -> token -> listed host
let siblingIdx: SiblingIndex = new Map();
let siblingHosts: string[] = [];

const SIBLING_STOP = new Set(["register", "registration", "allocation", "allocations", "quest", "quests", "signup", "proposal", "proposals", "distribution", "dashboard", "collab", "foundation", "enter", "chain", "check", "voting", "vote", "migrate", "migration", "trust", "casino", "community", "eligibility", "eligible", "treasury", "layer", "event", "events", "login", "account", "accounts", "support", "service", "services", "update", "security", "verification", "verify", "promo", "pages", "github", "vercel", "netlify", "webflow", "weebly", "wixsite", "portfolio", "project", "projects", "program", "programs", "campaign", "season", "round", "phase", "testnet", "mainnet", "alpha", "beta", "early", "access", "points", "rewards", "reward", "bonus", "prize", "winners", "lottery", "giveaway", "holders", "holder", "staking", "stake", "restake", "bridge", "swap", "trade", "trading", "exchange", "market", "markets", "finance", "capital", "invest", "investment", "fund", "funds", "token", "tokens", "coin", "coins", "crypto", "cryptos", "wallet", "wallets", "connect", "dapp", "dapps", "defi", "nft", "nfts", "airdrop", "airdrops", "claim", "claims", "claims", "airdrop", "airdrops", "rewards", "reward", "mint", "minting", "checker", "drop", "drops", "official", "portal", "app", "web", "www", "wallet", "connect", "verify", "secure", "login", "sign", "token", "tokens", "nft", "nfts", "crypto", "swap", "bridge", "stake", "staking", "presale", "whitelist", "giveaway", "bonus", "event", "events", "free", "live", "site", "page", "online", "network", "protocol", "finance", "exchange", "dapp", "dapps"]);

export function siblingTokens(label: string): string[] {
  return label.toLowerCase().split(/[-_.]+|(?<=\D)(?=\d)|(?<=\d)(?=\D)/).filter((t) => t.length >= 5 && /[a-z]/.test(t) && !SIBLING_STOP.has(t));
}

export function buildSiblingIndex(domains: Iterable<string>, freeHosts: string[]): SiblingIndex {
  const idx: SiblingIndex = new Map();
  const fh = freeHosts.map((h) => "." + h);
  for (const d of domains) {
    const suffix = fh.find((h) => d.endsWith(h));
    if (!suffix) continue;
    const label = d.slice(0, -suffix.length).split(".").pop() ?? "";
    for (const t of siblingTokens(label)) {
      let m = idx.get(suffix);
      if (!m) idx.set(suffix, (m = new Map()));
      if (!m.has(t)) m.set(t, d);
    }
  }
  return idx;
}

/** Returns the listed host that shares a distinctive token with `host` on the same free host, if any. */
export function findSibling(host: string, idx: SiblingIndex): string | undefined {
  for (const [suffix, m] of idx) {
    if (!host.endsWith(suffix)) continue;
    const label = host.slice(0, -suffix.length).split(".").pop() ?? "";
    for (const t of siblingTokens(label)) {
      const listed = m.get(t);
      if (listed && listed !== host) return listed;
    }
  }
  return undefined;
}

/**
 * Attacked-brand index: a token that appears in many listed phishing domains names a brand that is
 * being phished right now (pharosnetwork-tge.com, testnet-pharosnetwork.net, vote-pharosnetwork.xyz ...).
 * A fresh host carrying the same token (or its affix-stripped stem) inherits that knowledge before it is listed.
 */
export interface AttackedBrand { token: string; count: number; example: string }
export type AttackIndex = Map<string, AttackedBrand>;
let attackIdx: AttackIndex = new Map();

const STEM_AFFIX = ["foundation", "official", "finance", "protocol", "network", "testnet", "mainnet", "airdrop", "claim", "labs", "team", "dao", "fnd", "fdn", "app", "xyz", "eth", "sol", "ico", "tge", "net"];
export function stemToken(t: string): string {
  let s = t.toLowerCase();
  for (let pass = 0; pass < 2; pass++) {
    for (const a of STEM_AFFIX) {
      if (s.length - a.length >= 4 && s.endsWith(a)) { s = s.slice(0, -a.length); break; }
      if (s.length - a.length >= 4 && s.startsWith(a)) { s = s.slice(a.length); break; }
    }
  }
  return s;
}

export function buildAttackIndex(domains: Iterable<string>, minCount = 5, freeHosts: string[] = []): AttackIndex {
  const counts = new Map<string, { count: number; example: string; hosts: Set<string> }>();
  const fh = freeHosts.map((h) => "." + h);
  for (const d of domains) {
    const suffix = fh.find((h) => d.endsWith(h));
    const labels = (suffix ? d.slice(0, -suffix.length) : d).split(".");
    if (!suffix) labels.pop(); // drop the TLD (a free-host suffix was already removed)
    const seen = new Set<string>();
    for (const l of labels) {
      for (const t of siblingTokens(l)) {
        const stem = stemToken(t);
        if (stem.length < 5 || SIBLING_STOP.has(stem)) continue;
        if (seen.has(stem)) continue;
        seen.add(stem);
        const c = counts.get(stem) ?? { count: 0, example: d, hosts: new Set<string>() };
        // count distinct registrable-ish roots so 50 subdomains of one host do not inflate a token
        const root = labels.slice(-1)[0] + "." + (d.split(".").pop() ?? "");
        if (!c.hosts.has(root)) { c.hosts.add(root); c.count++; }
        counts.set(stem, c);
      }
    }
  }
  const idx: AttackIndex = new Map();
  for (const [stem, c] of counts) if (c.count >= minCount) idx.set(stem, { token: stem, count: c.count, example: c.example });
  return idx;
}

export function findAttackedBrand(host: string, idx: AttackIndex): AttackedBrand | undefined {
  const labels = host.split(".");
  labels.pop();
  let best: AttackedBrand | undefined;
  for (const l of labels) {
    for (const t of siblingTokens(l)) {
      const hit = idx.get(stemToken(t));
      if (hit && (!best || hit.count > best.count)) best = hit;
    }
  }
  return best;
}

export function attackedBrandHit(host: string): AttackedBrand | undefined {
  return findAttackedBrand(host, attackIdx);
}

export function siblingHit(host: string): string | undefined {
  return findSibling(host, siblingIdx);
}

export function rebuildSiblingIndex(freeHosts: string[]): void {
  siblingHosts = freeHosts;
  const all: string[] = [];
  for (const set of mem.values()) for (const d of set) all.push(d);
  siblingIdx = buildSiblingIndex(all, freeHosts);
  attackIdx = buildAttackIndex(all, 5, freeHosts);
  void persistIndexes();
}

/** The indexes are derived data; persist them so a service-worker restart does not re-scan 600k domains. */
async function persistIndexes(): Promise<void> {
  try {
    const sib: Array<[string, Array<[string, string]>]> = [...siblingIdx].map(([k, m]) => [k, [...m]]);
    await chrome.storage.local.set({ "idx:sibling": sib, "idx:attack": [...attackIdx.values()], "idx:at": Date.now() });
  } catch (e) {
    console.warn("[w3pg] persist indexes failed", e);
  }
}

async function loadIndexes(): Promise<boolean> {
  const got = await chrome.storage.local.get(["idx:sibling", "idx:attack", "idx:at"]);
  if (!got["idx:attack"] || !got["idx:sibling"]) return false;
  siblingIdx = new Map((got["idx:sibling"] as Array<[string, Array<[string, string]>]>).map(([k, m]) => [k, new Map(m)]));
  attackIdx = new Map((got["idx:attack"] as AttackedBrand[]).map((a) => [a.token, a]));
  return true;
}

/** Walk arbitrary JSON and collect string arrays under keys that look like domain lists. */
export function extractDomains(json: unknown, keys: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<unknown>();
  const walk = (node: unknown, key: string | null, depth: number) => {
    if (depth > 6 || node === null || typeof node !== "object" || seen.has(node)) return;
    seen.add(node);
    if (Array.isArray(node)) {
      if (key && keys.includes(key) && node.every((x) => typeof x === "string")) {
        for (const s of node as string[]) out.push(normalizeDomain(s));
        return;
      }
      for (const x of node) walk(x, key, depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) walk(v, k, depth + 1);
  };
  if (Array.isArray(json) && json.every((x) => typeof x === "string")) return (json as string[]).map(normalizeDomain);
  walk(json, null, 0);
  return out.filter(Boolean);
}

export function normalizeDomain(s: string): string {
  let d = s.trim().toLowerCase();
  if (d.includes("://")) {
    try { d = new URL(d).hostname; } catch { /* keep */ }
  }
  return d.replace(/^\*\./, "").replace(/^www\./, "").replace(/\/.*$/, "").replace(/\.$/, "");
}

async function fetchJson(url: string): Promise<unknown> {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

export async function refreshSource(src: ListSource): Promise<number> {
  const json = await fetchJson(src.url);
  let domains: string[];
  let mmLastUpdated: number | undefined;
  if (src.id === "metamask") {
    domains = extractDomains(json, ["blocklist", "blacklist"]);
    const allow = extractDomains(json, ["allowlist", "whitelist"]);
    await chrome.storage.local.set({ "list:metamask-allow": { domains: allow, updatedAt: Date.now() } satisfies StoredList });
    allowMem = new Set(allow);
    mmLastUpdated = findNumber(json, "lastUpdated");
  } else {
    domains = extractDomains(json, ["domains", "blocklist", "blacklist", "list", "data", "active_domains"]);
  }
  const stored: StoredList = { domains, updatedAt: Date.now(), mmLastUpdated };
  await chrome.storage.local.set({ [`list:${src.id}`]: stored });
  mem.set(src.id, new Set(domains));
  if (siblingHosts.length) rebuildSiblingIndex(siblingHosts);
  return domains.length;
}

/** MetaMask hotlist: apply additions/removals since the stored timestamp. */
export async function refreshMetaMaskDiffs(): Promise<void> {
  const stored = (await chrome.storage.local.get("list:metamask"))["list:metamask"] as StoredList | undefined;
  if (!stored?.mmLastUpdated) return;
  const json = (await fetchJson(MM_DIFFS + stored.mmLastUpdated)) as { data?: unknown[] };
  const entries = Array.isArray(json?.data) ? json.data : [];
  const set = new Set(stored.domains);
  let last = stored.mmLastUpdated;
  for (const e of entries as Array<Record<string, unknown>>) {
    const url = typeof e.url === "string" ? normalizeDomain(e.url) : "";
    const target = String(e.targetList ?? "");
    const ts = typeof e.timestamp === "number" ? e.timestamp : 0;
    if (!url || !target.includes("blocklist")) continue;
    if (e.isRemoval) set.delete(url); else set.add(url);
    if (ts > last) last = ts;
  }
  const domains = [...set];
  await chrome.storage.local.set({ "list:metamask": { domains, updatedAt: Date.now(), mmLastUpdated: last } satisfies StoredList });
  mem.set("metamask", set);
}

function findNumber(json: unknown, key: string, depth = 0): number | undefined {
  if (depth > 5 || !json || typeof json !== "object") return undefined;
  for (const [k, v] of Object.entries(json as Record<string, unknown>)) {
    if (k === key && typeof v === "number") return v;
    const r = findNumber(v, key, depth + 1);
    if (r !== undefined) return r;
  }
  return undefined;
}

/** Load lists from storage into memory (called on service worker start). */
export async function warmLists(freeHosts: string[] = []): Promise<void> {
  const keys = [...SOURCES.map((s) => `list:${s.id}`), "list:metamask-allow"];
  const got = await chrome.storage.local.get(keys);
  for (const s of SOURCES) {
    const v = got[`list:${s.id}`] as StoredList | undefined;
    if (v?.domains) mem.set(s.id, new Set(v.domains));
  }
  const a = got["list:metamask-allow"] as StoredList | undefined;
  allowMem = new Set(a?.domains ?? []);
  if (freeHosts.length) {
    siblingHosts = freeHosts;
    if (!(await loadIndexes())) rebuildSiblingIndex(freeHosts);
  }
}

export async function listStatus(): Promise<Record<string, { count: number; updatedAt: number }>> {
  const keys = [...SOURCES.map((s) => `list:${s.id}`), "list:metamask-allow"];
  const got = await chrome.storage.local.get(keys);
  const out: Record<string, { count: number; updatedAt: number }> = {};
  for (const k of keys) {
    const v = got[k] as StoredList | undefined;
    out[k.replace("list:", "")] = { count: v?.domains?.length ?? 0, updatedAt: v?.updatedAt ?? 0 };
  }
  return out;
}

/** Returns the source id whose list contains the host or one of its parent domains. */
export function blocklistHit(host: string): string | undefined {
  const parents = parentDomains(host);
  for (const [id, set] of mem) {
    if (!set.size) continue;
    for (const p of parents) if (set.has(p)) return id;
  }
  return undefined;
}

export function allowlistHit(host: string): boolean {
  if (!allowMem?.size) return false;
  return parentDomains(host).some((p) => allowMem!.has(p));
}

export function parentDomains(host: string): string[] {
  const parts = host.split(".");
  const out: string[] = [];
  for (let i = 0; i < parts.length - 1; i++) out.push(parts.slice(i).join("."));
  return out;
}

export function isWarm(): boolean {
  return mem.size > 0;
}
