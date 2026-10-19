/**
 * External list sync. Sources are plain JSON data (allowed under MV3's remote-code rules).
 *
 * Memory and storage are kept small: every list is held as a sorted array of 64-bit hashes (8 bytes per domain,
 * binary-searched) instead of a Set of strings, so ~650k entries cost ~5 MB and a service-worker wake decodes them
 * in milliseconds. Only the newest N domains of each feed are kept as strings (for the declarativeNetRequest rules),
 * and the sibling / attacked-brand indexes are derived per source at refresh time and merged at load.
 *
 * Parsing is defensive because none of these endpoints publishes a stable schema contract for third parties.
 */
import { parse as tldParse } from "tldts";
import { fetchVerifiedFile } from "./lists";

export interface ListSource {
  id: string;
  url: string;
  kind: "blocklist" | "allowlist";
  /** refresh interval in minutes */
  every: number;
  /** newest entries kept as strings for DNR rules */
  tail: number;
}

export const SOURCES: ListSource[] = [
  // MetaMask's own production endpoint (stalelist = full snapshot, refreshed by MetaMask every 30 days)
  { id: "metamask", url: "https://phishing-detection.api.cx.metamask.io/v1/stalelist", kind: "blocklist", every: 60 * 12, tail: 40_000 },
  // PhishDestroy DestroyList: crypto-focused, keyless, raw JSON
  { id: "phishdestroy", url: "https://gitlab.com/phishdestroy/destroylist/-/raw/main/dns/active_domains.json", kind: "blocklist", every: 60 * 6, tail: 0 },
  // Community reports approved by the Web3 Phish Guard moderators (published daily to the lists repo, signed)
  { id: "community", url: "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data/community-blocklist.json", kind: "blocklist", every: 60 * 6, tail: 10_000 },
  // same file, the AI-confirmed "auto" set (warn-only, never a network block)
  { id: "community-auto", url: "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data/community-blocklist.json", kind: "blocklist", every: 60 * 6, tail: 0 },
  // ScamSniffer open database (7-day delayed, GPL-3.0 data; fetched at runtime, not bundled)
  { id: "scamsniffer", url: "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json", kind: "blocklist", every: 60 * 24, tail: 15_000 },
];

const MM_DIFFS = "https://phishing-detection.api.cx.metamask.io/v2/diffsSince/";

/** legacy storage shape (list:<id>), still read once for migration */
interface StoredList { domains: string[]; updatedAt: number; mmLastUpdated?: number }
interface ListMeta { count: number; updatedAt: number; mmLastUpdated?: number }

// ---------------------------------------------------------------------------
// 64-bit hash index
// ---------------------------------------------------------------------------
/** Two independent 32-bit FNV-1a style passes make a 64-bit key: collisions are ~1 in 1.8e19, far below the feeds' own noise. */
export function hash64(s: string): bigint {
  let a = 0x811c9dc5 >>> 0, b = 0x01000193 >>> 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193) >>> 0;
    b = Math.imul(b ^ c, 0x9e3779b1) >>> 0;
    b = (b ^ (b >>> 15)) >>> 0;
  }
  return (BigInt(a) << 32n) | BigInt(b);
}

export type HashIndex = BigUint64Array;

function sortedUnique(values: bigint[]): HashIndex {
  const idx = BigUint64Array.from(values);
  idx.sort();
  let w = 0;
  for (let i = 0; i < idx.length; i++) if (i === 0 || idx[i] !== idx[i - 1]) idx[w++] = idx[i];
  return idx.subarray(0, w);
}

export function buildIndex(domains: Iterable<string>): HashIndex {
  const arr: bigint[] = [];
  for (const d of domains) arr.push(hash64(d));
  return sortedUnique(arr);
}

export function indexHas(idx: HashIndex | undefined, h: bigint): boolean {
  if (!idx || !idx.length) return false;
  let lo = 0, hi = idx.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const v = idx[mid];
    if (v === h) return true;
    if (v < h) lo = mid + 1; else hi = mid - 1;
  }
  return false;
}

/** Add and remove entries, returning a new sorted index. */
export function indexUpdate(idx: HashIndex, add: Iterable<string>, remove: Iterable<string>): HashIndex {
  const del = new Set<bigint>();
  for (const d of remove) del.add(hash64(d));
  const keep: bigint[] = [];
  for (const h of idx) if (!del.has(h)) keep.push(h);
  for (const d of add) keep.push(hash64(d));
  return sortedUnique(keep);
}

export function encodeIndex(idx: HashIndex): string {
  const bytes = new Uint8Array(idx.buffer, idx.byteOffset, idx.byteLength);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
export function decodeIndex(b64: string): HashIndex {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new BigUint64Array(bytes.buffer, 0, Math.floor(bytes.length / 8));
}

// ---------------------------------------------------------------------------
// in-memory state
// ---------------------------------------------------------------------------
const mem = new Map<string, HashIndex>();
const tails = new Map<string, string[]>();
const metas = new Map<string, ListMeta>();
let allowMem: Set<string> | null = null;
/** MetaMask blocklistPaths: host -> path prefixes ("sites.google.com" -> ["/view/robinhood-hold", ...]) */
let pathMem = new Map<string, string[]>();
let pathList: string[] = [];
/** set only by warmLists(): a single hotlist diff must not make the worker think every list is loaded */
let warmed = false;
/** strongest source first: reviewed lists beat the broad PhishDestroy feed */
const SOURCE_ORDER = ["metamask", "scamsniffer", "community", "community-auto", "phishdestroy"];

/**
 * Shared platforms that feeds sometimes list bare (ScamSniffer carries "sites.google.com", "r2.dev"; MetaMask's
 * blocklistPaths collapse to "sites.google.com" if the path is cut off). A bare entry for one of these must never
 * block the whole platform. Populated from free-hosts.json at warm time plus this built-in floor.
 */
const BUILTIN_SHARED = ["sites.google.com", "docs.google.com", "drive.google.com", "storage.googleapis.com", "firebasestorage.googleapis.com", "github.io", "github.com", "gitlab.io", "pages.dev", "vercel.app", "netlify.app", "web.app", "r2.dev", "workers.dev", "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "herokuapp.com", "ipfs.io", "dweb.link", "w3s.link", "nftstorage.link", "eth.limo", "eth.link", "mypinata.cloud", "fleek.co", "on-fleek.app", "wixsite.com", "weebly.com", "squarespace.com", "webflow.io", "carrd.co", "linktr.ee", "notion.site", "substack.com", "medium.com", "telegra.ph", "t.me", "x.com", "twitter.com", "youtube.com", "discord.com", "discord.gg", "google.com", "microsoft.com", "apple.com", "cloudflare.com"];
const sharedHosts = new Set<string>(BUILTIN_SHARED);

/** True when a feed entry names a whole platform rather than a phishing site: a shared host, a public suffix, or a bare TLD. */
export function isSharedEntry(d: string): boolean {
  if (!d || !d.includes(".")) return true;
  if (sharedHosts.has(d)) return true;
  const r = tldParse(d, { allowPrivateDomains: true });
  if (!r.domain || r.publicSuffix === d) return true; // "r2.dev", "github.io", "co.uk"
  return false;
}

export function setSharedHosts(freeHosts: string[]): void {
  for (const h of freeHosts) sharedHosts.add(h);
}

/** Feed entries worth keeping: normalized, not a shared platform. */
export function ingestDomains(raw: string[]): string[] {
  const out: string[] = [];
  for (const d of raw) if (d && !isSharedEntry(d)) out.push(d);
  return out;
}

/** "https://sites.google.com/view/Foo/" -> "sites.google.com/view/foo" */
export function normalizePath(s: string): string {
  let v = s.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").replace(/[?#].*$/, "").replace(/\/+$/, "");
  v = v.replace(/^\*\./, "");
  if (!v.includes("/")) return "";
  return v;
}

export function buildPathIndex(paths: Iterable<string>): Map<string, string[]> {
  const idx = new Map<string, string[]>();
  for (const e of paths) {
    const i = e.indexOf("/");
    if (i <= 0) continue;
    const host = e.slice(0, i), path = e.slice(i);
    const arr = idx.get(host) ?? [];
    arr.push(path);
    idx.set(host, arr);
  }
  return idx;
}

/** Path-level hit: the page lives at or under a listed host+path prefix (segment boundary). */
export function pathHit(idx: Map<string, string[]>, host: string, pathname: string): boolean {
  const list = idx.get(host.toLowerCase());
  if (!list?.length) return false;
  const path = pathname.toLowerCase().replace(/\/+$/, "") || "/";
  return list.some((pre) => path === pre || path.startsWith(pre + "/"));
}

export function blocklistPathHit(host: string, pathname: string): string | undefined {
  return pathHit(pathMem, host, pathname) ? "metamask" : undefined;
}

export function newestPaths(n: number): string[] {
  return pathList.slice(Math.max(0, pathList.length - n));
}

// ---------------------------------------------------------------------------
// sibling index: scammers rotate the label on a shared host
// ---------------------------------------------------------------------------
export type SiblingIndex = Map<string, Map<string, string>>; // freeHost -> token -> listed host
let siblingIdx: SiblingIndex = new Map();
let siblingHosts: string[] = [];

const SIBLING_STOP = new Set(["start", "desktop", "suite", "learn", "cloud", "clone", "listing", "launchpad", "launch", "governance", "votes", "refund", "ether", "ethereum", "bitcoin", "mobile", "online", "secure", "center", "centre", "help", "official", "download", "install", "extension", "browser", "register", "registration", "allocation", "allocations", "quest", "quests", "signup", "proposal", "proposals", "distribution", "dashboard", "collab", "foundation", "enter", "chain", "check", "voting", "vote", "migrate", "migration", "trust", "casino", "community", "eligibility", "eligible", "treasury", "layer", "event", "events", "login", "account", "accounts", "support", "service", "services", "update", "security", "verification", "verify", "promo", "pages", "github", "vercel", "netlify", "webflow", "weebly", "wixsite", "portfolio", "project", "projects", "program", "programs", "campaign", "season", "round", "phase", "testnet", "mainnet", "alpha", "beta", "early", "access", "points", "rewards", "reward", "bonus", "prize", "winners", "lottery", "giveaway", "holders", "holder", "staking", "stake", "restake", "bridge", "swap", "trade", "trading", "exchange", "market", "markets", "finance", "capital", "invest", "investment", "fund", "funds", "token", "tokens", "coin", "coins", "crypto", "cryptos", "wallet", "wallets", "connect", "dapp", "dapps", "defi", "nft", "nfts", "airdrop", "airdrops", "claim", "claims", "mint", "minting", "checker", "drop", "drops", "portal", "app", "web", "www", "sign", "presale", "whitelist", "free", "live", "site", "page", "network", "protocol"]);

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

// ---------------------------------------------------------------------------
// attacked-brand index: a token that appears in many listed domains names a brand under attack right now
// ---------------------------------------------------------------------------
export interface AttackedBrand { token: string; count: number; example: string }
export type AttackIndex = Map<string, AttackedBrand>;
let attackIdx: AttackIndex = new Map();
const ATTACK_MIN = 5;

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

export function buildAttackIndex(domains: Iterable<string>, minCount = ATTACK_MIN, freeHosts: string[] = []): AttackIndex {
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

/** Per-source derived indexes, persisted so a wake never needs the domain strings. */
interface DerivedIndexes { sibling: Array<[string, Array<[string, string]>]>; attack: AttackedBrand[] }
const derived = new Map<string, DerivedIndexes>();

function deriveFor(domains: string[], freeHosts: string[]): DerivedIndexes {
  const sib = buildSiblingIndex(domains, freeHosts);
  // keep stems seen at least twice per source; the merged threshold is applied at load
  const atk = buildAttackIndex(domains, 2, freeHosts);
  return { sibling: [...sib].map(([k, m]) => [k, [...m]]), attack: [...atk.values()] };
}

/** Merge every source's derived indexes into the live ones. Attack counts take the max across sources (lists overlap heavily). */
function mergeDerived(): void {
  const sib: SiblingIndex = new Map();
  const atk = new Map<string, AttackedBrand>();
  for (const id of SOURCE_ORDER) {
    const d = derived.get(id);
    if (!d) continue;
    for (const [suffix, entries] of d.sibling) {
      let m = sib.get(suffix);
      if (!m) sib.set(suffix, (m = new Map()));
      for (const [t, host] of entries) if (!m.has(t)) m.set(t, host);
    }
    for (const a of d.attack) {
      const cur = atk.get(a.token);
      if (!cur || a.count > cur.count) atk.set(a.token, a);
    }
  }
  siblingIdx = sib;
  attackIdx = new Map([...atk].filter(([, a]) => a.count >= ATTACK_MIN));
}

// ---------------------------------------------------------------------------
// feed parsing
// ---------------------------------------------------------------------------
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

/** Like extractDomains but keeps the path (for MetaMask blocklistPaths). */
export function extractPaths(json: unknown, keys: string[]): string[] {
  const out: string[] = [];
  const walk = (node: unknown, key: string | null, depth: number) => {
    if (depth > 6 || node === null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      if (key && keys.includes(key) && node.every((x) => typeof x === "string")) { for (const s of node as string[]) { const v = normalizePath(s); if (v) out.push(v); } }
      return;
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) walk(v, k, depth + 1);
  };
  walk(json, null, 0);
  return out;
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

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------
async function storeSource(id: string, domains: string[], meta: Omit<ListMeta, "count">): Promise<void> {
  const src = SOURCES.find((s) => s.id === id);
  const idx = buildIndex(domains);
  const tail = src?.tail ? domains.slice(Math.max(0, domains.length - src.tail)) : [];
  const m: ListMeta = { ...meta, count: idx.length };
  const d = deriveFor(domains, siblingHosts);
  mem.set(id, idx);
  tails.set(id, tail);
  metas.set(id, m);
  derived.set(id, d);
  await chrome.storage.local.set({ [`hidx:${id}`]: encodeIndex(idx), [`tail:${id}`]: tail, [`meta:${id}`]: m, [`didx:${id}`]: d });
  await chrome.storage.local.remove(`list:${id}`).catch(() => undefined);
}

export async function refreshSource(src: ListSource): Promise<number> {
  // our own community list is published under the signed manifest: verify it like every other data file
  const json = src.id === "community" || src.id === "community-auto" ? await fetchVerifiedFile<unknown>("community-blocklist.json") : await fetchJson(src.url);
  let domains: string[];
  let mmLastUpdated: number | undefined;
  if (src.id === "metamask") {
    domains = extractDomains(json, ["blocklist", "blacklist"]);
    const allow = extractDomains(json, ["allowlist", "whitelist"]);
    await chrome.storage.local.set({ "list:metamask-allow": { domains: allow, updatedAt: Date.now() } satisfies StoredList });
    allowMem = new Set(allow);
    mmLastUpdated = findNumber(json, "lastUpdated");
    // host+path entries (Google Sites pages and the like) live in their own index; never collapsed to the host
    const paths = extractPaths(json, ["blocklistPaths"]);
    await chrome.storage.local.set({ "list:metamask-paths": { domains: paths, updatedAt: Date.now() } satisfies StoredList });
    pathList = paths;
    pathMem = buildPathIndex(paths);
  } else if (src.id === "community-auto") {
    domains = extractDomains(json, ["auto"]);
  } else if (src.id === "community") {
    domains = extractDomains(json, ["domains"]);
  } else {
    domains = extractDomains(json, ["domains", "blocklist", "blacklist", "list", "data", "active_domains"]);
  }
  domains = ingestDomains(domains);
  await storeSource(src.id, domains, { updatedAt: Date.now(), mmLastUpdated });
  scheduleIndexMerge();
  return domains.length;
}

/** Pure: split MetaMask diff entries into host and path additions/removals. */
export function metaMaskDiffOps(entries: Array<Record<string, unknown>>, since: number): { addHosts: string[]; delHosts: string[]; addPaths: string[]; delPaths: string[]; last: number } {
  const r = { addHosts: [] as string[], delHosts: [] as string[], addPaths: [] as string[], delPaths: [] as string[], last: since };
  for (const e of entries) {
    const raw = typeof e.url === "string" ? e.url : "";
    const target = String(e.targetList ?? "");
    const ts = typeof e.timestamp === "number" ? e.timestamp : 0;
    if (!raw) continue;
    if (target === "eth_phishing_detect_config.blocklist") {
      const url = normalizeDomain(raw);
      if (!url) continue;
      if (e.isRemoval) r.delHosts.push(url); else if (!isSharedEntry(url)) r.addHosts.push(url);
    } else if (target === "eth_phishing_detect_config.blocklistPaths") {
      const v = normalizePath(raw);
      if (!v) continue;
      if (e.isRemoval) r.delPaths.push(v); else r.addPaths.push(v);
    } else continue;
    if (ts > r.last) r.last = ts;
  }
  return r;
}

/**
 * Pure: apply MetaMask diff entries to string sets (test helper). Host entries come only from the blocklist target;
 * blocklistPaths entries keep their path (cutting the path off would list "sites.google.com" itself).
 */
export function applyMetaMaskDiff(hosts: Set<string>, paths: Set<string>, entries: Array<Record<string, unknown>>, since: number): number {
  const ops = metaMaskDiffOps(entries, since);
  for (const d of ops.delHosts) hosts.delete(d);
  for (const d of ops.addHosts) hosts.add(d);
  for (const p of ops.delPaths) paths.delete(p);
  for (const p of ops.addPaths) paths.add(p);
  return ops.last;
}

/** MetaMask hotlist: apply additions/removals since the stored timestamp. */
export async function refreshMetaMaskDiffs(): Promise<void> {
  const meta = metas.get("metamask") ?? ((await chrome.storage.local.get("meta:metamask"))["meta:metamask"] as ListMeta | undefined);
  if (!meta?.mmLastUpdated) return;
  const json = (await fetchJson(MM_DIFFS + meta.mmLastUpdated)) as { data?: unknown[] };
  const entries = Array.isArray(json?.data) ? json.data : [];
  const ops = metaMaskDiffOps(entries as Array<Record<string, unknown>>, meta.mmLastUpdated);
  if (!entries.length && ops.last === meta.mmLastUpdated) return; // nothing changed: skip the write
  const got = await chrome.storage.local.get(["hidx:metamask", "tail:metamask", "list:metamask-paths"]);
  const idx = mem.get("metamask") ?? (got["hidx:metamask"] ? decodeIndex(got["hidx:metamask"] as string) : buildIndex([]));
  const next = indexUpdate(idx, ops.addHosts, ops.delHosts);
  const del = new Set(ops.delHosts);
  const tail = [...(tails.get("metamask") ?? (got["tail:metamask"] as string[] | undefined) ?? []).filter((d) => !del.has(d)), ...ops.addHosts].slice(-40_000);
  const paths = new Set(((got["list:metamask-paths"] as StoredList | undefined)?.domains) ?? pathList);
  for (const p of ops.delPaths) paths.delete(p);
  for (const p of ops.addPaths) paths.add(p);
  pathList = [...paths];
  pathMem = buildPathIndex(pathList);
  const m: ListMeta = { count: next.length, updatedAt: Date.now(), mmLastUpdated: ops.last };
  await chrome.storage.local.set({
    "hidx:metamask": encodeIndex(next), "tail:metamask": tail, "meta:metamask": m,
    "list:metamask-paths": { domains: pathList, updatedAt: Date.now() } satisfies StoredList,
  });
  if (warmed) { mem.set("metamask", next); tails.set("metamask", tail); metas.set("metamask", m); }
}

let mergeTimer: ReturnType<typeof setTimeout> | undefined;
/** Several sources refresh back-to-back on install; merge the derived indexes once after the burst. */
function scheduleIndexMerge(): void {
  if (mergeTimer) clearTimeout(mergeTimer);
  mergeTimer = setTimeout(() => { mergeTimer = undefined; mergeDerived(); }, 2000);
}

/** The freshest entries of a source as strings (feeds append, so the tail is the newest). */
export function newestDomains(sourceId: string, n: number): string[] {
  const arr = (tails.get(sourceId) ?? []).filter((d) => !isSharedEntry(d));
  return arr.slice(Math.max(0, arr.length - n));
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
  setSharedHosts(freeHosts);
  siblingHosts = freeHosts;
  const keys = SOURCES.flatMap((s) => [`hidx:${s.id}`, `tail:${s.id}`, `meta:${s.id}`, `didx:${s.id}`, `list:${s.id}`]).concat(["list:metamask-allow", "list:metamask-paths"]);
  const got = await chrome.storage.local.get(keys);
  for (const s of SOURCES) {
    const h = got[`hidx:${s.id}`] as string | undefined;
    if (h) {
      const idx = decodeIndex(h);
      mem.set(s.id, idx);
      tails.set(s.id, (got[`tail:${s.id}`] as string[] | undefined) ?? []);
      metas.set(s.id, (got[`meta:${s.id}`] as ListMeta | undefined) ?? { count: idx.length, updatedAt: 0 });
      const d = got[`didx:${s.id}`] as DerivedIndexes | undefined;
      if (d) derived.set(s.id, d);
      continue;
    }
    // one-time migration from the string-array format (the shared-platform filter applies on the way)
    const legacy = got[`list:${s.id}`] as StoredList | undefined;
    if (legacy?.domains) await storeSource(s.id, ingestDomains(legacy.domains), { updatedAt: legacy.updatedAt, mmLastUpdated: legacy.mmLastUpdated });
  }
  const a = got["list:metamask-allow"] as StoredList | undefined;
  allowMem = new Set(a?.domains ?? []);
  const pm = got["list:metamask-paths"] as StoredList | undefined;
  pathList = pm?.domains ?? [];
  pathMem = buildPathIndex(pathList);
  await chrome.storage.local.remove(["idx:sibling", "idx:attack", "idx:at"]).catch(() => undefined); // pre-index-format leftovers
  mergeDerived();
  warmed = true;
}

export async function listStatus(): Promise<Record<string, { count: number; updatedAt: number }>> {
  const keys = SOURCES.map((s) => `meta:${s.id}`).concat(["list:metamask-allow"]);
  const got = await chrome.storage.local.get(keys);
  const out: Record<string, { count: number; updatedAt: number }> = {};
  for (const s of SOURCES) {
    const m = got[`meta:${s.id}`] as ListMeta | undefined;
    out[s.id] = { count: m?.count ?? 0, updatedAt: m?.updatedAt ?? 0 };
  }
  const a = got["list:metamask-allow"] as StoredList | undefined;
  out["metamask-allow"] = { count: a?.domains?.length ?? 0, updatedAt: a?.updatedAt ?? 0 };
  return out;
}

/** Returns the source id whose list contains the host or one of its parent domains. */
export function blocklistHit(host: string): string | undefined {
  // lists stored before the shared-platform filter existed may still carry "sites.google.com" itself
  const parents = parentDomains(host).filter((p) => !isSharedEntry(p)).map(hash64);
  for (const id of SOURCE_ORDER) {
    const idx = mem.get(id);
    if (!idx?.length) continue;
    for (const h of parents) if (indexHas(idx, h)) return id;
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
  return warmed;
}
