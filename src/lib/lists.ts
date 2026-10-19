import type { Brand, SignalLists } from "./types";

let cache: { brands: Brand[]; lists: SignalLists } | null = null;

/**
 * Data files ship inside the extension (zero-latency fallback) and are refreshed from REMOTE_BASE,
 * where a daily GitHub Action publishes regenerated copies. Remote copies live in chrome.storage.local
 * and win over the bundled ones. Only JSON data is fetched, never code.
 */
export const DATA_FILES = ["brands.seed.json", "brands.generated.json", "brands.nft.json", "brands.cmc.json", "action-words.json", "free-hosts.json", "tlds.json", "trusted.json", "shared-hosts.json"] as const;
export const REMOTE_BASE = "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data";

interface RemoteManifest { updatedAt: number; files: Record<string, { bytes: number; sha256?: string }>; sig?: string }

/** Public half of the key the lists repo's Action signs manifests with (ECDSA P-256). */
const LISTS_PUBLIC_JWK: JsonWebKey = {"kty": "EC", "x": "BrgP2NFya33GKjoBAwOEs4IgRFIhwYP4b166fk82ciw", "y": "gPwAuGROUY7YXYcllu51OH39hODbNA8KcVcupMJfsEM", "crv": "P-256"};
/** A remote trusted list may only grow this much beyond the bundled one; anything larger is treated as tampering. */
const TRUSTED_GROWTH_LIMIT = 50;

/**
 * Every file that can make the extension *quieter* is capped against the bundled copy, so a signed-but-malicious
 * publish (a stolen signing key, a compromised Action) cannot whitelist the world or strip the word lists:
 *  - trusted.json: at most 50 new domains
 *  - brands.seed.json: at most 50 new official domains, at most 50 brands removed
 *  - free-hosts.json: at most 5 hosts removed
 *  - action-words.json / tlds.json: at most 20% of the bundled entries removed
 *  - auto-imported brand files: size may not change by more than half (they churn daily, and their "official"
 *    status never relaxes the wallet gate nor beats a reviewed blocklist hit)
 * Returns a reason when the remote copy must be rejected.
 */
export function remoteGuard(file: string, bundled: unknown, remote: unknown): string | null {
  const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : typeof v === "object" && v ? Object.values(v as Record<string, unknown>).flatMap(strs) : typeof v === "string" ? [v] : []);
  const brands = (v: unknown): Array<{ name?: string; domains?: string[] }> => (Array.isArray(v) ? (v as Array<{ name?: string; domains?: string[] }>) : []);
  if (file === "trusted.json") {
    const b = flattenTrusted(bundled as Record<string, string[] | string> | null), r = flattenTrusted(remote as Record<string, string[] | string> | null);
    const added = r.filter((d) => !b.includes(d)).length;
    return added > TRUSTED_GROWTH_LIMIT ? `grew by ${added}` : null;
  }
  if (file === "brands.seed.json") {
    const b = brands(bundled), r = brands(remote);
    const bd = new Set(b.flatMap((x) => x.domains ?? [])), rd = new Set(r.flatMap((x) => x.domains ?? []));
    const addedDomains = [...rd].filter((d) => !bd.has(d)).length;
    const bn = new Set(b.map((x) => x.name)), rn = new Set(r.map((x) => x.name));
    const removedBrands = [...bn].filter((n) => !rn.has(n)).length;
    if (addedDomains > 50) return `${addedDomains} new official domains`;
    if (removedBrands > 50) return `${removedBrands} brands removed`;
    return null;
  }
  if (file === "free-hosts.json" || file === "shared-hosts.json") {
    const b = strs(bundled), r = new Set(strs(remote));
    const removed = b.filter((h) => !r.has(h)).length;
    return removed > 5 ? `${removed} hosts removed` : null;
  }
  if (file === "action-words.json" || file === "tlds.json") {
    const b = strs(bundled), r = new Set(strs(remote));
    const removed = b.filter((h) => !r.has(h)).length;
    return b.length && removed > b.length * 0.2 ? `${removed} entries removed` : null;
  }
  if (file.startsWith("brands.")) {
    const b = brands(bundled).length, r = brands(remote).length;
    return b > 0 && (r < b / 2 || r > b * 2) ? `size ${b} -> ${r}` : null;
  }
  return null;
}

let manifestMem: { m: RemoteManifest; at: number } | null = null;
/** The signed manifest, re-fetched at most every 10 minutes. Throws when missing or not verifiably ours. */
export async function signedManifest(): Promise<RemoteManifest> {
  if (manifestMem && Date.now() - manifestMem.at < 10 * 60_000) return manifestMem.m;
  const res = await fetch(`${REMOTE_BASE}/manifest.json`, { cache: "no-store" });
  if (!res.ok) throw new Error(`manifest ${res.status}`);
  const m = (await res.json()) as RemoteManifest;
  if (!(await verifyManifest(m))) throw new Error("manifest signature invalid or missing");
  manifestMem = { m, at: Date.now() };
  return m;
}

/** Fetch one published file and check it against the signed manifest's hash (used for the community blocklist). */
export async function fetchVerifiedFile<T>(file: string): Promise<T> {
  const m = await signedManifest();
  const entry = m.files[file];
  if (!entry?.sha256) throw new Error(`${file} not in manifest`);
  const r = await fetch(`${REMOTE_BASE}/${file}`, { cache: "no-store" });
  if (!r.ok) throw new Error(`${file} ${r.status}`);
  const text = await r.text();
  if ((await sha256Hex(text)) !== entry.sha256) throw new Error(`${file}: hash mismatch`);
  return JSON.parse(text) as T;
}

async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function canonicalManifest(m: RemoteManifest): string {
  const files = Object.fromEntries(Object.keys(m.files).sort().map((k) => [k, { bytes: m.files[k].bytes, sha256: m.files[k].sha256 }]));
  return JSON.stringify({ updatedAt: m.updatedAt, files });
}

export async function verifyManifest(m: RemoteManifest): Promise<boolean> {
  if (!m.sig) return false;
  try {
    const key = await crypto.subtle.importKey("jwk", LISTS_PUBLIC_JWK, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const sig = Uint8Array.from(atob(m.sig), (c) => c.charCodeAt(0));
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, new TextEncoder().encode(canonicalManifest(m)));
  } catch {
    return false;
  }
}

async function loadBundled<T>(file: string): Promise<T | null> {
  try {
    const res = await fetch(chrome.runtime.getURL("data/" + file));
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

async function loadJson<T>(file: string): Promise<T | null> {
  try {
    const remote = (await chrome.storage.local.get("data:" + file))["data:" + file] as T | undefined;
    if (remote !== undefined) return remote;
  } catch {
    /* fall through */
  }
  return loadBundled<T>(file);
}

let handleMap: Map<string, Brand> | null = null;
/** X handle (lowercase, no @) -> brand, for "the page links to the project's real X account but is not the project's site". */
export function brandByHandle(brands: Brand[]): Map<string, Brand> {
  if (handleMap && handleMap.size) return handleMap;
  handleMap = new Map();
  for (const b of brands) {
    const h = (b.x ?? "").toLowerCase().replace(/^@/, "");
    if (h && !handleMap.has(h)) handleMap.set(h, b);
  }
  return handleMap;
}

let tokenMap: Map<string, Brand> | null = null;
/** brand token -> brand (first wins; seed before generated). */
export function brandByToken(brands: Brand[]): Map<string, Brand> {
  if (tokenMap && tokenMap.size) return tokenMap;
  tokenMap = new Map();
  for (const b of brands) for (const t of b.tokens) {
    const k = t.toLowerCase();
    if (k.length >= 5 && !tokenMap.has(k)) tokenMap.set(k, b);
  }
  return tokenMap;
}

/** Drop the in-memory cache so the next evaluation re-reads storage (after a remote refresh). */
export function invalidateStaticData(): void {
  cache = null;
  handleMap = null;
  tokenMap = null;
}

export async function remoteDataStatus(): Promise<{ updatedAt: number; files: number }> {
  const got = await chrome.storage.local.get(["data:updatedAt", "data:files"]);
  return { updatedAt: (got["data:updatedAt"] as number | undefined) ?? 0, files: (got["data:files"] as number | undefined) ?? 0 };
}

/** Fetch lists/manifest.json; download files only when the manifest is newer than what we hold. */
export async function refreshRemoteData(force = false): Promise<{ updated: boolean; files: number }> {
  // Supply-chain gate: the manifest must carry a valid signature from the lists repo's key, and every file must
  // match the hash the signed manifest names. A compromised repo or CDN cannot hand the extension a new allowlist.
  manifestMem = null;
  const manifest = await signedManifest();
  const have = ((await chrome.storage.local.get("data:updatedAt"))["data:updatedAt"] as number | undefined) ?? 0;
  if (manifest.updatedAt < have) throw new Error("manifest older than the installed data (rollback refused)");
  if (!force && manifest.updatedAt === have) return { updated: false, files: 0 };
  const updates: Record<string, unknown> = {};
  let n = 0;
  for (const file of DATA_FILES) {
    const entry = manifest.files[file];
    if (!entry?.sha256) continue;
    try {
      const r = await fetch(`${REMOTE_BASE}/${file}`, { cache: "no-store" });
      if (!r.ok) continue;
      const text = await r.text();
      if ((await sha256Hex(text)) !== entry.sha256) { console.warn(`[w3pg] ${file}: hash mismatch, skipped`); continue; }
      const json = JSON.parse(text);
      if (json === null || typeof json !== "object") continue;
      // curated files are capped against the bundled copy (cumulative: a stolen key cannot grow the trusted list 50 at a
      // time), the churny generated brand files against the last accepted copy
      const churny = file === "brands.generated.json" || file === "brands.cmc.json" || file === "brands.nft.json";
      const prev = churny ? (await chrome.storage.local.get("data:" + file))["data:" + file] : undefined;
      const why = remoteGuard(file, prev !== undefined ? prev : await loadBundled(file), json);
      if (why) { console.warn(`[w3pg] ${file} rejected (${why}), kept the previous copy`); continue; }
      updates["data:" + file] = json;
      n++;
    } catch {
      /* keep the previous copy of this file */
    }
  }
  if (n) {
    updates["data:updatedAt"] = manifest.updatedAt;
    updates["data:files"] = n;
    await chrome.storage.local.set(updates);
    invalidateStaticData();
  }
  return { updated: n > 0, files: n };
}

/** Bundled static data (brands + signal word lists). Cached per service-worker lifetime. */
export async function loadStaticData(): Promise<{ brands: Brand[]; lists: SignalLists }> {
  if (cache) return cache;
  const [seed, generated, nft, cmc, actions, hosts, tlds, trusted, sharedFile] = await Promise.all([
    loadJson<Brand[]>("brands.seed.json"),
    loadJson<Brand[]>("brands.generated.json"),
    loadJson<Brand[]>("brands.nft.json"),
    loadJson<Brand[]>("brands.cmc.json"),
    loadJson<{ strong: string[]; medium: string[] }>("action-words.json"),
    loadJson<{ strong: string[]; weak: string[] }>("free-hosts.json"),
    loadJson<{ strong: string[]; weak: string[] }>("tlds.json"),
    loadJson<Record<string, string[] | string>>("trusted.json"),
    loadJson<{ hosts: string[] }>("shared-hosts.json"),
  ]);
  const shared = [...(sharedFile?.hosts ?? []), ...(hosts?.strong ?? []), ...(hosts?.weak ?? [])];
  const trustedList = flattenTrusted(trusted); // curated by hand: marketplaces and social sites on it are deliberate
  const brands = sanitizeBrands(mergeBrands([...(seed ?? []), ...brandsFromTrusted(trustedList)], [...(generated ?? []), ...(nft ?? []), ...(cmc ?? [])]), shared);
  cache = {
    brands,
    lists: {
      shared,
      trusted: trustedList,
      actionStrong: actions?.strong ?? [],
      actionMedium: actions?.medium ?? [],
      freeHostsStrong: hosts?.strong ?? [],
      freeHostsWeak: hosts?.weak ?? [],
      tldStrong: tlds?.strong ?? [],
      tldWeak: tlds?.weak ?? [],
    },
  };
  return cache;
}

const TRUSTED_GENERIC = new Set(["rainbow", "phantom", "backpack", "exodus", "family", "frame", "magic", "dynamic", "brave", "gemini", "upside", "sonic", "mode", "spark", "sky", "blast", "shape", "world", "blockchain", "crypto", "wallet", "bridge", "explorer", "swap", "exchange", "network", "protocol", "finance", "foundation", "portal", "relay", "jumper", "family", "frame", "magic", "dynamic", "privy", "spark", "across", "scroll", "blast", "mode", "base", "zora", "blur", "tensor", "manifold", "highlight", "foundation", "superrare", "rarible", "github", "google", "apple", "microsoft", "cloudflare", "vercel", "netlify", "youtube", "discord", "telegram", "twitter", "medium", "notion", "gitbook", "mirror", "paragraph", "snapshot", "tally", "cookie", "kaito", "dune", "sky", "curve", "balancer", "matcha", "odos", "meteora", "photon", "axiom", "bullx", "gmgn", "pump", "relay", "socket", "bungee", "hop", "stargate", "wormhole", "portalbridge", "safe", "gnosis", "ens", "unstoppabledomains", "ipfs", "pinata", "alchemy", "infura", "quicknode", "helius", "thegraph", "chainlink", "chain", "sonic", "mantle", "linea", "monad", "sei", "celestia", "cosmos", "polkadot", "near", "ton", "tron", "sui", "aptoslabs", "avax", "bnbchain", "polygon", "optimism", "arbitrum", "solana", "ethereum", "revolut", "etoro", "robinhood", "moonpay", "transak", "ramp", "tradingview", "messari", "glassnode", "santiment", "mempool", "blockchair", "oklink", "3xpl", "routescan", "blockscout", "subscan", "mintscan", "tonscan", "tonviewer", "tronscan", "suiscan", "suivision", "aptoscan", "starkscan", "voyager", "seitrace", "hypurrscan", "cardanoscan", "sonarscan", "xray", "era", "explorer", "app"]);

/**
 * Every trusted domain also acts as a curated brand: "coinmarketcap.communityphase.app" must read as an
 * impersonation of coinmarketcap.com. Labels that are ordinary words or chain names already covered by the
 * seed list are skipped.
 */
export function brandsFromTrusted(trusted: string[]): Brand[] {
  const out: Brand[] = [];
  const seen = new Set<string>();
  for (const d of trusted) {
    const parts = d.split(".");
    const label = (parts.length > 2 && parts[0].length < 6 ? parts[1] : parts[0]).toLowerCase();
    // short names (okx, htx, mexc, jup, gmx, lido) are also ordinary words and other companies: they only count as a
    // whole label next to a bait word / free host / fresh registration, which the generated tier already enforces
    if (label.length < 3 || TRUSTED_GENERIC.has(label) || seen.has(label) || !/^[a-z0-9]+$/.test(label)) continue;
    seen.add(label);
    out.push({ name: label, tokens: [label], domains: [d], tier: label.length < 6 ? "generated" : "seed" });
  }
  return out;
}

/**
 * Shared platforms can never be a brand's own domain or a trusted domain: a generated entry naming "eth.limo" or a
 * trusted entry naming "vercel.app" would clear every page on that platform. Curated seed entries keep their domains
 * (a seed may deliberately name "metamask.github.io"); generated tiers lose any domain equal to or under a shared host.
 */
export function sanitizeBrands(brands: Brand[], shared: string[]): Brand[] {
  const under = (d: string) => shared.some((s) => d === s || d.endsWith("." + s));
  const ownsIt = (b: Brand, d: string) => { const label = d.split(".")[0].replace(/[^a-z0-9]/g, ""); return label.length >= 4 && b.name.toLowerCase().replace(/[^a-z0-9]/g, "").includes(label); };
  return brands.map((b) => (b.tier === "generated" ? { ...b, domains: b.domains.filter((d) => !under(d) || ownsIt(b, d)) } : b));
}
export function sanitizeTrusted(trusted: string[], shared: string[]): string[] {
  return trusted.filter((d) => !shared.includes(d));
}

export function flattenTrusted(json: Record<string, string[] | string> | null): string[] {
  if (!json) return [];
  const out = new Set<string>();
  for (const [k, v] of Object.entries(json)) {
    if (k.startsWith("_") || !Array.isArray(v)) continue;
    for (const d of v) out.add(d.toLowerCase());
  }
  return [...out];
}

/** Seed entries win over generated ones with the same name; domains are unioned. */
export function mergeBrands(seed: Brand[], generated: Brand[]): Brand[] {
  const byKey = new Map<string, Brand>();
  const tagged = [...generated.map((b) => ({ ...b, tier: "generated" as const })), ...seed.map((b) => ({ ...b, tier: "seed" as const }))];
  for (const b of tagged) {
    // a name collision across tiers stays two entries: an auto-imported "Aave" (ethlend.io) must not lend its
    // domains curated status, which would relax the wallet gate and outrank reviewed blocklist hits
    const key = `${b.tier}:${b.name.toLowerCase()}`;
    const prev = byKey.get(key);
    if (!prev) byKey.set(key, { ...b, tokens: [...b.tokens], domains: [...b.domains] });
    else {
      prev.tokens = [...new Set([...prev.tokens, ...b.tokens])];
      prev.domains = [...new Set([...prev.domains, ...b.domains])];
      prev.x = b.x || prev.x;
    }
  }
  // seed first so curated entries take precedence in matching order
  const seedKeys = new Set(seed.map((b) => b.name.toLowerCase()));
  const out = [...byKey.values()];
  out.sort((a, b) => Number(seedKeys.has(b.name.toLowerCase())) - Number(seedKeys.has(a.name.toLowerCase())));
  return out;
}
