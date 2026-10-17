import type { Brand, SignalLists } from "./types";

let cache: { brands: Brand[]; lists: SignalLists } | null = null;

/**
 * Data files ship inside the extension (zero-latency fallback) and are refreshed from REMOTE_BASE,
 * where a daily GitHub Action publishes regenerated copies. Remote copies live in chrome.storage.local
 * and win over the bundled ones. Only JSON data is fetched, never code.
 */
export const DATA_FILES = ["brands.seed.json", "brands.generated.json", "brands.nft.json", "brands.cmc.json", "action-words.json", "free-hosts.json", "tlds.json", "trusted.json"] as const;
export const REMOTE_BASE = "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data";

interface RemoteManifest { updatedAt: number; files: Record<string, { bytes: number; sha256?: string }> }

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

/** Drop the in-memory cache so the next evaluation re-reads storage (after a remote refresh). */
export function invalidateStaticData(): void {
  cache = null;
}

export async function remoteDataStatus(): Promise<{ updatedAt: number; files: number }> {
  const got = await chrome.storage.local.get(["data:updatedAt", "data:files"]);
  return { updatedAt: (got["data:updatedAt"] as number | undefined) ?? 0, files: (got["data:files"] as number | undefined) ?? 0 };
}

/** Fetch lists/manifest.json; download files only when the manifest is newer than what we hold. */
export async function refreshRemoteData(force = false): Promise<{ updated: boolean; files: number }> {
  const res = await fetch(`${REMOTE_BASE}/manifest.json`, { cache: "no-store" });
  if (!res.ok) throw new Error(`manifest ${res.status}`);
  const manifest = (await res.json()) as RemoteManifest;
  const have = ((await chrome.storage.local.get("data:updatedAt"))["data:updatedAt"] as number | undefined) ?? 0;
  if (!force && manifest.updatedAt <= have) return { updated: false, files: 0 };
  const updates: Record<string, unknown> = {};
  let n = 0;
  for (const file of DATA_FILES) {
    if (!manifest.files[file]) continue;
    try {
      const r = await fetch(`${REMOTE_BASE}/${file}`, { cache: "no-store" });
      if (!r.ok) continue;
      const json = await r.json();
      if (json === null || typeof json !== "object") continue;
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
  const [seed, generated, nft, cmc, actions, hosts, tlds, trusted] = await Promise.all([
    loadJson<Brand[]>("brands.seed.json"),
    loadJson<Brand[]>("brands.generated.json"),
    loadJson<Brand[]>("brands.nft.json"),
    loadJson<Brand[]>("brands.cmc.json"),
    loadJson<{ strong: string[]; medium: string[] }>("action-words.json"),
    loadJson<{ strong: string[]; weak: string[] }>("free-hosts.json"),
    loadJson<{ strong: string[]; weak: string[] }>("tlds.json"),
    loadJson<Record<string, string[] | string>>("trusted.json"),
  ]);
  const trustedList = flattenTrusted(trusted);
  const brands = mergeBrands([...(seed ?? []), ...brandsFromTrusted(trustedList)], [...(generated ?? []), ...(nft ?? []), ...(cmc ?? [])]);
  cache = {
    brands,
    lists: {
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
    if (label.length < 6 || TRUSTED_GENERIC.has(label) || seen.has(label)) continue;
    seen.add(label);
    out.push({ name: label, tokens: [label], domains: [d], tier: "seed" });
  }
  return out;
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
    const key = b.name.toLowerCase();
    const prev = byKey.get(key);
    if (!prev) byKey.set(key, { ...b, tokens: [...b.tokens], domains: [...b.domains] });
    else {
      prev.tokens = [...new Set([...prev.tokens, ...b.tokens])];
      prev.domains = [...new Set([...prev.domains, ...b.domains])];
      prev.x = b.x || prev.x;
      if (b.tier === "seed") prev.tier = "seed";
    }
  }
  // seed first so curated entries take precedence in matching order
  const seedKeys = new Set(seed.map((b) => b.name.toLowerCase()));
  const out = [...byKey.values()];
  out.sort((a, b) => Number(seedKeys.has(b.name.toLowerCase())) - Number(seedKeys.has(a.name.toLowerCase())));
  return out;
}
