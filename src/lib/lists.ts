import type { Brand, SignalLists } from "./types";

let cache: { brands: Brand[]; lists: SignalLists } | null = null;

async function loadJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(chrome.runtime.getURL(path));
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

/** Bundled static data (brands + signal word lists). Cached per service-worker lifetime. */
export async function loadStaticData(): Promise<{ brands: Brand[]; lists: SignalLists }> {
  if (cache) return cache;
  const [seed, generated, nft, cmc, actions, hosts, tlds, trusted] = await Promise.all([
    loadJson<Brand[]>("data/brands.seed.json"),
    loadJson<Brand[]>("data/brands.generated.json"),
    loadJson<Brand[]>("data/brands.nft.json"),
    loadJson<Brand[]>("data/brands.cmc.json"),
    loadJson<{ strong: string[]; medium: string[] }>("data/action-words.json"),
    loadJson<{ strong: string[]; weak: string[] }>("data/free-hosts.json"),
    loadJson<{ strong: string[]; weak: string[] }>("data/tlds.json"),
    loadJson<Record<string, string[] | string>>("data/trusted.json"),
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
