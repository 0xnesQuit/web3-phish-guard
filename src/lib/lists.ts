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
  const [seed, generated, actions, hosts, tlds, trusted] = await Promise.all([
    loadJson<Brand[]>("data/brands.seed.json"),
    loadJson<Brand[]>("data/brands.generated.json"),
    loadJson<{ strong: string[]; medium: string[] }>("data/action-words.json"),
    loadJson<{ strong: string[]; weak: string[] }>("data/free-hosts.json"),
    loadJson<{ strong: string[]; weak: string[] }>("data/tlds.json"),
    loadJson<Record<string, string[] | string>>("data/trusted.json"),
  ]);
  const brands = mergeBrands(seed ?? [], generated ?? []);
  cache = {
    brands,
    lists: {
      trusted: flattenTrusted(trusted),
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
