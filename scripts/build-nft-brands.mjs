/**
 * Builds data/brands.nft.json from OpenSea's collections API (v2).
 * Needs a free OpenSea API key in the OPENSEA_API_KEY env var; it is used only here, never in the extension.
 *
 *   OPENSEA_API_KEY=... node scripts/build-nft-brands.mjs            # top collections by 7d volume, all chains
 *   OPENSEA_API_KEY=... node scripts/build-nft-brands.mjs 2000       # fetch up to N collections (default 1000)
 *
 * Only collections OpenSea marked `verified` or `approved` are kept, and only those with a project_url
 * on a real domain. Output entries are "generated" tier in the extension (whole-token match only).
 */
import { writeFileSync, readFileSync } from "node:fs";
import { parse } from "tldts";

const key = process.env.OPENSEA_API_KEY;
if (!key) throw new Error("OPENSEA_API_KEY env var missing (get one at https://docs.opensea.io/reference/api-keys)");
const MAX = Number(process.argv[2] || 1000);

const GENERIC = new Set(["official", "collection", "genesis", "pass", "club", "labs", "studio", "world", "nft", "nfts", "the", "and", "by", "mint", "edition", "editions", "season", "origins", "legends", "heroes", "apes", "punks", "cats", "dogs", "birds", "frens", "friends"]);
const freeHosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const SHARED = new Set([...freeHosts.strong, ...freeHosts.weak, "x.com", "twitter.com", "github.com", "t.me", "medium.com", "youtube.com", "google.com", "discord.gg", "discord.com", "linktr.ee", "notion.site", "gitbook.io", "opensea.io", "magiceden.io", "blur.io", "zora.co", "manifold.xyz", "highlight.xyz", "mirror.xyz", "paragraph.xyz", "instagram.com", "tiktok.com"]);

function registrable(url) {
  try {
    const host = new URL(url.startsWith("http") ? url : `https://${url}`).hostname.toLowerCase();
    const d = parse(host, { allowPrivateDomains: true }).domain;
    if (!d) return null;
    for (const sh of SHARED) if (d === sh || d.endsWith("." + sh)) return null;
    return d;
  } catch {
    return null;
  }
}

function tokensFromName(name) {
  const base = name.toLowerCase().replace(/\(.*?\)/g, "").trim();
  const out = new Set();
  const glued = base.replace(/[^a-z0-9]/g, "");
  // NFT names are full of ordinary words ("Credits", "Abstract Chickens", "The Ape Society"), so only the
  // glued full name is a token; single words count only when the whole name is that one word.
  if (glued.length >= 5 && !GENERIC.has(glued)) out.add(glued);
  return [...out];
}

const out = new Map();
let fetched = 0;
// The free tier stops paginating after ~300 results per query, so sweep the main chains separately.
const CHAINS = ["", "ethereum", "base", "solana", "polygon", "abstract", "arbitrum", "optimism", "zora", "bsc", "avalanche", "ape_chain", "blast", "sei", "bera_chain", "ronin", "b3", "shape", "soneium", "unichain"];
for (const chain of CHAINS) {
let next = "";
let perChain = 0;
while (perChain < MAX) {
  const url = `https://api.opensea.io/api/v2/collections?order_by=seven_day_volume&limit=100${chain ? `&chain=${chain}` : ""}${next ? `&next=${encodeURIComponent(next)}` : ""}`;
  let res = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    res = await fetch(url, { headers: { "x-api-key": key, accept: "application/json" } });
    // OpenSea answers throttled requests with 429 *or* a spurious 401 "Invalid API key"; back off and retry both.
    if (res.status !== 429 && res.status !== 401) break;
    await new Promise((r) => setTimeout(r, 1500 * (attempt + 1)));
  }
  if (!res.ok) {
    console.error(`  ${chain || "all"}: OpenSea ${res.status} after ${perChain} results, moving on (${out.size} brands so far)`);
    break;
  }
  const json = await res.json();
  const cols = json.collections ?? [];
  fetched += cols.length;
  perChain += cols.length;
  for (const c of cols) {
    const status = String(c.safelist_status ?? "").toLowerCase();
    if (!["verified", "approved"].includes(status)) continue;
    const dom = registrable(c.project_url ?? "");
    if (!dom) continue;
    const tokens = tokensFromName(c.name ?? c.collection ?? "");
    if (!tokens.length) continue;
    const k = (c.name ?? c.collection).toLowerCase();
    const prev = out.get(k);
    if (prev) prev.domains = [...new Set([...prev.domains, dom])];
    else out.set(k, { name: c.name ?? c.collection, tokens, domains: [dom], x: c.twitter_username || "", opensea: c.collection, status });
  }
  next = json.next ?? "";
  if (!next || !cols.length) break;
  await new Promise((r) => setTimeout(r, 1200));
}
console.log(`  ${chain || "all"}: ${perChain} collections, ${out.size} brands total`);
await new Promise((r) => setTimeout(r, 2000));
}

writeFileSync("data/brands.nft.json", JSON.stringify([...out.values()]));
console.log(`collections fetched: ${fetched}, NFT brands written: ${out.size} -> data/brands.nft.json`);
