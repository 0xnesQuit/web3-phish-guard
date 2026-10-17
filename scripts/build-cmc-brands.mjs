/**
 * Builds data/brands.cmc.json from CoinMarketCap's API: every listed token's official website and X handle.
 * Free "Basic" key: https://pro.coinmarketcap.com/signup (15k credits/month; this script uses ~60).
 *
 *   CMC_API_KEY=... node scripts/build-cmc-brands.mjs          # top 5000 by rank
 *   CMC_API_KEY=... node scripts/build-cmc-brands.mjs 8000     # more
 *
 * Output entries are "generated" tier in the extension (whole-token match, only with a bait word / free host).
 */
import { writeFileSync, readFileSync } from "node:fs";
import { parse } from "tldts";

const key = process.env.CMC_API_KEY;
if (!key) throw new Error("CMC_API_KEY env var missing");
const LIMIT = Number(process.argv[2] || 5000);
const H = { "X-CMC_PRO_API_KEY": key, accept: "application/json" };

const GENERIC = new Set(["yield", "index", "smart", "super", "meta", "world", "space", "star", "moon", "rocket", "baby", "safe", "green", "black", "white", "silver", "pixel", "magic", "dragon", "shiba", "floki", "king", "queen", "pump", "high", "bond", "tokenized", "global", "digital", "first", "united", "alpha", "beta", "omega", "prime", "capital", "ventures", "token", "coin", "protocol", "network", "finance", "chain", "labs", "dao", "swap", "money", "cash", "gold", "dollar", "wrapped", "staked", "bridged", "liquid", "bitcoin", "ethereum", "binance", "pegged", "stable", "usd", "the", "and", "inu", "doge", "pepe", "meme", "ai", "agent", "official"]);
const freeHosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const SHARED = new Set([...freeHosts.strong, ...freeHosts.weak, "x.com", "twitter.com", "github.com", "t.me", "medium.com", "youtube.com", "google.com", "discord.gg", "discord.com", "linktr.ee", "notion.site", "gitbook.io", "coinmarketcap.com", "coingecko.com", "pump.fun", "etherscan.io", "bscscan.com", "solscan.io", "dexscreener.com", "uniswap.org", "raydium.io"]);

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
  if (glued.length >= 5 && !GENERIC.has(glued)) out.add(glued);
  const first = base.split(/[^a-z0-9]+/).filter(Boolean)[0];
  if (first && first.length >= 5 && !GENERIC.has(first) && !/^\d+$/.test(first)) out.add(first);
  return [...out];
}

async function get(url) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const res = await fetch(url, { headers: H });
    if (res.status === 429) { await new Promise((r) => setTimeout(r, 2000 * (attempt + 1))); continue; }
    if (!res.ok) throw new Error(`CMC ${res.status}: ${(await res.text()).slice(0, 200)}`);
    return (await res.json()).data;
  }
  throw new Error("CMC: rate limited");
}

// 1. id map, ranked (1 credit per 5000 rows)
const map = [];
for (let start = 1; start <= LIMIT; start += 5000) {
  const rows = await get(`https://pro-api.coinmarketcap.com/v1/cryptocurrency/map?sort=cmc_rank&start=${start}&limit=${Math.min(5000, LIMIT - start + 1)}`);
  map.push(...rows);
  if (rows.length < 5000) break;
}
console.log(`map: ${map.length} tokens`);

// 2. info in batches of 100 (1 credit per 100 ids)
const out = new Map();
for (let i = 0; i < map.length; i += 100) {
  const ids = map.slice(i, i + 100).map((r) => r.id).join(",");
  const info = await get(`https://pro-api.coinmarketcap.com/v2/cryptocurrency/info?id=${ids}&aux=urls`);
  for (const c of Object.values(info)) {
    const site = (c.urls?.website ?? []).map(registrable).filter(Boolean);
    if (!site.length) continue;
    const tokens = tokensFromName(c.name ?? "");
    if (!tokens.length) continue;
    const tw = (c.urls?.twitter ?? [])[0] ?? "";
    const handle = tw.match(/(?:twitter\.com|x\.com)\/@?([A-Za-z0-9_]{1,15})/)?.[1] ?? "";
    const k = c.name.toLowerCase();
    const prev = out.get(k);
    if (prev) prev.domains = [...new Set([...prev.domains, ...site])];
    else out.set(k, { name: c.name, tokens, domains: [...new Set(site)], x: handle, cmc: c.slug, rank: c.cmc_rank ?? null });
  }
  await new Promise((r) => setTimeout(r, 400));
  if ((i / 100) % 10 === 0) console.log(`  ${i + 100}/${map.length} -> ${out.size} brands`);
}

writeFileSync("data/brands.cmc.json", JSON.stringify([...out.values()]));
console.log(`CMC brands written: ${out.size} -> data/brands.cmc.json`);
