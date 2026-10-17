/**
 * Builds data/brands.generated.json from DefiLlama's free, keyless /protocols endpoint.
 * Each protocol becomes a brand: tokens from its name, official domain from its url.
 * Run: npm run brands
 */
import { writeFileSync, readFileSync } from "node:fs";
import { parse } from "tldts";

const GENERIC = new Set(["portal", "claims", "checker", "rewards", "airdrops", "launch", "launchpad", "connect", "verify", "secure", "official", "institutional", "liquidity", "native", "staked", "wrapped", "bridge", "earn", "points", "rewards", "claim", "airdrop", "foundation", "ecosystem", "official", "classic", "legacy", "mainnet", "testnet", "finance", "protocol", "network", "labs", "exchange", "swap", "dao", "money", "capital", "markets", "market", "chain", "bridge", "stake", "staking", "lend", "lending", "farm", "yield", "vault", "vaults", "pool", "pools", "wallet", "app", "defi", "the", "and", "token", "coin", "crypto", "dex", "perp", "perps", "liquid", "liquidity", "ai", "fi", "v1", "v2", "v3", "v4"]);

function tokensFromName(name) {
  const base = name.toLowerCase().replace(/\(.*?\)/g, "").trim();
  const out = new Set();
  const glued = base.replace(/[^a-z0-9]/g, "");
  if (glued.length >= 5 && !GENERIC.has(glued)) out.add(glued);
  const words = base.split(/[^a-z0-9]+/).filter((w) => w.length >= 5 && !GENERIC.has(w) && !/^\d+$/.test(w));
  for (const w of words) out.add(w);
  return [...out];
}

const freeHosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const SHARED = new Set([...freeHosts.strong, ...freeHosts.weak, "x.com", "twitter.com", "github.com", "t.me", "telegram.org", "medium.com", "youtube.com", "google.com", "discord.gg", "discord.com", "linktr.ee", "notion.site", "gitbook.io", "substack.com", "mirror.xyz", "paragraph.xyz", "docs.google.com", "apple.com", "play.google.com"]);

function registrable(url) {
  try {
    const host = new URL(url.startsWith("http") ? url : `https://${url}`).hostname.toLowerCase();
    // allowPrivateDomains: "foo.vercel.app" stays "foo.vercel.app" instead of collapsing to "vercel.app"
    const d = parse(host, { allowPrivateDomains: true }).domain;
    if (!d) return null;
    if (SHARED.has(d)) return null;
    // a bare shared/free host (or a page on a social platform) is never an "official domain"
    for (const sh of SHARED) if (d === sh || d.endsWith("." + sh)) return null;
    return d;
  } catch {
    return null;
  }
}

const res = await fetch("https://api.llama.fi/protocols");
if (!res.ok) throw new Error(`DefiLlama ${res.status}`);
const protocols = await res.json();

const byName = new Map();
for (const p of protocols) {
  if (!p.url || !p.name) continue;
  const dom = registrable(p.url);
  if (!dom) continue;
  const tokens = tokensFromName(p.name);
  if (!tokens.length) continue;
  const key = p.name.toLowerCase();
  const prev = byName.get(key);
  if (prev) {
    prev.domains = [...new Set([...prev.domains, dom])];
  } else {
    byName.set(key, { name: p.name, tokens, domains: [dom], x: p.twitter || "", llama: p.slug });
  }
}

// Also fold in the seed list so the generated file is self-contained for the extension.
const seed = JSON.parse(readFileSync("data/brands.seed.json", "utf8"));
const seedNames = new Set(seed.map((b) => b.name.toLowerCase()));
const out = [...byName.values()].filter((b) => !seedNames.has(b.name.toLowerCase()));

writeFileSync("data/brands.generated.json", JSON.stringify(out));
console.log(`protocols: ${protocols.length}, brands written: ${out.length} -> data/brands.generated.json`);
