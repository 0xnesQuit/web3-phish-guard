// Scoring latency over a mixed corpus: node scripts/bench.mjs   (budget: p95 < 5 ms per host)
import { readFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const esbuild = require("esbuild");
const out = esbuild.buildSync({ entryPoints: ["src/lib/scoring.ts", "src/lib/hostname.ts", "src/lib/lists.ts"], bundle: true, write: false, format: "esm", outdir: "x", external: ["chrome"] });
const mod = {};
for (const f of out.outputFiles) Object.assign(mod, await import("data:text/javascript;base64," + Buffer.from(f.text).toString("base64")));
const seed = JSON.parse(readFileSync("data/brands.seed.json", "utf8"));
const gen = ["data/brands.generated.json", "data/brands.nft.json", "data/brands.cmc.json"].flatMap((f) => (existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : []));
const tr = JSON.parse(readFileSync("data/trusted.json", "utf8"));
const brands = mod.mergeBrands([...seed, ...mod.brandsFromTrusted(mod.flattenTrusted(tr))], gen);
const a = JSON.parse(readFileSync("data/action-words.json", "utf8")), h = JSON.parse(readFileSync("data/free-hosts.json", "utf8")), t = JSON.parse(readFileSync("data/tlds.json", "utf8"));
const lists = { trusted: mod.flattenTrusted(tr), actionStrong: a.strong, actionMedium: a.medium, freeHostsStrong: h.strong, freeHostsWeak: h.weak, tldStrong: t.strong, tldWeak: t.weak };
const freeHosts = [...h.strong, ...h.weak];
const words = ["claim", "airdrop", "rewards", "app", "docs", "shop", "news", "blog", "mint", "portal", "uniswap", "pharos", "axisrobotics", "ethgas", "kamino", "metamask", "coinbase", "random", "alpha", "beta"];
const tlds = ["com", "xyz", "io", "app", "live", "net", "org", "fun", "cyou", "top"];
const hosts = [];
for (let i = 0; i < 1000; i++) hosts.push(`${words[i % words.length]}-${words[(i * 7) % words.length]}${i % 3 ? "" : i}.${tlds[i % tlds.length]}`);
for (let i = 0; i < 200; i++) hosts.push(`${words[i % words.length]}.${words[(i * 3) % words.length]}.netlify.app`);
const times = [];
for (const host of hosts) {
  const url = `https://${host}/claim`;
  const p = mod.parseHost(url, freeHosts);
  const t0 = performance.now();
  mod.score(url, p, { brands, lists, origin: { source: "x", at: 0, poster: "someone" } });
  times.push(performance.now() - t0);
}
times.sort((x, y) => x - y);
const pct = (q) => times[Math.floor(times.length * q)].toFixed(3);
console.log(`brands: ${brands.length}  hosts: ${hosts.length}  p50: ${pct(0.5)} ms  p95: ${pct(0.95)} ms  max: ${times[times.length - 1].toFixed(2)} ms`);
