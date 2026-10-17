// Quick CLI: node scripts/check.mjs <url...>  — scores URLs with seed + generated brands (no network).
import { readFileSync, existsSync } from "node:fs";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const esbuild = require("esbuild");
const out = esbuild.buildSync({ entryPoints: ["src/lib/scoring.ts", "src/lib/hostname.ts", "src/lib/lists.ts"], bundle: true, write: false, format: "esm", outdir: "x", external: ["chrome"] });
const mod = {};
for (const f of out.outputFiles) {
  const url = "data:text/javascript;base64," + Buffer.from(f.text).toString("base64");
  Object.assign(mod, await import(url));
}
const seed = JSON.parse(readFileSync("data/brands.seed.json", "utf8"));
const gen = [...(existsSync("data/brands.generated.json") ? JSON.parse(readFileSync("data/brands.generated.json", "utf8")) : []), ...(existsSync("data/brands.nft.json") ? JSON.parse(readFileSync("data/brands.nft.json", "utf8")) : [])];
const brands = mod.mergeBrands([...seed, ...mod.brandsFromTrusted(mod.flattenTrusted(JSON.parse(readFileSync("data/trusted.json", "utf8"))))], gen);
const a = JSON.parse(readFileSync("data/action-words.json", "utf8"));
const h = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const t = JSON.parse(readFileSync("data/tlds.json", "utf8"));
const tr = JSON.parse(readFileSync("data/trusted.json", "utf8"));
const lists = { trusted: mod.flattenTrusted(tr), actionStrong: a.strong, actionMedium: a.medium, freeHostsStrong: h.strong, freeHostsWeak: h.weak, tldStrong: t.strong, tldWeak: t.weak };
for (const u of process.argv.slice(2)) {
  const p = mod.parseHost(u, [...h.strong, ...h.weak]);
  const v = mod.score(u, p, { brands, lists, origin: process.env.ORIGIN ? { source: "x", at: 0, poster: process.env.POSTER, isReply: !!process.env.REPLY } : undefined });
  console.log(`${v.band.padEnd(5)} ${String(v.score).padStart(3)}  ${u}  ${v.brand ? "[" + v.brand + "]" : ""}  ${v.signals.filter(s=>s.weight).map(s=>s.id+"+"+s.weight).join(" ")}`);
}
