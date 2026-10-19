/**
 * Pulls the generated brand files (DefiLlama / CoinMarketCap / OpenSea) from the public lists repo into data/, verifying
 * each against the signed manifest's SHA-256, so a package never ships stale bundled data. Run before `npm run build:all`.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { writeFileSync, readFileSync } from "node:fs";

// the same public key the extension verifies manifests with (src/lib/lists.ts)
const jwk = JSON.parse(readFileSync("src/lib/lists.ts", "utf8").match(/LISTS_PUBLIC_JWK: JsonWebKey = (\{[^\n]*\});/)[1]);
function canonical(m) {
  const files = Object.fromEntries(Object.keys(m.files).sort().map((k) => [k, { bytes: m.files[k].bytes, sha256: m.files[k].sha256 }]));
  return JSON.stringify({ updatedAt: m.updatedAt, files });
}

const BASE = "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data";
const FILES = ["brands.generated.json", "brands.nft.json", "brands.cmc.json", "top-sites.json"];
const manifest = await (await fetch(`${BASE}/manifest.json`, { cache: "no-store" })).json();
if (!manifest.sig || !verify("sha256", Buffer.from(canonical(manifest)), { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, Buffer.from(manifest.sig, "base64"))) {
  console.error("manifest signature invalid: refusing to pull data"); process.exit(1);
}
console.log("manifest signature ok");
for (const f of FILES) {
  const entry = manifest.files?.[f];
  if (!entry?.sha256) { console.error(`${f}: not in manifest`); process.exit(1); }
  const text = await (await fetch(`${BASE}/${f}`, { cache: "no-store" })).text();
  const sha = createHash("sha256").update(text).digest("hex");
  if (sha !== entry.sha256) { console.error(`${f}: hash mismatch`); process.exit(1); }
  writeFileSync(`data/${f}`, text);
  const parsed = JSON.parse(text);
  console.log(`${f}: ${Array.isArray(parsed) ? parsed.length + " brands" : (parsed.hosts?.length ?? 0) + " hosts"}`);
}
