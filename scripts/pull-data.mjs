/**
 * Pulls the generated brand files (DefiLlama / CoinMarketCap / OpenSea) from the public lists repo into data/, verifying
 * each against the signed manifest's SHA-256, so a package never ships stale bundled data. Run before `npm run build:all`.
 */
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";

const BASE = "https://raw.githubusercontent.com/0xnesQuit/web3-phish-guard-lists/main/data";
const FILES = ["brands.generated.json", "brands.nft.json", "brands.cmc.json"];
const manifest = await (await fetch(`${BASE}/manifest.json`, { cache: "no-store" })).json();
for (const f of FILES) {
  const entry = manifest.files?.[f];
  if (!entry?.sha256) { console.error(`${f}: not in manifest`); process.exit(1); }
  const text = await (await fetch(`${BASE}/${f}`, { cache: "no-store" })).text();
  const sha = createHash("sha256").update(text).digest("hex");
  if (sha !== entry.sha256) { console.error(`${f}: hash mismatch`); process.exit(1); }
  writeFileSync(`data/${f}`, text);
  console.log(`${f}: ${JSON.parse(text).length} brands`);
}
