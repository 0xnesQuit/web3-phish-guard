/**
 * Copies the data files the extension consumes into lists/ and writes lists/manifest.json.
 * In this repo the scripts write into data/ and publish-lists.mjs is run with "data" so the manifest sits next to the files.
 * Run after the brand scripts: node scripts/publish-lists.mjs [outDir]   (default: lists/)
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";

const FILES = ["brands.seed.json", "brands.generated.json", "brands.nft.json", "brands.cmc.json", "action-words.json", "free-hosts.json", "tlds.json", "trusted.json", "community-blocklist.json"];
const OUT = process.argv[2] || "lists";
mkdirSync(OUT, { recursive: true });

const prev = existsSync(`${OUT}/manifest.json`) ? JSON.parse(readFileSync(`${OUT}/manifest.json`, "utf8")) : { files: {} };
const files = {};
let changed = false;
for (const f of FILES) {
  const src = `data/${f}`;
  if (!existsSync(src)) {
    // keep the previously published copy if this run could not regenerate it (e.g. missing API key)
    if (existsSync(`${OUT}/${f}`)) { files[f] = prev.files[f]; console.log(`  keep   ${f}`); }
    continue;
  }
  const buf = readFileSync(src);
  JSON.parse(buf.toString("utf8")); // refuse to publish a broken file
  const sha256 = createHash("sha256").update(buf).digest("hex");
  files[f] = { bytes: statSync(src).size, sha256 };
  if (prev.files?.[f]?.sha256 !== sha256) { writeFileSync(`${OUT}/${f}`, buf); changed = true; console.log(`  update ${f} (${files[f].bytes} bytes)`); }
  else console.log(`  same   ${f}`);
}
if (changed || !existsSync(`${OUT}/manifest.json`)) {
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify({ updatedAt: Date.now(), files }, null, 2) + "\n");
  console.log("manifest updated");
} else {
  console.log("nothing changed");
}
