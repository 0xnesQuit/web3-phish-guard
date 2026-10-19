/**
 * Copies the data files the extension consumes into lists/ and writes lists/manifest.json.
 * In this repo the scripts write into data/ and publish-lists.mjs is run with "data" so the manifest sits next to the files.
 * Run after the brand scripts: node scripts/publish-lists.mjs [outDir]   (default: lists/)
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from "node:fs";
import { createHash, createPrivateKey, sign } from "node:crypto";

/** Canonical bytes that get signed: the manifest without `sig`, keys in a fixed order. */
export function canonicalManifest(m) {
  const files = Object.fromEntries(Object.keys(m.files).sort().map((k) => [k, { bytes: m.files[k].bytes, sha256: m.files[k].sha256 }]));
  return JSON.stringify({ updatedAt: m.updatedAt, files });
}

const FILES = ["brands.seed.json", "brands.generated.json", "brands.nft.json", "brands.cmc.json", "action-words.json", "free-hosts.json", "tlds.json", "trusted.json", "shared-hosts.json", "top-sites.json", "community-blocklist.json"];
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
const keyPem = process.env.LISTS_SIGNING_KEY;
if (changed || !existsSync(`${OUT}/manifest.json`) || (keyPem && !prev.sig)) {
  const manifest = { updatedAt: Date.now(), files };
  if (keyPem) {
    // ECDSA P-256 / SHA-256, raw r||s so WebCrypto in the extension can verify it directly
    const sig = sign("sha256", Buffer.from(canonicalManifest(manifest)), { key: createPrivateKey(keyPem), dsaEncoding: "ieee-p1363" });
    manifest.sig = sig.toString("base64");
    console.log("manifest signed");
  } else {
    console.log("LISTS_SIGNING_KEY not set: manifest published unsigned (the extension will keep its bundled copy)");
  }
  writeFileSync(`${OUT}/manifest.json`, JSON.stringify(manifest, null, 2) + "\n");
  console.log("manifest updated");
} else {
  console.log("nothing changed");
}
