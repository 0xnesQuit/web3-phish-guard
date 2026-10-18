/**
 * Pushes the hand-maintained data files (seed brands, bait words, free hosts, TLDs, trusted list) and the
 * generator scripts to the public lists repo, so the extension's remote refresh picks them up.
 * Generated lists (DefiLlama / CMC / OpenSea / community) are NOT touched here; the lists repo's daily Action owns them.
 *
 *   node scripts/sync-lists.mjs            (needs git + push access to 0xnesQuit/web3-phish-guard-lists)
 */
import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const REPO = "https://github.com/0xnesQuit/web3-phish-guard-lists.git";
const dir = path.join(os.tmpdir(), "w3pg-lists-sync");
const run = (cmd, cwd = dir) => execSync(cmd, { cwd, stdio: "pipe" }).toString().trim();

if (!existsSync(path.join(dir, ".git"))) {
  mkdirSync(dir, { recursive: true });
  execSync(`git clone -q ${REPO} "${dir}"`, { stdio: "inherit" });
} else {
  run("git pull -q --ff-only");
}

for (const f of ["brands.seed.json", "action-words.json", "free-hosts.json", "tlds.json", "trusted.json"]) cpSync(`data/${f}`, path.join(dir, "data", f));
for (const f of ["build-brands.mjs", "build-cmc-brands.mjs", "build-nft-brands.mjs", "publish-lists.mjs"]) cpSync(`scripts/${f}`, path.join(dir, "scripts", f));

run("node scripts/publish-lists.mjs data");
run("git add -A");
if (run("git status --porcelain")) {
  run(`git -c user.name=lists-sync -c user.email=lists-sync@users.noreply.github.com commit -q -m "sync curated lists from main repo"`);
  run("git push -q origin main");
  console.log("lists repo updated");
} else {
  console.log("lists repo already up to date");
}
