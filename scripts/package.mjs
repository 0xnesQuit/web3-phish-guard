/**
 * Produces store-ready archives in packages/:
 *   packages/web3-phish-guard-chrome-<version>.zip     (Chrome Web Store / Edge Add-ons / Brave: upload the zip)
 *   packages/web3-phish-guard-firefox-<version>.zip    (Firefox Add-ons: upload the zip; AMO signs it)
 * Run after `npm run build:all`.
 */
import { createWriteStream, mkdirSync, readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

const version = JSON.parse(readFileSync("public/manifest.json", "utf8")).version;
mkdirSync("packages", { recursive: true });

function zipDir(dir, out) {
  if (!existsSync(dir)) throw new Error(`${dir} missing, run the build first`);
  const abs = path.resolve(out);
  // PowerShell's Compress-Archive is available on every Windows box; on macOS/Linux fall back to zip.
  const ps = spawnSync("powershell", ["-NoProfile", "-Command", `Compress-Archive -Force -Path '${path.resolve(dir)}\\*' -DestinationPath '${abs}'`], { stdio: "inherit" });
  if (ps.status !== 0) {
    const z = spawnSync("zip", ["-qr", abs, "."], { cwd: dir, stdio: "inherit" });
    if (z.status !== 0) throw new Error("neither Compress-Archive nor zip succeeded");
  }
  console.log(`-> ${out}`);
}

zipDir("dist", `packages/web3-phish-guard-chrome-${version}.zip`);
zipDir("dist-firefox", `packages/web3-phish-guard-firefox-${version}.zip`);

// Source archive for Firefox Add-ons review: everything needed to reproduce the minified bundles byte for byte,
// including the generated brand data files that git ignores. Build with `npm ci --ignore-scripts && npm run build:all`.
import { cpSync, rmSync, writeFileSync } from "node:fs";
const src = "packages/source-tmp";
rmSync(src, { recursive: true, force: true });
for (const d of ["src", "public", "scripts", "data", "test"]) cpSync(d, path.join(src, d), { recursive: true });
for (const f of ["package.json", "package-lock.json", "tsconfig.json", "README.md", "PRIVACY.md", "LICENSE"]) if (existsSync(f)) cpSync(f, path.join(src, f));
writeFileSync(path.join(src, "BUILD.md"), `# Reproducing the build

Node 22.

    npm ci --ignore-scripts
    npm run build:all

\`dist/\` is the Chrome package, \`dist-firefox/\` the Firefox package (version ${version}).
The data files under \`data/\` are the exact copies bundled in this release; \`scripts/build-*.mjs\` regenerate them from DefiLlama / CoinMarketCap / OpenSea.
`);
zipDir(src, `packages/web3-phish-guard-source-${version}.zip`);
rmSync(src, { recursive: true, force: true });
