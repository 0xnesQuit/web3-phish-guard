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
