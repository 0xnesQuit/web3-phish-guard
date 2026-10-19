import { readFileSync as _rf, readdirSync, readFileSync } from "node:fs";
{
  // refuse to ship data that calls a shared platform someone's official domain
  const shared = new Set([...JSON.parse(_rf("data/shared-hosts.json", "utf8")).hosts, ...Object.values(JSON.parse(_rf("data/free-hosts.json", "utf8"))).flat()]);
  for (const f of ["brands.generated.json", "brands.nft.json", "brands.cmc.json"]) {
    let list = [];
    try { list = JSON.parse(_rf(`data/${f}`, "utf8")); } catch { continue; }
    const owns = (b, d) => { const label = d.split(".")[0].replace(/[^a-z0-9]/g, ""); return label.length >= 4 && String(b.name).toLowerCase().replace(/[^a-z0-9]/g, "").includes(label); };
    const bad = list.flatMap((b) => (b.domains ?? []).filter((d) => !owns(b, d) && [...shared].some((s) => d === s || d.endsWith("." + s))).map((d) => `${b.name}: ${d}`));
    if (bad.length) { console.error(`${f} names shared platforms as official domains:\n  ${bad.slice(0, 20).join("\n  ")}`); process.exit(1); }
  }
}
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";

const watch = process.argv.includes("--watch");
const firefox = process.argv.includes("--firefox");
const outdir = firefox ? "dist-firefox" : "dist";

if (existsSync(outdir)) rmSync(outdir, { recursive: true });
mkdirSync(outdir, { recursive: true });

const common = {
  bundle: true,
  format: "iife",
  target: "chrome120",
  sourcemap: watch ? "inline" : false,
  minify: !watch,
  logLevel: "info",
};

const ctxs = await Promise.all([
  // Chrome runs the background as a module service worker; Firefox runs it as an event-page script, so bundle it as an IIFE there.
  esbuild.context({ ...common, entryPoints: ["src/background.ts"], outfile: `${outdir}/background.js`, format: firefox ? "iife" : "esm" }),
  esbuild.context({ ...common, entryPoints: ["src/content/overlay.ts"], outfile: `${outdir}/overlay.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/provider-guard.ts"], outfile: `${outdir}/provider-guard.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/bridge.ts"], outfile: `${outdir}/bridge.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/referrer.ts"], outfile: `${outdir}/referrer.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/x-watch.ts"], outfile: `${outdir}/x-watch.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/page-scan.ts"], outfile: `${outdir}/page-scan.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/seed-guard.ts"], outfile: `${outdir}/seed-guard.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/warning.ts"], outfile: `${outdir}/warning.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/popup.ts"], outfile: `${outdir}/popup.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/options.ts"], outfile: `${outdir}/options.js` }),
]);

function copyStatic() {
  cpSync("public", outdir, { recursive: true });
  cpSync("data", `${outdir}/data`, { recursive: true });
  // one manifest per browser
  if (firefox) cpSync(`${outdir}/manifest.firefox.json`, `${outdir}/manifest.json`);
  rmSync(`${outdir}/manifest.firefox.json`, { force: true });
  // store-listing assets the manifest never references: keep them out of the shipped package
  for (const f of ["icons/icon256.png", "icons/icon512.png", "icons/logo.svg"]) rmSync(`${outdir}/${f}`, { force: true });
}

if (watch) {
  copyStatic();
  await Promise.all(ctxs.map((c) => c.watch()));
  console.log("watching...");
} else {
  await Promise.all(ctxs.map((c) => c.rebuild()));
  await Promise.all(ctxs.map((c) => c.dispose()));
  copyStatic();
  // Chrome rejects a content script as "not UTF-8" if it contains a Unicode noncharacter (U+FFFE/U+FFFF).
  // The minifier can emit these literally from a regex range, so fail the build if any slipped into the JS.
  for (const name of readdirSync(outdir)) {
    if (!name.endsWith(".js")) continue;
    const text = readFileSync(`${outdir}/${name}`, "utf8");
    for (let i = 0; i < text.length; i++) { const c = text.charCodeAt(i); if (c === 0xfffe || c === 0xffff) throw new Error(`${name}: Unicode noncharacter U+${c.toString(16).toUpperCase()} at ${i} — Chrome will reject it as non-UTF-8`); }
  }
  console.log(`build done -> ${outdir}/`);
}
