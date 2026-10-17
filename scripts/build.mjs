import * as esbuild from "esbuild";
import { cpSync, mkdirSync, rmSync, existsSync } from "node:fs";

const watch = process.argv.includes("--watch");
const outdir = "dist";

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
  esbuild.context({ ...common, entryPoints: ["src/background.ts"], outfile: `${outdir}/background.js`, format: "esm" }),
  esbuild.context({ ...common, entryPoints: ["src/content/overlay.ts"], outfile: `${outdir}/overlay.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/provider-guard.ts"], outfile: `${outdir}/provider-guard.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/bridge.ts"], outfile: `${outdir}/bridge.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/referrer.ts"], outfile: `${outdir}/referrer.js` }),
  esbuild.context({ ...common, entryPoints: ["src/content/x-watch.ts"], outfile: `${outdir}/x-watch.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/warning.ts"], outfile: `${outdir}/warning.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/popup.ts"], outfile: `${outdir}/popup.js` }),
  esbuild.context({ ...common, entryPoints: ["src/pages/options.ts"], outfile: `${outdir}/options.js` }),
]);

function copyStatic() {
  cpSync("public", outdir, { recursive: true });
  cpSync("data", `${outdir}/data`, { recursive: true });
}

if (watch) {
  copyStatic();
  await Promise.all(ctxs.map((c) => c.watch()));
  console.log("watching...");
} else {
  await Promise.all(ctxs.map((c) => c.rebuild()));
  await Promise.all(ctxs.map((c) => c.dispose()));
  copyStatic();
  console.log("build done -> dist/");
}
