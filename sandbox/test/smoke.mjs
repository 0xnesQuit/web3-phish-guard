// Smoke test: serve the trap page locally and scan it. Run after `npx tsc`: node test/smoke.mjs
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { chromium } from "playwright";
import { scanUrl } from "../dist/scan.js";

const html = readFileSync(new URL("./trap.html", import.meta.url));
const server = createServer((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(html); });
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const url = `http://127.0.0.1:${port}/`;

const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
try {
  const report = await scanUrl(browser, url, { timeoutMs: 25000, interact: true });
  console.log("verdict:", report.verdict, "score:", report.score);
  console.log("flags:", report.flags);
  console.log("findings:", report.findings);
  console.log("requests:", report.requests.map((r) => `${r.method}/${r.kind}${r.unprompted ? " (unprompted)" : ""}`));
  console.log("simulations:", JSON.stringify(report.simulations));
  const ok = report.verdict === "malicious" && report.flags.includes("auto-request-on-load") && report.requests.some((r) => r.kind === "approve-unlimited");
  console.log(ok ? "SMOKE PASS" : "SMOKE FAIL");
  process.exitCode = ok ? 0 : 1;
} finally {
  await browser.close();
  server.close();
}
