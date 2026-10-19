/**
 * HTTP front door for the sandbox. The Cloudflare Worker (which holds this service's URL and token) calls POST
 * /scan; the extension never talks to this service directly. One shared headless browser, a small concurrency
 * cap, a bearer token, and an SSRF guard so the sandbox can only be pointed at public sites.
 */
import express from "express";
import { chromium, type Browser } from "playwright";
import { scanUrl } from "./scan.js";

const PORT = Number(process.env.PORT || 8080);
const TOKEN = process.env.SANDBOX_TOKEN || "";
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT || 3);
const SCAN_TIMEOUT_MS = Number(process.env.SCAN_TIMEOUT_MS || 30000);

if (!TOKEN) { console.error("SANDBOX_TOKEN is required (set it in the environment)"); process.exit(1); }

let browser: Browser | undefined;
async function getBrowser(): Promise<Browser> {
  if (browser && browser.isConnected()) return browser;
  browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"] });
  return browser;
}

// simple semaphore
let active = 0;
const queue: Array<() => void> = [];
async function acquire(): Promise<void> {
  if (active < MAX_CONCURRENT) { active++; return; }
  await new Promise<void>((res) => queue.push(res));
  active++;
}
function release(): void { active--; const next = queue.shift(); if (next) next(); }

/** Reject anything that is not a public http(s) host: no localhost, no private / link-local / loopback IPs. */
function isPublicUrl(raw: string): boolean {
  let u: URL;
  try { u = new URL(raw); } catch { return false; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const h = u.hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || !h.includes(".")) return false;
  // IPv4 literal in a private / loopback / link-local range
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])];
    if (a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return false;
  }
  if (h.includes(":") || h.startsWith("[")) return false; // no IPv6 literals
  return true;
}

const app = express();
app.use(express.json({ limit: "32kb" }));

app.get("/health", (_req, res) => { res.json({ ok: true, active, max: MAX_CONCURRENT }); });

app.post("/scan", async (req, res) => {
  const auth = req.header("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : req.header("x-token") || "";
  if (token !== TOKEN) { res.status(401).json({ error: "unauthorized" }); return; }

  const url = String((req.body as { url?: unknown })?.url || "");
  if (!isPublicUrl(url)) { res.status(400).json({ error: "bad-url" }); return; }
  if (active >= MAX_CONCURRENT + 10) { res.status(429).json({ error: "busy" }); return; }

  await acquire();
  try {
    const b = await getBrowser();
    const report = await scanUrl(b, url, { timeoutMs: SCAN_TIMEOUT_MS, interact: true });
    res.json(report);
  } catch (e) {
    res.status(500).json({ error: (e as Error)?.message?.slice(0, 120) || "scan-failed" });
  } finally {
    release();
  }
});

app.listen(PORT, () => console.log(`sandbox listening on :${PORT} (max ${MAX_CONCURRENT} concurrent)`));

for (const sig of ["SIGINT", "SIGTERM"] as const) process.on(sig, () => { browser?.close().catch(() => undefined); process.exit(0); });
