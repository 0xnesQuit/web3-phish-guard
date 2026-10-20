/**
 * One sandbox scan. Opens the url in a fresh, isolated, throw-away browser context with the observer provider
 * installed, lets the page run (and lightly nudges it by clicking obvious connect / claim buttons), then reads
 * back every wallet request the page made and simulates the transaction-shaped ones. No real wallet is ever
 * present and nothing is signed or sent.
 */
import type { Browser, BrowserContext, Page } from "playwright";
import { observerEntry, type ObserverConfig } from "./observer.js";
import { decodeTx, decodeTypedData, type TxLike } from "./lib/txdecode.js";
import { SCRIPT_MARKERS, SEED_FORM_HINTS, isBadHost, isPrivateHost, registrable } from "./markers.js";
import { simulate } from "./simrpc.js";
import { score } from "./score.js";
import { tryWalletConnect } from "./walletconnect.js";
import type { CapturedRequest, ScanOptions, ScanReport } from "./types.js";
import type { SimTx } from "./lib/simulate.js";

interface RawCapture { method: string; params: unknown; atMs: number; unprompted: boolean; chainId: string }

const randomAddress = () => "0x" + Array.from(crypto.getRandomValues(new Uint8Array(20)), (b) => b.toString(16).padStart(2, "0")).join("");

/** label a captured request and pull its counterparty / to, for the report and the simulation */
function decodeCapture(c: RawCapture): CapturedRequest {
  const params = Array.isArray(c.params) ? c.params : [];
  const base: CapturedRequest = { method: c.method, kind: c.method, atMs: c.atMs, unprompted: c.unprompted, chainId: c.chainId, params: c.params };
  if (c.method === "eth_sendTransaction" || c.method === "eth_signTransaction" || c.method === "wallet_sendTransaction") {
    const tx = params[0] as TxLike | undefined;
    const intent = decodeTx(tx);
    return { ...base, kind: intent.kind === "none" ? "tx" : intent.kind, to: tx?.to, counterparty: intent.counterparty };
  }
  if (/^eth_signTypedData(_v[134])?$/.test(c.method)) {
    const td = params.find((x) => typeof x === "string" && x.includes("primaryType")) ?? params[1] ?? params[0];
    const s = decodeTypedData(td);
    return { ...base, kind: s.kind, counterparty: s.counterparty };
  }
  return base;
}

export async function scanUrl(browser: Browser, url: string, opts: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = Date.now();
  const timeoutMs = Math.min(Math.max(opts.timeoutMs ?? 30000, 8000), 60000);
  const host = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
  const report: ScanReport = {
    url, host, ok: false, startedAt, durationMs: 0, score: 0, verdict: "unknown",
    flags: [], findings: [], requests: [], simulations: [], scriptMarkers: [], badHosts: [], seedForm: false,
  };
  if (!/^https?:\/\//i.test(url) || !host) { report.error = "bad-url"; report.durationMs = Date.now() - startedAt; return report; }

  let context: BrowserContext | undefined;
  const badHosts = new Set<string>();
  const scriptSrcs = new Set<string>();
  try {
    context = await browser.newContext({
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      viewport: { width: 1280, height: 800 },
      serviceWorkers: "block",
    });
    const cfg: ObserverConfig = { address: randomAddress(), chainId: "0x1" };
    await context.addInitScript(observerEntry, cfg);

    // app-layer egress guard: abort any request the page tries to make to a private / loopback / internal host, so
    // a hostile page cannot reach other services on the same machine. The container's network rules are the primary
    // barrier; this is defence in depth and also blocks requests before they leave the browser.
    await context.route("**/*", (route) => {
      try { const h = new URL(route.request().url()).hostname; if (h !== host && isPrivateHost(h)) { badHosts.add("private:" + h); void route.abort(); return; } } catch { /* fall through */ }
      void route.continue();
    });

    const page = await context.newPage();
    page.on("request", (req) => {
      try {
        const h = new URL(req.url()).hostname;
        if (h && h !== host && isBadHost(h)) badHosts.add(registrable(h));
        if (req.resourceType() === "script") scriptSrcs.add(req.url());
      } catch { /* ignore */ }
    });

    const deadline = startedAt + timeoutMs;
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: Math.min(20000, timeoutMs) }).catch(() => undefined);
    await page.waitForTimeout(1500);

    // page source: drainer markers + seed-phrase form
    const html = (await page.content().catch(() => "")) || "";
    for (const re of SCRIPT_MARKERS) { const m = html.match(re); if (m) report.scriptMarkers.push(m[0].slice(0, 60)); }
    report.seedForm = SEED_FORM_HINTS.some((re) => re.test(html)) && /<input|<textarea/i.test(html);

    // nudge: click obvious connect / claim / mint controls so the page reveals what it does on connect
    if (opts.interact !== false) {
      await page.evaluate(() => { (window as unknown as Record<string, unknown>).__w3pgClicked = true; }).catch(() => undefined);
      // "connect" opens the wallet picker; the wallet labels then select our injected decoy inside it (the modal
      // lists MetaMask/Injected/Browser Wallet or, for EIP-6963 dapps, our announced "Sandbox Observer"), so a
      // page that only drains AFTER a wallet connects actually connects and reveals its request. We never click
      // "WalletConnect" (a QR for a separate mobile wallet we cannot pair). The action words run last.
      const labels = ["connect", "metamask", "sandbox observer", "injected", "browser wallet", "browser extension", "claim", "mint", "verify", "continue", "approve", "start", "enter"];
      for (const label of labels) {
        if (Date.now() > deadline) break;
        const el = page.locator(`button, a, [role=button], div`).filter({ hasText: new RegExp(label, "i") }).first();
        try { if (await el.isVisible({ timeout: 400 })) { await el.click({ timeout: 1200, noWaitAfter: true }); await page.waitForTimeout(700); } } catch { /* ignore */ }
      }
      await page.waitForTimeout(1200);
    }

    // WalletConnect-routed requests never reach the injected observer; pair as a mobile wallet and capture them too.
    let wcRaw: RawCapture[] = [];
    if (opts.interact !== false) {
      wcRaw = await tryWalletConnect(page, cfg.address, cfg.chainId, startedAt, deadline).catch(() => []);
    }

    // read what the page asked the wallet to do
    const raw = (await page.evaluate(() => (window as unknown as { __w3pgCaptured?: unknown }).__w3pgCaptured).catch(() => [])) as RawCapture[];
    const captures = [...(Array.isArray(raw) ? raw : []), ...wcRaw].slice(0, 40).map(decodeCapture);
    report.requests = captures;

    // fetch a few external scripts and grep them too (CDN-hosted drainer logic)
    await scanScripts([...scriptSrcs], host, report);

    // simulate the transaction-shaped captures
    for (const c of captures) {
      if (!(c.method === "eth_sendTransaction" || c.method === "eth_signTransaction" || c.method === "wallet_sendTransaction" || c.method === "wallet_sendCalls")) continue;
      const txs = txsFor(c);
      if (!txs.length) continue;
      const from = cfg.address;
      const sim = await simulate(c.chainId, from, txs).catch(() => undefined);
      report.simulations.push({ kind: c.kind, chainId: c.chainId, sim });
    }

    for (const h of badHosts) report.badHosts.push(h);
    report.ok = true;
  } catch (e) {
    report.error = (e as Error)?.message?.slice(0, 120) || "scan-error";
  } finally {
    await context?.close().catch(() => undefined);
  }

  score(report);
  report.durationMs = Date.now() - startedAt;
  return report;
}

/** the eth_simulateV1 call(s) for a captured transaction request */
function txsFor(c: CapturedRequest): SimTx[] {
  const params = Array.isArray(c.params) ? c.params : [];
  if (c.method === "wallet_sendCalls") {
    const calls = (params[0] as { calls?: Array<{ to?: string; data?: string; value?: string }> } | undefined)?.calls ?? [];
    return calls.slice(0, 16).map((t) => ({ to: t.to, data: t.data, value: t.value }));
  }
  const tx = params[0] as { to?: string; data?: string; value?: string } | undefined;
  return tx && tx.to ? [{ to: tx.to, data: tx.data, value: tx.value }] : [];
}

async function scanScripts(srcs: string[], host: string, report: ScanReport): Promise<void> {
  const picks = srcs.filter((s) => !/jsdelivr|unpkg|cdnjs|googleapis|gstatic|cloudflare\.com\/|jquery|bootstrap|gtag|googletagmanager|facebook\.net|hotjar|intercom/i.test(s)).slice(0, 6);
  await Promise.all(picks.map(async (s) => {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 6000);
      const res = await fetch(s, { signal: ctl.signal });
      clearTimeout(t);
      if (!res.ok) return;
      const text = (await res.text()).slice(0, 800_000);
      for (const re of SCRIPT_MARKERS) { const m = text.match(re); if (m && report.scriptMarkers.length < 20) report.scriptMarkers.push(`${s.split("/").pop()?.slice(0, 30)}: ${m[0].slice(0, 40)}`); }
    } catch { /* ignore */ }
  }));
}
