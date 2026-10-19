/**
 * Deep scan orchestration (background side). Only runs when the user presses the button.
 * Collects the page snapshot, enriches it with what the background already knows
 * (verdict, RDAP age, X intel, provider events), optionally asks GoPlus, scans a few
 * external scripts for drainer markers, then asks the API (which holds the AI key) for a verdict.
 */
import type { DeepReport, PageSnapshot, SandboxReport, Verdict, OriginContext, XIntel } from "./types";
import { signalText } from "./i18n";

/** The only server the extension talks to for deep scans, reports and X lookups. Not user-configurable. */
export const API_BASE = "https://web3-phish-guard-api.w3pg.workers.dev";

const SCRIPT_MARKERS: RegExp[] = [/secureproxy\.php/i, /ping_proxy/i, /rotatingURL/i, /createPrizeTxs/i, /claimSolana/i, /\bdrainer\b/i, /inferno/i, /angel[_-]?drainer/i, /setApprovalForAll[\s\S]{0,300}(permit|transferFrom)/i, /eth_signTypedData_v4[\s\S]{0,300}Permit/i, /signAllTransactions[\s\S]{0,200}SystemProgram\.transfer/i];

/** Fetch up to N external scripts (bounded size) and grep for drainer markers; same-origin and CDN alike. */
export async function scanExternalScripts(scripts: string[], max = 5): Promise<string[]> {
  const found = new Set<string>();
  const picks = scripts.filter((s) => !/jsdelivr|unpkg|cdnjs|googleapis|gstatic|cloudflare\.com|jquery|bootstrap|gtag|googletagmanager|facebook\.net|hotjar|intercom/i.test(s)).slice(0, max);
  await Promise.all(picks.map(async (s) => {
    try {
      const host = s.split("/")[0].split(":")[0];
      // never fetch from private networks or single-label / internal names from the extension's own origin
      if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|\[)/.test(host) || !/\./.test(host) || /\.(local|internal|lan|home|corp|intranet|localhost|test|example|invalid)$/.test(host) || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return;
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 6000); // covers the whole read, not just the headers
      const res = await fetch("https://" + s, { signal: ctrl.signal, credentials: "omit" });
      if (!res.ok || !res.body) { clearTimeout(t); return; }
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (total < 600_000) {
        const { done, value } = await reader.read();
        if (done || !value) break;
        chunks.push(value);
        total += value.length;
      }
      reader.cancel().catch(() => undefined);
      clearTimeout(t);
      const text = new TextDecoder().decode(concat(chunks)).slice(0, 600_000);
      for (const re of SCRIPT_MARKERS) { const m = text.match(re); if (m) found.add(`${s.split("/").pop()?.slice(0, 40)}: ${m[0].slice(0, 50)}`); }
    } catch { /* ignore */ }
  }));
  return [...found].slice(0, 20);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export interface DeepContext {
  verdict: Verdict;
  origin?: OriginContext;
  x?: XIntel;
  providerEvents: string[];
  language: string;
}

export async function askApi(snapshot: PageSnapshot, ctx: DeepContext, extra: { markers: string[] }): Promise<DeepReport["ai"]> {
  const base = API_BASE;
  const v = ctx.verdict;
  const body = {
    url: v.url.replace(/[?#].*$/, ""), // never the query string: it can carry session tokens or referral ids
    host: v.host,
    registrable: v.registrable,
    localScore: v.score,
    localBand: v.band,
    signals: v.signals.filter((s) => s.weight !== 0).map((s) => `${signalText(s)} (${s.weight > 0 ? "+" : ""}${s.weight})`),
    ageDays: v.ageDays,
    origin: ctx.origin ? { source: ctx.origin.source, poster: ctx.origin.poster, display: ctx.origin.display, isReply: ctx.origin.isReply, shortener: ctx.origin.shortener } : undefined,
    x: ctx.x ? { token: ctx.x.token, officialHandle: ctx.x.official?.handle, officialDomains: ctx.x.official?.domains, posterFollowers: ctx.x.poster?.followers, posterAgeDays: ctx.x.poster?.ageDays } : undefined,
    language: ctx.language,
    page: { ...snapshot, drainerMarkers: [...new Set([...snapshot.drainerMarkers, ...extra.markers])].slice(0, 20), providerEvents: ctx.providerEvents },
  };
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 25_000);
  try {
    const res = await fetch(`${base}/v1/scan`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) {
      const err = (await res.json().catch(() => ({}))) as { error?: string };
      return { error: err.error ?? `http_${res.status}` };
    }
    return (await res.json()) as DeepReport["ai"];
  } catch {
    clearTimeout(t);
    return { error: "unreachable" };
  }
}

/**
 * Ask the server-side sandbox to open the url in a throw-away headless browser and report what the page tried to
 * do to a wallet. The sandbox's URL and token live in the Worker, never here. Slow (up to ~40 s); the caller runs
 * it in parallel with the AI scan and tolerates its absence.
 */
export async function askSandbox(url: string): Promise<SandboxReport | undefined> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 43_000);
  try {
    const res = await fetch(`${API_BASE}/v1/sandbox`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: url.replace(/[?#].*$/, "") }),
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (!res.ok) return undefined; // disabled (503), rate-limited (429) or unreachable: silently skip
    const r = (await res.json()) as SandboxReport & { error?: string };
    return r && typeof r.score === "number" ? r : undefined;
  } catch {
    clearTimeout(t);
    return undefined;
  }
}

export async function sendReport(v: Verdict, note: string): Promise<{ ok: boolean; error?: string }> {
  const base = API_BASE;
  try {
    const res = await fetch(`${base}/v1/report`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: v.url.replace(/[?#].*$/, ""), host: v.host, registrable: v.registrable, score: v.score, signals: v.signals.filter((s) => s.weight > 0).map(signalText), note }),
    });
    if (!res.ok) return { ok: false, error: ((await res.json().catch(() => ({}))) as { error?: string }).error ?? `http_${res.status}` };
    return { ok: true };
  } catch {
    return { ok: false, error: "unreachable" };
  }
}
