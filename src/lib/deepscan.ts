/**
 * Deep scan orchestration (background side). Only runs when the user presses the button.
 * Collects the page snapshot, enriches it with what the background already knows
 * (verdict, RDAP age, X intel, provider events), optionally asks GoPlus, scans a few
 * external scripts for drainer markers, then asks the API (which holds the AI key) for a verdict.
 */
import type { DeepReport, PageSnapshot, Verdict, OriginContext, XIntel } from "./types";
import { signalText } from "./i18n";

export const DEFAULT_API_BASE = "https://web3-phish-guard-api.w3pg.workers.dev";

export async function getApiBase(): Promise<string> {
  const v = (await chrome.storage.local.get("apiBase")).apiBase as string | undefined;
  return (v && v.trim().replace(/\/$/, "")) || DEFAULT_API_BASE;
}

export async function setApiBase(v: string): Promise<void> {
  await chrome.storage.local.set({ apiBase: v.trim().replace(/\/$/, "") });
}

const SCRIPT_MARKERS: RegExp[] = [/secureproxy\.php/i, /ping_proxy/i, /rotatingURL/i, /createPrizeTxs/i, /claimSolana/i, /\bdrainer\b/i, /inferno/i, /angel[_-]?drainer/i, /setApprovalForAll[\s\S]{0,300}(permit|transferFrom)/i, /eth_signTypedData_v4[\s\S]{0,300}Permit/i, /signAllTransactions[\s\S]{0,200}SystemProgram\.transfer/i];

/** Fetch up to N external scripts (bounded size) and grep for drainer markers; same-origin and CDN alike. */
export async function scanExternalScripts(scripts: string[], max = 5): Promise<string[]> {
  const found = new Set<string>();
  const picks = scripts.filter((s) => !/jsdelivr|unpkg|cdnjs|googleapis|gstatic|cloudflare\.com|jquery|bootstrap|gtag|googletagmanager|facebook\.net|hotjar|intercom/i.test(s)).slice(0, max);
  await Promise.all(picks.map(async (s) => {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 6000);
      const res = await fetch("https://" + s, { signal: ctrl.signal, credentials: "omit" });
      clearTimeout(t);
      if (!res.ok) return;
      const text = (await res.text()).slice(0, 600_000);
      for (const re of SCRIPT_MARKERS) { const m = text.match(re); if (m) found.add(`${s.split("/").pop()?.slice(0, 40)}: ${m[0].slice(0, 50)}`); }
    } catch { /* ignore */ }
  }));
  return [...found].slice(0, 20);
}

/** GoPlus phishing_site (free, keyless). Sent only during an explicit deep scan. */
export async function goPlus(host: string): Promise<{ phishing?: boolean } | undefined> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`https://api.gopluslabs.io/api/v1/phishing_site?url=${encodeURIComponent(host)}`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return undefined;
    const j = (await res.json()) as { result?: { phishing_site?: number } };
    if (!j.result) return undefined;
    return { phishing: j.result.phishing_site === 1 };
  } catch {
    return undefined;
  }
}

export interface DeepContext {
  verdict: Verdict;
  origin?: OriginContext;
  x?: XIntel;
  providerEvents: string[];
  language: string;
}

export async function askApi(snapshot: PageSnapshot, ctx: DeepContext, extra: { markers: string[]; goplus?: { phishing?: boolean } }): Promise<DeepReport["ai"]> {
  const base = await getApiBase();
  const v = ctx.verdict;
  const body = {
    url: v.url,
    host: v.host,
    registrable: v.registrable,
    localScore: v.score,
    localBand: v.band,
    signals: v.signals.filter((s) => s.weight !== 0).map((s) => `${signalText(s)} (${s.weight > 0 ? "+" : ""}${s.weight})`),
    ageDays: v.ageDays,
    origin: ctx.origin ? { source: ctx.origin.source, poster: ctx.origin.poster, display: ctx.origin.display, isReply: ctx.origin.isReply, shortener: ctx.origin.shortener } : undefined,
    x: ctx.x ? { token: ctx.x.token, officialHandle: ctx.x.official?.handle, officialDomains: ctx.x.official?.domains, posterFollowers: ctx.x.poster?.followers, posterAgeDays: ctx.x.poster?.ageDays } : undefined,
    gopluss: extra.goplus,
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

export async function sendReport(v: Verdict, note: string): Promise<{ ok: boolean; error?: string }> {
  const base = await getApiBase();
  try {
    const res = await fetch(`${base}/v1/report`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: v.url, host: v.host, registrable: v.registrable, score: v.score, signals: v.signals.filter((s) => s.weight > 0).map(signalText), note }),
    });
    if (!res.ok) return { ok: false, error: ((await res.json().catch(() => ({}))) as { error?: string }).error ?? `http_${res.status}` };
    return { ok: true };
  } catch {
    return { ok: false, error: "unreachable" };
  }
}
