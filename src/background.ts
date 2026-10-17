import { parseHost } from "./lib/hostname";
import { score, bandOf, BLOCK_THRESHOLD, WARN_THRESHOLD } from "./lib/scoring";
import { loadStaticData } from "./lib/lists";
import { SOURCES, refreshSource, refreshMetaMaskDiffs, warmLists, isWarm, blocklistHit, allowlistHit, siblingHit, attackedBrandHit, listStatus } from "./lib/blocklist";
import { domainAgeDays } from "./lib/rdap";
import { setTabVerdict, getTabVerdict, clearTab, addBypass, isBypassed, addUserAllow, getUserAllow, removeUserAllow } from "./lib/state";
import { sourceFromHost, setTabOrigin, getTabOrigin, setPendingClick, takePendingClick, peekPendingClick, isShortener } from "./lib/origin";
import { resolveBrand, resolvePoster, getApiKey, setApiKey } from "./lib/xquik";
import type { XIntel } from "./lib/types";
import type { OriginContext, ProviderEvent, Signal, Verdict } from "./lib/types";

const WARNING_PAGE = chrome.runtime.getURL("warning.html");

// ---------------------------------------------------------------------------
// list refresh scheduling
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  for (const s of SOURCES) chrome.alarms.create(`refresh:${s.id}`, { periodInMinutes: s.every, delayInMinutes: 0.1 });
  chrome.alarms.create("refresh:metamask-diffs", { periodInMinutes: 5, delayInMinutes: 2 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  const id = alarm.name.replace("refresh:", "");
  try {
    if (id === "metamask-diffs") await refreshMetaMaskDiffs();
    else {
      const src = SOURCES.find((s) => s.id === id);
      if (src) {
        const n = await refreshSource(src);
        console.info(`[w3pg] ${id}: ${n} domains`);
      }
    }
  } catch (e) {
    console.warn(`[w3pg] refresh ${id} failed`, e);
  }
});

async function ensureReady() {
  const data = await loadStaticData();
  if (!isWarm()) await warmLists([...data.lists.freeHostsStrong, ...data.lists.freeHostsWeak]);
  return data;
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------
async function evaluate(url: string, extra: { ageDays?: number; origin?: OriginContext; x?: XIntel } = {}): Promise<Verdict | null> {
  if (!/^https?:/.test(url)) return null;
  const { brands, lists } = await ensureReady();
  const p = parseHost(url, [...lists.freeHostsStrong, ...lists.freeHostsWeak]);
  if (!p) return null;
  if (p.host === "localhost" || p.host.endsWith(".localhost")) return null;

  const userAllow = await getUserAllow();
  return score(url, p, {
    brands,
    lists,
    blocklistHit: blocklistHit(p.host),
    siblingHit: siblingHit(p.host),
    attacked: attackedBrandHit(p.host),
    allowlistHit: allowlistHit(p.host),
    userAllowed: userAllow.some((d) => p.host === d || p.host.endsWith("." + d)),
    ageDays: extra.ageDays,
    origin: extra.origin,
    x: extra.x,
  });
}

/** Ask X (via Xquik) about the brand token and the poster; null when no key / nothing to ask. */
async function xIntelFor(v: Verdict, origin?: OriginContext): Promise<XIntel | undefined> {
  if (!v.xToken) return undefined;
  if (!(await getApiKey())) return undefined;
  const brand = await resolveBrand(v.xToken);
  const posterHandle = origin?.poster;
  const poster = posterHandle ? await resolvePoster(posterHandle) : null;
  if (!brand && !poster) return undefined;
  return {
    token: v.xToken,
    confidence: brand?.confidence ?? 0,
    official: brand?.official ? { handle: brand.official.handle, domains: brand.official.domains, followers: brand.official.followers, verifiedType: brand.official.verifiedType } : undefined,
    poster: poster ? { handle: poster.handle, followers: poster.followers, ageDays: poster.ageDays, domains: poster.domains } : undefined,
  };
}

/** Full pipeline for one navigation: local score -> RDAP age -> X resolver, re-applying when the band changes. */
async function evaluateAndApply(tabId: number, url: string, origin?: OriginContext): Promise<void> {
  let v = await evaluate(url, { origin });
  if (!v) {
    await clearTab(tabId);
    await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => undefined);
    return;
  }
  await applyVerdict(tabId, v);
  let ageDays: number | undefined;
  if (v.needsAgeCheck) {
    ageDays = await domainAgeDays(v.registrable);
    if (ageDays !== undefined) {
      const v2 = await evaluate(url, { ageDays, origin });
      if (v2) {
        if (v2.band !== v.band) await applyVerdict(tabId, v2); else await setTabVerdict(tabId, v2);
        v = v2;
      }
    }
  }
  if (v.xToken && v.band !== "block") {
    const x = await xIntelFor(v, origin);
    if (x) {
      const v3 = await evaluate(url, { ageDays, origin, x });
      if (v3) {
        if (v3.band !== v.band) await applyVerdict(tabId, v3); else await setTabVerdict(tabId, v3);
      }
    }
  }
}

/** Follow a short-link (t.co) to its final URL. Cached; only the redirect target is kept. */
const redirectCache = new Map<string, string>();
async function resolveRedirect(url: string): Promise<string | null> {
  const hit = redirectCache.get(url);
  if (hit !== undefined) return hit || null;
  try {
    const ctrl = new AbortController();
    const tmr = setTimeout(() => ctrl.abort(), 6000);
    let res = await fetch(url, { method: "HEAD", redirect: "follow", signal: ctrl.signal, credentials: "omit" });
    const stuck = (r: Response) => isShortener(new URL(r.url).hostname); // the target may answer 403 to bots; its URL is still the answer
    if (stuck(res)) {
      // many shorteners refuse HEAD (tr.ee answers 405) or interpose an HTML page; GET follows the real redirect
      res = await fetch(url, { method: "GET", redirect: "follow", signal: ctrl.signal, credentials: "omit" });
    }
    let finalUrl = stuck(res) ? "" : res.url;
    if (!finalUrl && res.ok) {
      // last resort: meta refresh / JS redirect in the interstitial body
      const body = (await res.text()).slice(0, 20000);
      const m = body.match(/(?:http-equiv="refresh"[^>]*url=|window\.location(?:\.href)?\s*=\s*["'])(https?:[^"'>\s]+)/i);
      if (m) finalUrl = m[1];
    }
    clearTimeout(tmr);
    redirectCache.set(url, finalUrl);
    return finalUrl || null;
  } catch {
    redirectCache.set(url, "");
    return null;
  }
}

/** Pure hostname scoring for the X timeline badges: no RDAP, no tab state. */
async function scoreHostOnly(host: string, ctx: Partial<OriginContext>): Promise<{ band: string; score: number; signals: Signal[] } | null> {
  const v = await evaluate(`https://${host}/`, { origin: { source: "x", at: Date.now(), ...ctx } });
  if (!v) return null;
  return { band: v.band, score: v.score, signals: v.signals.filter((s) => s.weight > 0) };
}

async function applyVerdict(tabId: number, v: Verdict) {
  await setTabVerdict(tabId, v);
  const color = v.band === "block" ? "#e5484d" : v.band === "warn" ? "#f5a524" : "#2e7d32";
  await chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => undefined);
  await chrome.action.setBadgeText({ tabId, text: v.band === "none" ? "" : String(v.score) }).catch(() => undefined);

  if (v.band === "block" && !(await isBypassed(v.host))) {
    const target = `${WARNING_PAGE}#${encodeURIComponent(JSON.stringify({ url: v.url, host: v.host, score: v.score, signals: v.signals }))}`;
    await chrome.tabs.update(tabId, { url: target }).catch(() => undefined);
    return;
  }
  if (v.band === "warn") {
    chrome.tabs.sendMessage(tabId, { type: "w3pg:overlay", verdict: v }).catch(() => undefined);
  }
}

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  try {
    // Redirector hop (t.co, out.reddit.com...): remember the source for the hop that follows.
    let host = "";
    try { host = new URL(d.url).hostname; } catch { /* ignore */ }
    const src = host ? sourceFromHost(host) : null;
    if (src && (host === "t.co" || host === "out.reddit.com")) {
      const pending = await takePendingClick();
      await setTabOrigin(d.tabId, { source: src, at: Date.now(), ...(pending ?? {}) });
      return;
    }
    if (src) return; // the social site itself is never evaluated
    if (host && isShortener(host)) {
      // tr.ee / bit.ly hop: keep the origin alive, remember that the destination was hidden
      const existing = (await getTabOrigin(d.tabId)) ?? (await takePendingClick());
      if (existing) await setTabOrigin(d.tabId, { ...existing, shortener: host, at: Date.now() });
      return;
    }

    let origin = await getTabOrigin(d.tabId);
    if (!origin) {
      // Article / card links often leave X without a t.co hop and open in a new tab with no referrer.
      const pending = await peekPendingClick();
      if (pending && (!pending.target || pending.target === "t.co" || pending.target === host || host.endsWith("." + pending.target))) {
        await takePendingClick();
        origin = { ...pending, at: Date.now() };
        await setTabOrigin(d.tabId, origin);
      }
    }
    await evaluateAndApply(d.tabId, d.url, origin);
  } catch (e) {
    console.warn("[w3pg] evaluate failed", e);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => void clearTab(tabId));

// ---------------------------------------------------------------------------
// messages from content scripts / pages
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "w3pg:getVerdict": {
        const tabId = msg.tabId ?? sender.tab?.id;
        sendResponse(tabId !== undefined ? await getTabVerdict(tabId) : undefined);
        return;
      }
      case "w3pg:bypass": {
        await addBypass(String(msg.host));
        sendResponse(true);
        return;
      }
      case "w3pg:allow": {
        await addUserAllow(String(msg.registrable));
        sendResponse(true);
        return;
      }
      case "w3pg:unallow": {
        await removeUserAllow(String(msg.registrable));
        sendResponse(true);
        return;
      }
      case "w3pg:status": {
        sendResponse({ lists: await listStatus(), userAllow: await getUserAllow() });
        return;
      }
      case "w3pg:provider": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url) return;
        const ev = msg.event as ProviderEvent;
        const prev = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        if (!prev) return;
        if (prev.signals.some((s) => s.id === "user-allow" || s.id === "brand-official")) return;
        const weight = providerWeight(ev);
        if (!weight) return;
        const id = `provider-${ev.kind}`;
        if (prev.signals.some((s) => s.id === id)) return;
        const signals = [...prev.signals, { id, weight, ...providerKey(ev) }];
        const total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        const v: Verdict = { ...prev, signals, score: total, band: bandOf(total), at: Date.now() };
        await applyVerdict(tabId, v);
        sendResponse(v);
        return;
      }
      case "w3pg:referrer": {
        // Fallback when no redirector hop was seen (e.g. Discord opens links directly).
        const tabId = sender.tab?.id;
        if (tabId === undefined || sender.frameId !== 0 || !sender.url) return;
        let rh = "";
        try { rh = new URL(String(msg.referrer)).hostname; } catch { return; }
        const src = sourceFromHost(rh);
        if (!src) return;
        if (await getTabOrigin(tabId)) return;
        const pending = (await takePendingClick()) ?? {};
        const origin: OriginContext = { ...pending, source: src, at: Date.now() };
        await setTabOrigin(tabId, origin);
        await evaluateAndApply(tabId, sender.url, origin);
        return;
      }
      case "w3pg:xclick": {
        const c = (msg.ctx ?? {}) as Partial<OriginContext>;
        await setPendingClick({ source: "x", at: Date.now(), poster: c.poster, posterVerified: c.posterVerified, isReply: c.isReply, display: c.display, target: c.target });
        sendResponse(true);
        return;
      }
      case "w3pg:scoreHost": {
        sendResponse(await scoreHostOnly(String(msg.host), (msg.ctx ?? {}) as Partial<OriginContext>));
        return;
      }
      case "w3pg:scoreLink": {
        // Timeline / article link: resolve t.co to the real target, then score that host with the shown text as display.
        const href = String(msg.href);
        let target = "";
        try { target = new URL(href).hostname.toLowerCase(); } catch { sendResponse(null); return; }
        if (isShortener(target)) {
          const finalUrl = await resolveRedirect(href);
          if (!finalUrl) { sendResponse(null); return; }
          try { target = new URL(finalUrl).hostname.toLowerCase(); } catch { sendResponse(null); return; }
        }
        const r = await scoreHostOnly(target, (msg.ctx ?? {}) as Partial<OriginContext>);
        sendResponse(r ? { ...r, host: target } : null);
        return;
      }
      case "w3pg:getSettings": {
        sendResponse({ xquikKey: await getApiKey() });
        return;
      }
      case "w3pg:setSettings": {
        if (typeof msg.xquikKey === "string") await setApiKey(msg.xquikKey);
        sendResponse(true);
        return;
      }
      case "w3pg:testXquik": {
        const r = await resolveBrand(String(msg.token || "uniswap"));
        sendResponse(r);
        return;
      }
      case "w3pg:refreshNow": {
        for (const s of SOURCES) {
          try { await refreshSource(s); } catch (e) { console.warn(e); }
        }
        sendResponse(await listStatus());
        return;
      }
    }
  })();
  return true;
});

function providerWeight(ev: ProviderEvent): number {
  switch (ev.kind) {
    case "auto-connect":
      return ev.hadGesture ? 0 : 15;
    case "risky-sign":
      return ev.hadGesture ? 20 : 35;
    case "risky-tx":
      return ev.hadGesture ? 20 : 35;
    case "chain-switch":
      return ev.hadGesture ? 0 : 5;
  }
}

const DETAIL_KEYS: Record<string, string> = {
  approve: "sig_tx_approve",
  increaseAllowance: "sig_tx_approve",
  setApprovalForAll: "sig_tx_set_approval_for_all",
  permit: "sig_tx_permit",
  permit2: "sig_tx_permit",
  transfer: "sig_tx_transfer",
  payable_unknown: "sig_tx_payable_unknown",
  typed: "sig_sign_typed",
  eth_sign: "sig_sign_eth_sign",
  solana: "sig_sol_sign",
};

function providerKey(ev: ProviderEvent): { key: string; sub?: string[] } {
  switch (ev.kind) {
    case "auto-connect":
      return { key: "sig_auto_connect" };
    case "chain-switch":
      return { key: "sig_chain_switch" };
    default:
      return { key: DETAIL_KEYS[ev.detail] ?? "sig_tx_generic", sub: ev.param ? [ev.param] : undefined };
  }
}

export { BLOCK_THRESHOLD, WARN_THRESHOLD };
