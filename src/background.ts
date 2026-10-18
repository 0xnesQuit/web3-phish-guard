import { parseHost } from "./lib/hostname";
import { score, bandOf, BLOCK_THRESHOLD, WARN_THRESHOLD } from "./lib/scoring";
import { loadStaticData, refreshRemoteData, remoteDataStatus, brandByHandle, brandByToken } from "./lib/lists";
import { SOURCES, refreshSource, refreshMetaMaskDiffs, warmLists, isWarm, blocklistHit, allowlistHit, siblingHit, attackedBrandHit, listStatus, newestDomains } from "./lib/blocklist";
import { domainAgeDays } from "./lib/rdap";
import { setTabVerdict, getTabVerdict, clearTab, addBypass, isBypassed, addUserAllow, getUserAllow, removeUserAllow, putWarning, getWarning } from "./lib/state";
import { sourceFromHost, setTabOrigin, getTabOrigin, setPendingClick, takePendingClick, peekPendingClick, isShortener, isAdHop } from "./lib/origin";
import { resolveBrand, resolvePoster } from "./lib/xquik";
import { scanExternalScripts, askApi, sendReport, API_BASE } from "./lib/deepscan";
import { buildRules, applyRules, addBypassRule } from "./lib/dnr";
import type { XIntel } from "./lib/types";
import type { DeepReport, OriginContext, PageSnapshot, PageSocials, ProviderEvent, Signal, Verdict } from "./lib/types";

const WARNING_PAGE = chrome.runtime.getURL("warning.html");
const EXT_ORIGIN = chrome.runtime.getURL("").replace(/\/$/, "");
const REVIEWED = new Set(["metamask", "scamsniffer", "community"]);

/** Messages that change state or read other tabs are accepted from the extension's own pages only. */
function fromExtension(sender: chrome.runtime.MessageSender): boolean {
  return !!sender.url && sender.url.startsWith(EXT_ORIGIN + "/");
}

// ---------------------------------------------------------------------------
// list refresh scheduling
// ---------------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(() => {
  for (const s of SOURCES) chrome.alarms.create(`refresh:${s.id}`, { periodInMinutes: s.every, delayInMinutes: 0.1 });
  chrome.alarms.create("refresh:metamask-diffs", { periodInMinutes: 5, delayInMinutes: 2 });
  chrome.alarms.create("refresh:data", { periodInMinutes: 60 * 12, delayInMinutes: 1 });
  chrome.alarms.create("prune", { periodInMinutes: 60 * 24, delayInMinutes: 30 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  const id = alarm.name.replace("refresh:", "");
  try {
    if (alarm.name === "prune") { await pruneCaches(); return; }
    if (id === "metamask-diffs") { await refreshMetaMaskDiffs(); if (isWarm()) await syncDnr(); }
    else if (id === "data") {
      const r = await refreshRemoteData();
      if (r.updated) console.info(`[w3pg] remote data: ${r.files} files`);
    } else {
      const src = SOURCES.find((s) => s.id === id);
      if (src) {
        const n = await refreshSource(src);
        console.info(`[w3pg] ${id}: ${n} domains`);
        if (isWarm()) await syncDnr();
      }
    }
  } catch (e) {
    console.warn(`[w3pg] refresh ${id} failed`, e);
  }
});

let readyPromise: Promise<Awaited<ReturnType<typeof loadStaticData>>> | null = null;
async function ensureReady() {
  if (!readyPromise) {
    readyPromise = (async () => {
      const data = await loadStaticData();
      if (!isWarm()) {
        await warmLists([...data.lists.freeHostsStrong, ...data.lists.freeHostsWeak]);
        await syncDnr();
      }
      return data;
    })().catch((e) => { readyPromise = null; throw e; });
  }
  return readyPromise;
}

/** Push the freshest known-phishing hosts into declarativeNetRequest so they are cancelled before any request. */
const bypassedHosts: string[] = [];
async function syncDnr(): Promise<void> {
  try {
    const { lists } = await loadStaticData();
    const block = [
      ...newestDomains("metamask", 40_000),
      ...newestDomains("scamsniffer", 15_000),
      ...newestDomains("community", 10_000),
      ...newestDomains("community-auto", 10_000),
    ];
    const allow = [...(await getUserAllow()), ...lists.trusted, ...bypassedHosts];
    await applyRules(buildRules(block, allow));
  } catch (e) {
    console.warn("[w3pg] DNR sync failed", e);
  }
}

/** rdap:* / x:* cache entries have TTLs but were never deleted; sweep them daily. */
async function pruneCaches(): Promise<void> {
  const all = await chrome.storage.local.get(null);
  const now = Date.now();
  const drop: string[] = [];
  for (const [k, v] of Object.entries(all)) {
    const rec = v as { at?: number; checkedAt?: number } | null;
    const at = rec?.at ?? rec?.checkedAt;
    if ((k.startsWith("rdap:") || k.startsWith("x:")) && typeof at === "number" && now - at > 14 * 86400_000) drop.push(k);
  }
  if (drop.length) await chrome.storage.local.remove(drop);
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------
async function evaluate(url: string, extra: { ageDays?: number; origin?: OriginContext; x?: XIntel; socials?: PageSocials } = {}): Promise<Verdict | null> {
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
    socials: extra.socials,
    handleIndex: extra.socials ? brandByHandle(brands) : undefined,
    brandByToken: extra.socials ? brandByToken(brands) : undefined,
  });
}

async function getTabSocials(tabId: number): Promise<PageSocials | undefined> {
  return (await chrome.storage.session.get(`soc:${tabId}`))[`soc:${tabId}`] as PageSocials | undefined;
}

async function warnDisplay(): Promise<"page" | "popup"> {
  return (((await chrome.storage.local.get("warnDisplay")).warnDisplay as string | undefined) === "popup" ? "popup" : "page");
}

/** True while the tab still shows the host a (slow) verdict was computed for. */
async function stillOn(tabId: number, host: string): Promise<boolean> {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url) return false;
  try { return new URL(tab.url).hostname === host; } catch { return false; }
}

/** Ask the API (which holds the Xquik key) about the brand token and the poster. */
async function xIntelFor(v: Verdict, origin?: OriginContext): Promise<XIntel | undefined> {
  if (!v.xToken) return undefined;
  const [brand, poster] = await Promise.all([resolveBrand(v.xToken), origin?.poster ? resolvePoster(origin.poster) : Promise.resolve(null)]);
  if (!brand && !poster) return undefined;
  return {
    token: v.xToken,
    confidence: brand?.confidence ?? 0,
    official: brand?.official ? { handle: brand.official.handle, domains: brand.official.domains, followers: brand.official.followers, verifiedType: brand.official.verifiedType } : undefined,
    poster: poster ? { handle: poster.handle, followers: poster.followers, ageDays: poster.ageDays, domains: poster.domains } : undefined,
  };
}

/** Full pipeline for one navigation: local score -> RDAP age -> X resolver. Later passes are dropped if the tab moved on. */
async function evaluateAndApply(tabId: number, url: string, origin?: OriginContext): Promise<void> {
  await chrome.storage.session.remove([`soc:${tabId}`, `pev:${tabId}`]);
  let v = await evaluate(url, { origin });
  if (!v) {
    await resetTab(tabId);
    return;
  }
  await applyVerdict(tabId, v);
  if (v.band === "block") return;
  let ageDays: number | undefined;
  if (v.needsAgeCheck) {
    ageDays = await domainAgeDays(v.registrable);
    if (ageDays !== undefined && (await stillOn(tabId, v.host))) {
      const v2 = await evaluate(url, { ageDays, origin, socials: await getTabSocials(tabId) });
      if (v2) { await applyVerdict(tabId, v2); v = v2; }
    }
  }
  if (v.xToken && v.band !== "block") {
    const x = await xIntelFor(v, origin);
    if (x && (await stillOn(tabId, v.host))) {
      const v3 = await evaluate(url, { ageDays, origin, x, socials: await getTabSocials(tabId) });
      if (v3) await applyVerdict(tabId, v3);
    }
  }
}

/** Follow a short-link to its final URL. Resolved by the API (our IP, not the user's); local fetch only as a fallback. */
const redirectCache = new Map<string, string>();
async function resolveRedirect(url: string): Promise<string | null> {
  const hit = redirectCache.get(url);
  if (hit !== undefined) return hit || null;
  if (redirectCache.size > 500) redirectCache.delete(redirectCache.keys().next().value as string);
  try {
    const r = await fetch(`${API_BASE}/v1/resolve?url=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const j = (await r.json()) as { url?: string | null };
      redirectCache.set(url, j.url ?? "");
      return j.url ?? null;
    }
    if (r.status === 400 || r.status === 429) { redirectCache.set(url, ""); return null; }
  } catch { /* API unreachable: resolve locally */ }
  try {
    const ctrl = new AbortController();
    const tmr = setTimeout(() => ctrl.abort(), 6000);
    let res = await fetch(url, { method: "HEAD", redirect: "follow", signal: ctrl.signal, credentials: "omit" });
    const stuck = (r: Response) => isShortener(new URL(r.url).hostname);
    if (stuck(res)) res = await fetch(url, { method: "GET", redirect: "follow", signal: ctrl.signal, credentials: "omit" });
    let finalUrl = stuck(res) ? "" : res.url;
    if (!finalUrl && res.ok) {
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

/** User-triggered deep scan: page snapshot + external script grep + API verdict (the API also asks GoPlus). */
async function deepScan(tabId: number, language: string): Promise<DeepReport | { error: string }> {
  const tab = await chrome.tabs.get(tabId).catch(() => null);
  if (!tab?.url || !/^https?:/.test(tab.url)) return { error: "not_http" };
  // Firefox 140+: the page snapshot leaves the browser, so ask for the declared optional data-collection permission first.
  try {
    const bss = chrome.runtime.getManifest().browser_specific_settings as { gecko?: { data_collection_permissions?: unknown } } | undefined;
    const perms = chrome.permissions as unknown as { request?: (p: { data_collection?: string[] }) => Promise<boolean>; contains?: (p: { data_collection?: string[] }) => Promise<boolean> };
    if (bss?.gecko?.data_collection_permissions && perms?.request) {
      const wanted = { data_collection: ["websiteContent", "websiteActivity"] };
      const has = perms.contains ? await perms.contains(wanted).catch(() => false) : false;
      if (!has) {
        // request() must run from a user gesture; the popup click is one. A thrown error means "not granted".
        const ok = await perms.request(wanted).catch(() => false);
        if (!ok) return { error: "permission_denied" };
      }
    }
  } catch { /* Chrome: no data-collection permissions */ }
  let v = await getTabVerdict(tabId);
  if (!v) v = (await evaluate(tab.url)) ?? undefined;
  if (!v) return { error: "no_verdict" };
  const cacheKey = `deep:${tabId}`;
  const cached = (await chrome.storage.session.get(cacheKey))[cacheKey] as DeepReport | undefined;
  if (cached && cached.host === v.host && Date.now() - cached.at < 10 * 60_000 && !cached.ai.error) return cached;

  let snapshot: PageSnapshot | null = null;
  try {
    snapshot = (await chrome.tabs.sendMessage(tabId, { type: "w3pg:collect" })) as PageSnapshot;
  } catch { /* content script not present (e.g. page blocked scripts) */ }
  if (!snapshot || (snapshot as unknown as { error?: string }).error) return { error: "collect_failed" };

  const origin = await getTabOrigin(tabId);
  const pev = ((await chrome.storage.session.get(`pev:${tabId}`))[`pev:${tabId}`] as string[] | undefined) ?? [];
  const [markers, ageDays] = await Promise.all([
    scanExternalScripts(snapshot.scripts),
    v.ageDays !== undefined ? Promise.resolve(v.ageDays) : domainAgeDays(v.registrable),
  ]);
  const socials = snapshot.socials ?? (await getTabSocials(tabId));
  const x = v.xToken ? await xIntelFor(v, origin) : undefined;
  const v3 = await evaluate(tab.url, { ageDays, origin, x, socials });
  if (v3) v = v3;
  const ai = await askApi(snapshot, { verdict: v, origin, x, providerEvents: pev, language }, { markers });
  const report: DeepReport = { host: v.host, at: Date.now(), local: { score: v.score, band: v.band, signals: v.signals }, page: snapshot, markers, goplus: ai.goplus, ai };
  await chrome.storage.session.set({ [cacheKey]: report });
  return report;
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
    await showWarning(tabId, v);
    return;
  }
  if (v.band === "warn" && (await warnDisplay()) === "page") {
    chrome.tabs.sendMessage(tabId, { type: "w3pg:overlay", verdict: v }).catch(() => undefined);
  } else if (v.band === "none") {
    chrome.tabs.sendMessage(tabId, { type: "w3pg:clear" }).catch(() => undefined);
  }
}

async function showWarning(tabId: number, v: Verdict) {
  const { brands } = await ensureReady();
  const brand = v.brand ? brands.find((b) => b.name === v.brand) : undefined;
  const reviewed = v.signals.some((s) => s.id === "blocklist" && s.sub?.[0] !== undefined && REVIEWED.has(s.sub[0]));
  const nonce = await putWarning({ url: v.url, host: v.host, score: v.score, signals: v.signals, brandDomain: brand?.domains[0], reviewed, tabId });
  await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?n=${nonce}` }).catch(() => undefined);
}

/** Official extension ids of major wallets on the Chrome Web Store; a listing named like a wallet with another id is a counterfeit. */
const WALLET_STORE_IDS: Array<[RegExp, string[]]> = [
  [/metamask/i, ["nkbihfbeogaeaoehlefnkodbefgpgknn"]],
  [/phantom/i, ["bfnaelmomeimhlpmgjnjophhpkkoljpa"]],
  [/coinbase/i, ["hnfanknocfeofbddgcijnmhnfnkdnaad"]],
  [/rabby/i, ["acmacodkjbdgmoleebolmdjonilkdbch"]],
  [/okx/i, ["mcohilncbfahbmgdjkbpemcciiolgcge"]],
  [/trust ?wallet/i, ["egjidjbpglichdcondbcbdnbeeppgdph"]],
  [/keplr/i, ["dmkamcknogkgcdfhhbddcghachkejeap"]],
  [/backpack/i, ["aflkmfhebedbjioipglgcbcmnbpgliof"]],
  [/solflare/i, ["bhhhlbepdkbapadjdnnojkbgioiodbic"]],
  [/rainbow/i, ["opfgelmcmbiajamepnmloijbpoleiama"]],
  [/unisat/i, ["ppbibelpcjmhbdihakflkdcoccbgbkpo"]],
  [/argent/i, ["dlcobpjiigpikoobohmabehhmhfoodbb"]],
];
async function checkStoreListing(tabId: number, url: string): Promise<boolean> {
  const m = url.match(/^https:\/\/chromewebstore\.google\.com\/detail\/([^/]+)\/([a-p]{32})/);
  if (!m) return false;
  const slug = decodeURIComponent(m[1]).replace(/-/g, " ");
  const id = m[2];
  for (const [re, ids] of WALLET_STORE_IDS) {
    if (re.test(slug) && !ids.includes(id)) {
      const v: Verdict = { url, host: "chromewebstore.google.com", registrable: "google.com", score: 75, band: "block", signals: [{ id: "fake-wallet-listing", weight: 75, key: "sig_fake_wallet_listing", sub: [slug] }], needsAgeCheck: false, at: Date.now() };
      await applyVerdict(tabId, v);
      return true;
    }
  }
  return false;
}

async function resetTab(tabId: number) {
  await clearTab(tabId);
  await chrome.action.setBadgeText({ tabId, text: "" }).catch(() => undefined);
}

chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  try {
    let host = "";
    try { host = new URL(d.url).hostname; } catch { /* ignore */ }
    const src = host ? sourceFromHost(host) : null;
    if (src === "ads" || isAdHop(host)) {
      await setTabOrigin(d.tabId, { source: "ads", at: Date.now() });
      await resetTab(d.tabId);
      return;
    }
    if (src && (host === "t.co" || host === "out.reddit.com")) {
      const pending = await takePendingClick();
      await setTabOrigin(d.tabId, { source: src, at: Date.now(), ...(pending ?? {}) });
      await resetTab(d.tabId);
      return;
    }
    if (src) { await resetTab(d.tabId); return; } // the social site itself is never evaluated
    if (host && isShortener(host)) {
      const existing = (await getTabOrigin(d.tabId)) ?? (await takePendingClick());
      if (existing) await setTabOrigin(d.tabId, { ...existing, shortener: host, at: Date.now() });
      await resetTab(d.tabId);
      return;
    }
    if (d.url.startsWith(EXT_ORIGIN)) return;
    if (await checkStoreListing(d.tabId, d.url)) return;

    let origin = await getTabOrigin(d.tabId);
    if (!origin) {
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

// A DNR block shows the browser's error page; swap it for our warning with the real reasons.
chrome.webNavigation.onErrorOccurred.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  if (!/BLOCKED_BY_CLIENT|NS_ERROR_ABORT|NS_BINDING_ABORTED/i.test(d.error ?? "")) return;
  try {
    const v = await evaluate(d.url, { origin: await getTabOrigin(d.tabId) });
    if (v && v.signals.some((s) => s.id === "blocklist")) {
      await setTabVerdict(d.tabId, v);
      await showWarning(d.tabId, v);
    }
  } catch { /* ignore */ }
});

chrome.tabs.onRemoved.addListener((tabId) => void clearTab(tabId));

// The overlay content script may load after the verdict was decided; nudge it once the page is complete.
chrome.webNavigation.onCompleted.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const v = await getTabVerdict(d.tabId);
  if (v && v.band === "warn" && v.url === d.url && (await warnDisplay()) === "page") {
    chrome.tabs.sendMessage(d.tabId, { type: "w3pg:overlay", verdict: v }).catch(() => undefined);
  }
});

// ---------------------------------------------------------------------------
// messages from content scripts / pages
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "w3pg:getVerdict": {
        const tabId = fromExtension(sender) ? (msg.tabId ?? sender.tab?.id) : sender.tab?.id;
        sendResponse(tabId !== undefined ? await getTabVerdict(tabId) : undefined);
        return;
      }
      case "w3pg:getWarning": {
        if (!fromExtension(sender)) return;
        sendResponse((await getWarning(String(msg.nonce))) ?? null);
        return;
      }
      case "w3pg:bypass": {
        if (!fromExtension(sender)) return;
        const p = await getWarning(String(msg.nonce));
        if (!p) { sendResponse(false); return; }
        await addBypass(p.host);
        bypassedHosts.push(p.host);
        await addBypassRule(p.host);
        sendResponse(true);
        return;
      }
      case "w3pg:leave": {
        const tabId = sender.tab?.id;
        if (!fromExtension(sender) || tabId === undefined) return;
        await chrome.tabs.update(tabId, { url: "about:blank" }).catch(() => undefined);
        sendResponse(true);
        return;
      }
      case "w3pg:allow": {
        if (!fromExtension(sender)) return;
        await addUserAllow(String(msg.registrable));
        await syncDnr();
        sendResponse(true);
        return;
      }
      case "w3pg:unallow": {
        if (!fromExtension(sender)) return;
        await removeUserAllow(String(msg.registrable));
        await syncDnr();
        sendResponse(true);
        return;
      }
      case "w3pg:status": {
        if (!fromExtension(sender)) return;
        sendResponse({ lists: await listStatus(), userAllow: await getUserAllow(), data: await remoteDataStatus() });
        return;
      }
      case "w3pg:provider": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url) return;
        const ev = msg.event as ProviderEvent;
        const prev = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        if (!prev) return;
        let frameHost = "";
        try { frameHost = new URL(sender.url).hostname; } catch { /* ignore */ }
        if (sender.frameId !== 0 && frameHost !== prev.host) return;
        const safeSite = prev.signals.some((s) => s.id === "user-allow" || s.id === "brand-official" || s.id === "trusted");
        const alwaysCounts = ev.kind === "seed-input" || ev.kind === "clickfix" || ev.kind === "clipboard-swap" || ev.kind === "fake-wallet" || ev.detail === "eoa-spender" || ev.detail === "poisoning" || ev.detail === "delegation";
        if (safeSite && !alwaysCounts) return;
        let weight = providerWeight(ev);
        if (safeSite) weight = Math.min(weight, 30);
        if (!weight) return;
        const id = `provider-${ev.kind}${ev.detail && ["eoa-spender", "poisoning", "delegation"].includes(ev.detail) ? "-" + ev.detail : ""}`;
        if (prev.signals.some((s) => s.id === id)) return;
        const signals = [...prev.signals, { id, weight, ...providerKey(ev) }];
        try {
          const k = `pev:${tabId}`;
          const list = ((await chrome.storage.session.get(k))[k] as string[] | undefined) ?? [];
          list.push(`${ev.method}${ev.param ? " " + ev.param : ""} ${ev.hadGesture ? "(after click)" : "(no click)"} +${ev.msSinceLoad}ms`);
          await chrome.storage.session.set({ [k]: list.slice(-20) });
        } catch { /* ignore */ }
        const total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        const v: Verdict = { ...prev, signals, score: total, band: bandOf(total), at: Date.now() };
        await applyVerdict(tabId, v);
        sendResponse(v);
        return;
      }
      case "w3pg:socials": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || sender.frameId !== 0 || !sender.url) return;
        const socials = msg.socials as PageSocials;
        const prev = await getTabVerdict(tabId);
        if (prev?.signals.some((s) => s.id === "user-allow" || s.id === "brand-official" || s.id === "trusted")) return;
        if (socials.xHandles.length && prev && prev.score >= 10) {
          const acc = await resolvePoster(socials.xHandles[0]);
          if (acc && acc.followers >= 5000) socials.verified = { handle: acc.handle, name: acc.name, followers: acc.followers, domains: acc.domains };
        }
        await chrome.storage.session.set({ [`soc:${tabId}`]: socials });
        let host = "";
        try { host = new URL(sender.url).hostname; } catch { return; }
        if (!(await stillOn(tabId, host))) return;
        const origin = await getTabOrigin(tabId);
        const v = await evaluate(sender.url, { ageDays: prev?.ageDays, origin, socials });
        if (v && (!prev || v.score !== prev.score)) {
          const extra = (prev?.signals ?? []).filter((s) => s.id.startsWith("provider-"));
          const merged = extra.length ? { ...v, signals: [...v.signals, ...extra] } : v;
          const total = Math.max(0, Math.min(100, merged.signals.reduce((s, x) => s + x.weight, 0)));
          await applyVerdict(tabId, { ...merged, score: total, band: bandOf(total) });
        }
        return;
      }
      case "w3pg:gate": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url) { sendResponse({ ask: false }); return; }
        const v = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        sendResponse(gateDecision(v, (msg.details ?? {}) as Record<string, unknown>));
        return;
      }
      case "w3pg:gateRejected": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url) return;
        const prev = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        if (!prev || prev.signals.some((s) => s.id === "provider-gate-rejected")) return;
        const signals = [...prev.signals, { id: "provider-gate-rejected", weight: 40, key: "sig_gate_rejected" }];
        const total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        await applyVerdict(tabId, { ...prev, signals, score: total, band: bandOf(total), at: Date.now() });
        return;
      }
      case "w3pg:leaveTab": {
        const tabId = sender.tab?.id;
        if (tabId === undefined) return;
        await chrome.tabs.update(tabId, { url: "about:blank" }).catch(() => undefined);
        return;
      }
      case "w3pg:referrer": {
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
        if (!fromExtension(sender)) return;
        sendResponse({ warnDisplay: await warnDisplay() });
        return;
      }
      case "w3pg:setSettings": {
        if (!fromExtension(sender)) return;
        if (msg.warnDisplay === "page" || msg.warnDisplay === "popup") await chrome.storage.local.set({ warnDisplay: msg.warnDisplay });
        sendResponse(true);
        return;
      }
      case "w3pg:deepScan": {
        if (!fromExtension(sender)) return;
        sendResponse(await deepScan(Number(msg.tabId), String(msg.language || "en")));
        return;
      }
      case "w3pg:getDeepReport": {
        if (!fromExtension(sender)) return;
        const tabId = Number(msg.tabId);
        sendResponse((await chrome.storage.session.get(`deep:${tabId}`))[`deep:${tabId}`] ?? null);
        return;
      }
      case "w3pg:report": {
        if (!fromExtension(sender)) return;
        const tabId = Number(msg.tabId);
        let v = await getTabVerdict(tabId);
        if (!v) {
          const tab = await chrome.tabs.get(tabId).catch(() => null);
          if (tab?.url) v = (await evaluate(tab.url)) ?? undefined;
        }
        if (!v) { sendResponse({ ok: false, error: "no_verdict" }); return; }
        sendResponse(await sendReport(v, String(msg.note ?? "").slice(0, 1000)));
        return;
      }
      case "w3pg:refreshNow": {
        if (!fromExtension(sender)) return;
        try { await refreshRemoteData(true); } catch (e) { console.warn(e); }
        for (const s of SOURCES) {
          try { await refreshSource(s); } catch (e) { console.warn(e); }
        }
        await syncDnr();
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
      if (ev.detail === "eoa-spender") return 40;
      return ev.hadGesture ? 20 : 35;
    case "risky-tx":
      if (ev.detail === "eoa-spender" || ev.detail === "poisoning" || ev.detail === "delegation") return 40;
      if (ev.detail === "solana") return ev.hadGesture ? 5 : 15;
      if (ev.detail === "solana_batch") return 25;
      if (ev.detail === "eth_send") return ev.hadGesture ? 5 : 20;
      return ev.hadGesture ? 20 : 35;
    case "chain-switch":
      return ev.hadGesture ? 0 : 5;
    case "fake-wallet":
      return 40;
    case "clickfix":
    case "clipboard-swap":
    case "seed-input":
      return 60;
    case "wc-modal":
      return 15;
    case "gate-rejected":
      return 40;
  }
}

/** Should a held wallet request be shown to the user before it reaches the wallet? */
function gateDecision(v: Verdict | null, g: Record<string, unknown>): { ask: boolean; score?: number } {
  const kind = String(g.kind ?? "");
  const eoa = g.counterpartyEoa === true;
  const poisoned = !!g.poisonedTwin;
  const band = v?.band ?? "none";
  const safeSite = !!v && v.signals.some((s) => s.id === "user-allow" || s.id === "brand-official" || s.id === "trusted");
  // always: things no legitimate flow asks for from a page
  if (eoa || poisoned || kind === "delegation-7702" || kind === "eth_sign") return { ask: true, score: v?.score };
  if (safeSite) return { ask: false };
  // unknown or suspicious sites: hold anything that can move assets later without another click
  const alwaysHold = new Set(["setApprovalForAll", "approve-unlimited", "permit2", "permit", "permit-batch", "permit-for-all", "delegation"]);
  if (alwaysHold.has(kind)) return { ask: true, score: v?.score };
  if (band !== "none") return { ask: true, score: v?.score };
  return { ask: false };
}

const DETAIL_KEYS: Record<string, string> = {
  "eoa-spender": "sig_tx_eoa_spender",
  poisoning: "sig_tx_poisoning",
  delegation: "sig_tx_delegation",
  eth_send: "sig_tx_eth_send",
  solana_batch: "sig_sol_batch",
  fake_wallet: "sig_fake_wallet",
  clickfix: "sig_clickfix",
  clipboard_swap: "sig_clipboard_swap",
  seed_phrase: "sig_seed_phrase",
  private_key: "sig_private_key",
  wc_modal: "sig_wc_modal",
  rejected: "sig_gate_rejected",
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
