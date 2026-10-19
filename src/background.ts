import { parseHost, isUnderDomain } from "./lib/hostname";
import { score, bandOf, BLOCK_THRESHOLD, WARN_THRESHOLD } from "./lib/scoring";
import { loadStaticData, refreshRemoteData, remoteDataStatus, brandByHandle, brandByToken } from "./lib/lists";
import { SOURCES, refreshSource, refreshMetaMaskDiffs, warmLists, isWarm, blocklistHit, blocklistPathHit, allowlistHit, siblingHit, attackedBrandHit, listStatus, newestDomains, newestPaths } from "./lib/blocklist";
import { domainAgeDays } from "./lib/rdap";
import { simulateEnabled, setTabVerdict, getTabVerdict, clearTab, addBypass, isBypassed, addUserAllow, getUserAllow, removeUserAllow, putWarning, getWarning, consumeWarning } from "./lib/state";
import { sourceFromHost, setTabOrigin, getTabOrigin, setPendingClick, takePendingClick, peekPendingClick, isShortener, isAdHop } from "./lib/origin";
import { resolveBrand, resolvePoster } from "./lib/xquik";
import { scanExternalScripts, askApi, askSandbox, sendReport, API_BASE } from "./lib/deepscan";
import { buildRules, applyRules, addBypassRule } from "./lib/dnr";
import { SOL_ENDPOINTS, parseMessageAccounts, diffSolana, mergeDiffs, summarizeSolana, type SolAccount } from "./lib/solana";
import { RPC_ENDPOINTS, buildSimulateRequest, parseSimulation, summarizeChanges } from "./lib/simulate";
import { decodeString, decodeUint, SEL } from "./lib/impact";
import { t } from "./lib/i18n";
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
/** Alarms are not guaranteed to survive a browser restart (Firefox drops them); (re)create any that are missing. */
async function ensureAlarms(): Promise<void> {
  const wanted: Array<[string, chrome.alarms.AlarmCreateInfo]> = [
    ...SOURCES.map((s): [string, chrome.alarms.AlarmCreateInfo] => [`refresh:${s.id}`, { periodInMinutes: s.every, delayInMinutes: 0.1 }]),
    ["refresh:metamask-diffs", { periodInMinutes: 5, delayInMinutes: 2 }],
    ["refresh:data", { periodInMinutes: 60 * 12, delayInMinutes: 1 }],
    ["prune", { periodInMinutes: 60 * 24, delayInMinutes: 30 }],
  ];
  const have = new Set((await chrome.alarms.getAll().catch(() => [])).map((a) => a.name));
  for (const [name, info] of wanted) if (!have.has(name)) chrome.alarms.create(name, info);
}
chrome.runtime.onInstalled.addListener(() => void ensureAlarms());
chrome.runtime.onStartup.addListener(() => void ensureAlarms());

chrome.alarms.onAlarm.addListener(async (alarm) => {
  const id = alarm.name.replace("refresh:", "");
  try {
    // an alarm usually wakes a cold worker: load the salt, the shared hosts and the indexes before touching any list
    await ensureReady();
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
let popularSet = new Set<string>();
/** Popular means the site itself (apex or www.), never a user page on a Tranco-listed hosting platform (x.wordpress.com, y.run.app). */
const isPopular = (p: { host: string; registrable: string; freeHost?: string }) => !p.freeHost && (p.host === p.registrable || p.host === "www." + p.registrable) && popularSet.has(p.registrable);
async function ensureReady() {
  if (!readyPromise) {
    readyPromise = (async () => {
      const data = await loadStaticData();
      popularSet = new Set(data.lists.popular ?? []);
      if (!isWarm()) {
        const w = await warmLists([...data.lists.freeHostsStrong, ...data.lists.freeHostsWeak], data.lists.shared ?? []);
        await syncDnr();
        void ensureAlarms();
        if (w.needsRefresh) void refreshAllSources();
      }
      return data;
    })().catch((e) => { readyPromise = null; throw e; });
  }
  return readyPromise;
}

let refreshing: Promise<void> | null = null;
/** Fetch every feed now (first run, salt rotation, or the user's "refresh" button); concurrent calls share one run. */
function refreshAllSources(): Promise<void> {
  if (!refreshing) {
    refreshing = (async () => {
      for (const s of SOURCES) {
        try { await refreshSource(s); } catch (e) { console.warn(`[w3pg] ${s.id} refresh failed`, e); }
      }
      await syncDnr();
    })().finally(() => { refreshing = null; });
  }
  return refreshing;
}

/** Push the freshest known-phishing hosts into declarativeNetRequest so they are cancelled before any request. */
const bypassedHosts: string[] = [];
async function syncDnr(): Promise<void> {
  try {
    const { lists } = await loadStaticData();
    // network-level blocks come from the reviewed lists only (MetaMask, our moderators); ScamSniffer and
    // PhishDestroy warn post-commit. A top-50k site is never cancelled at the network level.
    const block = [
      ...newestDomains("metamask", 40_000),
      ...newestDomains("community", 10_000),
    ].filter((d) => !popularSet.has(d) && !popularSet.has(d.replace(/^www\./, "")));
    const allow = [...(await getUserAllow()), ...lists.trusted, ...bypassedHosts];
    await applyRules(buildRules(block, allow, newestPaths(2000)));
  } catch (e) {
    console.warn("[w3pg] DNR sync failed", e);
  }
}

/** rdap:* / x:* cache entries have TTLs but were never deleted; sweep them daily. Session entries of closed tabs go too. */
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
  await pruneSession();
}

/** storage.session has a 10 MB quota; per-tab entries (verdict, deep report, origin, socials, provider log) must not outlive their tab. */
async function pruneSession(): Promise<void> {
  try {
    const all = await chrome.storage.session.get(null);
    const open = new Set((await chrome.tabs.query({})).map((t) => t.id));
    const drop: string[] = [];
    for (const k of Object.keys(all)) {
      const m = /^(verdict|deep|origin|soc|pev|click|xclick):(\d+)$/.exec(k);
      if (m && !open.has(Number(m[2]))) drop.push(k);
      else if (k.startsWith("warn:")) { const w = all[k] as { at?: number } | null; if (typeof w?.at === "number" && Date.now() - w.at > 60 * 60_000) drop.push(k); }
    }
    if (drop.length) await chrome.storage.session.remove(drop);
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------
function safePath(url: string): string {
  try { return new URL(url).pathname; } catch { return "/"; }
}
/** host + the first two path segments: the granularity MetaMask's blocklistPaths use */
function pathEntryFor(host: string, pathname: string): string {
  return host + "/" + pathname.split("/").filter(Boolean).slice(0, 2).join("/");
}

async function evaluate(url: string, extra: { ageDays?: number; origin?: OriginContext; x?: XIntel; socials?: PageSocials } = {}): Promise<Verdict | null> {
  if (!/^https?:/.test(url)) return null;
  const { brands, lists } = await ensureReady();
  const p = parseHost(url, [...lists.freeHostsStrong, ...lists.freeHostsWeak]);
  if (!p) return null;
  if (p.host === "localhost" || p.host.endsWith(".localhost") || p.host === "127.0.0.1") {
    // Drill mode, local pages only: "#w3pg-drill=45" makes the page score 45 so the score-dependent gate can be
    // exercised against a real wallet without a real phishing site (see test-dapp/).
    const m = /#w3pg-drill=(\d{1,3})/.exec(url);
    if (!m) return null;
    const score = Math.max(0, Math.min(100, Number(m[1])));
    return { url, host: p.host, registrable: p.registrable, score, band: bandOf(score), signals: [{ id: "drill", weight: score, key: "sig_drill" }], needsAgeCheck: false, at: Date.now() };
  }

  const userAllow = await getUserAllow();
  return score(url, p, {
    brands,
    lists,
    blocklistHit: blocklistHit(p.host) ?? blocklistPathHit(p.host, safePath(url)),
    popular: isPopular(p),
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

// ---------------------------------------------------------------------------
// transaction simulation (held transactions only): eth_simulateV1 on a public RPC, see PRIVACY.md
// ---------------------------------------------------------------------------
const simStamps = new Map<number, number[]>();
/** at most one simulation per 2 s and 20 per minute per tab */
function simAllowed(tabId: number): boolean {
  const now = Date.now();
  const list = (simStamps.get(tabId) ?? []).filter((x) => now - x < 60_000);
  if (list.length >= 20 || (list.length && now - list[list.length - 1] < 2000)) { simStamps.set(tabId, list); return false; }
  list.push(now);
  simStamps.set(tabId, list);
  return true;
}

async function jsonRpc(url: string, body: unknown, ms: number): Promise<unknown> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: ctl.signal, credentials: "omit" });
    return r.ok ? await r.json() : null;
  } catch { return null; } finally { clearTimeout(timer); }
}

type SimMeta = { symbol?: string; decimals?: number };
/** symbol / decimals per chain+token, kept for the worker's lifetime (insertion-ordered, oldest dropped past 500) */
const simLabels = new Map<string, SimMeta>();
async function simTokenLabels(chainId: number, endpoint: string, tokens: string[]): Promise<Map<string, SimMeta>> {
  const labels = new Map<string, SimMeta>();
  const missing: string[] = [];
  for (const tk of tokens) {
    const hit = simLabels.get(`${chainId}:${tk}`);
    if (hit) labels.set(tk, hit); else missing.push(tk);
  }
  if (!missing.length) return labels;
  // one batched request to the endpoint that just answered the simulation
  const batch = missing.flatMap((tk, i) => [
    { jsonrpc: "2.0", id: i * 2, method: "eth_call", params: [{ to: tk, data: SEL.symbol }, "latest"] },
    { jsonrpc: "2.0", id: i * 2 + 1, method: "eth_call", params: [{ to: tk, data: SEL.decimals }, "latest"] },
  ]);
  const res = await jsonRpc(endpoint, batch, 3000);
  if (!Array.isArray(res)) return labels;
  const byId = new Map<number, string>();
  for (const r of res as Array<{ id?: number; result?: unknown }>) if (typeof r?.id === "number" && typeof r.result === "string") byId.set(r.id, r.result);
  missing.forEach((tk, i) => {
    const d = decodeUint(byId.get(i * 2 + 1));
    const meta: SimMeta = { symbol: decodeString(byId.get(i * 2)), decimals: d !== undefined && d <= 77n ? Number(d) : undefined };
    if (meta.symbol === undefined && meta.decimals === undefined) return;
    simLabels.set(`${chainId}:${tk}`, meta);
    if (simLabels.size > 500) simLabels.delete(simLabels.keys().next().value as string);
    labels.set(tk, meta);
  });
  return labels;
}

type SimReply = { ok: true; reverted: boolean; error?: string; out: string[]; in: string[]; approvals: string[] } | { ok: false; reason: string };
async function simulateTx(tabId: number | undefined, msg: { chainId?: unknown; tx?: Record<string, unknown>; calls?: unknown }): Promise<SimReply> {
  if (!(await simulateEnabled())) return { ok: false, reason: "disabled" };
  if (tabId === undefined) return { ok: false, reason: "no-tab" };
  const chain = typeof msg.chainId === "string" && /^0x[0-9a-f]{1,8}$/i.test(msg.chainId) ? parseInt(msg.chainId, 16) : 0;
  const endpoints = RPC_ENDPOINTS[chain];
  if (!endpoints) return { ok: false, reason: "chain" };
  // one transaction (`tx`) or a wallet_sendCalls batch (`calls`, at most 16, simulated in order)
  const rawList = Array.isArray(msg.calls) ? (msg.calls as Array<Record<string, unknown>>) : [msg.tx ?? {}];
  if (!rawList.length || rawList.length > 16) return { ok: false, reason: "tx" };
  const addr = /^0x[0-9a-fA-F]{40}$/;
  const list: Array<{ from: string; to: string; data: string; value: string }> = [];
  for (const raw of rawList) {
    const tx = raw && typeof raw === "object" ? raw : {};
    const from = String(tx.from ?? ""), to = String(tx.to ?? "");
    const data = tx.data === undefined || tx.data === "" ? "0x" : String(tx.data);
    const value = tx.value === undefined || tx.value === "" ? "0x0" : String(tx.value);
    if (!addr.test(from) || !addr.test(to) || !/^0x([0-9a-fA-F]{2}){0,100000}$/.test(data) || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) return { ok: false, reason: "tx" };
    list.push({ from, to, data, value });
  }
  const from = list[0].from;
  if (!simAllowed(tabId)) return { ok: false, reason: "rate" };
  const req = buildSimulateRequest(Array.isArray(msg.calls) ? list : list[0]);
  for (const url of endpoints) {
    const res = (await jsonRpc(url, req, 5000)) as { result?: unknown; error?: { code?: number; message?: string } } | null;
    if (!res) continue; // timeout, network error or HTTP failure: next operator
    if (res.error) {
      if (res.error.code === -32601 || /not (found|supported|available)|unsupported|unknown method|does not exist/i.test(String(res.error.message ?? ""))) continue;
      return { ok: false, reason: "rpc-error" };
    }
    const parsed = parseSimulation(res.result, from);
    if (!parsed) return { ok: false, reason: "bad-response" };
    const tokens = [...new Set([...parsed.out, ...parsed.in].filter((c) => c.kind !== "native").map((c) => c.token).concat(parsed.approvals.map((a) => a.token)))].slice(0, 20);
    const labels = tokens.length ? await simTokenLabels(chain, url, tokens) : new Map<string, SimMeta>();
    const s = summarizeChanges(parsed, labels, msg.chainId as string, { unlimited: t("gate_sim_unlimited"), all: t("gate_sim_all_nfts") });
    return { ok: true, reverted: parsed.reverted, error: parsed.error, ...s };
  }
  return { ok: false, reason: "unavailable" };
}

type SolSimReply = { ok: true; failed: boolean; out: string[]; in: string[]; warnings: string[] } | { ok: false; reason: string };
/** Solana: simulateTransaction on a public RPC (jsonParsed accounts before / after), diffed for the signer */
async function simulateSol(tabId: number | undefined, msg: { txs?: unknown }): Promise<SolSimReply> {
  if (!(await simulateEnabled())) return { ok: false, reason: "disabled" };
  if (tabId === undefined) return { ok: false, reason: "no-tab" };
  const txs = Array.isArray(msg.txs) ? (msg.txs as unknown[]).filter((x): x is string => typeof x === "string" && x.length > 0 && x.length <= 2400 && /^[A-Za-z0-9+/]+={0,2}$/.test(x)).slice(0, 4) : [];
  if (!txs.length) return { ok: false, reason: "tx" };
  const parsed = txs.map((x) => ({ tx: x, msg: parseMessageAccounts(x) }));
  if (parsed.some((p) => !p.msg)) return { ok: false, reason: "tx" };
  if (!simAllowed(tabId)) return { ok: false, reason: "rate" };
  const rpc = async (url: string, method: string, params: unknown[]) =>
    (await jsonRpc(url, { jsonrpc: "2.0", id: 1, method, params }, 5000)) as { result?: unknown; error?: unknown } | null;
  for (const url of SOL_ENDPOINTS) {
    const diffs = [];
    let failed = false, user = "";
    let usable = true;
    for (const p of parsed) {
      const { keys, signer } = p.msg!;
      user = user || signer;
      const addresses = keys.slice(0, 64);
      const [preRes, postRes] = await Promise.all([
        rpc(url, "getMultipleAccounts", [addresses, { encoding: "jsonParsed", commitment: "processed" }]),
        rpc(url, "simulateTransaction", [p.tx, { encoding: "base64", replaceRecentBlockhash: true, sigVerify: false, commitment: "processed", accounts: { encoding: "jsonParsed", addresses } }]),
      ]);
      if (!preRes || !postRes) { usable = false; break; } // timeout, network or HTTP failure: next operator
      if (preRes.error || postRes.error) return { ok: false, reason: "rpc-error" };
      const pre = (preRes.result as { value?: SolAccount[] } | undefined)?.value;
      const sim = (postRes.result as { value?: { err?: unknown; accounts?: SolAccount[] } } | undefined)?.value;
      if (!Array.isArray(pre) || !sim || typeof sim !== "object") return { ok: false, reason: "bad-response" };
      if (sim.err) { failed = true; continue; }
      if (!Array.isArray(sim.accounts)) return { ok: false, reason: "bad-response" };
      diffs.push(diffSolana(pre, sim.accounts, signer, addresses));
    }
    if (!usable) continue;
    if (failed) return { ok: true, failed: true, out: [], in: [], warnings: [] };
    const s = summarizeSolana(mergeDiffs(diffs), new Map(), { delegate: (l) => t("gate_sim_sol_delegate", [l]), owner: t("gate_sim_sol_owner") });
    return { ok: true, failed: false, ...s };
  }
  return { ok: false, reason: "unavailable" };
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
  if (!(await stillOn(tabId, v.host))) return; // the tab moved on while the lists were warming
  // a block that rests on the card's displayed address alone waits for the redirect chain (the chain may show the
  // address was honest); everything else is applied at once
  const chainPending = !!(origin?.display && origin.href && !origin.hops);
  if (chainPending && v.band === "block") {
    const withoutDisplay = v.signals.filter((s) => !s.id.startsWith("display-")).reduce((s, x) => s + x.weight, 0);
    if (withoutDisplay < BLOCK_THRESHOLD) { const capped = BLOCK_THRESHOLD - 1; v = { ...v, score: capped, band: bandOf(capped) }; }
  }
  await applyVerdict(tabId, v);
  if (v.band === "block") return;
  // a click from X that showed one domain and landed on another: learn the redirect chain and re-judge (the first
  // verdict is already on screen; this only ever adds or removes the deception signals)
  if (origin?.display && origin.href && !origin.hops) {
    const disp = origin.display.toLowerCase();
    if (v.host !== disp && !isUnderDomain(v.host, disp) && !isUnderDomain(disp, v.registrable)) {
      const res = await resolveRedirect(origin.href);
      if (res && (await stillOn(tabId, v.host))) {
        origin = { ...origin, hops: res.hops, shortener: origin.shortener ?? res.hops.find((h) => h !== "t.co" && isShortener(h)) };
        const v2 = await evaluate(url, { origin });
        if (v2) { await applyVerdict(tabId, v2); v = v2; if (v.band === "block") return; }
      }
    }
  }
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
interface Resolved { url: string; hops: string[] }
const redirectCache = new Map<string, Resolved | null>();
async function resolveRedirect(url: string): Promise<Resolved | null> {
  if (redirectCache.has(url)) return redirectCache.get(url) ?? null;
  if (redirectCache.size > 500) redirectCache.delete(redirectCache.keys().next().value as string);
  const hostOf = (u: string) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
  try {
    const r = await fetch(`${API_BASE}/v1/resolve?url=${encodeURIComponent(url)}`, { signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const j = (await r.json()) as { url?: string | null; hops?: string[] };
      const out = j.url ? { url: j.url, hops: Array.isArray(j.hops) && j.hops.length ? j.hops : [hostOf(url)] } : null;
      redirectCache.set(url, out);
      return out;
    }
    if (r.status === 400 || r.status === 429) { redirectCache.set(url, null); return null; }
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
    const out = finalUrl ? { url: finalUrl, hops: [hostOf(url), hostOf(res.url)].filter(Boolean) } : null;
    redirectCache.set(url, out);
    return out;
  } catch {
    redirectCache.set(url, null);
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
      const wanted = { data_collection: ["websiteContent"] };
      // the popup asks for it inside its click handler (Firefox requires a user-input handler); here we only verify
      const has = perms.contains ? await perms.contains(wanted).catch(() => false) : false;
      if (!has) return { error: "permission_denied" };
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
  // the AI verdict and the headless-browser sandbox run in parallel; the sandbox is best-effort and may be absent
  const [ai, sandbox] = await Promise.all([
    askApi(snapshot, { verdict: v, origin, x, providerEvents: pev, language }, { markers }),
    askSandbox(v.url),
  ]);
  const report: DeepReport = { host: v.host, at: Date.now(), local: { score: v.score, band: v.band, signals: v.signals }, page: snapshot, markers, goplus: ai.goplus, ai, sandbox };
  await chrome.storage.session.set({ [cacheKey]: report });
  return report;
}

/** Hostname scoring for the X timeline badges: no tab state; a registry age lookup (cached) only for undecided hosts. */
async function scoreHostOnly(host: string, ctx: Partial<OriginContext>): Promise<{ band: string; score: number; signals: Signal[] } | null> {
  const origin = { source: "x" as const, at: Date.now(), ...ctx };
  let v = await evaluate(`https://${host}/`, { origin });
  if (!v) return null;
  if (v.needsAgeCheck || v.band === "warn") {
    const ageDays = await domainAgeDays(v.registrable, { priority: false }).catch(() => undefined); // timeline badge: behind the current page
    if (ageDays !== undefined) v = (await evaluate(`https://${host}/`, { origin, ageDays })) ?? v;
  }
  return { band: v.band, score: v.score, signals: v.signals.filter((s) => s.weight > 0) };
}

async function applyVerdict(tabId: number, v: Verdict) {
  await setTabVerdict(tabId, v);
  const color = v.band === "block" ? "#e5484d" : v.band === "warn" ? "#f5a524" : "#2e7d32";
  await chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => undefined);
  await chrome.action.setBadgeText({ tabId, text: v.band === "none" ? "" : String(v.score) }).catch(() => undefined);

  if (v.band === "block" && !(await isBypassed(v.host, safePath(v.url)))) {
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
  const pathEntry = !blocklistHit(v.host) && blocklistPathHit(v.host, safePath(v.url)) ? pathEntryFor(v.host, safePath(v.url)) : undefined;
  const nonce = await putWarning({ url: v.url, host: v.host, score: v.score, signals: v.signals, brandDomain: brand?.domains[0], reviewed, tabId, pathEntry });
  await chrome.tabs.update(tabId, { url: `${WARNING_PAGE}?n=${nonce}` }).catch(() => undefined);
}

/** Official extension ids of major wallets on the Chrome Web Store; a listing named like a wallet with another id is a counterfeit. */
const WALLET_STORE_IDS: Array<[RegExp, string[]]> = [
  // the listing title must *be* the wallet (optionally followed by "wallet"), not merely mention it:
  // "MetaMask Flask" is MetaMask's own, "Rainbow Tables" is not a wallet at all
  [/^metamask(\s+(wallet|flask|institutional))?$/i, ["nkbihfbeogaeaoehlefnkodbefgpgknn", "ljfoeinjpaedjfecbmggjgebmfmaigon", "nmpcffchpjmjafidpilhicebcckopnfp"]],
  [/^phantom(\s+wallet)?$/i, ["bfnaelmomeimhlpmgjnjophhpkkoljpa"]],
  [/^coinbase\s+wallet(\s+extension)?$/i, ["hnfanknocfeofbddgcijnmhnfnkdnaad"]],
  [/^rabby(\s+wallet)?$/i, ["acmacodkjbdgmoleebolmdjonilkdbch"]],
  [/^okx\s+wallet$/i, ["mcohilncbfahbmgdjkbpemcciiolgcge"]],
  [/^trust\s*wallet$/i, ["egjidjbpglichdcondbcbdnbeeppgdph"]],
  [/^keplr(\s+wallet)?$/i, ["dmkamcknogkgcdfhhbddcghachkejeap"]],
  [/^backpack(\s+wallet)?$/i, ["aflkmfhebedbjioipglgcbcmnbpgliof"]],
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

// the Chrome Web Store is a single-page app: a search result opens a listing via pushState, not a navigation
chrome.webNavigation.onHistoryStateUpdated.addListener(async (d) => {
  if (d.frameId !== 0 || !d.url.startsWith("https://chromewebstore.google.com/")) return;
  try { await checkStoreListing(d.tabId, d.url); } catch { /* ignore */ }
});

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

chrome.tabs.onRemoved.addListener((tabId) => {
  simStamps.delete(tabId);
  void clearTab(tabId);
  void chrome.storage.session.remove([`deep:${tabId}`, `origin:${tabId}`, `soc:${tabId}`, `pev:${tabId}`]).catch(() => undefined);
});

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
        // a path-level hit (one Google Sites page) is bypassed for that page only, never for the whole platform
        const entry = p.pathEntry ?? p.host;
        await addBypass(entry);
        await consumeWarning(String(msg.nonce)); // a bypass is a one-shot use of the nonce
        if (!p.pathEntry) bypassedHosts.push(p.host);
        await addBypassRule(entry);
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
        // a cross-origin iframe is judged by its own host (an embedded drainer is not cleared by a trusted top page);
        // its events still surface on the tab the user is looking at
        const foreign = sender.frameId !== 0 && frameHost !== prev.host;
        const frameV = foreign ? await evaluate(sender.url) : null;
        const judge = frameV ?? prev;
        // A third-party frame (an ad, an embed) can post whatever it likes through its own guard. Its events are only
        // worth a bounded warning on the tab, never a block, and only when the frame's own host already looks risky.
        if (foreign && (!frameV || frameV.band === "none")) return;
        const safeSite = judge.signals.some((s) => s.id === "user-allow" || s.id === "brand-official" || s.id === "trusted");
        const alwaysCounts = ev.kind === "seed-input" || ev.kind === "clickfix" || ev.kind === "clipboard-swap" || ev.kind === "fake-wallet" || ev.detail === "eoa-spender" || ev.detail === "poisoning" || ev.detail === "delegation";
        if (safeSite && !alwaysCounts) return;
        let weight = providerWeight(ev);
        if (safeSite) weight = Math.min(weight, 30);
        if (foreign) weight = Math.min(weight, 30);
        if (!weight) return;
        const id = `${foreign ? "frame-" : ""}provider-${ev.kind}${ev.detail && ["eoa-spender", "poisoning", "delegation"].includes(ev.detail) ? "-" + ev.detail : ""}`;
        if (prev.signals.some((s) => s.id === id)) return;
        const signals = [...prev.signals, { id, weight, ...providerKey(ev) }];
        try {
          const k = `pev:${tabId}`;
          const list = ((await chrome.storage.session.get(k))[k] as string[] | undefined) ?? [];
          list.push(`${ev.method}${ev.param ? " " + ev.param : ""} ${ev.hadGesture ? "(after click)" : "(no click)"} +${ev.msSinceLoad}ms`);
          await chrome.storage.session.set({ [k]: list.slice(-20) });
        } catch { /* ignore */ }
        let total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        // evidence from third-party frames may raise a warning but never tips the top page into a block
        const ownTotal = Math.max(0, Math.min(100, signals.filter((s) => !s.id.startsWith("frame-")).reduce((s, x) => s + x.weight, 0)));
        if (total >= BLOCK_THRESHOLD && ownTotal < BLOCK_THRESHOLD) total = BLOCK_THRESHOLD - 1;
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
          const extra = (prev?.signals ?? []).filter((s) => s.id.startsWith("provider-") || s.id.startsWith("frame-provider-"));
          const merged = extra.length ? { ...v, signals: [...v.signals, ...extra] } : v;
          const total = Math.max(0, Math.min(100, merged.signals.reduce((s, x) => s + x.weight, 0)));
          await applyVerdict(tabId, { ...merged, score: total, band: bandOf(total) });
        }
        return;
      }
      case "w3pg:gate": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url) { sendResponse({ ask: false }); return; }
        let v = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        if (sender.frameId !== 0) {
          let frameHost = "";
          try { frameHost = new URL(sender.url).hostname; } catch { /* ignore */ }
          if (v && frameHost && frameHost !== v.host) {
            const own = await evaluate(sender.url);
            // the frame's own verdict decides; a "safe" top page never relaxes the gate for a foreign frame
            if (own) v = own.score >= v.score || own.signals.some((s) => s.id === "trusted" || s.id === "brand-official") ? own : { ...v, signals: v.signals.filter((s) => !["user-allow", "brand-official", "trusted"].includes(s.id)) };
          }
        }
        sendResponse(gateDecision(v, (msg.details ?? {}) as Record<string, unknown>));
        return;
      }
      case "w3pg:gateTop": {
        // an iframe asks the top frame to render its modal
        const tabId = sender.tab?.id;
        if (tabId === undefined) { sendResponse({}); return; }
        try {
          const r = await chrome.tabs.sendMessage(tabId, { type: "w3pg:showGate", details: msg.details, decision: msg.decision, frameHost: msg.frameHost }, { frameId: 0 });
          sendResponse(r ?? {});
        } catch { sendResponse({}); }
        return;
      }
      case "w3pg:gateRejected": {
        const tabId = sender.tab?.id;
        if (tabId === undefined || !sender.url || sender.frameId !== 0) return; // a frame's rejection is the frame's business
        const prev = (await getTabVerdict(tabId)) ?? (await evaluate(sender.url));
        if (!prev || prev.signals.some((s) => s.id === "provider-gate-rejected")) return;
        const signals = [...prev.signals, { id: "provider-gate-rejected", weight: 40, key: "sig_gate_rejected" }];
        const total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        await applyVerdict(tabId, { ...prev, signals, score: total, band: bandOf(total), at: Date.now() });
        return;
      }
      case "w3pg:simulate": {
        sendResponse(await simulateTx(sender.tab?.id, msg).catch((): SimReply => ({ ok: false, reason: "error" })));
        return;
      }
      case "w3pg:simulateSol": {
        sendResponse(await simulateSol(sender.tab?.id, msg).catch((): SolSimReply => ({ ok: false, reason: "error" })));
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
        await setPendingClick({ source: "x", at: Date.now(), poster: c.poster, posterVerified: c.posterVerified, isReply: c.isReply, display: c.display, target: c.target, href: typeof msg.href === "string" ? msg.href : undefined });
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
        const ctx = { ...((msg.ctx ?? {}) as Partial<OriginContext>) };
        if (isShortener(target)) {
          const res = await resolveRedirect(href);
          if (!res) { sendResponse(null); return; }
          ctx.hops = res.hops;
          // t.co wraps every link on X; only a *second* hop through a shortener hides the destination
          ctx.shortener = res.hops.find((h) => h !== "t.co" && isShortener(h));
          try { target = new URL(res.url).hostname.toLowerCase(); } catch { sendResponse(null); return; }
        }
        const r = await scoreHostOnly(target, ctx);
        sendResponse(r ? { ...r, host: target } : null);
        return;
      }
      case "w3pg:getSettings": {
        if (!fromExtension(sender)) return;
        sendResponse({ warnDisplay: await warnDisplay(), simulate: await simulateEnabled() });
        return;
      }
      case "w3pg:setSettings": {
        if (!fromExtension(sender)) return;
        if (msg.warnDisplay === "page" || msg.warnDisplay === "popup") await chrome.storage.local.set({ warnDisplay: msg.warnDisplay });
        if (typeof msg.simulate === "boolean") await chrome.storage.local.set({ simulate: msg.simulate });
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
        await ensureReady();
        try { await refreshRemoteData(true); } catch (e) { console.warn(e); }
        await refreshAllSources();
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
    case "wallet-standard":
      return 0; // informational: a Wallet Standard wallet registered and was wrapped
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
  const alwaysHold = new Set(["setApprovalForAll", "approve-unlimited", "permit2", "permit", "permit-batch", "permit-for-all", "delegation", "seaport-order", "blur-order", "transfer-auth", "safe-delegatecall", "agent-approval", "undecodable"]);
  // Solana signing on a page the heuristics already dislike: ask; on an unknown page let the wallet's own prompt do it
  if (kind === "solana-sign") return band !== "none" ? { ask: true, score: v?.score } : { ask: false };
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
