import { parseHost } from "./lib/hostname";
import { score, bandOf, BLOCK_THRESHOLD, WARN_THRESHOLD } from "./lib/scoring";
import { loadStaticData } from "./lib/lists";
import { SOURCES, refreshSource, refreshMetaMaskDiffs, warmLists, isWarm, blocklistHit, allowlistHit, listStatus } from "./lib/blocklist";
import { domainAgeDays } from "./lib/rdap";
import { setTabVerdict, getTabVerdict, clearTab, addBypass, isBypassed, addUserAllow, getUserAllow, removeUserAllow } from "./lib/state";
import type { ProviderEvent, Verdict } from "./lib/types";

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
  if (!isWarm()) await warmLists();
  return loadStaticData();
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------
async function evaluate(url: string, extra: { ageDays?: number } = {}): Promise<Verdict | null> {
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
    allowlistHit: allowlistHit(p.host),
    userAllowed: userAllow.some((d) => p.host === d || p.host.endsWith("." + d)),
    ageDays: extra.ageDays,
  });
}

async function applyVerdict(tabId: number, v: Verdict) {
  await setTabVerdict(tabId, v);
  const color = v.band === "block" ? "#e5484d" : v.band === "warn" ? "#f5a524" : "#2e7d32";
  await chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => undefined);
  await chrome.action.setBadgeText({ tabId, text: v.band === "none" ? "" : String(v.score) }).catch(() => undefined);

  if (v.band === "block" && !(await isBypassed(v.host))) {
    const target = `${WARNING_PAGE}#${encodeURIComponent(JSON.stringify({ url: v.url, host: v.host, score: v.score, signals: v.signals.map((s) => s.label) }))}`;
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
    const v = await evaluate(d.url);
    if (!v) {
      await clearTab(d.tabId);
      await chrome.action.setBadgeText({ tabId: d.tabId, text: "" }).catch(() => undefined);
      return;
    }
    await applyVerdict(d.tabId, v);

    // Second pass: only for suspicious-but-undecided hosts, fetch domain age (registrable domain only).
    if (v.needsAgeCheck) {
      const ageDays = await domainAgeDays(v.registrable);
      if (ageDays !== undefined) {
        const v2 = await evaluate(d.url, { ageDays });
        if (v2 && v2.band !== v.band) await applyVerdict(d.tabId, v2);
        else if (v2) await setTabVerdict(d.tabId, v2);
      }
    }
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
        const signals = [...prev.signals, { id, weight, label: providerLabel(ev) }];
        const total = Math.max(0, Math.min(100, signals.reduce((s, x) => s + x.weight, 0)));
        const v: Verdict = { ...prev, signals, score: total, band: bandOf(total), at: Date.now() };
        await applyVerdict(tabId, v);
        sendResponse(v);
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

function providerLabel(ev: ProviderEvent): string {
  switch (ev.kind) {
    case "auto-connect":
      return "Sayfa açılır açılmaz, tıklama olmadan cüzdan bağlantısı istedi";
    case "risky-sign":
      return `Tehlikeli imza isteği: ${ev.detail}`;
    case "risky-tx":
      return `Tehlikeli işlem isteği: ${ev.detail}`;
    case "chain-switch":
      return "Tıklama olmadan ağ değiştirme isteği";
  }
}

export { BLOCK_THRESHOLD, WARN_THRESHOLD };
