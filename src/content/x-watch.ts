/**
 * Runs on x.com / twitter.com.
 *  1. On click of an external link inside a tweet or article, captures the context
 *     (poster handle, verified badge, reply-or-not, the domain shown as link text and the
 *     real href) and hands it to the background, which attaches it to the navigation that follows.
 *  2. Proactively scores every external link visible in the timeline / article and marks
 *     suspicious ones with a badge. Links whose visible text names one domain while the href
 *     goes somewhere else ("jup.ag/claim" -> surge.sh) are the classic deception and are
 *     flagged before the click; t.co links are resolved by the background to find the real target.
 */
import type { Signal } from "../lib/types";
import { t, signalText } from "../lib/i18n";

interface Ctx { poster?: string; posterVerified?: boolean; isReply?: boolean; display?: string; target?: string }
type HostVerdict = { host: string; band: string; score: number; signals: Signal[] };

const BADGE_ATTR = "data-w3pg";
const verdictCache = new Map<string, HostVerdict>(); // key: href|display

function hrefHost(a: HTMLAnchorElement): string | null {
  try {
    return new URL(a.href, location.href).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Profile / hashtag / status links are same-origin paths; everything else leaves X. */
function isExternalLink(a: HTMLAnchorElement): boolean {
  const h = hrefHost(a);
  return !!h && !/(^|\.)(x\.com|twitter\.com)$/.test(h);
}

/** The domain the link *shows* to the user, if its text looks like a URL. */
function textHost(a: HTMLAnchorElement): string | null {
  const text = (a.textContent || "").trim().replace(/…$/, "");
  const m = text.match(/^(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
  if (!m) return null;
  const h = m[1].toLowerCase();
  if (/(^|\.)(x\.com|twitter\.com|t\.co|pic\.twitter\.com)$/.test(h)) return null;
  return h;
}

function containerOf(el: Element): HTMLElement | null {
  return (el.closest('article[data-testid="tweet"]') ?? el.closest("article") ?? el.closest("main")) as HTMLElement | null;
}

function contextOf(article: HTMLElement | null): Ctx {
  if (!article) return {};
  const ctx: Ctx = {};
  const userName = article.querySelector('div[data-testid="User-Name"]');
  if (userName) {
    const handle = Array.from(userName.querySelectorAll("a[href^='/']"))
      .map((a) => (a as HTMLAnchorElement).getAttribute("href") || "")
      .find((h) => /^\/[A-Za-z0-9_]{1,15}$/.test(h));
    if (handle) ctx.poster = handle.slice(1);
    ctx.posterVerified = !!userName.querySelector('svg[data-testid="icon-verified"]');
  }
  const head = (article.innerText || "").slice(0, 300);
  ctx.isReply = /replying to|yanıt olarak|antwort an|en réponse à|respondiendo a/i.test(head);
  return ctx;
}

// ---- 1. click capture --------------------------------------------------------
document.addEventListener(
  "click",
  (e) => {
    const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
    if (!a || !isExternalLink(a)) return;
    const ctx = contextOf(containerOf(a));
    ctx.display = textHost(a) ?? undefined;
    ctx.target = hrefHost(a) ?? undefined;
    chrome.runtime.sendMessage({ type: "w3pg:xclick", ctx, href: a.href }).catch(() => undefined);
  },
  true,
);

// ---- 2. proactive badges -----------------------------------------------------
function badge(a: HTMLAnchorElement, v: HostVerdict) {
  if (a.hasAttribute(BADGE_ATTR)) return;
  a.setAttribute(BADGE_ATTR, v.band);
  if (v.band === "none") return;
  const s = document.createElement("span");
  s.textContent = " " + t(v.band === "block" ? "badge_block" : "badge_suspicious");
  s.title = `${t("badge_tooltip", [v.host, String(v.score)])}\n${v.signals.map(signalText).join("\n")}`;
  s.style.cssText = `display:inline-block;margin-left:4px;padding:0 6px;border-radius:999px;font:600 11px/18px system-ui,sans-serif;color:#fff;background:${v.band === "block" ? "#e5484d" : "#d08700"};vertical-align:middle;`;
  a.insertAdjacentElement("afterend", s);
}

let queue = new Set<HTMLAnchorElement>();
let timer: number | undefined;

function scan(root: ParentNode = document) {
  const anchors = root.querySelectorAll<HTMLAnchorElement>(`a[href]:not([${BADGE_ATTR}])`);
  for (const a of anchors) {
    if (isExternalLink(a) && (textHost(a) || hrefHost(a) !== "t.co")) queue.add(a);
  }
  if (queue.size && timer === undefined) timer = window.setTimeout(flush, 300);
}

async function flush() {
  timer = undefined;
  const batch = [...queue];
  queue = new Set();
  for (const a of batch) {
    if (a.hasAttribute(BADGE_ATTR)) continue;
    const display = textHost(a);
    const target = hrefHost(a);
    if (!target) continue;
    if (!display && target === "t.co") continue; // card links without a visible domain: nothing to judge yet
    const key = `${a.href}|${display ?? ""}`;
    let v = verdictCache.get(key);
    if (!v) {
      const ctx = contextOf(containerOf(a));
      ctx.display = display ?? undefined;
      let r: Omit<HostVerdict, "host"> | null = null;
      try {
        r = (await chrome.runtime.sendMessage({ type: "w3pg:scoreLink", href: a.href, ctx })) as (Omit<HostVerdict, "host"> & { host?: string }) | null;
      } catch { r = null; }
      if (!r) continue;
      v = { ...r, host: (r as { host?: string }).host ?? target };
      if (v.band !== "none") console.debug("[w3pg]", v.host, v.score, v.signals.map(signalText));
      verdictCache.set(key, v);
    }
    badge(a, v);
  }
}

const mo = new MutationObserver((muts) => {
  for (const m of muts) for (const n of m.addedNodes) if (n instanceof Element) scan(n);
});
mo.observe(document.documentElement, { childList: true, subtree: true });
scan();
