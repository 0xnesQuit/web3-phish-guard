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

/** After an extension reload the old script lingers in open X tabs; runtime calls then throw synchronously. */
const orphaned = () => { try { return !chrome.runtime?.id; } catch { return true; } };
const safeSend = (msg: unknown): Promise<unknown> => { try { return chrome.runtime.sendMessage(msg).catch(() => undefined); } catch { return Promise.resolve(undefined); } };

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
  let m = text.match(/^(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
  if (!m) {
    // link-preview cards: the only domain-like text is the "From coinmarketcap.com" / "Kaynak: ..." line,
    // which X fills from the page's own metadata and scammers spoof
    // Only an element whose entire text is a bare domain counts (X's "From example.com" / "Kaynak: example.com"
    // line); a headline that merely mentions "Pump.fun" must not become the displayed address.
    const card = a.closest('[data-testid="card.wrapper"]') ?? a;
    let found: string | null = null;
    for (const el of Array.from(card.querySelectorAll("span, div"))) {
      if (el.children.length) continue;
      const t = (el.textContent || "").trim().replace(/^(from|kaynak|von|de|da|источник|स्रोत|来源|出典|출처|nguồn|sumber)\s*:?\s*/i, "");
      if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(t)) found = t;
    }
    if (found) m = [found, found];
  }
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
  ctx.isReply = /replying to|yanıt olarak|antwort an|en réponse à|respondiendo a|em resposta a|в ответ|के जवाब में|回复|返信先|답글|đang trả lời|membalas/i.test(head);
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
    void safeSend({ type: "w3pg:xclick", ctx, href: a.href });
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

const seen = new WeakSet<HTMLAnchorElement>();
function scan(root: ParentNode = document) {
  const anchors = root.querySelectorAll<HTMLAnchorElement>(`a[href]:not([${BADGE_ATTR}])`);
  for (const a of anchors) {
    if (seen.has(a)) continue;
    if (!(isExternalLink(a) && (textHost(a) || hrefHost(a) !== "t.co"))) continue;
    seen.add(a);
    if (io) io.observe(a); else queue.add(a);
  }
  if (!io && queue.size && timer === undefined) timer = window.setTimeout(flush, 300);
}

async function flush() {
  timer = undefined;
  const batch = [...queue];
  queue = new Set();
  // up to 4 lookups in flight: one slow redirect resolution must not stall the rest of the timeline
  let cursor = 0;
  const worker = async () => { while (cursor < batch.length) await scoreOne(batch[cursor++]); };
  await Promise.all([worker(), worker(), worker(), worker()]);
}

async function scoreOne(a: HTMLAnchorElement) {
  {
    if (a.hasAttribute(BADGE_ATTR)) return;
    const display = textHost(a);
    const target = hrefHost(a);
    if (!target) return;
    if (!display && target === "t.co") return; // card links without a visible domain: nothing to judge yet
    const key = `${a.href}|${display ?? ""}`;
    let v = verdictCache.get(key);
    if (!v) {
      const ctx = contextOf(containerOf(a));
      ctx.display = display ?? undefined;
      let r: Omit<HostVerdict, "host"> | null = null;
      try {
        r = (await safeSend({ type: "w3pg:scoreLink", href: a.href, ctx })) as (Omit<HostVerdict, "host"> & { host?: string }) | null;
      } catch { r = null; }
      if (!r) return;
      v = { ...r, host: (r as { host?: string }).host ?? target };
      if (v.band !== "none") console.debug("[w3pg]", v.host, v.score, v.signals.map(signalText));
      if (verdictCache.size > 500) verdictCache.delete(verdictCache.keys().next().value as string);
      verdictCache.set(key, v);
    }
    badge(a, v);
  }
}

// Only links that scroll into view are looked up (a timeline holds hundreds of links the user never sees).
const io = typeof IntersectionObserver === "function" ? new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    io?.unobserve(e.target);
    queue.add(e.target as HTMLAnchorElement);
  }
  if (queue.size && timer === undefined) timer = window.setTimeout(flush, 200);
}, { rootMargin: "200px" }) : null;

const mo = new MutationObserver((muts) => {
  if (orphaned()) { mo.disconnect(); io?.disconnect(); return; } // a newer script owns the page now
  for (const m of muts) for (const n of m.addedNodes) if (n instanceof Element) scan(n);
});
mo.observe(document.documentElement, { childList: true, subtree: true });
scan();
