/**
 * Runs on x.com / twitter.com.
 *  1. On click of an external link inside a tweet, captures the tweet's context
 *     (poster handle, verified badge, reply-or-not, displayed domain) and hands it
 *     to the background, which attaches it to the navigation that follows.
 *  2. Proactively scores every external link visible in the timeline (pure
 *     hostname heuristics, no network) and marks suspicious ones with a badge.
 */

interface Ctx { poster?: string; posterVerified?: boolean; isReply?: boolean; display?: string }

const BADGE_ATTR = "data-w3pg";
const hostCache = new Map<string, { band: string; score: number; reasons: string[] }>();

function displayHost(a: HTMLAnchorElement): string | null {
  const text = (a.textContent || "").trim().replace(/…$/, "");
  const m = text.match(/^(?:https?:\/\/)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
  if (!m) return null;
  const h = m[1].toLowerCase();
  if (/(^|\.)(x\.com|twitter\.com|t\.co|pic\.twitter\.com)$/.test(h)) return null;
  return h;
}

function tweetOf(el: Element): HTMLElement | null {
  return el.closest('article[data-testid="tweet"]') as HTMLElement | null;
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
  // "Replying to @x" row sits above the tweet text; X renders it with a link to the parent author.
  const head = (article.innerText || "").slice(0, 300);
  ctx.isReply = /replying to|yanıt olarak|antwort an|en réponse à|respondiendo a/i.test(head);
  return ctx;
}

// ---- 1. click capture --------------------------------------------------------
document.addEventListener(
  "click",
  (e) => {
    const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
    if (!a) return;
    let href = "";
    try { href = new URL(a.href, location.href).hostname; } catch { return; }
    const external = href === "t.co" || (!/(^|\.)(x\.com|twitter\.com)$/.test(href));
    if (!external) return;
    const ctx = contextOf(tweetOf(a));
    ctx.display = displayHost(a) ?? undefined;
    chrome.runtime.sendMessage({ type: "w3pg:xclick", ctx }).catch(() => undefined);
  },
  true,
);

// ---- 2. proactive badges -----------------------------------------------------
function badge(a: HTMLAnchorElement, v: { band: string; score: number; reasons: string[] }) {
  if (a.hasAttribute(BADGE_ATTR)) return;
  a.setAttribute(BADGE_ATTR, v.band);
  if (v.band === "none") return;
  const s = document.createElement("span");
  s.textContent = v.band === "block" ? " ⛔ scam?" : " ⚠️ şüpheli";
  s.title = `Web3 Phish Guard · risk ${v.score}/100\n${v.reasons.join("\n")}`;
  s.style.cssText = `display:inline-block;margin-left:4px;padding:0 6px;border-radius:999px;font:600 11px/18px system-ui,sans-serif;color:#fff;background:${v.band === "block" ? "#e5484d" : "#d08700"};vertical-align:middle;`;
  a.insertAdjacentElement("afterend", s);
}

let queue = new Set<HTMLAnchorElement>();
let timer: number | undefined;

function scan(root: ParentNode = document) {
  const anchors = root.querySelectorAll<HTMLAnchorElement>(`article[data-testid="tweet"] a[href]:not([${BADGE_ATTR}])`);
  for (const a of anchors) {
    if (displayHost(a)) queue.add(a);
  }
  if (queue.size && timer === undefined) timer = window.setTimeout(flush, 300);
}

async function flush() {
  timer = undefined;
  const batch = [...queue];
  queue = new Set();
  const byHost = new Map<string, HTMLAnchorElement[]>();
  for (const a of batch) {
    const h = displayHost(a);
    if (!h) continue;
    (byHost.get(h) ?? byHost.set(h, []).get(h)!).push(a);
  }
  for (const [host, anchors] of byHost) {
    let v = hostCache.get(host);
    if (!v) {
      const ctx = contextOf(tweetOf(anchors[0]));
      try {
        v = (await chrome.runtime.sendMessage({ type: "w3pg:scoreHost", host, ctx })) as typeof v;
      } catch { v = undefined; }
      if (!v) continue;
      hostCache.set(host, v);
    }
    for (const a of anchors) badge(a, v);
  }
}

const mo = new MutationObserver((muts) => {
  for (const m of muts) for (const n of m.addedNodes) if (n instanceof Element) scan(n);
});
mo.observe(document.documentElement, { childList: true, subtree: true });
scan();
