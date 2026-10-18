import type { OriginContext } from "./types";

const TTL = 60_000;

/** URL shorteners that hide the destination; treated as redirect hops, never evaluated themselves. */
export const SHORTENERS = new Set(["t.co", "tr.ee", "bit.ly", "bitly.com", "tinyurl.com", "cutt.ly", "t.ly", "rb.gy", "shorturl.at", "is.gd", "v.gd", "rebrand.ly", "short.io", "tiny.cc", "lnkd.in", "buff.ly", "ow.ly", "s.id", "qrco.de", "dub.sh", "bl.ink", "shorte.st", "clck.ru", "goo.su", "u.to", "linkly.co", "snip.ly", "tiny.one", "urlz.fr", "shrtco.de", "l.linklyhq.com", "go.link", "out.reddit.com"]);
export function isShortener(host: string): boolean {
  return SHORTENERS.has(host.toLowerCase());
}

/** Map a referrer / redirector hostname to a social source. */
export function sourceFromHost(host: string): OriginContext["source"] | null {
  const h = host.toLowerCase();
  if (h === "t.co" || h === "x.com" || h === "twitter.com" || h.endsWith(".x.com") || h.endsWith(".twitter.com")) return "x";
  if (h === "discord.com" || h.endsWith(".discord.com") || h === "discordapp.com") return "discord";
  if (h === "t.me" || h === "web.telegram.org" || h.endsWith(".telegram.org")) return "telegram";
  if (h === "reddit.com" || h.endsWith(".reddit.com") || h === "out.reddit.com") return "reddit";
  if (h === "youtube.com" || h.endsWith(".youtube.com") || h === "youtu.be") return "youtube";
  if (isAdHop(h)) return "ads";
  return null;
}

/** Click-tracking hops of search ads: the page after them was reached through an ad for some keyword. */
export function isAdHop(host: string): boolean {
  const h = host.toLowerCase();
  return h === "www.googleadservices.com" || h === "googleadservices.com" || h.endsWith(".doubleclick.net") || h === "doubleclick.net" || h === "bing.com" && false || h === "www.bing.com" && false || h.endsWith(".adsrvr.org") || h === "clickserve.dartsearch.net" || h === "ad.doubleclick.net";
}

export async function setTabOrigin(tabId: number, o: OriginContext): Promise<void> {
  await chrome.storage.session.set({ [`origin:${tabId}`]: o });
}

export async function getTabOrigin(tabId: number): Promise<OriginContext | undefined> {
  const o = (await chrome.storage.session.get(`origin:${tabId}`))[`origin:${tabId}`] as OriginContext | undefined;
  if (!o) return undefined;
  if (Date.now() - o.at > TTL) {
    await chrome.storage.session.remove(`origin:${tabId}`);
    return undefined;
  }
  return o;
}

/** A click captured on x.com, waiting for the navigation it will cause (often in a new tab). */
export async function setPendingClick(o: OriginContext): Promise<void> {
  await chrome.storage.session.set({ pendingClick: o });
}

export async function peekPendingClick(): Promise<OriginContext | undefined> {
  const o = (await chrome.storage.session.get("pendingClick")).pendingClick as OriginContext | undefined;
  return o && Date.now() - o.at < 15_000 ? o : undefined;
}

export async function takePendingClick(): Promise<OriginContext | undefined> {
  const o = (await chrome.storage.session.get("pendingClick")).pendingClick as OriginContext | undefined;
  if (!o) return undefined;
  await chrome.storage.session.remove("pendingClick");
  return Date.now() - o.at < 15_000 ? o : undefined;
}
