import type { OriginContext } from "./types";

const TTL = 60_000;

/** Map a referrer / redirector hostname to a social source. */
export function sourceFromHost(host: string): OriginContext["source"] | null {
  const h = host.toLowerCase();
  if (h === "t.co" || h === "x.com" || h === "twitter.com" || h.endsWith(".x.com") || h.endsWith(".twitter.com")) return "x";
  if (h === "discord.com" || h.endsWith(".discord.com") || h === "discordapp.com") return "discord";
  if (h === "t.me" || h === "web.telegram.org" || h.endsWith(".telegram.org")) return "telegram";
  if (h === "reddit.com" || h.endsWith(".reddit.com") || h === "out.reddit.com") return "reddit";
  if (h === "youtube.com" || h.endsWith(".youtube.com") || h === "youtu.be") return "youtube";
  return null;
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

export async function takePendingClick(): Promise<OriginContext | undefined> {
  const o = (await chrome.storage.session.get("pendingClick")).pendingClick as OriginContext | undefined;
  if (!o) return undefined;
  await chrome.storage.session.remove("pendingClick");
  return Date.now() - o.at < 15_000 ? o : undefined;
}
