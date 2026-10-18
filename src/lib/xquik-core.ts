/**
 * Pure X-account resolution logic shared by the API worker (which holds the Xquik key) and the tests.
 * Nothing here touches chrome.* or secrets.
 */
import { parse } from "tldts";

export interface XAccount {
  handle: string;
  name: string;
  followers: number;
  verifiedType?: string;
  blue?: boolean;
  ageDays?: number;
  /** registrable domains found in the profile url / bio links */
  domains: string[];
}

export interface XBrand {
  token: string;
  official?: XAccount;
  /** how confident we are that `official` really is the project (0..1) */
  confidence: number;
}

export interface RawUser {
  id?: string;
  username?: string;
  name?: string;
  followers?: number;
  verified?: boolean;
  verifiedType?: string;
  isBlueVerified?: boolean;
  createdAt?: string;
  url?: string;
  contactInfo?: { links?: Array<{ url?: string }> };
  unavailable?: boolean;
}

export function registrableOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    const host = new URL(url.startsWith("http") ? url : `https://${url}`).hostname.toLowerCase();
    return parse(host, { allowPrivateDomains: true }).domain ?? null;
  } catch {
    return null;
  }
}

/** Link-in-bio aggregators: we fetch these pages and take the outbound links instead. */
const LINK_PAGES = new Set(["linktr.ee", "bio.link", "beacons.ai", "link3.to", "lnk.bio", "bento.me", "linkin.bio", "taplink.cc", "solo.to"]);
/** Platforms that never count as a project's own domain. */
const PLATFORMS = new Set(["t.co", "x.com", "twitter.com", "discord.gg", "discord.com", "t.me", "telegram.org", "medium.com", "youtube.com", "youtu.be", "github.com", "instagram.com", "facebook.com", "tiktok.com", "reddit.com", "opensea.io", "magiceden.io", "blur.io", "coingecko.com", "coinmarketcap.com", "dexscreener.com", "dextools.io", "etherscan.io", "solscan.io", "basescan.org", "apps.apple.com", "play.google.com", "chrome.google.com", "mirror.xyz", "paragraph.xyz", "substack.com", "notion.site", "gitbook.io", "docs.google.com", "warpcast.com", "farcaster.xyz", "zealy.io", "galxe.com", "layer3.xyz", "linktr.ee", "linkedin.com", "xhslink.com", "xiaohongshu.com", "weibo.com", "bilibili.com", "vk.com", "threads.net", "bsky.app", "twitch.tv", "kick.com", "spotify.com", "wikipedia.org"]);

export function toAccount(u: RawUser): XAccount {
  const domains = new Set<string>();
  const d1 = registrableOf(u.url);
  if (d1 && !PLATFORMS.has(d1) && !LINK_PAGES.has(d1)) domains.add(d1);
  for (const l of u.contactInfo?.links ?? []) {
    const d = registrableOf(l.url);
    if (d && !PLATFORMS.has(d) && !LINK_PAGES.has(d)) domains.add(d);
  }
  const created = u.createdAt ? Date.parse(u.createdAt) : NaN;
  return {
    handle: (u.username ?? "").toLowerCase(),
    name: u.name ?? "",
    followers: u.followers ?? 0,
    verifiedType: u.verifiedType,
    blue: u.isBlueVerified ?? u.verified,
    ageDays: Number.isFinite(created) ? (Date.now() - created) / 86400000 : undefined,
    domains: [...domains],
  };
}

export const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
const ORG_AFFIX = /(foundation|fndn|fnd|fdn|official|labs|team|dao|hq|eco|ecosystem|network|protocol)+$/g;

/**
 * Pick the account that most plausibly *is* the project named by `token`, and merge the bio domains of the
 * project's other sizeable accounts (foundation, official, regional) into the official domain set.
 */
export function pickOfficial(token: string, users: RawUser[]): XBrand {
  const t = norm(token);
  let best: { acc: XAccount; score: number } | null = null;
  for (const u of users) {
    if (u.unavailable) continue;
    const acc = toAccount(u);
    const h = norm(acc.handle);
    const n = norm(acc.name);
    let s = 0;
    if (h === t || n === t) s += 3;
    else if (h.startsWith(t) || n.startsWith(t)) s += 2;
    else if (h.includes(t) || n.includes(t)) s += 1;
    else continue;
    // scam handles: "<brand>_claim", "<brand>airdrop" ...
    if (/(claim|airdrop|drop|reward|giveaway|bonus|support|official|mint|wl)/.test(h.replace(t, ""))) s -= 2;
    if (acc.verifiedType && /business|government/i.test(acc.verifiedType)) s += 2;
    if (acc.followers >= 100_000) s += 2;
    else if (acc.followers >= 10_000) s += 1.5;
    else if (acc.followers >= 2_000) s += 1;
    else if (acc.followers < 200) s -= 1;
    if (acc.ageDays !== undefined && acc.ageDays < 60) s -= 1.5;
    if (acc.domains.length) s += 0.5;
    if (!best || s > best.score) best = { acc, score: s };
  }
  if (!best || best.score < 3) return { token, confidence: 0 };
  const confidence = Math.max(0, Math.min(1, (best.score - 2) / 6));
  const domains = new Set(best.acc.domains);
  for (const u of users) {
    const acc = toAccount(u);
    if (acc.handle === best.acc.handle || acc.followers < 5000) continue;
    if (norm(acc.handle).replace(ORG_AFFIX, "") === t || norm(acc.name).replace(ORG_AFFIX, "") === t) for (const d of acc.domains) domains.add(d);
  }
  return { token, official: { ...best.acc, domains: [...domains] }, confidence };
}

/** All link-in-bio page URLs an account exposes (profile url + bio links). */
export function linkPagesOf(u: RawUser): string[] {
  const out = new Set<string>();
  for (const url of [u.url, ...(u.contactInfo?.links ?? []).map((l) => l.url)]) {
    const d = registrableOf(url);
    if (url && d && LINK_PAGES.has(d)) out.add(url.startsWith("http") ? url : `https://${url}`);
  }
  return [...out];
}

/**
 * Extract the page owner's outbound registrable domains from a link-in-bio page.
 * Linktree ships the owner's links in the __NEXT_DATA__ JSON (`links[].url`); the regex fallback
 * only keeps domains that carry the brand token (the rest of the HTML is Linktree's own promotions).
 */
export function domainsFromLinkPage(html: string, token?: string): string[] {
  const out = new Set<string>();
  const keep = (url: string) => {
    const d = registrableOf(url);
    if (d && !PLATFORMS.has(d) && !LINK_PAGES.has(d)) out.add(d);
  };
  const m = html.match(/<script[^>]*id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/i);
  if (m) {
    try {
      const json = JSON.parse(m[1]) as unknown;
      const walk = (node: unknown, underLinks: boolean, depth: number) => {
        if (depth > 12 || !node || typeof node !== "object") return;
        if (Array.isArray(node)) { for (const x of node) walk(x, underLinks, depth + 1); return; }
        const o = node as Record<string, unknown>;
        if (underLinks && typeof o.url === "string" && /^https?:\/\//i.test(o.url)) keep(o.url);
        for (const [k, v] of Object.entries(o)) walk(v, underLinks || k === "links" || k === "socialLinks", depth + 1);
      };
      walk(json, false, 0);
      if (out.size) return [...out];
    } catch {
      /* fall through to regex */
    }
  }
  const t = token ? norm(token) : "";
  const re = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s"'<>\\]*)?/gi;
  for (const u of html.match(re) ?? []) {
    const d = registrableOf(u);
    if (!d || PLATFORMS.has(d) || LINK_PAGES.has(d)) continue;
    if (t && !norm(d).includes(t)) continue;
    out.add(d);
  }
  return [...out];
}

export async function expandLinkPages(acc: XAccount, pages: string[], token: string): Promise<XAccount> {
  if (!pages.length) return acc;
  const domains = new Set(acc.domains);
  for (const page of pages.slice(0, 2)) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(page, { signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) continue;
      for (const d of domainsFromLinkPage(await res.text(), token)) domains.add(d);
    } catch {
      /* ignore */
    }
  }
  return { ...acc, domains: [...domains] };
}

/** Full brand resolution given an Xquik fetcher (the worker supplies one with its key). */
export async function resolveBrandRaw(token: string, xquik: (path: string) => Promise<unknown>): Promise<XBrand | null> {
  const json = (await xquik(`/x/users/search?q=${encodeURIComponent(token)}&pageSize=20&hasWebsite=true&minFollowers=200`)) as { users?: RawUser[] } | null;
  if (!json) return null;
  const users = json.users ?? [];
  const picked = pickOfficial(token, users);
  if (picked.official && !picked.official.domains.length) {
    const raw = users.find((u) => (u.username ?? "").toLowerCase() === picked.official!.handle);
    if (raw) picked.official = await expandLinkPages(picked.official, linkPagesOf(raw), token);
  }
  return picked;
}

export async function resolveUserRaw(handle: string, xquik: (path: string) => Promise<unknown>): Promise<XAccount | null> {
  const h = handle.toLowerCase().replace(/^@/, "");
  const json = (await xquik(`/x/users/${encodeURIComponent(h)}`)) as RawUser | null;
  if (!json || json.unavailable) return null;
  return toAccount(json);
}
