/**
 * Optional X (Twitter) resolution through the Xquik API (https://docs.xquik.com).
 *
 * Privacy contract: only a brand token (e.g. "axisrobotics") or an X handle is ever
 * sent, never the URL the user visited. Calls happen only for pages the local
 * heuristics already consider suspicious, and results are cached for days.
 *
 * The API key lives in chrome.storage.local (entered on the options page); it is
 * never bundled into the extension. When no key is configured this module is inert.
 */
import { parse } from "tldts";

const BASE = "https://xquik.com/api/v1";
const BRAND_TTL = 7 * 24 * 3600 * 1000;
const POSTER_TTL = 24 * 3600 * 1000;
const FAIL_TTL = 6 * 3600 * 1000;

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

interface RawUser {
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

export async function getApiKey(): Promise<string> {
  return ((await chrome.storage.local.get("xquikKey")).xquikKey as string | undefined) ?? "";
}

export async function setApiKey(key: string): Promise<void> {
  await chrome.storage.local.set({ xquikKey: key.trim() });
}

async function api<T>(path: string, key: string): Promise<T | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10_000);
    const res = await fetch(BASE + path, { headers: { "x-api-key": key, accept: "application/json" }, signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) {
      console.warn("[w3pg] xquik", path.split("?")[0], res.status);
      return null;
    }
    return (await res.json()) as T;
  } catch (e) {
    console.warn("[w3pg] xquik failed", e);
    return null;
  }
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
const PLATFORMS = new Set(["t.co", "x.com", "twitter.com", "discord.gg", "discord.com", "t.me", "telegram.org", "medium.com", "youtube.com", "youtu.be", "github.com", "instagram.com", "facebook.com", "tiktok.com", "reddit.com", "opensea.io", "magiceden.io", "blur.io", "coingecko.com", "coinmarketcap.com", "dexscreener.com", "dextools.io", "etherscan.io", "solscan.io", "basescan.org", "apps.apple.com", "play.google.com", "chrome.google.com", "mirror.xyz", "paragraph.xyz", "substack.com", "notion.site", "gitbook.io", "docs.google.com", "warpcast.com", "farcaster.xyz", "zealy.io", "galxe.com", "layer3.xyz", "linktr.ee"]);

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

/**
 * Pick the account that most plausibly *is* the project named by `token`.
 * Pure so it can be unit-tested with canned search results.
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
  return { token, official: best.acc, confidence };
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

/** Extract outbound registrable domains from a link-in-bio page's HTML (Linktree embeds them as JSON). */
export function domainsFromLinkPage(html: string): string[] {
  const out = new Set<string>();
  const re = /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}(?:\/[^\s"'<>\\]*)?/gi;
  for (const m of html.match(re) ?? []) {
    const d = registrableOf(m);
    if (!d || PLATFORMS.has(d) || LINK_PAGES.has(d)) continue;
    // skip the aggregator's own asset / tracking hosts
    if (/(^|\.)(linktr\.ee|ltclick\.co|lnkimg\.com|googleapis\.com|gstatic\.com|cloudfront\.net|sentry\.io|segment\.com|cookielaw\.org|onetrust\.com|w3\.org|schema\.org|jsdelivr\.net|unpkg\.com|cloudflare\.com|cdnjs\.com|google\.com|googletagmanager\.com|doubleclick\.net|facebook\.net|apple\.com|microsoft\.com|amazonaws\.com|typekit\.net|hotjar\.com|intercom\.io|stripe\.com|paypal\.com|cash\.app|venmo\.com|shopify\.com|spotify\.com|soundcloud\.com|twitch\.tv|snapchat\.com|pinterest\.com|linkedin\.com|whatsapp\.com|threads\.net|bsky\.app|vercel\.com|netlify\.com|webflow\.com)$/.test(d)) continue;
    out.add(d);
  }
  return [...out];
}

async function expandLinkPages(acc: XAccount, pages: string[]): Promise<XAccount> {
  if (!pages.length) return acc;
  const domains = new Set(acc.domains);
  for (const page of pages.slice(0, 2)) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(page, { signal: ctrl.signal, credentials: "omit" });
      clearTimeout(t);
      if (!res.ok) continue;
      for (const d of domainsFromLinkPage(await res.text())) domains.add(d);
    } catch {
      /* ignore */
    }
  }
  return { ...acc, domains: [...domains] };
}

export async function resolveBrand(token: string): Promise<XBrand | null> {
  const key = await getApiKey();
  if (!key) return null;
  const ck = `x:brand:${norm(token)}`;
  const cached = (await chrome.storage.local.get(ck))[ck] as (XBrand & { at: number; failed?: boolean }) | undefined;
  if (cached && Date.now() - cached.at < (cached.failed ? FAIL_TTL : BRAND_TTL)) return cached.failed ? null : cached;
  const q = encodeURIComponent(token);
  const json = await api<{ users?: RawUser[] }>(`/x/users/search?q=${q}&pageSize=20&hasWebsite=true&minFollowers=200`, key);
  if (!json) {
    await chrome.storage.local.set({ [ck]: { token, confidence: 0, at: Date.now(), failed: true } });
    return null;
  }
  const users = json.users ?? [];
  const picked = pickOfficial(token, users);
  if (picked.official && !picked.official.domains.length) {
    // official account only links to a Linktree-style page: follow it for the real domains
    const raw = users.find((u) => (u.username ?? "").toLowerCase() === picked.official!.handle);
    if (raw) picked.official = await expandLinkPages(picked.official, linkPagesOf(raw));
  }
  await chrome.storage.local.set({ [ck]: { ...picked, at: Date.now() } });
  return picked;
}

export async function resolvePoster(handle: string): Promise<XAccount | null> {
  const key = await getApiKey();
  if (!key) return null;
  const h = handle.toLowerCase().replace(/^@/, "");
  const ck = `x:user:${h}`;
  const cached = (await chrome.storage.local.get(ck))[ck] as (XAccount & { at: number; failed?: boolean }) | undefined;
  if (cached && Date.now() - cached.at < (cached.failed ? FAIL_TTL : POSTER_TTL)) return cached.failed ? null : cached;
  const json = await api<RawUser>(`/x/users/${encodeURIComponent(h)}`, key);
  if (!json || json.unavailable) {
    await chrome.storage.local.set({ [ck]: { handle: h, name: "", followers: 0, domains: [], at: Date.now(), failed: true } });
    return null;
  }
  const acc = toAccount(json);
  await chrome.storage.local.set({ [ck]: { ...acc, at: Date.now() } });
  return acc;
}
