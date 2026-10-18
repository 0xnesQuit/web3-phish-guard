/**
 * X (Twitter) resolution, served by our API worker (which holds the Xquik key).
 *
 * Privacy contract: only a brand token (e.g. "axisrobotics") or an X handle is ever sent, never the URL the user
 * visited. Calls happen only for pages the local heuristics already consider suspicious; results are cached locally.
 */
import { API_BASE } from "./deepscan";
import type { XAccount, XBrand } from "./xquik-core";

export type { XAccount, XBrand } from "./xquik-core";

const BRAND_TTL = 7 * 24 * 3600 * 1000;
const POSTER_TTL = 24 * 3600 * 1000;
const FAIL_TTL = 6 * 3600 * 1000;
const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

async function api<T>(path: string): Promise<T | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15_000);
    const res = await fetch(API_BASE + path, { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export async function resolveBrand(token: string): Promise<XBrand | null> {
  const ck = `x:brand:${norm(token)}`;
  const cached = (await chrome.storage.local.get(ck))[ck] as (XBrand & { at: number; failed?: boolean }) | undefined;
  if (cached && Date.now() - cached.at < (cached.failed ? FAIL_TTL : BRAND_TTL)) return cached.failed ? null : cached;
  const r = await api<XBrand>(`/v1/x/brand?token=${encodeURIComponent(token)}`);
  if (!r) {
    await chrome.storage.local.set({ [ck]: { token, confidence: 0, at: Date.now(), failed: true } });
    return null;
  }
  await chrome.storage.local.set({ [ck]: { ...r, at: Date.now() } });
  return r;
}

export async function resolvePoster(handle: string): Promise<XAccount | null> {
  const h = handle.toLowerCase().replace(/^@/, "");
  const ck = `x:user:${h}`;
  const cached = (await chrome.storage.local.get(ck))[ck] as (XAccount & { at: number; failed?: boolean }) | undefined;
  if (cached && Date.now() - cached.at < (cached.failed ? FAIL_TTL : POSTER_TTL)) return cached.failed ? null : cached;
  const r = await api<XAccount | { error: string }>(`/v1/x/user?handle=${encodeURIComponent(h)}`);
  if (!r || "error" in r) {
    await chrome.storage.local.set({ [ck]: { handle: h, name: "", followers: 0, domains: [], at: Date.now(), failed: true } });
    return null;
  }
  await chrome.storage.local.set({ [ck]: { ...r, at: Date.now() } });
  return r;
}
