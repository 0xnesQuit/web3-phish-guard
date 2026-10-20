import type { Verdict } from "./types";

/** Per-tab verdicts and session bypasses live in chrome.storage.session (cleared on browser restart). */

export async function setTabVerdict(tabId: number, v: Verdict): Promise<void> {
  await chrome.storage.session.set({ [`tab:${tabId}`]: v });
}
export async function getTabVerdict(tabId: number): Promise<Verdict | undefined> {
  return (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`] as Verdict | undefined;
}
export async function clearTab(tabId: number): Promise<void> {
  await chrome.storage.session.remove([`tab:${tabId}`, `bypass:${tabId}`]);
}

export interface WarningPayload { url: string; host: string; score: number; signals: Verdict["signals"]; brandDomain?: string; reviewed?: boolean; tabId: number; /** host+path prefix when the hit came from a path-level entry (Google Sites pages): the bypass stays that narrow */ pathEntry?: string }

/** Store the warning page's payload under a random nonce: readable for 10 minutes (reloads), consumed by a bypass. */
export async function putWarning(p: WarningPayload): Promise<string> {
  const nonce = crypto.randomUUID();
  await chrome.storage.session.set({ [`warn:${nonce}`]: { ...p, at: Date.now() } });
  return nonce;
}
export async function getWarning(nonce: string): Promise<WarningPayload | undefined> {
  if (!/^[0-9a-f-]{36}$/.test(nonce)) return undefined;
  const p = (await chrome.storage.session.get(`warn:${nonce}`))[`warn:${nonce}`] as (WarningPayload & { at: number }) | undefined;
  if (!p || Date.now() - p.at > 10 * 60_000) return undefined;
  return p;
}
export async function consumeWarning(nonce: string): Promise<void> {
  if (/^[0-9a-f-]{36}$/.test(nonce)) await chrome.storage.session.remove(`warn:${nonce}`).catch(() => undefined);
}

/** Bypass entries are hosts, or "host/path" prefixes for path-level hits. Scoped to the tab where the user clicked
 *  "continue anyway", and cleared when that tab closes (clearTab), so reopening a blocked site warns again. */
export async function addBypass(entry: string, tabId: number): Promise<void> {
  const k = `bypass:${tabId}`;
  const cur = ((await chrome.storage.session.get(k))[k] as string[] | undefined) ?? [];
  if (!cur.includes(entry)) await chrome.storage.session.set({ [k]: [...cur, entry] });
}
export async function isBypassed(host: string, pathname: string, tabId: number): Promise<boolean> {
  const k = `bypass:${tabId}`;
  const cur = ((await chrome.storage.session.get(k))[k] as string[] | undefined) ?? [];
  const path = pathname.toLowerCase().replace(/\/+$/, "");
  return cur.some((e) => (e.includes("/") ? e.startsWith(host + "/") && (host + path === e || (host + path).startsWith(e + "/")) : e === host));
}

export async function addUserAllow(registrable: string): Promise<void> {
  const cur = ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
  if (!cur.includes(registrable)) await chrome.storage.local.set({ userAllow: [...cur, registrable] });
}
export async function removeUserAllow(registrable: string): Promise<void> {
  const cur = ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
  await chrome.storage.local.set({ userAllow: cur.filter((d) => d !== registrable) });
}
/** Transaction simulation through a public RPC (PRIVACY.md): on unless the user turned it off. */
export async function simulateEnabled(): Promise<boolean> {
  return (await chrome.storage.local.get("simulate")).simulate !== false;
}

export async function getUserAllow(): Promise<string[]> {
  return ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
}
