import type { Verdict } from "./types";

/** Per-tab verdicts and session bypasses live in chrome.storage.session (cleared on browser restart). */

export async function setTabVerdict(tabId: number, v: Verdict): Promise<void> {
  await chrome.storage.session.set({ [`tab:${tabId}`]: v });
}
export async function getTabVerdict(tabId: number): Promise<Verdict | undefined> {
  return (await chrome.storage.session.get(`tab:${tabId}`))[`tab:${tabId}`] as Verdict | undefined;
}
export async function clearTab(tabId: number): Promise<void> {
  await chrome.storage.session.remove(`tab:${tabId}`);
}

export interface WarningPayload { url: string; host: string; score: number; signals: Verdict["signals"]; brandDomain?: string; reviewed?: boolean; tabId: number }

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

export async function addBypass(host: string): Promise<void> {
  const cur = ((await chrome.storage.session.get("bypass")).bypass as string[] | undefined) ?? [];
  if (!cur.includes(host)) await chrome.storage.session.set({ bypass: [...cur, host] });
}
export async function isBypassed(host: string): Promise<boolean> {
  const cur = ((await chrome.storage.session.get("bypass")).bypass as string[] | undefined) ?? [];
  return cur.includes(host);
}

export async function addUserAllow(registrable: string): Promise<void> {
  const cur = ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
  if (!cur.includes(registrable)) await chrome.storage.local.set({ userAllow: [...cur, registrable] });
}
export async function removeUserAllow(registrable: string): Promise<void> {
  const cur = ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
  await chrome.storage.local.set({ userAllow: cur.filter((d) => d !== registrable) });
}
export async function getUserAllow(): Promise<string[]> {
  return ((await chrome.storage.local.get("userAllow")).userAllow as string[] | undefined) ?? [];
}
