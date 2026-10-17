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
