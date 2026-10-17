import type { Signal } from "./types";

/** chrome.i18n wrapper; falls back to the key so a missing translation is visible, never a crash. */
export function t(key: string, sub?: string[]): string {
  try {
    const m = chrome.i18n.getMessage(key, sub);
    return m || key;
  } catch {
    return key;
  }
}

export function signalText(s: Signal): string {
  return t(s.key, s.sub);
}

/** Translate every element carrying data-i18n / data-i18n-title in a static page. */
export function localizePage(root: ParentNode = document): void {
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n!);
  }
  for (const el of root.querySelectorAll<HTMLElement>("[data-i18n-title]")) {
    el.title = t(el.dataset.i18nTitle!);
  }
  for (const el of root.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder!);
  }
  try {
    document.documentElement.lang = chrome.i18n.getUILanguage();
  } catch {
    /* ignore */
  }
}
