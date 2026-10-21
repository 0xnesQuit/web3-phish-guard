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

/** Friendly, static text for a deep-scan error code (never the raw code). Minutes are substituted once, no timer. */
export function deepErrorText(code: string | undefined, retryAfterMin?: number): string {
  switch (code) {
    case "host_cooldown": {
      const m = Number.isFinite(retryAfterMin) && (retryAfterMin as number) > 0 ? Math.ceil(retryAfterMin as number) : 30;
      return t("ai_err_cooldown", [String(m)]);
    }
    case "rate_limited":
    case "host_capacity_reached":
    case "daily_capacity_reached":
      return t("popup_scan_limited");
    case "collect_failed": return t("ai_err_collect");
    case "not_http": return t("ai_err_not_http");
    default: return t("ai_err_generic");
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
