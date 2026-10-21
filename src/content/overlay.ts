/**
 * In-page warning for the "warn" band. Does not block the page.
 *
 * A compact card in the bottom-right corner, so a site's own dialogs (wallet-connect modals, cookie bars, footers)
 * stay usable. After a few seconds, or as soon as the user interacts with the page, it folds into a one-line
 * badge; hovering or clicking the badge opens the card again. Only the user's own click closes it.
 */
import type { Verdict } from "../lib/types";
import type { DeepReport } from "../lib/types";
import { t, signalText, deepErrorText } from "../lib/i18n";

const ID = "w3pg-banner";
const COLLAPSE_AFTER_MS = 8000;
let current: HTMLElement | null = null;
/** disconnects the current card's re-mount observer before it is replaced; otherwise it resurrects itself */
let disposeCurrent: (() => void) | null = null;

/** After an extension update the old content script lingers in open tabs; its chrome.runtime.id is gone. */
const orphaned = () => { try { return !chrome.runtime?.id; } catch { return true; } };

function render(v: Verdict) {
  disposeCurrent?.();
  disposeCurrent = null;
  current?.remove();
  // Cards left behind by a previous script instance (extension reload / update). Older builds re-mount their card
  // whenever it is removed, so leftovers are hidden in place rather than removed: a hidden node is still connected
  // and their observer stays quiet.
  for (const old of Array.from(document.querySelectorAll<HTMLElement>("#" + ID))) { old.style.cssText = "display:none !important"; old.removeAttribute("id"); }
  const host = document.createElement("div");
  host.id = ID;
  host.style.cssText = "all:initial !important;position:fixed !important;right:16px !important;bottom:16px !important;z-index:2147483646 !important;display:block !important;max-width:min(420px, calc(100vw - 32px)) !important;";
  current = host;
  const root = host.attachShadow({ mode: "closed" });
  const reasons = v.signals.filter((s) => s.weight > 0).map((s) => `<li>${esc(signalText(s))}</li>`).join("");
  root.innerHTML = `
    <style>
      :host{all:initial}
      .card{font:13px/1.45 system-ui,sans-serif;background:#2b1f00;color:#ffe6a8;border:1px solid #a97a1a;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.45);overflow:hidden}
      .head{display:flex;align-items:center;gap:10px;padding:10px 12px;cursor:pointer;user-select:none}
      .i{font-size:18px;line-height:1}
      .t{font-weight:700;flex:1;min-width:0}
      .score{flex:none;background:#f5a524;color:#1a1200;font-weight:800;font-size:12px;border-radius:999px;padding:2px 8px}
      .x{background:transparent;border:1px solid #a97a1a;color:#ffe6a8;border-radius:6px;padding:3px 8px;cursor:pointer;font:inherit;font-size:12px}
      .body{padding:0 12px 10px 40px}
      ul{margin:0 0 6px;padding-left:16px}
      li{margin:2px 0}
      .s{opacity:.8;font-size:12px}
      .card.min .body{display:none}
      .card.min .head{padding:6px 10px}
      .card.min .t{font-weight:600;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
      .card.min .x{display:none}
      .deep{margin-top:4px;font:inherit;font-weight:600;font-size:12px;background:#f5a524;color:#1a1200;border:0;border-radius:8px;padding:6px 12px;cursor:pointer}
      .deep[disabled]{opacity:.6;cursor:default}
      .card.min .deep,.card.min .deepout{display:none}
      .deepout{margin-top:8px}
      .deepout .v{font-weight:700;margin-bottom:4px}
      .deepout .v.dangerous{color:#ff8a8a}
      .deepout .v.suspicious{color:#ffd27a}
      .deepout .v.safe{color:#9be3b0}
      .deepout .sum{opacity:.92;margin-bottom:4px}
      .deepout ul{margin:4px 0}
      .deepout .sbx{opacity:.8;font-size:12px;margin-top:4px}
    </style>
    <div class="card" id="card" role="alert" aria-live="polite">
      <div class="head" id="head">
        <div class="i" aria-hidden="true">⚠️</div>
        <div class="t">${esc(t("overlay_short"))}</div>
        <div class="score" aria-label="${esc(t("overlay_title", [String(v.score)]))}">${v.score}/100</div>
        <button class="x" id="close" aria-label="${esc(t("overlay_close"))}">${esc(t("overlay_close"))}</button>
      </div>
      <div class="body">
        <ul>${reasons}</ul>
        <div class="s">${esc(t("overlay_hint"))}</div>
        <button class="deep" id="deep">${esc(t("popup_deep_scan"))}</button>
        <div class="deepout" id="deepout"></div>
      </div>
    </div>`;
  const card = root.getElementById("card") as HTMLElement;
  let closed = false;
  let pinnedOpen = false;
  const collapse = () => { if (!pinnedOpen) card.classList.add("min"); };
  const expand = () => card.classList.remove("min");
  let timer: number | undefined = window.setTimeout(collapse, COLLAPSE_AFTER_MS);
  const cancelTimer = () => { if (timer !== undefined) { clearTimeout(timer); timer = undefined; } };
  // the user started using the PAGE: get out of the way. Interacting with our own card (e.target is the shadow host
  // after retargeting) must NOT collapse it — otherwise clicking the Deep scan button hides it before the click lands.
  const onFirstInteraction = (e: Event) => { if (!e.isTrusted || !host.isConnected || e.target === host) return; cancelTimer(); collapse(); };
  window.addEventListener("pointerdown", onFirstInteraction, { capture: true, passive: true });
  window.addEventListener("keydown", onFirstInteraction, { capture: true, passive: true });
  card.addEventListener("mouseenter", () => { cancelTimer(); expand(); });
  card.addEventListener("mouseleave", () => { if (!pinnedOpen) collapse(); });
  root.getElementById("head")!.addEventListener("click", (e) => { if (!e.isTrusted || (e.target as HTMLElement).id === "close") return; pinnedOpen = !pinnedOpen; if (pinnedOpen) expand(); else collapse(); });
  root.getElementById("close")!.addEventListener("click", (e) => { if (!e.isTrusted) return; closed = true; keep.disconnect(); host.remove(); current = null; });
  root.getElementById("deep")!.addEventListener("click", async (e) => {
    if (!e.isTrusted) return;
    pinnedOpen = true; expand();
    const btn = e.currentTarget as HTMLButtonElement;
    const out = root.getElementById("deepout") as HTMLElement;
    btn.disabled = true; out.textContent = t("overlay_scanning");
    try {
      const lang = (() => { try { return chrome.i18n.getUILanguage().split("-")[0]; } catch { return "en"; } })();
      const r = (await chrome.runtime.sendMessage({ type: "w3pg:overlayDeepScan", language: lang })) as DeepReport | { error: string } | undefined;
      renderDeepInline(out, r);
    } catch { out.textContent = deepErrorText(undefined); }
    if (host.isConnected) btn.disabled = false;
  });
  const mount = () => (document.documentElement || document.body).appendChild(host);
  // a page that deletes the card gets it back; only the user's own click closes it
  const keep = new MutationObserver(() => {
    if (orphaned()) { keep.disconnect(); host.remove(); current = null; return; } // a newer script owns the page now
    if (!closed && !host.isConnected) mount();
  });
  keep.observe(document.documentElement, { childList: true });
  disposeCurrent = () => { closed = true; keep.disconnect(); };
  mount();
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

function renderDeepInline(out: HTMLElement, r: DeepReport | { error: string } | undefined) {
  const err = !r || "error" in r ? (r && "error" in r ? r.error : "error") : (r.ai?.error ?? "");
  if (!r || "error" in r || err) {
    out.innerHTML = `<div class="sbx">${esc(deepErrorText(String(err), r && "ai" in r ? r.ai?.retryAfterMin : undefined))}</div>`;
    return;
  }
  const ai = r.ai ?? {};
  const v = ai.verdict ?? "safe";
  const cls = v === "dangerous" ? "dangerous" : v === "suspicious" ? "suspicious" : "safe";
  const conf = Math.round((ai.confidence ?? 0) * 100);
  const imp = ai.impersonates ? " · " + t("popup_impersonates", [ai.impersonates]) : "";
  const reasons = (ai.reasons ?? []).slice(0, 4).map((x) => `<li>${esc(x)}</li>`).join("");
  const sb = r.sandbox;
  const sbxLine = sb && sb.ok
    ? `<div class="sbx">${esc(t("popup_sandbox_title"))}: ${esc(sb.challenge ? t("sbx_state_challenge") : t("verdict_" + (sb.verdict ?? "unknown")))}</div>`
    : "";
  out.innerHTML = `<div class="v ${cls}">${esc(t("verdict_" + v))} · ${conf}%${esc(imp)}</div>${ai.summary ? `<div class="sum">${esc(ai.summary)}</div>` : ""}${reasons ? `<ul>${reasons}</ul>` : ""}${sbxLine}`;
}

const clear = () => { disposeCurrent?.(); disposeCurrent = null; current?.remove(); current = null; shownScore = -1; };

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "w3pg:overlay" && msg.verdict) { shownScore = (msg.verdict as Verdict).score; render(msg.verdict as Verdict); }
  if (msg?.type === "w3pg:clear") clear();
});

// If the verdict was decided before this script loaded, ask for it; ask again later for slow pages / SPAs.
let shownScore = -1;
let settledClean = false;
function pull() {
  if (orphaned()) { clear(); return; }
  try {
    chrome.runtime.sendMessage({ type: "w3pg:getVerdict" }).then((v: Verdict | undefined) => {
      if (v && v.band === "warn" && v.score !== shownScore) { shownScore = v.score; render(v); }
      else if (v && v.band !== "warn") { settledClean = true; clear(); }
    }).catch(() => clear());
  } catch { clear(); }
}
pull();
// later signals (a WalletConnect modal, a wallet request) raise the score after the first render: keep the card in
// step even if a pushed update was missed, cheaply, for the first minutes of the page's life
let pulls = 0;
// a clean page stops re-polling once the background has answered with a non-warn verdict (no more service-worker wakeups); pushed updates and visibilitychange still apply
const repull = () => { if (settledClean || orphaned()) return; if (document.visibilityState === "visible") pull(); if (++pulls < 24) setTimeout(repull, 5000); };
setTimeout(repull, 5000);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") pull(); });
