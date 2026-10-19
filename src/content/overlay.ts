/**
 * In-page warning for the "warn" band. Does not block the page.
 *
 * A compact card in the bottom-right corner, so a site's own dialogs (wallet-connect modals, cookie bars, footers)
 * stay usable. After a few seconds, or as soon as the user interacts with the page, it folds into a one-line
 * badge; hovering or clicking the badge opens the card again. Only the user's own click closes it.
 */
import type { Verdict } from "../lib/types";
import { t, signalText } from "../lib/i18n";

const ID = "w3pg-banner";
const COLLAPSE_AFTER_MS = 8000;
let current: HTMLElement | null = null;

/** After an extension update the old content script lingers in open tabs; its chrome.runtime.id is gone. */
const orphaned = () => { try { return !chrome.runtime?.id; } catch { return true; } };

function render(v: Verdict) {
  current?.remove();
  // cards left behind by a previous script instance (extension reload / update)
  for (const old of Array.from(document.querySelectorAll("#" + ID))) old.remove();
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
      </div>
    </div>`;
  const card = root.getElementById("card") as HTMLElement;
  let closed = false;
  let pinnedOpen = false;
  const collapse = () => { if (!pinnedOpen) card.classList.add("min"); };
  const expand = () => card.classList.remove("min");
  let timer: number | undefined = window.setTimeout(collapse, COLLAPSE_AFTER_MS);
  const onFirstInteraction = (e: Event) => { if (!e.isTrusted || !host.isConnected) return; if (timer !== undefined) { clearTimeout(timer); timer = undefined; } collapse(); };
  // the user started using the page: get out of the way
  window.addEventListener("pointerdown", onFirstInteraction, { capture: true, passive: true });
  window.addEventListener("keydown", onFirstInteraction, { capture: true, passive: true });
  card.addEventListener("mouseenter", expand);
  card.addEventListener("mouseleave", () => { if (!pinnedOpen) collapse(); });
  root.getElementById("head")!.addEventListener("click", (e) => { if (!e.isTrusted || (e.target as HTMLElement).id === "close") return; pinnedOpen = !pinnedOpen; if (pinnedOpen) expand(); else collapse(); });
  root.getElementById("close")!.addEventListener("click", (e) => { if (!e.isTrusted) return; closed = true; keep.disconnect(); host.remove(); current = null; });
  const mount = () => (document.documentElement || document.body).appendChild(host);
  // a page that deletes the card gets it back; only the user's own click closes it
  const keep = new MutationObserver(() => {
    if (orphaned()) { keep.disconnect(); host.remove(); current = null; return; } // a newer script owns the page now
    if (!closed && !host.isConnected) mount();
  });
  keep.observe(document.documentElement, { childList: true });
  mount();
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

const clear = () => { current?.remove(); current = null; shownScore = -1; };

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "w3pg:overlay" && msg.verdict) { shownScore = (msg.verdict as Verdict).score; render(msg.verdict as Verdict); }
  if (msg?.type === "w3pg:clear") clear();
});

// If the verdict was decided before this script loaded, ask for it; ask again later for slow pages / SPAs.
let shownScore = -1;
function pull() {
  if (orphaned()) { clear(); return; }
  try {
    chrome.runtime.sendMessage({ type: "w3pg:getVerdict" }).then((v: Verdict | undefined) => {
      if (v && v.band === "warn" && v.score !== shownScore) { shownScore = v.score; render(v); }
      else if (v && v.band !== "warn") clear();
    }).catch(() => clear());
  } catch { clear(); }
}
pull();
// later signals (a WalletConnect modal, a wallet request) raise the score after the first render: keep the card in
// step even if a pushed update was missed, cheaply, for the first minutes of the page's life
let pulls = 0;
const repull = () => { if (document.visibilityState === "visible") pull(); if (++pulls < 24) setTimeout(repull, 5000); };
setTimeout(repull, 5000);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") pull(); });
