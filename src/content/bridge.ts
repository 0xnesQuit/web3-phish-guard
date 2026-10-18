/**
 * Isolated-world relay (document_start, every frame):
 *  - hands the MAIN-world guard a private MessageChannel port before any page script runs
 *  - forwards the guard's provider events to the background
 *  - answers the guard's "gate" requests: asks the background whether the request should be held, renders the
 *    confirmation modal when it should (always in the top frame, so an invisible iframe cannot hide it), and
 *    sends the decision back over the port
 */
import { t } from "../lib/i18n";

const TAG = "w3pg";

interface GateDetails { id: string; method: string; kind: string; counterparty?: string; counterpartyEoa?: boolean; unlimited?: boolean; token?: string; poisonedTwin?: string; batch?: string[]; primaryType?: string; deadline?: string; hadGesture: boolean }
type Decision = { ask: boolean; reason?: string; score?: number };

// ---- private channel -------------------------------------------------------------------
const channel = new MessageChannel();
const port = channel.port1;
port.onmessage = (e) => {
  const d = e.data;
  if (!d || typeof d !== "object") return;
  if (d.type === "event" && d.event) chrome.runtime.sendMessage({ type: "w3pg:provider", event: d.event }).catch(() => undefined);
  if (d.type === "gate" && d.gate) void handleGate(d.gate as GateDetails);
};
try { window.postMessage({ source: TAG + "-ext", type: "port" }, "*", [channel.port2]); } catch { /* ignore */ }

async function handleGate(g: GateDetails) {
  let decision: Decision = { ask: false };
  try {
    decision = (await chrome.runtime.sendMessage({ type: "w3pg:gate", details: g })) ?? { ask: false };
  } catch { /* background unavailable: the guard's own fail-closed rule applies */ }
  port.postMessage({ type: "gate-ack", id: g.id, ask: decision.ask });
  let allow = true;
  if (decision.ask) {
    if (window.top !== window) {
      // raise the modal in the top frame; fall back to this frame if the top frame cannot be reached
      try {
        const r = (await chrome.runtime.sendMessage({ type: "w3pg:gateTop", details: g, decision, frameHost: location.hostname })) as { allow?: boolean } | undefined;
        allow = typeof r?.allow === "boolean" ? r.allow : await modal(g, decision, location.hostname);
      } catch { allow = await modal(g, decision, location.hostname); }
    } else {
      allow = await modal(g, decision, location.hostname);
    }
  }
  port.postMessage({ type: "gate-result", id: g.id, allow });
  if (!allow) chrome.runtime.sendMessage({ type: "w3pg:gateRejected", details: g }).catch(() => undefined);
}

// the top frame renders modals for its iframes
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "w3pg:showGate" || window.top !== window) return;
  modal(msg.details as GateDetails, (msg.decision as Decision) ?? { ask: true }, String(msg.frameHost ?? location.hostname)).then((allow) => sendResponse({ allow }));
  return true;
});

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
const short = (a?: string) => (a ? `${a.slice(0, 8)}…${a.slice(-6)}` : "");

function modal(g: GateDetails, d: { reason?: string; score?: number }, hostLabel: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.id = "w3pg-gate";
    host.style.cssText = "all:initial !important;position:fixed !important;inset:0 !important;z-index:2147483647 !important;display:block !important;";
    const root = host.attachShadow({ mode: "closed" });
    const rows: string[] = [];
    const kindText = t(`gate_kind_${g.kind.replace(/-/g, "_")}`) || g.kind;
    rows.push(`<li>${esc(t("gate_request"))}: <b>${esc(kindText)}</b>${g.primaryType ? ` (${esc(g.primaryType)})` : ""}</li>`);
    if (g.counterparty) rows.push(`<li>${esc(t("gate_counterparty"))}: <code>${esc(short(g.counterparty))}</code>${g.counterpartyEoa ? ` <b class="bad">${esc(t("gate_eoa"))}</b>` : ""}</li>`);
    if (g.unlimited) rows.push(`<li class="bad">${esc(t("gate_unlimited"))}</li>`);
    if (g.poisonedTwin) rows.push(`<li class="bad">${esc(t("gate_poison", [short(g.poisonedTwin)]))}</li>`);
    if (g.batch) rows.push(`<li>${esc(t("gate_batch", [g.batch.join(", ")]))}</li>`);
    if (!g.hadGesture) rows.push(`<li class="bad">${esc(t("gate_no_click"))}</li>`);
    if (d.reason) rows.push(`<li>${esc(d.reason)}</li>`);
    root.innerHTML = `
      <style>
        .bg{position:fixed;inset:0;background:rgba(0,0,0,.72);display:flex;align-items:center;justify-content:center;font:14px/1.5 system-ui,sans-serif}
        .card{max-width:520px;width:calc(100% - 32px);background:#1b0e0e;color:#f5e9e9;border:2px solid #e5484d;border-radius:14px;padding:22px 24px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
        h1{font-size:18px;margin:0 0 6px;color:#ff6b6b}
        .sub{opacity:.8;margin-bottom:12px}
        ul{margin:0 0 14px;padding-left:18px}
        li{margin:4px 0}
        .bad{color:#ff9b9b}
        code{font-family:ui-monospace,monospace;background:#2a1414;padding:1px 6px;border-radius:5px}
        .row{display:flex;gap:10px;flex-wrap:wrap}
        button{font:inherit;font-weight:600;padding:10px 16px;border-radius:9px;border:0;cursor:pointer}
        .rej{background:#e5484d;color:#fff}
        .ok{background:transparent;color:#f5b8b8;border:1px solid #7a3030}
        .ok:hover{background:#2a1414}
        .host{font-size:12px;opacity:.6;margin-top:10px;word-break:break-all}
      </style>
      <div class="bg" role="dialog" aria-modal="true" aria-labelledby="w3pg-t">
        <div class="card">
          <h1 id="w3pg-t">${esc(t("gate_title"))}</h1>
          <div class="sub">${esc(t("gate_sub", [String(d.score ?? "")]))}</div>
          <ul>${rows.join("")}</ul>
          <div class="row">
            <button class="rej" id="rej">${esc(t("gate_reject"))}</button>
            <button class="ok" id="ok">${esc(t("gate_allow"))}</button>
          </div>
          <div class="host">${esc(hostLabel)}</div>
        </div>
      </div>`;
    let settled = false;
    const mount = () => (document.documentElement || document.body).appendChild(host);
    // a page that removes the dialog node gets it straight back; only the user's click settles the request
    const keep = new MutationObserver(() => { if (!settled && !host.isConnected) mount(); });
    keep.observe(document.documentElement, { childList: true, subtree: false });
    const done = (allow: boolean) => { settled = true; keep.disconnect(); host.remove(); resolve(allow); };
    root.getElementById("rej")!.addEventListener("click", (e) => { if (e.isTrusted) done(false); });
    root.getElementById("ok")!.addEventListener("click", (e) => { if (e.isTrusted) done(true); });
    root.addEventListener("keydown", (e) => { if (e.isTrusted && (e as KeyboardEvent).key === "Escape") done(false); });
    mount();
    setTimeout(() => (root.getElementById("rej") as HTMLButtonElement | null)?.focus(), 0);
  });
}
