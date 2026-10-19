/**
 * Isolated-world side of the wallet gate (document_start, every frame).
 *
 * The MAIN-world guard (provider-guard.ts) only hooks and relays; everything that decides lives here, in a JavaScript
 * realm the page cannot reach: decoding calldata and typed data, the EOA-spender and address-poisoning checks,
 * ClickFix / clipboard patterns, the gate decision (via the background) and the confirmation modal (rendered in the
 * top frame, re-mounted if removed, trusted clicks only). Answers travel back over a MessageChannel port the guard
 * received before any page script ran.
 */
import { t } from "../lib/i18n";
import { decodeTx, decodeSendCalls, decodeTypedData, looksPoisoned, CLICKFIX_RE, CRYPTO_ADDR_RE, type TxIntent, type SignIntent } from "../lib/txdecode";

const TAG = "w3pg";

interface GateDetails { id: string; method: string; kind: string; counterparty?: string; counterpartyEoa?: boolean; unlimited?: boolean; token?: string; poisonedTwin?: string; batch?: string[]; primaryType?: string; deadline?: string; hadGesture: boolean }
type Decision = { ask: boolean; reason?: string; score?: number };
interface InspectMsg { type: "inspect"; id: string; method: string; params: unknown; chain: "evm" | "solana"; hadGesture: boolean; msSinceLoad: number }

const ALWAYS_HOLD = new Set(["setApprovalForAll", "approve-unlimited", "permit2", "permit", "permit-batch", "permit-for-all", "delegation", "delegation-7702", "eth_sign", "seaport-order", "blur-order", "transfer-auth", "safe-delegatecall", "agent-approval", "undecodable"]);

// ---- private channel -------------------------------------------------------------------
const channel = new MessageChannel();
const port = channel.port1;
const codeWaiters = new Map<string, (code: string | null) => void>();
port.onmessage = (e) => {
  const d = e.data;
  if (!d || typeof d !== "object") return;
  if (d.type === "event" && d.event) void safeSend({ type: "w3pg:provider", event: d.event });
  else if (d.type === "inspect") void handleInspect(d as InspectMsg);
  else if (d.type === "code") { const w = codeWaiters.get(String(d.id)); if (w) { codeWaiters.delete(String(d.id)); w(typeof d.code === "string" ? d.code : null); } }
  else if (d.type === "copy") inspectCopy(String(d.text ?? ""), String(d.selection ?? ""));
};
try { window.postMessage({ source: TAG + "-ext", type: "port" }, "*", [channel.port2]); } catch { /* ignore */ }

/** runtime calls throw synchronously once the extension context is invalidated (after an update); never let that escape */
const safeSend = (msg: unknown): Promise<unknown> => { try { return chrome.runtime.sendMessage(msg).catch(() => undefined); } catch { return Promise.resolve(undefined); } };
const post = (event: Record<string, unknown>) => safeSend({ type: "w3pg:provider", event });

/** eth_getCode through the page's provider (the guard runs it with the unwrapped request). A 7702-delegated EOA counts as an EOA. */
function isEoa(address: string | undefined): Promise<boolean | undefined> {
  if (!address || !/^0x[0-9a-f]{40}$/.test(address)) return Promise.resolve(undefined);
  const id = Math.random().toString(36).slice(2);
  return new Promise((resolve) => {
    const timer = setTimeout(() => { codeWaiters.delete(id); resolve(undefined); }, 3500);
    codeWaiters.set(id, (code) => {
      clearTimeout(timer);
      if (code === null) { resolve(undefined); return; }
      const c = code.toLowerCase();
      resolve(c === "0x" || c === "0x0" || c === "" || c.startsWith("0xef0100"));
    });
    port.postMessage({ type: "getCode", id, address });
  });
}

// ---- recipients seen on this origin (address poisoning) ----
const knownRecipients: string[] = [];
function checkPoison(to: string | undefined): string | undefined {
  if (!to || !/^0x[0-9a-fA-F]{40}$/.test(to)) return undefined;
  const twin = looksPoisoned(to, knownRecipients);
  if (!twin && !knownRecipients.includes(to.toLowerCase())) knownRecipients.push(to.toLowerCase());
  return twin;
}

async function handleInspect(m: InspectMsg): Promise<void> {
  let allow = true;
  try {
    const r = await inspect(m);
    allow = r;
  } catch { allow = true; }
  port.postMessage({ type: "decision", id: m.id, allow });
}

/** Mirrors the former MAIN-world logic: name the intent, report it, and hold what needs holding. */
async function inspect(m: InspectMsg): Promise<boolean> {
  const { method, params, hadGesture: g, msSinceLoad } = m;
  const p = Array.isArray(params) ? params : [];
  const ack = (hold: boolean) => port.postMessage({ type: "ack", id: m.id, hold });

  if (m.chain === "solana") {
    const batch = typeof (params as { batch?: number })?.batch === "number" ? (params as { batch: number }).batch : 1;
    post({ kind: "risky-tx", method, detail: batch > 1 ? "solana_batch" : "solana", param: method, msSinceLoad, hadGesture: g });
    ack(false);
    return gate({ id: m.id, method, kind: "solana-sign", batch: batch > 1 ? Array(batch).fill("sign") : undefined, hadGesture: g });
  }
  if (method === "eth_requestAccounts" || method === "wallet_requestPermissions" || method === "enable") {
    if (!g && msSinceLoad < 5000) post({ kind: "auto-connect", method, detail: "", msSinceLoad, hadGesture: g });
    ack(false); return true;
  }
  if (method === "wallet_switchEthereumChain" || method === "wallet_addEthereumChain") {
    if (!g) post({ kind: "chain-switch", method, detail: "", msSinceLoad, hadGesture: g });
    ack(false); return true;
  }
  // the guard could not snapshot a signing request (a page broke structuredClone, or params carry live getters):
  // never let an undecodable signing request through unseen
  if ((params as { w3pgUndecodable?: boolean } | null)?.w3pgUndecodable) {
    post({ kind: "risky-sign", method, detail: "undecodable", msSinceLoad, hadGesture: g });
    ack(true);
    return gate({ id: m.id, method, kind: "undecodable", hadGesture: g });
  }
  if (method === "eth_sign") {
    post({ kind: "risky-sign", method, detail: "eth_sign", msSinceLoad, hadGesture: g });
    ack(true);
    return gate({ id: m.id, method, kind: "eth_sign", hadGesture: g });
  }
  if (/^eth_signTypedData(_v[34])?$/.test(method)) {
    const td = p.find((x) => typeof x === "string" && x.includes("primaryType")) ?? p[1] ?? p[0];
    const s: SignIntent = decodeTypedData(td);
    if (s.kind === "other") { ack(false); return true; }
    ack(ALWAYS_HOLD.has(s.kind));
    post({ kind: "risky-sign", method, detail: "typed", param: s.primaryType, msSinceLoad, hadGesture: g });
    const eoa = await isEoa(s.counterparty);
    if (eoa) post({ kind: "risky-sign", method, detail: "eoa-spender", param: s.counterparty, msSinceLoad, hadGesture: g });
    return gate({ id: m.id, method, kind: s.kind, primaryType: s.primaryType, counterparty: s.counterparty, counterpartyEoa: eoa, deadline: s.deadline, hadGesture: g });
  }
  if (method === "eth_sendTransaction" || method === "eth_signTransaction" || method === "wallet_sendCalls") {
    const intent: TxIntent = method === "wallet_sendCalls" ? decodeSendCalls(p[0] as { calls?: never[] }) : decodeTx(p[0] as never);
    const flat = intent.kind === "multicall" ? intent.inner ?? [] : [intent];
    const risky = flat.filter((i) => ["approve-unlimited", "approve", "setApprovalForAll", "permit2", "transfer", "transferFrom", "delegation-7702", "unknown-payable", "eth-send"].includes(i.kind));
    if (intent.kind === "multicall" && (intent.inner?.length ?? 0) === 0 && method === "wallet_sendCalls" && ((p[0] as { calls?: unknown[] })?.calls?.length ?? 0) > 20) {
      // more calls than the decoder reads: hold rather than wave through
      ack(true);
      return gate({ id: m.id, method, kind: "undecodable", batch: ["calls>20"], hadGesture: g });
    }
    if (!risky.length) { ack(false); return true; }
    const top = risky.find((i) => i.kind === "delegation-7702") ?? risky.find((i) => i.kind === "setApprovalForAll") ?? risky.find((i) => i.kind === "approve-unlimited") ?? risky[0];
    ack(ALWAYS_HOLD.has(top.kind));
    const detailCode = top.kind === "approve-unlimited" ? "approve" : top.kind === "delegation-7702" ? "delegation" : top.kind === "unknown-payable" ? "payable_unknown" : top.kind === "eth-send" ? "eth_send" : top.kind;
    post({ kind: "risky-tx", method, detail: detailCode, param: top.counterparty, msSinceLoad, hadGesture: g });
    const twin = checkPoison(top.counterparty);
    const eoa = ["approve-unlimited", "approve", "setApprovalForAll", "permit2"].includes(top.kind) ? await isEoa(top.counterparty) : undefined;
    if (eoa) post({ kind: "risky-tx", method, detail: "eoa-spender", param: top.counterparty, msSinceLoad, hadGesture: g });
    if (twin) post({ kind: "risky-tx", method, detail: "poisoning", param: top.counterparty, msSinceLoad, hadGesture: g });
    return gate({ id: m.id, method, kind: top.kind, counterparty: top.counterparty, counterpartyEoa: eoa, unlimited: top.unlimited, token: top.token, poisonedTwin: twin, batch: flat.length > 1 ? flat.map((i) => i.kind) : undefined, hadGesture: g });
  }
  ack(false);
  return true;
}

/** Ask the background whether to hold; if so, show the modal (in the top frame) and return the user's answer. */
async function gate(g: GateDetails): Promise<boolean> {
  let decision: Decision = { ask: false };
  const fallback = { ask: ALWAYS_HOLD.has(g.kind) || g.counterpartyEoa === true || !!g.poisonedTwin };
  try {
    // background unavailable (or the context invalidated by an update): the kinds no legitimate flow needs fail
    // closed, everything else proceeds
    const r = (await safeSend({ type: "w3pg:gate", details: g })) as Decision | undefined;
    decision = r ?? fallback;
  } catch {
    decision = fallback;
  }
  if (!decision.ask) return true;
  // the modal is about to open: tell the guard to hold the request for as long as it takes
  port.postMessage({ type: "ack", id: g.id, hold: true });
  let allow: boolean;
  if (window.top !== window) {
    try {
      const r = (await safeSend({ type: "w3pg:gateTop", details: g, decision, frameHost: location.hostname })) as { allow?: boolean } | undefined;
      allow = typeof r?.allow === "boolean" ? r.allow : await modal(g, decision, location.hostname);
    } catch { allow = await modal(g, decision, location.hostname); }
  } else {
    allow = await modal(g, decision, location.hostname);
  }
  if (!allow) void safeSend({ type: "w3pg:gateRejected", details: g });
  return allow;
}

// the top frame renders modals for its iframes
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "w3pg:showGate" || window.top !== window) return;
  modal(msg.details as GateDetails, (msg.decision as Decision) ?? { ask: true }, String(msg.frameHost ?? location.hostname)).then((allow) => sendResponse({ allow }));
  return true;
});

// ---- clipboard patterns (text arrives from the guard) ----
function inspectCopy(text: string, selection: string) {
  if (!text) return;
  const now = performance.now();
  if (CLICKFIX_RE.test(text)) { post({ kind: "clickfix", method: "clipboard", detail: "clickfix", param: text.slice(0, 80), msSinceLoad: now, hadGesture: true }); return; }
  const copied = text.match(CRYPTO_ADDR_RE)?.[1];
  if (!copied) return;
  const selected = selection.match(CRYPTO_ADDR_RE)?.[1];
  if (selected && selected !== copied) post({ kind: "clipboard-swap", method: "clipboard", detail: "clipboard_swap", param: `${selected.slice(0, 8)}… → ${copied.slice(0, 8)}…`, msSinceLoad: now, hadGesture: true });
}

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
    // a page that removes the dialog node gets it straight back; only the user's click settles the request.
    // (A page can still cover it with its own top layer; the request stays held until this dialog is answered.)
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
