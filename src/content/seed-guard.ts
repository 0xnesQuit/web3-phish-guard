/**
 * Seed-phrase / private-key input guard (isolated world, every page).
 * Watches typed and pasted text in inputs, textareas and contenteditable elements. A 12/15/18/21/24-word BIP39
 * sequence, a 64-hex private key or an 88-char base58 Solana key triggers a full-page stop before anything is
 * submitted. The text never leaves the page: only the fact that a phrase was entered is reported.
 */
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { t } from "../lib/i18n";

const WORDS = new Set(wordlist);
const PRIV_HEX = /\b(0x)?[0-9a-fA-F]{64}\b/;
const SOL_KEY = /\b[1-9A-HJ-NP-Za-km-z]{86,90}\b/;
/** words near an input that say "this field is for a key" (a bare 64-hex string is just as likely a tx hash) */
const KEY_CONTEXT_RE = /private\s*key|secret\s*key|priv\s*key|özel\s*anahtar|gizli\s*anahtar|privater\s*schlüssel|clave\s*privada|cl[eé]\s*priv[eé]e|chave\s*privada|приватн|закрытый\s*ключ|निजी\s*कुंजी|私钥|秘密鍵|개인\s*키|khóa\s*riêng|kunci\s*privat|import\s*wallet|restore\s*wallet|recover\s*wallet/i;
let fired = false;
/** the user chose "stay" on this page: do not interrupt again for the page's lifetime */
let suppressed = false;

export function looksLikeSeed(text: string, keyContext = false): "mnemonic" | "private-key" | null {
  const s = text.trim();
  if (!s) return null;
  // A 64-hex string or an 88-char base58 blob is also what a transaction hash / signature looks like, and people
  // paste those into explorers all day. Only call it a key when the page asks for one.
  if (keyContext && PRIV_HEX.test(s) && s.replace(/\s/g, "").length <= 70) return "private-key";
  if (keyContext && SOL_KEY.test(s)) return "private-key";
  const words = s.toLowerCase().split(/[\s,]+/).filter(Boolean);
  if (words.length < 11 || words.length > 25) return null;
  const hits = words.filter((w) => WORDS.has(w)).length;
  return hits >= Math.max(11, Math.floor(words.length * 0.9)) ? "mnemonic" : null;
}

/** Does the field, its label or the surrounding text say it is for a private key? */
function keyContextOf(el: Element | null): boolean {
  if (!el) return false;
  const bits: string[] = [];
  const input = el as HTMLInputElement;
  bits.push(input.placeholder ?? "", input.name ?? "", input.id ?? "", el.getAttribute("aria-label") ?? "", el.getAttribute("autocomplete") ?? "");
  if (input.labels) for (const l of Array.from(input.labels)) bits.push(l.textContent ?? "");
  let node: Element | null = el;
  for (let i = 0; i < 4 && node; i++) { bits.push((node as HTMLElement).innerText?.slice(0, 400) ?? ""); node = node.parentElement; }
  bits.push(document.title);
  return KEY_CONTEXT_RE.test(bits.join(" "));
}

/** inputs anywhere, including open shadow roots */
function allFields(root: ParentNode = document): Array<HTMLInputElement | HTMLTextAreaElement | HTMLElement> {
  const out: Array<HTMLInputElement | HTMLTextAreaElement | HTMLElement> = [];
  for (const el of Array.from(root.querySelectorAll<HTMLElement>("input, textarea, [contenteditable=''], [contenteditable='true'], *"))) {
    if (el.matches("input, textarea, [contenteditable=''], [contenteditable='true']")) out.push(el);
    if (el.shadowRoot) out.push(...allFields(el.shadowRoot));
  }
  return out;
}

function allInputs(): Array<{ text: string; el: Element | null }> {
  const out: Array<{ text: string; el: Element | null }> = [];
  const fields = allFields();
  for (const el of fields) {
    const v = "value" in el ? String((el as HTMLInputElement).value ?? "") : (el.textContent ?? "");
    if (v) out.push({ text: v, el });
  }
  // 12 separate single-word inputs (the usual wallet "restore" layout) count as one phrase
  const singles = fields.filter((f): f is HTMLInputElement => f instanceof HTMLInputElement).map((i) => (i.value ?? "").trim().toLowerCase()).filter((v) => v && /^[a-z]+$/.test(v));
  if (singles.length >= 11) out.push({ text: singles.join(" "), el: null });
  return out;
}

function check() {
  if (fired || suppressed) return;
  for (const { text, el } of allInputs()) {
    const kind = looksLikeSeed(text, keyContextOf(el));
    if (kind) { fired = true; stop(kind); return; }
  }
}

/** Paste is checked synchronously: a keystroke-exfiltrating kit must not get the phrase before the stop goes up. */
function onPaste(e: ClipboardEvent) {
  if (fired || suppressed) return;
  try {
    const text = e.clipboardData?.getData("text/plain") ?? "";
    const target = (e.composedPath()[0] as Element | undefined) ?? null;
    const kind = looksLikeSeed(text, keyContextOf(target));
    if (kind) { e.preventDefault(); e.stopImmediatePropagation(); fired = true; stop(kind); }
  } catch { /* ignore */ }
}

function stop(kind: "mnemonic" | "private-key") {
  chrome.runtime.sendMessage({ type: "w3pg:provider", event: { kind: "seed-input", method: "input", detail: kind === "mnemonic" ? "seed_phrase" : "private_key", msSinceLoad: 0, hadGesture: true } }).catch(() => undefined);
  const host = document.createElement("div");
  host.id = "w3pg-seed";
  host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;";
  const root = host.attachShadow({ mode: "closed" });
  const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
  root.innerHTML = `
    <style>
      .bg{position:fixed;inset:0;background:rgba(20,0,0,.94);display:flex;align-items:center;justify-content:center;font:15px/1.5 system-ui,sans-serif;color:#f5e9e9}
      .card{max-width:560px;width:calc(100% - 32px);padding:28px}
      h1{font-size:24px;margin:0 0 10px;color:#ff6b6b}
      p{margin:8px 0}
      .row{display:flex;gap:10px;margin-top:18px;flex-wrap:wrap}
      button{font:inherit;font-weight:600;padding:12px 18px;border-radius:10px;border:0;cursor:pointer}
      .leave{background:#e5484d;color:#fff}
      .stay{background:transparent;color:#f5b8b8;border:1px solid #7a3030}
    </style>
    <div class="bg" role="alertdialog" aria-modal="true">
      <div class="card">
        <h1>${esc(t(kind === "mnemonic" ? "seed_title" : "key_title"))}</h1>
        <p>${esc(t("seed_body"))}</p>
        <p>${esc(t("seed_body2"))}</p>
        <div class="row">
          <button class="leave" id="leave">${esc(t("seed_leave"))}</button>
          <button class="stay" id="stay">${esc(t("seed_stay"))}</button>
        </div>
      </div>
    </div>`;
  root.getElementById("leave")!.addEventListener("click", () => { chrome.runtime.sendMessage({ type: "w3pg:leaveTab" }).catch(() => undefined); });
  root.getElementById("stay")!.addEventListener("click", (e) => { if (!e.isTrusted) return; host.remove(); suppressed = true; });
  (document.documentElement || document.body).appendChild(host);
  (root.getElementById("leave") as HTMLButtonElement | null)?.focus();
}

let timer: number | undefined;
const schedule = () => { if (timer === undefined) timer = window.setTimeout(() => { timer = undefined; check(); }, 250); };
window.addEventListener("input", schedule, true);
window.addEventListener("paste", onPaste, true);
window.addEventListener("submit", check, true);
