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
let fired = false;

export function looksLikeSeed(text: string): "mnemonic" | "private-key" | null {
  const s = text.trim();
  if (!s) return null;
  if (PRIV_HEX.test(s) && s.replace(/\s/g, "").length <= 70) return "private-key";
  if (SOL_KEY.test(s)) return "private-key";
  const words = s.toLowerCase().split(/[\s,]+/).filter(Boolean);
  if (words.length < 11 || words.length > 25) return null;
  const hits = words.filter((w) => WORDS.has(w)).length;
  return hits >= Math.max(11, Math.floor(words.length * 0.9)) ? "mnemonic" : null;
}

function allInputs(): string[] {
  const out: string[] = [];
  for (const el of Array.from(document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement | HTMLElement>("input, textarea, [contenteditable=''], [contenteditable='true']"))) {
    const v = "value" in el ? String((el as HTMLInputElement).value ?? "") : (el.textContent ?? "");
    if (v) out.push(v);
  }
  // 12 separate single-word inputs (the usual wallet "restore" layout) count as one phrase
  const singles = Array.from(document.querySelectorAll<HTMLInputElement>("input")).map((i) => (i.value ?? "").trim().toLowerCase()).filter((v) => v && /^[a-z]+$/.test(v));
  if (singles.length >= 11) out.push(singles.join(" "));
  return out;
}

function check() {
  if (fired) return;
  for (const text of allInputs()) {
    const kind = looksLikeSeed(text);
    if (kind) { fired = true; stop(kind); return; }
  }
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
  root.getElementById("stay")!.addEventListener("click", () => { host.remove(); fired = false; setTimeout(() => (fired = false), 0); });
  (document.documentElement || document.body).appendChild(host);
  (root.getElementById("leave") as HTMLButtonElement | null)?.focus();
}

let timer: number | undefined;
const schedule = () => { if (timer === undefined) timer = window.setTimeout(() => { timer = undefined; check(); }, 250); };
document.addEventListener("input", schedule, true);
document.addEventListener("paste", () => setTimeout(check, 50), true);
document.addEventListener("submit", check, true);
