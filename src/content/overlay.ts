/** In-page warning banner for the "warn" band. Does not block the page. */
import type { Verdict } from "../lib/types";

const ID = "w3pg-banner";

function render(v: Verdict) {
  document.getElementById(ID)?.remove();
  const host = document.createElement("div");
  host.id = ID;
  host.style.cssText = "all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;";
  const root = host.attachShadow({ mode: "closed" });
  const reasons = v.signals.filter((s) => s.weight > 0).map((s) => `<li>${esc(s.label)}</li>`).join("");
  root.innerHTML = `
    <style>
      .b{font:14px/1.4 system-ui,sans-serif;background:#3a2a00;color:#ffe6a8;border-bottom:3px solid #f5a524;padding:12px 16px;display:flex;gap:14px;align-items:flex-start;box-shadow:0 4px 16px rgba(0,0,0,.4)}
      .i{font-size:22px;line-height:1}
      .t{font-weight:700;margin-bottom:4px}
      ul{margin:4px 0 0;padding-left:18px}
      .x{margin-left:auto;background:transparent;border:1px solid #a97a1a;color:#ffe6a8;border-radius:6px;padding:4px 10px;cursor:pointer;font:inherit}
      .s{opacity:.8;font-size:12px;margin-top:6px}
    </style>
    <div class="b">
      <div class="i">⚠️</div>
      <div>
        <div class="t">Web3 Phish Guard: bu site şüpheli görünüyor (risk ${v.score}/100)</div>
        <ul>${reasons}</ul>
        <div class="s">Cüzdanınızı bağlamadan ve hiçbir şey imzalamadan önce adresi projenin resmi X/Discord hesabından doğrulayın.</div>
      </div>
      <button class="x" id="close">Kapat</button>
    </div>`;
  root.getElementById("close")?.addEventListener("click", () => host.remove());
  (document.documentElement || document.body).appendChild(host);
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "w3pg:overlay" && msg.verdict) render(msg.verdict as Verdict);
});

// If the verdict was decided before this script loaded, ask for it.
chrome.runtime.sendMessage({ type: "w3pg:getVerdict" }).then((v: Verdict | undefined) => {
  if (v && v.band === "warn") render(v);
}).catch(() => undefined);
