import type { Verdict } from "../lib/types";

const $ = (id: string) => document.getElementById(id)!;

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const v = tab?.id !== undefined ? ((await chrome.runtime.sendMessage({ type: "w3pg:getVerdict", tabId: tab.id })) as Verdict | undefined) : undefined;
  const badge = $("badge");

  if (!v) {
    $("host").textContent = tab?.url ? new URL(tab.url).hostname : "–";
    badge.textContent = "kontrol dışı";
    badge.className = "badge none";
  } else {
    $("host").textContent = v.host;
    badge.textContent = v.band === "block" ? `engellendi · ${v.score}` : v.band === "warn" ? `şüpheli · ${v.score}` : `temiz · ${v.score}`;
    badge.className = `badge ${v.band === "none" ? "safe" : v.band}`;
    $("reasons").innerHTML = v.signals.map((s) => `<li>${esc(s.label)}${s.weight ? ` <span style="opacity:.5">(+${s.weight})</span>` : ""}</li>`).join("");
    if (v.band !== "none") {
      const btn = $("allow") as HTMLButtonElement;
      btn.hidden = false;
      btn.onclick = async () => {
        await chrome.runtime.sendMessage({ type: "w3pg:allow", registrable: v.registrable });
        btn.textContent = "Eklendi. Sayfayı yenileyin.";
        btn.disabled = true;
      };
    }
  }

  const st = (await chrome.runtime.sendMessage({ type: "w3pg:status" })) as { lists: Record<string, { count: number; updatedAt: number }>; userAllow: string[] };
  $("meta").innerHTML = Object.entries(st.lists)
    .map(([k, s]) => `${esc(k)}: ${s.count.toLocaleString("tr-TR")} domain${s.updatedAt ? ` · ${new Date(s.updatedAt).toLocaleString("tr-TR")}` : " · henüz indirilmedi"}`)
    .join("<br>") + (st.userAllow.length ? `<br>güvenilir: ${st.userAllow.map(esc).join(", ")}` : "");
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

main().catch((e) => { $("meta").textContent = String(e); });
