import type { Verdict } from "../lib/types";
import { t, signalText, localizePage } from "../lib/i18n";

const $ = (id: string) => document.getElementById(id)!;

async function main() {
  localizePage();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const v = tab?.id !== undefined ? ((await chrome.runtime.sendMessage({ type: "w3pg:getVerdict", tabId: tab.id })) as Verdict | undefined) : undefined;
  const badge = $("badge");

  if (!v) {
    $("host").textContent = tab?.url ? new URL(tab.url).hostname : "–";
    badge.textContent = t("popup_unchecked");
    badge.className = "badge none";
  } else {
    $("host").textContent = v.host;
    badge.textContent = `${t(v.band === "block" ? "popup_blocked" : v.band === "warn" ? "popup_suspicious" : "popup_clean")} · ${v.score}`;
    badge.className = `badge ${v.band === "none" ? "safe" : v.band}`;
    $("reasons").innerHTML = v.signals.map((s) => `<li>${esc(signalText(s))}${s.weight ? ` <span style="opacity:.5">(+${s.weight})</span>` : ""}</li>`).join("");
    if (v.band !== "none") {
      const btn = $("allow") as HTMLButtonElement;
      btn.hidden = false;
      btn.onclick = async () => {
        await chrome.runtime.sendMessage({ type: "w3pg:allow", registrable: v.registrable });
        btn.textContent = t("popup_added");
        btn.disabled = true;
      };
    }
  }

  $("options").onclick = () => chrome.runtime.openOptionsPage();
  const st = (await chrome.runtime.sendMessage({ type: "w3pg:status" })) as { lists: Record<string, { count: number; updatedAt: number }>; userAllow: string[]; data: { updatedAt: number; files: number } };
  $("meta").innerHTML = Object.entries(st.lists)
    .map(([k, s]) => `${esc(k)}: ${t("popup_domains", [s.count.toLocaleString()])}${s.updatedAt ? ` · ${new Date(s.updatedAt).toLocaleString()}` : ` · ${t("popup_not_downloaded")}`}`)
    .join("<br>") + `<br>${t("popup_brand_data")}: ${st.data.updatedAt ? new Date(st.data.updatedAt).toLocaleString() : t("popup_bundled")}` + (st.userAllow.length ? `<br>${t("popup_trusted")}: ${st.userAllow.map(esc).join(", ")}` : "");
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

main().catch((e) => { $("meta").textContent = String(e); });
