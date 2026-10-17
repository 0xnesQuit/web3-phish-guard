import type { DeepReport, Verdict } from "../lib/types";
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
  if (tab?.id !== undefined && tab.url && /^https?:/.test(tab.url)) {
    const tabId = tab.id;
    const existing = (await chrome.runtime.sendMessage({ type: "w3pg:getDeepReport", tabId })) as DeepReport | null;
    if (existing && !existing.ai.error) renderDeep(existing);
    $("deepscan").onclick = async () => {
      const btn = $("deepscan") as HTMLButtonElement;
      btn.disabled = true;
      const box = $("deep");
      box.style.display = "block";
      box.innerHTML = `<div class="spin">${esc(t("popup_scanning"))}</div>`;
      const r = (await chrome.runtime.sendMessage({ type: "w3pg:deepScan", tabId, language: chrome.i18n.getUILanguage().split("-")[0] })) as DeepReport | { error: string };
      btn.disabled = false;
      if ("error" in r && !("ai" in r)) { box.innerHTML = `<div>${esc(t("popup_scan_failed"))} (${esc(r.error)})</div>`; return; }
      renderDeep(r as DeepReport);
    };
    $("reportbtn").onclick = () => { ($("reportbox") as HTMLElement).hidden = false; $("note").focus(); };
    $("cancelreport").onclick = () => { ($("reportbox") as HTMLElement).hidden = true; };
    $("sendreport").onclick = async () => {
      const b = $("sendreport") as HTMLButtonElement;
      b.disabled = true;
      const r = (await chrome.runtime.sendMessage({ type: "w3pg:report", tabId, note: ($("note") as HTMLTextAreaElement).value })) as { ok: boolean; error?: string };
      ($("reportbox") as HTMLElement).hidden = true;
      b.disabled = false;
      $("reportbtn").textContent = r.ok ? t("popup_report_sent") : `${t("popup_report_failed")} (${r.error ?? ""})`;
      ($("reportbtn") as HTMLButtonElement).disabled = r.ok;
    };
  } else {
    ($("deepscan") as HTMLButtonElement).disabled = true;
    ($("reportbtn") as HTMLButtonElement).disabled = true;
  }
  const st = (await chrome.runtime.sendMessage({ type: "w3pg:status" })) as { lists: Record<string, { count: number; updatedAt: number }>; userAllow: string[]; data: { updatedAt: number; files: number } };
  $("meta").innerHTML = Object.entries(st.lists)
    .map(([k, s]) => `${esc(k)}: ${t("popup_domains", [s.count.toLocaleString()])}${s.updatedAt ? ` · ${new Date(s.updatedAt).toLocaleString()}` : ` · ${t("popup_not_downloaded")}`}`)
    .join("<br>") + `<br>${t("popup_brand_data")}: ${st.data.updatedAt ? new Date(st.data.updatedAt).toLocaleString() : t("popup_bundled")}` + (st.userAllow.length ? `<br>${t("popup_trusted")}: ${st.userAllow.map(esc).join(", ")}` : "");
}

function renderDeep(r: DeepReport) {
  const box = $("deep");
  box.style.display = "block";
  const ai = r.ai;
  const facts = `${t("popup_facts_libs")}: ${r.page.libs.join(", ") || "–"} · ${t("popup_facts_scripts")}: ${r.page.scripts.length} · ${t("popup_facts_wallet")}: ${r.page.walletButtons.length} · ${t("popup_facts_seed")}: ${r.page.seedPhraseInputs} · ${t("popup_facts_markers")}: ${[...r.page.drainerMarkers, ...r.markers].length}${r.goplus?.phishing ? " · GoPlus: phishing" : ""}`;
  if (ai.error) {
    box.innerHTML = `<div class="v ${r.local.band === "block" ? "dangerous" : r.local.band === "warn" ? "suspicious" : "likely_safe"}">${esc(t("popup_local_only"))} · ${r.local.score}/100</div><div>${esc(t("popup_ai_unavailable"))} (${esc(ai.error)})</div><div class="facts">${esc(facts)}</div>`;
    return;
  }
  const label = t(`verdict_${ai.verdict}`);
  box.innerHTML = `
    <div class="v ${esc(ai.verdict ?? "")}">${esc(label)} · ${Math.round((ai.confidence ?? 0) * 100)}%${ai.impersonates ? ` · ${esc(t("popup_impersonates", [ai.impersonates]))}` : ""}</div>
    <div>${esc(ai.summary ?? "")}</div>
    <ul>${(ai.reasons ?? []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    ${(ai.advice ?? []).length ? `<div class="adv">${(ai.advice ?? []).map((x) => `→ ${esc(x)}`).join("<br>")}</div>` : ""}
    <div class="facts">${esc(facts)}${ai.cached ? " · cached" : ""}</div>`;
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

main().catch((e) => { $("meta").textContent = String(e); });
