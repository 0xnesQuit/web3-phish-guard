import type { DeepReport, SandboxReport, Verdict } from "../lib/types";
import { queueSandbox, pollJob, cancelJob, asReport, addJob, removeJob, getJobs, getDone, sameUrl } from "../lib/sandboxq";
import { t, signalText, localizePage, deepErrorText } from "../lib/i18n";

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
    $("reasons").innerHTML = v.signals.map((s) => `<li>${esc(signalText(s))}${s.weight ? ` <span style="opacity:.5">(${s.weight > 0 ? "+" : ""}${s.weight})</span>` : ""}</li>`).join("");
    if (v.band !== "none") {
      const btn = $("allow") as HTMLButtonElement;
      btn.hidden = false;
      const risky = v.signals.some((s) => s.id.startsWith("provider-") || s.id === "blocklist");
      let armed = !risky;
      btn.onclick = async () => {
        if (!armed) { armed = true; btn.textContent = t("popup_allow_confirm"); return; }
        await chrome.runtime.sendMessage({ type: "w3pg:allow", registrable: v.registrable });
        btn.textContent = t("popup_added");
        btn.disabled = true;
      };
    }
  }

  $("options").onclick = () => chrome.runtime.openOptionsPage();
  // The stored deep report is keyed by tab id, so it is shown even when the tab is the extension's warning page.
  const isHttp = tab?.id !== undefined && !!tab.url && /^https?:/.test(tab.url);
  if (tab?.id !== undefined) {
    const existing = (await chrome.runtime.sendMessage({ type: "w3pg:getDeepReport", tabId: tab.id })) as DeepReport | null;
    if (isHttp) {
      sb.url = tab.url!;
      sb.title = tab.title;
      chrome.action.setBadgeText({ text: "" }).catch(() => undefined); // clears the "sandbox result waiting" fallback badge
    }
    if (existing && !existing.ai.error) renderDeep(existing);
    // no live sandbox jobs can be matched without an http url; the report's own sandbox block is already painted
    if (isHttp) await restoreSandbox(!!existing && !existing.ai.error);
  }
  if (isHttp && tab?.id !== undefined) {
    const tabId = tab.id;
    $("deepscan").onclick = async () => {
      const btn = $("deepscan") as HTMLButtonElement;
      btn.disabled = true;
      // Firefox 140+: the optional data-collection permission must be requested from a user-input handler, which
      // this click is; the background cannot do it on our behalf.
      try {
        const bss = chrome.runtime.getManifest().browser_specific_settings as { gecko?: { data_collection_permissions?: unknown } } | undefined;
        const perms = chrome.permissions as unknown as { request?: (p: { data_collection?: string[] }) => Promise<boolean>; contains?: (p: { data_collection?: string[] }) => Promise<boolean> };
        if (bss?.gecko?.data_collection_permissions && perms?.request) {
          const wanted = { data_collection: ["websiteContent"] };
          const has = perms.contains ? await perms.contains(wanted).catch(() => false) : false;
          if (!has && !(await perms.request(wanted).catch(() => false))) {
            btn.disabled = false;
            const box = $("deep"); box.style.display = "block"; box.innerHTML = `<div>${esc(t("popup_scan_failed"))} (permission_denied)</div>`;
            return;
          }
        }
      } catch { /* Chrome: no data-collection permissions */ }
      const box = $("deep");
      box.style.display = "block";
      box.innerHTML = `<div class="spin">${esc(t("popup_scanning"))}</div>`;
      const r = (await chrome.runtime.sendMessage({ type: "w3pg:deepScan", tabId, language: chrome.i18n.getUILanguage().split("-")[0] })) as DeepReport | { error: string };
      btn.disabled = false;
      if ("error" in r && !("ai" in r)) {
        const limited = ["host_cooldown", "rate_limited", "host_capacity_reached", "daily_capacity_reached"].includes(r.error);
        const known = limited || r.error === "collect_failed" || r.error === "not_http";
        box.innerHTML = `<div>${esc(known ? deepErrorText(r.error) : t("popup_scan_failed"))}</div>`;
        return;
      }
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
  sb.report = r.sandbox;
  sb.pageRisky = r.local.band !== "none" || r.ai?.verdict === "dangerous" || r.ai?.verdict === "suspicious";
  const facts = `${t("popup_facts_libs")}: ${r.page.libs.join(", ") || "–"} · ${t("popup_facts_scripts")}: ${r.page.scripts.length} · ${t("popup_facts_wallet")}: ${r.page.walletButtons.length} · ${t("popup_facts_seed")}: ${r.page.seedPhraseInputs} · ${t("popup_facts_markers")}: ${[...r.page.drainerMarkers, ...r.markers].length}${r.goplus?.phishing ? " · GoPlus: phishing" : ""}`;
  if (ai.error) {
    box.innerHTML = `<div class="v ${r.local.band === "block" ? "dangerous" : r.local.band === "warn" ? "suspicious" : "likely_safe"}">${esc(t("popup_local_only"))} · ${r.local.score}/100</div><div>${esc(deepErrorText(ai.error, ai.retryAfterMin))}</div><div class="facts">${esc(facts)}</div>${sandboxHtml()}`;
  paintSandbox();
    return;
  }
  const label = t(`verdict_${ai.verdict}`);
  box.innerHTML = `
    <div class="v ${esc(ai.verdict ?? "")}">${esc(label)} · ${Math.round((ai.confidence ?? 0) * 100)}%${ai.impersonates ? ` · ${esc(t("popup_impersonates", [ai.impersonates]))}` : ""}</div>
    <div>${esc(ai.summary ?? "")}</div>
    <ul>${(ai.reasons ?? []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    ${(ai.advice ?? []).length ? `<div class="adv">${(ai.advice ?? []).map((x) => `→ ${esc(x)}`).join("<br>")}</div>` : ""}
    <div class="facts">${esc(facts)}${ai.cached ? " · cached" : ""}</div>${sandboxHtml()}`;
  paintSandbox();
}

// ---------------------------------------------------------------------------
// sandbox status block + queue flow
// ---------------------------------------------------------------------------
interface Pending { jobId: string; state: "queued" | "running"; position?: number; eta?: number }
const sb: { url: string; title?: string; pageRisky?: boolean; scanning?: boolean; report?: SandboxReport; job?: Pending; retryUntil?: number; retryKey?: string; err?: boolean; cancelled?: boolean; timer?: number; tick?: number } = { url: "" };

const USED = new Set(["fresh", "coalesced", "queued_done"]);
const SHOW_RESULT = new Set(["fresh", "coalesced", "queued_done", "cache_hit", "blocklist", "challenge"]);

/** Container only; paintSandbox() fills it (and re-fills it on every state change). */
function sandboxHtml(): string {
  return `<div class="sandbox" id="sbx"></div>`;
}

function paintSandbox() {
  const el = document.getElementById("sbx");
  if (!el) return;
  const s = sb.report;
  const st = s?.state ?? (s?.ok ? "fresh" : "unreachable");
  let bucket: "used" | "off" | "busy" = "off";
  let line = "";
  let btn = "";
  const now = Date.now();
  const left = sb.retryUntil && sb.retryUntil > now ? Math.ceil((sb.retryUntil - now) / 1000) : 0;
  if (sb.job) {
    bucket = "busy";
    line = sb.job.state === "running" ? t("sbx_queue_running") : t("sbx_queue_waiting", [String(sb.job.position ?? "?"), String(sb.job.eta ?? "?")]);
    btn = `<button id="sbxcancel">${esc(t("sbx_queue_cancel"))}</button>`;
  } else if (sb.scanning) {
    bucket = "busy";
    line = t("sbx_queue_running");
  } else {
    if (USED.has(st)) { bucket = "used"; line = t(st === "queued_done" ? "sbx_state_queued_done" : "sbx_state_used", [t(`verdict_${s?.verdict ?? "unknown"}`)]); }
    else if (st === "busy") { bucket = "busy"; line = t("sbx_state_busy"); }
    else if (st === "cache_hit") line = t("sbx_state_cache_hit");
    else if (st === "blocklist") line = t("sbx_state_blocklist");
    else if (st === "chain_unsupported") line = t("sbx_state_chain_unsupported");
    else if (st === "challenge") { bucket = "busy"; line = t("sbx_state_challenge"); }
    else line = t("sbx_state_unavailable");
    if (sb.cancelled) line += " · " + t("sbx_queue_cancelled");
    if (left > 0) { bucket = "busy"; line = t(sb.retryKey ?? "sbx_queue_full", [String(left)]); }
    if (st === "busy" || left > 0) btn = `<button id="sbxqueue" class="primary" ${left > 0 ? "disabled" : ""}>${esc(t("sbx_queue_btn"))}</button>`;
    else if (st === "cache_hit" || st === "blocklist") btn = `<button id="sbxqueue" data-force="1">${esc(t("sbx_queue_rescan"))}</button>`;
    if (sb.err) line += " · " + t("sbx_queue_error");
  }
  const icon = s?.challenge ? "⚠" : bucket === "used" ? "✓" : bucket === "busy" ? "⏳" : "○";
  let body = "";
  if (!sb.job && s && s.ok && SHOW_RESULT.has(st)) {
    if (s.challenge) {
      body = `<div class="v suspicious">${esc(t("sbx_challenge_title"))}${s.verdict === "suspicious" ? ` · ${s.score}/100` : ""}</div><div class="sbwarn">${esc(t("sbx_challenge_body"))}</div>`;
    } else if (sb.pageRisky && (s.verdict === "clean" || s.verdict === "unknown")) {
      body = `<div class="v suspicious">${esc(t("sbx_inconclusive_title"))}</div><div class="sbwarn">${esc(t("sbx_inconclusive_body"))}</div>`;
    } else {
      const cls = s.verdict === "malicious" ? "dangerous" : s.verdict === "suspicious" ? "suspicious" : "likely_safe";
      const calm = s.verdict !== "malicious" && s.verdict !== "suspicious";
      // Drop the server's free-text "drainer kit" marker line; we render markers ourselves, softened and localized.
      const items = (s.findings ?? []).filter((x) => !/drainer\s*kit/i.test(x)).slice(0, 8);
      const markerCount = s.scriptMarkers?.length ?? 0;
      if (markerCount > 0) items.unshift(t("sbx_markers_note", [String(markerCount)]));
      const reassure = calm && items.length ? `<div class="sbcalm">${esc(t("sbx_clean_reassure"))}</div>` : "";
      const listHead = items.length ? `<div class="sbsub2">${esc(t(calm ? "sbx_observations_label" : "sbx_findings_label"))}</div>` : "";
      const list = items.length ? `<ul>${items.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "";
      body = `<div class="v ${cls}">${esc(t(`verdict_${s.verdict}`))} · ${s.score}/100</div><div class="sbsub">${esc(t("popup_sandbox_sub"))}</div>${reassure}${listHead}${list}`;
    }
  }
  el.innerHTML = `<div class="sbh">${esc(t("popup_sandbox_title"))}</div><div class="sbstate sb-${bucket}"><span class="sbicon">${icon}</span> ${esc(line)}</div>${body}${btn}`;
  el.querySelector("#sbxqueue")?.addEventListener("click", (e) => void startQueue((e.currentTarget as HTMLElement).getAttribute("data-force") === "1"));
  el.querySelector("#sbxcancel")?.addEventListener("click", () => void cancelQueued());
  window.clearInterval(sb.tick);
  if (left > 0) sb.tick = window.setInterval(() => { if (!sb.retryUntil || sb.retryUntil <= Date.now()) { window.clearInterval(sb.tick); sb.retryUntil = undefined; } paintSandbox(); }, 1000);
}

/** Make sure the #deep box exists with a sandbox container even when no deep scan has run. */
function ensureBox() {
  const box = $("deep");
  if (!document.getElementById("sbx")) { box.style.display = "block"; box.innerHTML = sandboxHtml(); }
}

function finishWith(report: SandboxReport) {
  window.clearTimeout(sb.timer);
  sb.job = undefined; sb.report = report; sb.err = false; sb.cancelled = false;
  ensureBox(); paintSandbox();
}

function applyQueue(r: Awaited<ReturnType<typeof queueSandbox>>, retried = false) {
  sb.err = false; sb.cancelled = false; sb.scanning = false;
  if (r.state === "cache_hit" || r.state === "blocklist") return finishWith(asReport(r.report, r.state));
  if (r.state === "done") { void removeJob(r.jobId); return finishWith(asReport(r.report, "queued_done")); }
  if (r.state === "queued" || r.state === "running") {
    sb.job = { jobId: r.jobId, state: r.state, position: r.state === "queued" ? r.position : undefined, eta: r.state === "queued" ? r.etaSeconds : undefined };
    void addJob(r.jobId, { url: sb.url, host: hostOf(sb.url), enqueuedAt: Date.now(), lastState: r.state, eta: sb.job.eta, tabTitle: sb.title });
    ensureBox(); paintSandbox();
    schedulePoll(r.nextPollMs, retried);
    return;
  }
  if (r.state === "queue_full") {
    const secs = Math.max(1, Math.min(600, Math.round(r.retryAfter ?? 30)));
    sb.retryUntil = Date.now() + secs * 1000;
    sb.retryKey = r.reason === "install_limit" ? "sbx_queue_limit" : r.reason === "rate_limited" ? "sbx_queue_rate" : "sbx_queue_full";
    ensureBox(); paintSandbox();
    return;
  }
  sb.err = true;
  ensureBox(); paintSandbox();
}

function hostOf(u: string) { try { return new URL(u).hostname; } catch { return u; } }

async function startQueue(force = false) {
  if (!sb.url) return;
  const b = document.getElementById("sbxqueue") as HTMLButtonElement | null;
  if (b) b.disabled = true;
  sb.scanning = true; ensureBox(); paintSandbox(); // visible "scanning…" while the fresh scan runs
  applyQueue(await queueSandbox(sb.url, force));
}

function schedulePoll(nextMs: number | undefined, retried: boolean) {
  window.clearTimeout(sb.timer);
  const ms = Math.min(6000, Math.max(1500, nextMs ?? 2500));
  sb.timer = window.setTimeout(async () => {
    const job = sb.job;
    if (!job) return;
    const r = await pollJob(job.jobId);
    if (!sb.job || sb.job.jobId !== job.jobId) return; // cancelled or replaced meanwhile
    if (r.state === "done") { await removeJob(job.jobId); return finishWith(asReport(r.report, "queued_done")); }
    if (r.state === "expired") {
      await removeJob(job.jobId);
      // the background alarm may have finished it first
      const d = Object.values(await getDone()).find((x) => sameUrl(x.url, sb.url));
      if (d) return finishWith(d.report);
      sb.job = undefined;
      if (retried) { sb.err = true; paintSandbox(); return; }
      return applyQueue(await queueSandbox(sb.url), true);
    }
    if (r.state === "queued" || r.state === "running") {
      sb.job = { jobId: job.jobId, state: r.state, position: r.state === "queued" ? r.position : undefined, eta: r.state === "queued" ? r.etaSeconds : undefined };
      paintSandbox();
      schedulePoll(r.nextPollMs, retried);
      return;
    }
    schedulePoll(4000, retried); // network hiccup: keep trying while the popup is open
  }, ms);
}

async function cancelQueued() {
  const job = sb.job;
  if (!job) return;
  window.clearTimeout(sb.timer);
  sb.job = undefined; sb.cancelled = true;
  paintSandbox();
  await Promise.all([cancelJob(job.jobId), removeJob(job.jobId)]);
}

/** On popup open: show the last-known sandbox state for this tab (finished result or pending job) before anything else. */
async function restoreSandbox(haveReport: boolean | undefined) {
  const done = Object.entries(await getDone()).filter(([, d]) => sameUrl(d.url, sb.url)).sort((x, y) => y[1].at - x[1].at)[0];
  if (done) { finishWith(done[1].report); return; }
  const jobs = await getJobs();
  const hit = Object.entries(jobs).find(([, j]) => sameUrl(j.url, sb.url));
  if (hit) {
    sb.job = { jobId: hit[0], state: hit[1].lastState === "running" ? "running" : "queued", eta: hit[1].eta };
    ensureBox(); paintSandbox();
    schedulePoll(1500, false);
    return;
  }
  if (haveReport) paintSandbox();
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

main().catch((e) => { $("meta").textContent = String(e); });
