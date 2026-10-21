import { t, localizePage } from "../lib/i18n";

const $ = (id: string) => document.getElementById(id)!;

async function main() {
  localizePage();
  const s = (await chrome.runtime.sendMessage({ type: "w3pg:getSettings" })) as { warnDisplay: "page" | "popup" | "off"; simulate: boolean; strictGate?: boolean; addrScreen?: boolean };
  ($(s.warnDisplay === "popup" ? "warn-popup" : s.warnDisplay === "off" ? "warn-off" : "warn-page") as HTMLInputElement).checked = true;
  // the "70+ always blocks" note is only true while page protection is on; hide it for "off"
  const syncWarnNote = () => { ($("warn-note") as HTMLElement).style.display = ($("warn-off") as HTMLInputElement).checked ? "none" : ""; };
  for (const id of ["warn-page", "warn-popup", "warn-off"]) {
    $(id).onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", warnDisplay: ($(id) as HTMLInputElement).value }); syncWarnNote(); };
  }
  syncWarnNote();


  const sim = $("simulate") as HTMLInputElement;
  sim.checked = s.simulate !== false;
  sim.onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", simulate: sim.checked }); };

  const strict = $("strict") as HTMLInputElement;
  strict.checked = s.strictGate === true;
  strict.onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", strictGate: strict.checked }); };
  const addr = $("addrscreen") as HTMLInputElement;
  addr.checked = s.addrScreen !== false;
  addr.onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", addrScreen: addr.checked }); };

  $("refreshlists").onclick = async () => {
    const b = $("refreshlists") as HTMLButtonElement;
    b.disabled = true;
    $("listsstatus").textContent = "…";
    const st = (await chrome.runtime.sendMessage({ type: "w3pg:refreshNow" })) as Record<string, { count: number }>;
    $("listsstatus").textContent = Object.entries(st).map(([k, v]) => `${k}: ${v.count}`).join(" · ");
    b.disabled = false;
  };

  await renderTrusted();
}

async function renderTrusted() {
  const st = (await chrome.runtime.sendMessage({ type: "w3pg:status" })) as { userAllow: string[] };
  const ul = $("trusted");
  ul.innerHTML = "";
  for (const d of st.userAllow) {
    const li = document.createElement("li");
    li.textContent = d;
    const a = document.createElement("a");
    a.className = "rm";
    a.textContent = t("opt_remove");
    a.onclick = async () => {
      await chrome.runtime.sendMessage({ type: "w3pg:unallow", registrable: d });
      await renderTrusted();
    };
    li.appendChild(a);
    ul.appendChild(li);
  }
}

main().catch((e) => ($("status").textContent = String(e)));
