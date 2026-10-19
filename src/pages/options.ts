import { t, localizePage } from "../lib/i18n";

const $ = (id: string) => document.getElementById(id)!;

async function main() {
  localizePage();
  const s = (await chrome.runtime.sendMessage({ type: "w3pg:getSettings" })) as { warnDisplay: "page" | "popup"; simulate: boolean };
  ($(s.warnDisplay === "popup" ? "warn-popup" : "warn-page") as HTMLInputElement).checked = true;
  for (const id of ["warn-page", "warn-popup"]) {
    $(id).onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", warnDisplay: ($(id) as HTMLInputElement).value }); };
  }


  const sim = $("simulate") as HTMLInputElement;
  sim.checked = s.simulate !== false;
  sim.onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", simulate: sim.checked }); };

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
