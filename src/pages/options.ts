import { t, localizePage } from "../lib/i18n";

const $ = (id: string) => document.getElementById(id)!;

async function main() {
  localizePage();
  const s = (await chrome.runtime.sendMessage({ type: "w3pg:getSettings" })) as { xquikKey: string; apiBase: string; warnDisplay: "page" | "popup" };
  ($(s.warnDisplay === "popup" ? "warn-popup" : "warn-page") as HTMLInputElement).checked = true;
  for (const id of ["warn-page", "warn-popup"]) {
    $(id).onchange = async () => { await chrome.runtime.sendMessage({ type: "w3pg:setSettings", warnDisplay: ($(id) as HTMLInputElement).value }); };
  }
  ($("key") as HTMLInputElement).value = s.xquikKey ?? "";
  ($("apibase") as HTMLInputElement).value = s.apiBase ?? "";
  $("saveapi").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "w3pg:setSettings", apiBase: ($("apibase") as HTMLInputElement).value });
    $("apistatus").textContent = t("opt_saved");
    setTimeout(() => ($("apistatus").textContent = ""), 2000);
  };

  $("save").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "w3pg:setSettings", xquikKey: ($("key") as HTMLInputElement).value });
    $("status").textContent = t("opt_saved");
    setTimeout(() => ($("status").textContent = ""), 2000);
  };

  $("test").onclick = async () => {
    await chrome.runtime.sendMessage({ type: "w3pg:setSettings", xquikKey: ($("key") as HTMLInputElement).value });
    $("status").textContent = "…";
    const r = await chrome.runtime.sendMessage({ type: "w3pg:testXquik", token: "uniswap" });
    $("status").textContent = "";
    const pre = $("result") as HTMLPreElement;
    pre.hidden = false;
    pre.textContent = r?.official ? JSON.stringify(r, null, 2) : t("opt_test_fail");
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
