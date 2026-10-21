import type { Signal } from "../lib/types";
import { t, signalText, localizePage } from "../lib/i18n";

interface Payload { url: string; host: string; score: number; signals: Signal[]; brandDomain?: string; reviewed?: boolean; deep?: { summary?: string; reasons?: string[]; impersonates?: string } }

const $ = (id: string) => document.getElementById(id)!;
localizePage();

const nonce = new URLSearchParams(location.search).get("n") ?? "";

async function main() {
  // The payload lives in the background's session storage under a one-shot nonce, so a web page
  // cannot open this page with a forged host and talk a user into bypassing it.
  const p = (await chrome.runtime.sendMessage({ type: "w3pg:getWarning", nonce })) as Payload | null;
  if (!p) {
    $("host").textContent = "–";
    ($("proceed") as HTMLButtonElement).hidden = true;
    return;
  }
  $("host").textContent = p.host;
  $("score").textContent = t("warning_score", [String(p.score)]);
  $("reasons").innerHTML = p.signals.filter((s) => s.weight > 0).map((s) => `<li>${esc(signalText(s))}</li>`).join("");
  if (p.deep && (p.deep.summary || p.deep.reasons?.length)) {
    $("deepbox").hidden = false;
    $("deepsum").textContent = p.deep.summary ?? "";
    $("deepreasons").innerHTML = (p.deep.reasons ?? []).map((x) => `<li>${esc(x)}</li>`).join("");
  }
  if (p.brandDomain) {
    const b = $("official") as HTMLButtonElement;
    b.hidden = false;
    b.textContent = t("warning_official", [p.brandDomain]);
    b.onclick = () => location.replace(`https://${p.brandDomain}/`);
  }
  $("host").focus();

  $("back").addEventListener("click", async () => {
    // Going back one step would re-commit the phishing URL and loop; leave via the background.
    await chrome.runtime.sendMessage({ type: "w3pg:leave" });
  });

  const proceed = $("proceed") as HTMLButtonElement;
  let armed = false;
  proceed.addEventListener("click", async () => {
    // Reviewed-list hits (MetaMask / ScamSniffer / moderators) need a second, explicit click.
    if (p.reviewed && !armed) {
      armed = true;
      proceed.textContent = t("warning_proceed_confirm");
      proceed.classList.add("armed");
      return;
    }
    const ok = await chrome.runtime.sendMessage({ type: "w3pg:bypass", nonce });
    if (ok) location.replace(p.url);
  });
}

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
}

main().catch(() => undefined);
