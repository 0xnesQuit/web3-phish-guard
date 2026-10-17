import type { Signal } from "../lib/types";
import { t, signalText, localizePage } from "../lib/i18n";

interface Payload { url: string; host: string; score: number; signals: Signal[] }

function read(): Payload | null {
  try {
    return JSON.parse(decodeURIComponent(location.hash.slice(1))) as Payload;
  } catch {
    return null;
  }
}

const p = read();
const $ = (id: string) => document.getElementById(id)!;
localizePage();

if (p) {
  $("host").textContent = p.host;
  $("score").textContent = t("warning_score", [String(p.score)]);
  $("reasons").innerHTML = p.signals.filter((s) => s.weight > 0).map((s) => `<li>${signalText(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] as string)}</li>`).join("");
}

$("back").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else window.close();
});

$("proceed").addEventListener("click", async () => {
  if (!p) return;
  await chrome.runtime.sendMessage({ type: "w3pg:bypass", host: p.host });
  location.replace(p.url);
});
