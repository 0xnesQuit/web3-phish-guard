interface Payload { url: string; host: string; score: number; signals: string[] }

function read(): Payload | null {
  try {
    return JSON.parse(decodeURIComponent(location.hash.slice(1))) as Payload;
  } catch {
    return null;
  }
}

const p = read();
const $ = (id: string) => document.getElementById(id)!;

if (p) {
  $("host").textContent = p.host;
  $("score").textContent = `Risk puanı: ${p.score}/100`;
  $("reasons").innerHTML = p.signals.map((s) => `<li>${s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] as string)}</li>`).join("");
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
