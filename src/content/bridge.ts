/** Isolated-world relay: MAIN-world provider events -> background. */
window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  const d = e.data;
  if (!d || d.source !== "w3pg" || !d.event) return;
  chrome.runtime.sendMessage({ type: "w3pg:provider", event: d.event }).catch(() => undefined);
});
