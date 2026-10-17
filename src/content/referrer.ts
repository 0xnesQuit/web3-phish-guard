/** Reports the page's referrer so the background can tell when a link came from a social platform. */
try {
  const r = document.referrer;
  if (r) chrome.runtime.sendMessage({ type: "w3pg:referrer", referrer: r }).catch(() => undefined);
} catch {
  /* ignore */
}
