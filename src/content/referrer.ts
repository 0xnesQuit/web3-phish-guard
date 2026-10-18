/** Reports the page's referrer so the background can tell when a link came from a social platform. */
try {
  const r = document.referrer;
  // only social / redirector referrers matter; everything else must not wake the service worker
  if (r && /^https?:\/\/([a-z0-9.-]*\.)?(t\.co|x\.com|twitter\.com|discord\.com|discordapp\.com|t\.me|telegram\.org|reddit\.com|youtube\.com|youtu\.be)\//i.test(r)) {
    chrome.runtime.sendMessage({ type: "w3pg:referrer", referrer: r }).catch(() => undefined);
  }
} catch {
  /* ignore */
}
