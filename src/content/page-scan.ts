/**
 * On-demand page snapshot for the deep scan. Runs in the isolated world on every page
 * but does nothing until the background asks (user pressed "deep scan"). Collects
 * structure and a bounded text sample; never form values, never cookies.
 */
import type { PageSignals, PageSnapshot, PageSocials, Verdict } from "../lib/types";

const LIBS: Array<[RegExp, string]> = [
  [/ethers(?:\.min)?\.js|ethers@|\bethers\b/i, "ethers.js"],
  [/web3(?:\.min)?\.js|web3@/i, "web3.js"],
  [/\bviem\b/i, "viem"],
  [/\bwagmi\b/i, "wagmi"],
  [/@solana\/web3|solana-web3/i, "solana-web3.js"],
  [/walletconnect|@reown|appkit/i, "WalletConnect/Reown"],
  [/web3modal|rainbowkit|connectkit|@dynamic-labs|privy/i, "wallet-ui-kit"],
  [/sweetalert/i, "sweetalert2"],
  [/merkletree/i, "merkletreejs"],
  [/moralis|thirdweb/i, "web3-sdk"],
];

const DRAINER_MARKERS: RegExp[] = [
  /secureproxy\.php/i, /ping_proxy/i, /rotatingURL/i, /createPrizeTxs/i, /claimSolana/i, /drainer/i,
  /scripts\/seaport\.js/i, /scripts\/wallet_connect\.js/i, /webchunk\.js/i, /inferno/i, /angel[_-]?drainer/i,
  /setApprovalForAll[\s\S]{0,200}permit/i, /permit2[\s\S]{0,200}transferFrom/i,
];

// en / tr / de / es / fr / pt / ru / hi / zh / ja / ko / vi / id
const SEED_RE = /(seed|mnemonic|recovery|secret)\s*(phrase|words?)|private\s*key|12\s*words|24\s*words|kurtarma|gizli\s*anahtar|wiederherstellungsphrase|privater\s*schlüssel|frase\s*(semilla|de\s*recuperaci[oó]n)|clave\s*privada|phrase\s*(de\s*r[eé]cup[eé]ration|secr[eè]te)|cl[eé]\s*priv[eé]e|frase\s*de\s*recupera[cç][aã]o|chave\s*privada|сид[- ]?фраз|приватн\w*\s*ключ|секретн\w*\s*фраз|रिकवरी\s*फ्रेज|निजी\s*कुंजी|助记词|私钥|助記詞|シードフレーズ|リカバリーフレーズ|秘密鍵|복구\s*구문|시드\s*구문|개인\s*키|cụm\s*từ\s*khôi\s*phục|khóa\s*riêng|frasa\s*pemulihan|kunci\s*privat/i;
const COUNTDOWN_RE = /\b\d{1,2}\s*:\s*\d{2}\s*:\s*\d{2}\b|\b(\d+\s*(h|hours?|saat|std|horas?|heures?|часов?|घंटे|小时|時間|시간|giờ|jam)\s*\d+\s*(m|min|dakika|minuten|minutos?|minutes?|минут|मिनट|分钟|分|분|phút|menit))\b|ends? in|time left|kalan süre|endet in|termina en|se termine dans|termina em|осталось|समाप्त|剩余|残り|남은 시간|còn lại|berakhir dalam|expires in/i;
const WALLET_BTN_RE = /connect\s*wallet|cüzdan\s*bağla|claim|mint|airdrop|verify\s*wallet|check\s*eligibility|sync\s*wallet|validate|migrate|restore|wallet\s*verbinden|conectar\s*(billetera|wallet)|reclamar|connecter\s*(le\s*)?portefeuille|r[eé]clamer|conectar\s*carteira|resgatar|подключить\s*кошел[её]к|получить|вывести|वॉलेट\s*कनेक्ट|दावा|连接钱包|领取|铸造|ウォレット(を)?接続|請求|受け取る|지갑\s*연결|받기|클레임|kết nối ví|nhận|hubungkan\s*dompet|klaim/i;

// ClickFix lure: instructions to run a command AND to paste. Both halves are required; either alone is common in tutorials.
// Strong run triggers (the Windows Run dialog) are ClickFix-specific. Weak ones (Terminal, Spotlight) overlap with
// legitimate install docs ("open your terminal and paste this"), so they also require fake-verification framing.
const LURE_RUN_STRONG = /\b(?:win(?:dows)?(?:\s*key)?|⊞)\s*\+\s*r\b|⊞\s*\+?\s*r\b|\brun\s+dialog\b/i;
const LURE_RUN_WEAK = /\bterminal\b|\b(?:cmd|command|⌘)\s*\+\s*space\b/i;
const LURE_PASTE_RE = /\b(?:ctrl|control)\s*\+\s*v\b|\b(?:cmd|command)\s*\+\s*v\b|\bpaste\b/i;
const LURE_VERIFY_RE = /\b(?:verif\w*|captcha|robot|cloudflare|human|security check)\b|\bnot a (?:ro)?bot\b/i;
export function hasClickfixLure(text: string): boolean {
  const t = text.slice(0, 20_000);
  if (!LURE_PASTE_RE.test(t)) return false;
  if (LURE_RUN_STRONG.test(t)) return true;
  return LURE_RUN_WEAK.test(t) && LURE_VERIFY_RE.test(t);
}

function hostOf(u: string): string | null {
  try { return new URL(u, location.href).hostname.toLowerCase(); } catch { return null; }
}

function registrableish(h: string): string {
  const p = h.split(".");
  return p.length <= 2 ? h : p.slice(-2).join(".");
}

/** X handles linked anywhere on the page (footer, header, cards). */
export function collectSocials(): PageSocials {
  const handles = new Set<string>();
  let count = 0;
  for (const a of Array.from(document.querySelectorAll<HTMLAnchorElement>("a[href]"))) {
    const h = hostOf(a.href);
    if (!h) continue;
    if (/(^|\.)(x\.com|twitter\.com)$/.test(h)) {
      count++;
      const m = a.href.match(/(?:x\.com|twitter\.com)\/@?([A-Za-z0-9_]{1,15})(?:[/?#]|$)/i);
      if (m && !/^(intent|share|home|search|i|hashtag|login|signup)$/i.test(m[1])) handles.add(m[1]);
    } else if (/(^|\.)(discord\.(gg|com)|t\.me|telegram\.org)$/.test(h)) count++;
  }
  return { xHandles: [...handles].slice(0, 10), count };
}

function meta(name: string): string {
  return document.querySelector<HTMLMetaElement>(`meta[name="${name}"], meta[property="${name}"]`)?.content ?? "";
}

/** Inputs that look like a recovery-phrase / private-key field (label text or nearby text). Shared by the deep scan and quickScan. */
function countSeedInputs(inputs: Iterable<HTMLElement>, stopAtFirst = false): number {
  let n = 0;
  for (const i of inputs) {
    const label = `${i.getAttribute("placeholder") ?? ""} ${i.getAttribute("name") ?? ""} ${i.getAttribute("aria-label") ?? ""} ${i.id} ${(i as HTMLTextAreaElement).rows ? "textarea" : ""}`;
    const near = (i.closest("label, div, form")?.textContent ?? "").slice(0, 200);
    if (SEED_RE.test(label) || SEED_RE.test(near)) { n++; if (stopAtFirst) break; }
  }
  return n;
}

export function collect(): PageSnapshot {
  const ownReg = registrableish(location.hostname.toLowerCase());
  const scripts = Array.from(document.scripts);
  const external: string[] = [];
  let inlineBytes = 0;
  let inlineCount = 0;
  let hexVars = 0, evalAtob = 0, debuggerTraps = 0;
  const libs = new Set<string>();
  const markers = new Set<string>();
  const scanText = (s: string) => {
    hexVars += (s.match(/_0x[0-9a-f]{4,}/gi) ?? []).length;
    evalAtob += (s.match(/\beval\s*\(|\batob\s*\(|Function\s*\(\s*["']/g) ?? []).length;
    debuggerTraps += (s.match(/\bdebugger\b/g) ?? []).length;
    for (const [re, name] of LIBS) if (re.test(s)) libs.add(name);
    for (const re of DRAINER_MARKERS) { const m = s.match(re); if (m) markers.add(m[0].slice(0, 60)); }
  };
  for (const s of scripts) {
    if (s.src) {
      external.push(s.src.replace(/^https?:\/\//, "").slice(0, 160));
      for (const [re, name] of LIBS) if (re.test(s.src)) libs.add(name);
      for (const re of DRAINER_MARKERS) if (re.test(s.src)) markers.add(s.src.slice(-60));
    } else {
      inlineCount++;
      inlineBytes += s.textContent?.length ?? 0;
      scanText((s.textContent ?? "").slice(0, 200_000));
    }
  }
  const anchors = Array.from(document.querySelectorAll<HTMLAnchorElement>("a[href]"));
  const extDomains = new Map<string, number>();
  let same = 0;
  for (const a of anchors) {
    const h = hostOf(a.href);
    if (!h) continue;
    if (registrableish(h) === ownReg) same++;
    else extDomains.set(registrableish(h), (extDomains.get(registrableish(h)) ?? 0) + 1);
  }
  const bodyText = (document.body?.innerText ?? "").replace(/\s+/g, " ").trim();
  const buttons = Array.from(document.querySelectorAll<HTMLElement>("button, a[role=button], [class*=btn], [class*=button], input[type=submit]"))
    .map((b) => (b.innerText || (b as HTMLInputElement).value || "").trim())
    .filter((t) => t && t.length < 60 && WALLET_BTN_RE.test(t));
  const seedInputs = countSeedInputs(document.querySelectorAll<HTMLElement>("input, textarea"));
  return {
    title: document.title.slice(0, 300),
    description: (meta("description") || meta("og:description")).slice(0, 500),
    text: bodyText.slice(0, 6000),
    libs: [...libs],
    scripts: external.slice(0, 40),
    inlineScripts: inlineCount,
    inlineBytes,
    obfuscation: { hexVars, evalAtob, debuggerTraps },
    links: {
      total: anchors.length,
      externalDomains: [...extDomains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([d]) => d),
      sameDomainRatio: anchors.length ? Math.round((same / anchors.length) * 100) / 100 : 0,
    },
    walletButtons: [...new Set(buttons)].slice(0, 10),
    seedPhraseInputs: seedInputs,
    countdown: COUNTDOWN_RE.test(bodyText.slice(0, 20000)),
    iframes: document.querySelectorAll("iframe").length,
    drainerMarkers: [...markers].slice(0, 20),
    providerEvents: [],
    socials: collectSocials(),
  };
}

// Report social links once at idle, so the background can check whether the page links to a real project's X
// account while sitting on a different domain. Socials only change a verdict on a page that already looks off
// (see scoring), so the anchor walk is skipped on plain pages; one re-check on the first trusted gesture.
let lastSent = "";
function sendSocials() {
  try {
    const s = collectSocials();
    const key = s.xHandles.join(",");
    if (!s.xHandles.length || key === lastSent) return;
    lastSent = key;
    chrome.runtime.sendMessage({ type: "w3pg:socials", socials: s }).catch(() => undefined);
  } catch { /* ignore */ }
}
let socialsRecheck = true;
async function maybeSendSocials() {
  try {
    if (window.top !== window) return; // background ignores socials from subframes
    const v = (await chrome.runtime.sendMessage({ type: "w3pg:getVerdict", originSeen: true })) as (Verdict & { originSeen?: boolean }) | undefined;
    // no verdict yet: stay conservative and walk. Otherwise only when something could use the socials.
    if (v && v.band === "none" && !v.xToken && !v.originSeen && !v.score && !v.signals.some((s) => s.id.startsWith("provider-"))) return;
    sendSocials();
  } catch { /* ignore */ }
}
if (typeof requestIdleCallback === "function") requestIdleCallback(() => void maybeSendSocials(), { timeout: 3000 });
else setTimeout(() => void maybeSendSocials(), 1500);

// One cheap pass at idle for the on-load verdict: seed field, drainer-kit script URLs, brand name in the title.
// Top frame, once, no observer, no network. Inline script bodies are left to the deep scan.
let quickDone = false;
function quickScan() {
  if (quickDone) return;
  quickDone = true;
  try {
    if (window.top !== window || !/^https?:$/.test(location.protocol)) return;
    const markers = new Set<string>();
    for (const s of Array.from(document.scripts).slice(0, 200)) {
      if (!s.src) continue;
      for (const re of DRAINER_MARKERS) { const m = re.exec(s.src); if (m) markers.add(m[0].toLowerCase().slice(0, 40)); }
    }
    const inputs = Array.from(document.querySelectorAll<HTMLElement>("input, textarea")).slice(0, 60);
    const heads = new Set<string>();
    for (const seg of [document.title, meta("og:site_name"), meta("og:title")]) {
      for (const w of seg.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).slice(0, 3)) heads.add(w);
    }
    const signals: PageSignals = { seedInputOnLoad: countSeedInputs(inputs, true) > 0, drainerSrcMarkers: [...markers].slice(0, 10), titleHeads: [...heads].slice(0, 12), clickfixLure: hasClickfixLure(document.body?.innerText ?? "") };
    chrome.runtime.sendMessage({ type: "w3pg:pagesignals", signals }).catch(() => undefined);
  } catch { /* ignore */ }
}
if (typeof requestIdleCallback === "function") requestIdleCallback(quickScan, { timeout: 3000 });
else setTimeout(quickScan, 1200);

// WalletConnect / AppKit modal: mobile wallets bypass the provider wrapper, so the modal itself is the signal.
// Nothing is observed until there is a reason: a wallet-connect CTA is on the page at idle, or the user clicks one.
const WC_MODAL_SEL = "wcm-modal, w3m-modal, w3m-router, wui-flex, #walletconnect-wrapper, [class*='walletconnect-modal']";
const WC_CTA_SEL = "w3m-button, appkit-button, w3m-connect-button, appkit-connect-button, w3m-core-button, appkit-core-button, wcm-button";
let wcSent = false;
let wcTimer: ReturnType<typeof setTimeout> | undefined;
function wcFire() {
  wcSent = true;
  wcObs.disconnect();
  clearTimeout(wcTimer);
  chrome.runtime.sendMessage({ type: "w3pg:provider", event: { kind: "wc-modal", method: "walletconnect", detail: "wc_modal", msSinceLoad: performance.now(), hadGesture: true } }).catch(() => undefined);
}
const wcObs = new MutationObserver(() => {
  if (!wcSent && document.querySelector(WC_MODAL_SEL)) wcFire();
});
/** Watch document.body for a WC modal for a short bounded window. */
function wcArm(ms: number) {
  if (wcSent || !document.body) return;
  if (document.querySelector(WC_MODAL_SEL)) { wcFire(); return; }
  wcObs.observe(document.body, { childList: true, subtree: true });
  clearTimeout(wcTimer);
  wcTimer = setTimeout(() => wcObs.disconnect(), ms);
}
// one-shot at idle: a modal already open, or a known connect-button element on the page (cheap selector, no text scan)
function wcIdleCheck() {
  try { if (document.querySelector(WC_MODAL_SEL)) wcFire(); else if (document.querySelector(WC_CTA_SEL)) wcArm(10_000); } catch { /* ignore */ }
}
if (typeof requestIdleCallback === "function") requestIdleCallback(wcIdleCheck, { timeout: 3000 });
else setTimeout(wcIdleCheck, 1500);
// a trusted click on a wallet-connect CTA: watch 8s for the modal (then drop the observer)
const wcGesture = (e: Event) => {
  if (!e.isTrusted) return;
  try { if (!chrome.runtime?.id) { wcObs.disconnect(); return; } } catch { wcObs.disconnect(); return; }
  // any trusted gesture may open a WC modal (a plain, icon-only or oddly worded connect button too): watch briefly.
  // this is still far cheaper than the old always-on observer, which watched every page for 20s from load with no interaction.
  if (!wcSent) wcArm(8_000);
  // one late social-link check for pages that only turned wallet-active after load
  if (socialsRecheck) { socialsRecheck = false; setTimeout(() => void maybeSendSocials(), 1500); }
};
window.addEventListener("pointerdown", wcGesture, { capture: true, passive: true });
window.addEventListener("keydown", wcGesture, { capture: true, passive: true });

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "w3pg:collect") {
    try { sendResponse(collect()); } catch (e) { sendResponse({ error: String(e) }); }
    return true;
  }
  return undefined;
});
