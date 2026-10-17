/**
 * Runs in the page's MAIN world at document_start, before any page script.
 * Wraps EIP-1193 providers (window.ethereum + EIP-6963 announced providers) and
 * window.solana to observe *intent*, never to block. Findings are posted to the
 * isolated-world bridge via window.postMessage.
 *
 * Observed patterns (from drainer-kit research):
 *  - eth_requestAccounts / wallet_requestPermissions fired on load without a user gesture
 *  - eth_signTypedData_v4 with Permit / Permit2 / Seaport / Blur order types
 *  - eth_sendTransaction with approve / setApprovalForAll / increaseAllowance selectors or value to an unknown target
 *  - wallet_switchEthereumChain without gesture
 */
(() => {
  const TAG = "w3pg";
  const loadedAt = Date.now();
  let lastGesture = 0;
  const gesture = () => { lastGesture = Date.now(); };
  for (const ev of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(ev, gesture, { capture: true, passive: true });

  const SELECTORS: Record<string, string> = {
    "0x095ea7b3": "approve (ERC-20 harcama izni)",
    "0x39509351": "increaseAllowance",
    "0xa22cb465": "setApprovalForAll (tüm NFT'ler için izin)",
    "0xd505accf": "permit (ERC-2612)",
    "0x2b67b570": "Permit2 permit",
    "0x30f28b7a": "Permit2 permitTransferFrom",
    "0x23b872dd": "transferFrom",
    "0x42842e0e": "safeTransferFrom",
  };
  const TYPED_RISK = /"primaryType"\s*:\s*"(Permit|PermitSingle|PermitBatch|PermitTransferFrom|PermitBatchTransferFrom|OrderComponents|Order|BulkOrder|SeaportOrder|Listing)"/i;

  const post = (event: Record<string, unknown>) => {
    try { window.postMessage({ source: TAG, event }, "*"); } catch { /* ignore */ }
  };
  const hadGesture = () => Date.now() - lastGesture < 1500;

  function inspect(method: string, params: unknown) {
    const msSinceLoad = Date.now() - loadedAt;
    const g = hadGesture();
    if (method === "eth_requestAccounts" || method === "wallet_requestPermissions") {
      if (!g && msSinceLoad < 5000) post({ kind: "auto-connect", method, detail: "", msSinceLoad, hadGesture: g });
      return;
    }
    if (method === "wallet_switchEthereumChain" || method === "wallet_addEthereumChain") {
      if (!g) post({ kind: "chain-switch", method, detail: "", msSinceLoad, hadGesture: g });
      return;
    }
    if (method === "eth_signTypedData_v4" || method === "eth_signTypedData_v3" || method === "eth_signTypedData") {
      const raw = Array.isArray(params) ? params.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join(" ") : "";
      const m = raw.match(TYPED_RISK);
      if (m) post({ kind: "risky-sign", method, detail: `${m[1]} tipli imza (token/NFT transfer yetkisi)`, msSinceLoad, hadGesture: g });
      return;
    }
    if (method === "eth_sign") {
      post({ kind: "risky-sign", method, detail: "eth_sign (ham imza, her şeyi imzalatabilir)", msSinceLoad, hadGesture: g });
      return;
    }
    if (method === "eth_sendTransaction") {
      const tx = Array.isArray(params) ? (params[0] as Record<string, string> | undefined) : undefined;
      const data = (tx?.data ?? "").toLowerCase();
      const sel = data.slice(0, 10);
      if (SELECTORS[sel]) {
        post({ kind: "risky-tx", method, detail: SELECTORS[sel], msSinceLoad, hadGesture: g });
      } else if (tx?.value && /^0x0*[1-9a-f]/i.test(tx.value) && data.length > 10) {
        post({ kind: "risky-tx", method, detail: "ETH gönderen bilinmeyen kontrat çağrısı (sahte claim/mint kalıbı)", msSinceLoad, hadGesture: g });
      }
    }
  }

  const wrapped = new WeakSet<object>();
  function wrapProvider(p: any) {
    if (!p || typeof p !== "object" || wrapped.has(p)) return;
    wrapped.add(p);
    const orig = p.request;
    if (typeof orig !== "function") return;
    try {
      Object.defineProperty(p, "request", {
        configurable: true,
        writable: true,
        value: function (args: { method?: string; params?: unknown }) {
          try { if (args?.method) inspect(args.method, args.params); } catch { /* never break the dapp */ }
          return orig.apply(this, arguments as any);
        },
      });
    } catch { /* frozen provider */ }
  }

  // window.ethereum (may be injected later by the wallet, so observe assignment too)
  const tryWrap = () => wrapProvider((window as any).ethereum);
  tryWrap();
  let current = (window as any).ethereum;
  try {
    Object.defineProperty(window, "ethereum", {
      configurable: true,
      get: () => current,
      set: (v) => { current = v; wrapProvider(v); },
    });
  } catch { /* already non-configurable; fall back to polling */
    let n = 0;
    const iv = setInterval(() => { tryWrap(); if (++n > 20) clearInterval(iv); }, 250);
  }

  // EIP-6963 providers (Angel drainer enumerates these)
  window.addEventListener("eip6963:announceProvider", (e: any) => wrapProvider(e?.detail?.provider));

  // Solana wallets
  const wrapSolana = () => {
    const s = (window as any).solana ?? (window as any).phantom?.solana;
    if (!s || wrapped.has(s)) return;
    wrapped.add(s);
    for (const m of ["signTransaction", "signAllTransactions", "signAndSendTransaction"]) {
      const f = s[m];
      if (typeof f !== "function") continue;
      try {
        s[m] = function () {
          post({ kind: "risky-tx", method: m, detail: `Solana ${m}`, msSinceLoad: Date.now() - loadedAt, hadGesture: hadGesture() });
          return f.apply(this, arguments as any);
        };
      } catch { /* ignore */ }
    }
  };
  wrapSolana();
  let sn = 0;
  const siv = setInterval(() => { wrapSolana(); if (++sn > 20) clearInterval(siv); }, 500);
})();
