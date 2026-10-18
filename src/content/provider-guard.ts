/**
 * Runs in the page's MAIN world at document_start, in every frame, before any page script.
 *
 * 1. Wraps EIP-1193 providers (window.ethereum, EIP-6963 announcements, legacy send/sendAsync/enable) and the
 *    Solana provider to observe intent and, for high-risk requests, HOLD the request until the user decides in a
 *    modal rendered by the isolated-world bridge (bridge.ts). A rejected request resolves with EIP-1193 error 4001.
 * 2. Wraps clipboard writes to catch ClickFix command injection and address swapping.
 * 3. Flags wallet providers whose EIP-6963 identity does not match the wallet they claim to be.
 *
 * It never blocks silently: if the extension does not answer within the timeout, the request proceeds.
 */
import { decodeTx, decodeSendCalls, decodeTypedData, looksPoisoned, CLICKFIX_RE, CRYPTO_ADDR_RE, type TxIntent, type SignIntent } from "../lib/txdecode";

(() => {
  const TAG = "w3pg";
  const loadedAt = Date.now();
  let lastGesture = 0;
  const gesture = (e: Event) => { if (e.isTrusted) lastGesture = Date.now(); };
  for (const ev of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(ev, gesture, { capture: true, passive: true });
  const hadGesture = () => Date.now() - lastGesture < 1500;

  const post = (event: Record<string, unknown>) => {
    try { window.postMessage({ source: TAG, event }, "*"); } catch { /* ignore */ }
  };

  // ---- gate: ask the extension whether to hold a request ----------------------------------
  const pending = new Map<string, (allow: boolean) => void>();
  window.addEventListener("message", (e) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.source !== TAG + "-ext" || d.type !== "gate-result") return;
    const r = pending.get(String(d.id));
    if (r) { pending.delete(String(d.id)); r(!!d.allow); }
  });
  function gate(details: Record<string, unknown>): Promise<boolean> {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    return new Promise((resolve) => {
      const timer = setTimeout(() => { pending.delete(id); resolve(true); }, 90_000); // never wedge a dapp
      pending.set(id, (allow) => { clearTimeout(timer); resolve(allow); });
      try { window.postMessage({ source: TAG, gate: { id, ...details } }, "*"); } catch { clearTimeout(timer); pending.delete(id); resolve(true); }
    });
  }
  const rejected = () => Object.assign(new Error("User rejected the request (Web3 Phish Guard)."), { code: 4001 });

  // ---- recipients seen on this origin (address poisoning) ----
  const knownRecipients: string[] = [];
  function checkPoison(to: string | undefined): string | undefined {
    if (!to || !/^0x[0-9a-fA-F]{40}$/.test(to)) return undefined;
    const twin = looksPoisoned(to, knownRecipients);
    if (!twin && !knownRecipients.includes(to.toLowerCase())) knownRecipients.push(to.toLowerCase());
    return twin;
  }

  /** eth_getCode through the same provider: an EOA spender/operator is a drainer hallmark. */
  async function isEoa(provider: any, address: string | undefined): Promise<boolean | undefined> {
    if (!address || !/^0x[0-9a-f]{40}$/.test(address) || !origRequest) return undefined;
    try {
      const code = await Promise.race([
        origRequest.call(provider, { method: "eth_getCode", params: [address, "latest"] }) as Promise<string>,
        new Promise<string>((_, rej) => setTimeout(() => rej(new Error("timeout")), 3000)),
      ]);
      return typeof code === "string" && (code === "0x" || code === "0x0" || code === "");
    } catch {
      return undefined;
    }
  }

  let origRequest: ((args: unknown) => Promise<unknown>) | null = null;

  async function inspect(provider: any, method: string, params: unknown): Promise<"allow" | "reject"> {
    const msSinceLoad = Date.now() - loadedAt;
    const g = hadGesture();
    const p = Array.isArray(params) ? params : [];

    if (method === "eth_requestAccounts" || method === "wallet_requestPermissions" || method === "enable") {
      if (!g && msSinceLoad < 5000) post({ kind: "auto-connect", method, detail: "", msSinceLoad, hadGesture: g });
      return "allow";
    }
    if (method === "wallet_switchEthereumChain" || method === "wallet_addEthereumChain") {
      if (!g) post({ kind: "chain-switch", method, detail: "", msSinceLoad, hadGesture: g });
      return "allow";
    }
    if (method === "eth_sign") {
      post({ kind: "risky-sign", method, detail: "eth_sign", msSinceLoad, hadGesture: g });
      return (await gate({ method, kind: "eth_sign", hadGesture: g })) ? "allow" : "reject";
    }
    if (/^eth_signTypedData(_v[34])?$/.test(method)) {
      const td = p.find((x) => typeof x === "string" && x.includes("primaryType")) ?? p[1] ?? p[0];
      const s: SignIntent = decodeTypedData(td);
      if (s.kind === "other") return "allow";
      post({ kind: "risky-sign", method, detail: "typed", param: s.primaryType, msSinceLoad, hadGesture: g });
      const eoa = await isEoa(provider, s.counterparty);
      const details = { method, kind: s.kind, primaryType: s.primaryType, counterparty: s.counterparty, counterpartyEoa: eoa, deadline: s.deadline, hadGesture: g };
      if (eoa) post({ kind: "risky-sign", method, detail: "eoa-spender", param: s.counterparty, msSinceLoad, hadGesture: g });
      return (await gate(details)) ? "allow" : "reject";
    }
    if (method === "eth_sendTransaction" || method === "eth_signTransaction" || method === "wallet_sendCalls") {
      const intent: TxIntent = method === "wallet_sendCalls" ? decodeSendCalls(p[0] as { calls?: never[] }) : decodeTx(p[0] as never);
      const flat = intent.kind === "multicall" ? intent.inner ?? [] : [intent];
      const risky = flat.filter((i) => ["approve-unlimited", "approve", "setApprovalForAll", "permit2", "transfer", "transferFrom", "delegation-7702", "unknown-payable", "eth-send"].includes(i.kind));
      if (!risky.length) return "allow";
      const top = risky.find((i) => i.kind === "delegation-7702") ?? risky.find((i) => i.kind === "setApprovalForAll") ?? risky.find((i) => i.kind === "approve-unlimited") ?? risky[0];
      const detailCode = top.kind === "approve-unlimited" ? "approve" : top.kind === "delegation-7702" ? "delegation" : top.kind === "unknown-payable" ? "payable_unknown" : top.kind === "eth-send" ? "eth_send" : top.kind;
      post({ kind: "risky-tx", method, detail: detailCode, param: top.counterparty, msSinceLoad, hadGesture: g });
      const twin = checkPoison(top.counterparty);
      const eoa = ["approve-unlimited", "approve", "setApprovalForAll", "permit2"].includes(top.kind) ? await isEoa(provider, top.counterparty) : undefined;
      if (eoa) post({ kind: "risky-tx", method, detail: "eoa-spender", param: top.counterparty, msSinceLoad, hadGesture: g });
      if (twin) post({ kind: "risky-tx", method, detail: "poisoning", param: top.counterparty, msSinceLoad, hadGesture: g });
      const details = { method, kind: top.kind, counterparty: top.counterparty, counterpartyEoa: eoa, unlimited: top.unlimited, token: top.token, poisonedTwin: twin, batch: flat.length > 1 ? flat.map((i) => i.kind) : undefined, hadGesture: g };
      return (await gate(details)) ? "allow" : "reject";
    }
    return "allow";
  }

  const wrapped = new WeakSet<object>();
  function wrapProvider(p: any) {
    if (!p || typeof p !== "object" || wrapped.has(p)) return;
    wrapped.add(p);
    const orig = p.request;
    if (typeof orig === "function") {
      if (!origRequest) origRequest = orig;
      const guarded = function (this: unknown, args: { method?: string; params?: unknown }) {
        const self = this ?? p;
        const run = () => orig.apply(self, [args]);
        if (!args?.method) return run();
        return inspect(p, args.method, args.params).then((d) => (d === "reject" ? Promise.reject(rejected()) : run()), () => run());
      };
      try { Object.defineProperty(p, "request", { configurable: true, writable: true, value: guarded }); } catch { /* frozen */ }
    }
    // legacy paths some kits still use
    for (const legacy of ["send", "sendAsync"] as const) {
      const fn = p[legacy];
      if (typeof fn !== "function") continue;
      try {
        p[legacy] = function (this: unknown, a: any, b: any) {
          const self = this ?? p;
          const method = typeof a === "string" ? a : a?.method;
          const params = typeof a === "string" ? b : a?.params;
          if (!method) return fn.apply(self, [a, b]);
          const invoke = () => fn.apply(self, [a, b]);
          const decided = inspect(p, method, params);
          if (typeof b === "function") { decided.then((d) => (d === "reject" ? b(rejected()) : invoke()), invoke); return undefined; }
          return decided.then((d) => (d === "reject" ? Promise.reject(rejected()) : invoke()), invoke);
        };
      } catch { /* ignore */ }
    }
    // identity check: a provider claiming to be MetaMask must announce MetaMask's rdns (set below for EIP-6963)
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
  } catch {
    let n = 0;
    const iv = setInterval(() => { tryWrap(); if (++n > 20) clearInterval(iv); }, 250);
  }

  // EIP-6963 providers (drainers enumerate these; fake wallets announce wrong identities)
  const KNOWN_RDNS: Record<string, RegExp> = {
    "io.metamask": /metamask/i, "app.phantom": /phantom/i, "com.coinbase.wallet": /coinbase/i, "io.rabby": /rabby/i,
    "com.okex.wallet": /okx/i, "com.trustwallet.app": /trust/i, "com.brave.wallet": /brave/i, "me.rainbow": /rainbow/i,
    "app.backpack": /backpack/i, "xyz.argent": /argent/i, "io.zerion.wallet": /zerion/i, "app.keplr": /keplr/i,
  };
  window.addEventListener("eip6963:announceProvider", (e: any) => {
    const info = e?.detail?.info ?? {};
    const provider = e?.detail?.provider;
    wrapProvider(provider);
    try {
      const rdns = String(info.rdns ?? "");
      const name = String(info.name ?? "");
      const claimsMM = provider?.isMetaMask === true;
      const okRdns = Object.entries(KNOWN_RDNS).find(([r]) => rdns === r);
      if (okRdns && !okRdns[1].test(name)) post({ kind: "fake-wallet", method: "eip6963", detail: "fake_wallet", param: `${name} (${rdns})`, msSinceLoad: Date.now() - loadedAt, hadGesture: false });
      else if (claimsMM && rdns && rdns !== "io.metamask" && !/metamask/i.test(name)) post({ kind: "fake-wallet", method: "eip6963", detail: "fake_wallet", param: `${name} (${rdns})`, msSinceLoad: Date.now() - loadedAt, hadGesture: false });
    } catch { /* ignore */ }
  });

  // ---- Solana wallets ----
  const wrapSolana = () => {
    const s = (window as any).solana ?? (window as any).phantom?.solana;
    if (!s || wrapped.has(s)) return;
    wrapped.add(s);
    for (const m of ["signTransaction", "signAllTransactions", "signAndSendTransaction", "signMessage"]) {
      const f = s[m];
      if (typeof f !== "function") continue;
      try {
        s[m] = function (this: unknown) {
          const g = hadGesture();
          const many = m === "signAllTransactions" && Array.isArray(arguments[0]) && arguments[0].length > 1;
          post({ kind: "risky-tx", method: m, detail: many ? "solana_batch" : "solana", param: m, msSinceLoad: Date.now() - loadedAt, hadGesture: g });
          return f.apply(this ?? s, arguments as any);
        };
      } catch { /* ignore */ }
    }
  };
  wrapSolana();
  let sn = 0;
  const siv = setInterval(() => { wrapSolana(); if (++sn > 20) clearInterval(siv); }, 500);

  // ---- clipboard: ClickFix commands and address swapping ----
  function inspectCopy(text: string) {
    if (typeof text !== "string" || !text) return;
    if (CLICKFIX_RE.test(text)) { post({ kind: "clickfix", method: "clipboard", detail: "clickfix", param: text.slice(0, 80), msSinceLoad: Date.now() - loadedAt, hadGesture: hadGesture() }); return; }
    const copied = text.match(CRYPTO_ADDR_RE)?.[1];
    if (!copied) return;
    const sel = String(window.getSelection?.()?.toString() ?? "");
    const selected = sel.match(CRYPTO_ADDR_RE)?.[1];
    if (selected && selected !== copied) post({ kind: "clipboard-swap", method: "clipboard", detail: "clipboard_swap", param: `${selected.slice(0, 8)}… → ${copied.slice(0, 8)}…`, msSinceLoad: Date.now() - loadedAt, hadGesture: hadGesture() });
  }
  try {
    const cb = navigator.clipboard;
    if (cb && typeof cb.writeText === "function") {
      const ow = cb.writeText.bind(cb);
      Object.defineProperty(cb, "writeText", { configurable: true, value: (t: string) => { inspectCopy(t); return ow(t); } });
    }
    const oe = document.execCommand?.bind(document);
    if (oe) {
      document.execCommand = function (cmd: string, ...rest: any[]) {
        if (String(cmd).toLowerCase() === "copy") {
          const active = document.activeElement as HTMLInputElement | HTMLTextAreaElement | null;
          const val = active && "value" in active ? String(active.value ?? "") : String(window.getSelection?.()?.toString() ?? "");
          inspectCopy(val);
        }
        return oe(cmd, ...(rest as [boolean?, string?]));
      } as typeof document.execCommand;
    }
    document.addEventListener("copy", (e) => {
      // a page that rewrites the clipboard in a copy handler: compare what it sets with what was selected
      const data = (e as ClipboardEvent).clipboardData;
      setTimeout(() => { try { const t = data?.getData("text/plain"); if (t) inspectCopy(t); } catch { /* ignore */ } }, 0);
    }, true);
  } catch { /* ignore */ }
})();
