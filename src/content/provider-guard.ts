/**
 * Runs in the page's MAIN world at document_start, in every frame, before any page script.
 *
 * 1. Wraps EIP-1193 providers (window.ethereum, EIP-6963 announcements, legacy send/sendAsync, MetaMask's
 *    internal _rpcRequest) and the Solana provider to observe intent and, for high-risk requests, HOLD the
 *    request until the user decides in a modal rendered by the isolated-world bridge (bridge.ts). A rejected
 *    request resolves with EIP-1193 error 4001.
 * 2. Wraps clipboard writes to catch ClickFix command injection and address swapping.
 * 3. Flags wallet providers whose EIP-6963 identity does not match the wallet they claim to be.
 *
 * Hardening against page JavaScript:
 *  - the bridge hands this script a MessageChannel port at document_start; gate answers only travel over that
 *    port, so a page cannot forge "allow" by posting a window message;
 *  - methods are replaced on the instance AND on every prototype in the chain that owns them, so
 *    Object.getPrototypeOf(ethereum).request.call(ethereum, ...) still meets the guard;
 *  - for the kinds no legitimate flow needs (unlimited approve, operator approval, permits, delegation,
 *    eth_sign, EOA spender, poisoned recipient) the request fails closed if the extension does not answer;
 *    everything else proceeds after a short grace period so a dapp can never wedge on a dead extension.
 *
 * It stops off-the-shelf drainer kits. Code that targets this extension specifically (for example a wallet
 * built into the page) is out of its reach by design: the real line of defence is the warning before the page.
 */
import { decodeTx, decodeSendCalls, decodeTypedData, looksPoisoned, CLICKFIX_RE, CRYPTO_ADDR_RE, type TxIntent, type SignIntent } from "../lib/txdecode";

(() => {
  const TAG = "w3pg";
  const loadedAt = Date.now();
  let lastGesture = 0;
  const gesture = (e: Event) => { if (e.isTrusted) lastGesture = Date.now(); };
  for (const ev of ["pointerdown", "keydown", "touchstart"]) window.addEventListener(ev, gesture, { capture: true, passive: true });
  const hadGesture = () => Date.now() - lastGesture < 1500;

  // ---- private channel to the isolated-world bridge ----------------------------------------
  let port: MessagePort | null = null;
  const queued: unknown[] = [];
  const send = (m: unknown) => { if (port) { try { port.postMessage(m); } catch { /* ignore */ } } else queued.push(m); };
  const post = (event: Record<string, unknown>) => send({ type: "event", event });

  interface Waiter { ack: () => void; done: (allow: boolean) => void }
  const pending = new Map<string, Waiter>();
  const onPortMessage = (e: MessageEvent) => {
    const d = e.data;
    if (!d || typeof d !== "object") return;
    const w = pending.get(String(d.id));
    if (!w) return;
    if (d.type === "gate-ack") w.ack();
    else if (d.type === "gate-result") { pending.delete(String(d.id)); w.done(!!d.allow); }
  };
  const adoptPort = (p: MessagePort) => {
    if (port) return;
    port = p;
    p.onmessage = onPortMessage;
    for (const m of queued) { try { p.postMessage(m); } catch { /* ignore */ } }
    queued.length = 0;
  };
  // The bridge posts its port as a transferable before any page script can run (both scripts are document_start);
  // the first port wins and the listener goes away, so a later forged "port" message changes nothing.
  const portListener = (e: MessageEvent) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.source !== TAG + "-ext" || d.type !== "port" || !e.ports?.[0]) return;
    e.stopImmediatePropagation();
    window.removeEventListener("message", portListener, true);
    adoptPort(e.ports[0]);
  };
  window.addEventListener("message", portListener, true);

  /** Kinds that fail closed when the extension is silent: nothing legitimate needs them from a web page. */
  const ALWAYS_HOLD = new Set(["setApprovalForAll", "approve-unlimited", "permit2", "permit", "permit-batch", "permit-for-all", "delegation", "delegation-7702", "eth_sign", "seaport-order", "blur-order", "transfer-auth"]);

  function gate(details: Record<string, unknown>): Promise<boolean> {
    const id = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const hold = ALWAYS_HOLD.has(String(details.kind)) || details.counterpartyEoa === true || !!details.poisonedTwin;
    return new Promise((resolve) => {
      let acked = false;
      // Until the bridge acknowledges, a dead extension must not wedge a dapp: ordinary requests go through after
      // the grace period; always-hold kinds are rejected instead. Once acknowledged, the user's answer is awaited
      // for as long as the modal is on screen, with no timer.
      const graceTimer = setTimeout(() => { if (!acked) { pending.delete(id); resolve(!hold); } }, 8000);
      pending.set(id, {
        ack: () => { acked = true; clearTimeout(graceTimer); },
        done: (allow) => { clearTimeout(graceTimer); resolve(allow); },
      });
      send({ type: "gate", gate: { id, ...details } });
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

  /** The first unwrapped request() we saw, for our own read-only calls. */
  let rawRequest: ((args: unknown) => Promise<unknown>) | null = null;

  /** eth_getCode through the same provider: an EOA spender/operator is a drainer hallmark. A 7702-delegated EOA (code 0xef0100…) counts as an EOA too. */
  async function isEoa(address: string | undefined): Promise<boolean | undefined> {
    if (!address || !/^0x[0-9a-f]{40}$/.test(address) || !rawRequest) return undefined;
    try {
      const code = await Promise.race([
        rawRequest({ method: "eth_getCode", params: [address, "latest"] }) as Promise<string>,
        new Promise<string>((_, rej) => setTimeout(() => rej(new Error("timeout")), 3000)),
      ]);
      if (typeof code !== "string") return undefined;
      const c = code.toLowerCase();
      return c === "0x" || c === "0x0" || c === "" || c.startsWith("0xef0100");
    } catch {
      return undefined;
    }
  }

  async function inspect(method: string, params: unknown): Promise<"allow" | "reject"> {
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
      const eoa = await isEoa(s.counterparty);
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
      const eoa = ["approve-unlimited", "approve", "setApprovalForAll", "permit2"].includes(top.kind) ? await isEoa(top.counterparty) : undefined;
      if (eoa) post({ kind: "risky-tx", method, detail: "eoa-spender", param: top.counterparty, msSinceLoad, hadGesture: g });
      if (twin) post({ kind: "risky-tx", method, detail: "poisoning", param: top.counterparty, msSinceLoad, hadGesture: g });
      const details = { method, kind: top.kind, counterparty: top.counterparty, counterpartyEoa: eoa, unlimited: top.unlimited, token: top.token, poisonedTwin: twin, batch: flat.length > 1 ? flat.map((i) => i.kind) : undefined, hadGesture: g };
      return (await gate(details)) ? "allow" : "reject";
    }
    return "allow";
  }

  // ---- provider wrapping: instance + prototype chain -------------------------------------
  const ourFns = new WeakSet<object>();
  const wrappedProviders = new WeakSet<object>();

  /** Every object in the prototype chain (instance first) that owns `name` as a plain function. */
  function owners(p: object, name: string): object[] {
    const out: object[] = [];
    let o: object | null = p;
    while (o && o !== Object.prototype && o !== Function.prototype) {
      const desc = Object.getOwnPropertyDescriptor(o, name);
      if (desc && typeof desc.value === "function") out.push(o);
      o = Object.getPrototypeOf(o);
    }
    return out;
  }
  function patch(owner: object, name: string, make: (orig: (...a: any[]) => any) => (...a: any[]) => any): void {
    const desc = Object.getOwnPropertyDescriptor(owner, name);
    if (!desc || typeof desc.value !== "function" || ourFns.has(desc.value)) return;
    const wrapper = make(desc.value);
    ourFns.add(wrapper);
    try { Object.defineProperty(owner, name, { configurable: true, writable: true, enumerable: desc.enumerable, value: wrapper }); } catch { /* frozen */ }
  }
  const asList = (payload: unknown) => (Array.isArray(payload) ? payload : [payload]) as Array<{ method?: string; params?: unknown } | null>;

  function wrapProvider(p: any) {
    if (!p || typeof p !== "object" || wrappedProviders.has(p)) return;
    wrappedProviders.add(p);
    if (!rawRequest) {
      const o = owners(p, "request")[0];
      const fn = o && (Object.getOwnPropertyDescriptor(o, "request")!.value as (a: unknown) => Promise<unknown>);
      if (fn && !ourFns.has(fn)) rawRequest = (args) => fn.call(p, args);
    }
    // MetaMask-style providers funnel request/send/sendAsync through _rpcRequest: inspect there, once, so a
    // request cannot slip past by calling the lower layer directly and the user is not asked twice.
    const deep = owners(p, "_rpcRequest").length > 0;
    for (const o of owners(p, "_rpcRequest")) {
      patch(o, "_rpcRequest", (orig) => function (this: unknown, payload: unknown, cb?: unknown) {
        const self = this;
        const args = arguments;
        const checks = asList(payload).map((x) => (x?.method ? inspect(x.method, x.params) : Promise.resolve("allow" as const)));
        void Promise.all(checks).then((ds) => {
          if (ds.includes("reject")) { if (typeof cb === "function") cb(rejected()); return; }
          orig.apply(self, args as unknown as unknown[]);
        }, () => orig.apply(self, args as unknown as unknown[]));
        return undefined;
      });
    }
    for (const o of owners(p, "request")) {
      patch(o, "request", (orig) => function (this: unknown, args: { method?: string; params?: unknown }) {
        const self = this ?? p;
        const run = () => orig.apply(self, [args]);
        if (deep || !args?.method) return run();
        return inspect(args.method, args.params).then((d) => (d === "reject" ? Promise.reject(rejected()) : run()), () => run());
      });
    }
    for (const legacy of ["send", "sendAsync"] as const) {
      for (const o of owners(p, legacy)) {
        patch(o, legacy, (orig) => function (this: unknown, a: any, b: any) {
          const self = this ?? p;
          const invoke = () => orig.apply(self, [a, b]);
          if (deep) return invoke();
          const items = typeof a === "string" ? [{ method: a, params: b }] : asList(a);
          const checks = items.map((x) => (x?.method ? inspect(x.method, x.params) : Promise.resolve("allow" as const)));
          const decided = Promise.all(checks).then((ds) => (ds.includes("reject") ? "reject" : "allow"), () => "allow");
          if (typeof b === "function") { decided.then((d) => (d === "reject" ? b(rejected()) : invoke()), invoke); return undefined; }
          return decided.then((d) => (d === "reject" ? Promise.reject(rejected()) : invoke()), invoke);
        });
      }
    }
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
    "io.metamask": /metamask/i, "io.metamask.flask": /metamask/i, "app.phantom": /phantom/i, "com.coinbase.wallet": /coinbase/i, "io.rabby": /rabby/i,
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
      else if (claimsMM && rdns && !rdns.startsWith("io.metamask") && !/metamask/i.test(name)) post({ kind: "fake-wallet", method: "eip6963", detail: "fake_wallet", param: `${name} (${rdns})`, msSinceLoad: Date.now() - loadedAt, hadGesture: false });
    } catch { /* ignore */ }
  });

  // ---- Solana wallets (legacy window.solana API) ----
  const SOL_METHODS = ["signTransaction", "signAllTransactions", "signAndSendTransaction", "signAndSendAllTransactions", "signMessage"];
  const wrapSolana = () => {
    const s = (window as any).solana ?? (window as any).phantom?.solana;
    if (!s || typeof s !== "object" || wrappedProviders.has(s)) return;
    wrappedProviders.add(s);
    const report = (m: string, batch: boolean) => post({ kind: "risky-tx", method: m, detail: batch ? "solana_batch" : "solana", param: m, msSinceLoad: Date.now() - loadedAt, hadGesture: hadGesture() });
    for (const m of SOL_METHODS) {
      for (const o of owners(s, m)) {
        patch(o, m, (orig) => function (this: unknown) {
          const many = /All/.test(m) && Array.isArray(arguments[0]) && arguments[0].length > 1;
          report(m, many);
          return orig.apply(this ?? s, arguments as any);
        });
      }
    }
    // request({ method: "signAndSendTransaction" }) form
    for (const o of owners(s, "request")) {
      patch(o, "request", (orig) => function (this: unknown, args: { method?: string; params?: unknown }) {
        const m = String(args?.method ?? "");
        if (SOL_METHODS.includes(m)) report(m, /All/.test(m));
        return orig.apply(this ?? s, [args]);
      });
    }
  };
  wrapSolana();
  let sn = 0;
  const siv = setInterval(() => { wrapSolana(); if (++sn > 20) clearInterval(siv); }, 500);

  // ---- Wallet Standard (window.navigator.wallets / "wallet-standard:register-wallet") ----
  // Modern Solana (and some multichain) wallets do not expose window.solana at all: they announce a wallet object
  // whose `features` carry the signing methods. Every registration path funnels through a callback that receives
  // { register }; we call that callback ourselves with a register() that patches the signing features in place,
  // so the same wallet object the dapp later receives is already guarded.
  const SIGNING_FEATURE = /^(solana|sui|aptos|standard|experimental):(signTransaction|signAndSendTransaction|signAllTransactions|signMessage|signIn|signTransactionBlock|signAndExecuteTransactionBlock|signAndSubmitTransaction)$/;
  const wrapStandardWallet = (w: any) => {
    if (!w || typeof w !== "object" || wrappedProviders.has(w)) return;
    wrappedProviders.add(w);
    const name = String(w.name ?? "wallet");
    const features = w.features;
    if (!features || typeof features !== "object") return;
    for (const key of Object.keys(features)) {
      if (!SIGNING_FEATURE.test(key)) continue;
      const feat = features[key];
      if (!feat || typeof feat !== "object") continue;
      const method = key.split(":")[1];
      for (const o of owners(feat, method)) {
        patch(o, method, (orig) => function (this: unknown, ...inputs: any[]) {
          const many = inputs.length > 1 || (/All/.test(method) && Array.isArray(inputs[0]) && inputs[0].length > 1);
          post({ kind: "risky-tx", method: key, detail: many ? "solana_batch" : "solana", param: name, msSinceLoad: Date.now() - loadedAt, hadGesture: hadGesture() });
          return orig.apply(this ?? feat, inputs);
        });
      }
    }
  };
  const standardApi = { register: (...wallets: any[]) => { for (const w of wallets) wrapStandardWallet(w); return () => undefined; } };
  window.addEventListener("wallet-standard:register-wallet", (e: any) => {
    try { if (typeof e?.detail === "function") e.detail(standardApi); } catch { /* ignore */ }
  }, true);
  try {
    const nav = window.navigator as any;
    const existing = Array.isArray(nav.wallets) ? nav.wallets : [];
    for (const cb of existing) { try { if (typeof cb === "function") cb(standardApi); } catch { /* ignore */ } }
    const guardedPush = (...cbs: any[]) => { for (const cb of cbs) { try { if (typeof cb === "function") cb(standardApi); } catch { /* ignore */ } } return existing.push(...cbs); };
    const arr: any = existing;
    arr.push = guardedPush;
    Object.defineProperty(nav, "wallets", { configurable: true, get: () => arr, set: (v) => { if (Array.isArray(v)) { for (const cb of v) { try { if (typeof cb === "function") cb(standardApi); } catch { /* ignore */ } } arr.length = 0; arr.push(...v); } } });
  } catch { /* navigator.wallets not configurable here */ }

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
    // prototype-level so Clipboard.prototype.writeText.call(navigator.clipboard, ...) is covered as well
    const proto = (window as any).Clipboard?.prototype;
    if (proto) {
      patch(proto, "writeText", (orig) => function (this: unknown, t: string) { inspectCopy(t); return orig.call(this, t); });
      patch(proto, "write", (orig) => function (this: unknown, items: unknown) {
        try {
          for (const it of (items as Array<{ types?: string[]; getType?: (t: string) => Promise<Blob> }>) ?? []) {
            if (it?.types?.includes("text/plain") && it.getType) void it.getType("text/plain").then((b) => b.text()).then(inspectCopy).catch(() => undefined);
          }
        } catch { /* ignore */ }
        return orig.call(this, items);
      });
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
    // A page that rewrites the clipboard inside its own copy handler: by the time the event bubbles to window the
    // handler has run, and clipboardData is still readable synchronously during dispatch.
    window.addEventListener("copy", (e) => {
      try {
        const data = (e as ClipboardEvent).clipboardData;
        if (!data || !e.defaultPrevented) return; // not rewritten: the browser copies the selection itself
        const t = data.getData("text/plain");
        if (t) inspectCopy(t);
      } catch { /* ignore */ }
    }, false);
  } catch { /* ignore */ }
})();
