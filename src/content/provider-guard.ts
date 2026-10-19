/**
 * Runs in the page's MAIN world at document_start, in every frame, before any page script.
 *
 * This file is deliberately thin: it hooks the wallet entry points and relays every request over a private
 * MessageChannel port to bridge.ts (isolated world), which decodes the request, asks the background whether to hold
 * it, renders the confirmation modal and answers. Nothing here parses calldata or decides anything, so a page that
 * rewrites JSON.parse, Map.prototype.set, Promise.prototype.then or Array.prototype.includes changes nothing: every
 * built-in this script relies on is captured at document_start and invoked through the captured Reflect.apply.
 *
 * Hooks: EIP-1193 providers (window.ethereum, EIP-6963 announcements, request/send/sendAsync and MetaMask's
 * _rpcRequest, patched on the instance and on every prototype that owns them), the legacy Solana provider,
 * Wallet Standard wallets (navigator.wallets and the register-wallet / app-ready events), and clipboard writes.
 *
 * It stops off-the-shelf drainer kits. A wallet built into the page itself is out of reach by design.
 */
(() => {
  // ---- captured built-ins -------------------------------------------------------------------
  const R = Reflect.apply;
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const getPrototypeOf = Object.getPrototypeOf;
  const objectKeys = Object.keys;
  const objectCreate = Object.create;
  const isArray = Array.isArray;
  const PromiseC = Promise;
  const promiseThen = Promise.prototype.then;
  const setTimeoutF = setTimeout;
  const clearTimeoutF = clearTimeout;
  const dateNow = Date.now;
  const mathRandom = Math.random;
  const stringSlice = String.prototype.slice;
  const toStr = (v: unknown) => (typeof v === "string" ? v : String(v));
  const addListener = EventTarget.prototype.addEventListener;
  const removeListener = EventTarget.prototype.removeEventListener;
  const stopImmediate = Event.prototype.stopImmediatePropagation;
  const portPost = MessagePort.prototype.postMessage;
  const portStart = MessagePort.prototype.start;
  const portOnMessage = getOwnPropertyDescriptor(MessagePort.prototype, "onmessage")!.set!;
  const weakSetAdd = WeakSet.prototype.add, weakSetHas = WeakSet.prototype.has;
  const weakMapGet = WeakMap.prototype.get, weakMapSet = WeakMap.prototype.set;
  const reTest = RegExp.prototype.test;
  const arrayPush = Array.prototype.push;
  const promiseReject = Promise.reject;
  const cloneF = (window as unknown as { structuredClone?: <T>(v: T) => T }).structuredClone;
  const jsonStringify = JSON.stringify, jsonParse = JSON.parse;
  const strIndexOf = String.prototype.indexOf, strLower = String.prototype.toLowerCase, strSplit = String.prototype.split;
  const createEvent = (name: string, detail: unknown) => new CustomEvent(name, { detail });
  const dispatch = EventTarget.prototype.dispatchEvent;
  const freeze = Object.freeze;
  /** One snapshot of the request: the bridge inspects it and the wallet receives the very same object, so a getter that answers differently on the second read gains nothing. */
  const snapshot = <T,>(v: T): T | undefined => {
    try { if (cloneF) return R(cloneF, window, [v]) as T; } catch { /* fall through */ }
    try { return R(jsonParse, JSON, [R(jsonStringify, JSON, [v])]) as T; } catch { return undefined; }
  };
  const reject = (e: unknown) => R(promiseReject, PromiseC, [e]) as Promise<never>;

  const TAG = "w3pg";
  const now = () => R(dateNow, Date, []);
  const loadedAt = now();
  let lastGesture = 0;
  const gesture = (e: Event) => { if (e.isTrusted) lastGesture = now(); };
  for (const ev of ["pointerdown", "keydown", "touchstart"]) R(addListener, window, [ev, gesture, { capture: true, passive: true }]);
  const hadGesture = () => now() - lastGesture < 1500;
  const newId = () => toStr(R(stringSlice, toStr(R(mathRandom, Math, [])), [2])) + toStr(now());
  const later = (fn: () => void, ms: number): unknown => R(setTimeoutF, window, [fn, ms]);
  const cancel = (h: unknown) => { R(clearTimeoutF, window, [h]); };
  const then = <T,>(p: Promise<T>, ok: (v: T) => unknown, bad?: (e: unknown) => unknown) => R(promiseThen, p, [ok, bad]) as Promise<unknown>;

  // ---- private channel to the isolated-world bridge ----------------------------------------
  let port: MessagePort | null = null;
  const queued: unknown[] = [];
  const send = (m: unknown) => { if (port) { try { R(portPost, port, [m]); } catch { /* ignore */ } } else queued[queued.length] = m; };
  const post = (event: Record<string, unknown>) => send({ type: "event", event });

  interface Waiter { ack: (hold: boolean) => void; done: (allow: boolean) => void }
  const pending: Record<string, Waiter> = objectCreate(null);

  const onPortMessage = (e: MessageEvent) => {
    const d = e.data;
    if (!d || typeof d !== "object") return;
    const id = toStr(d.id);
    if (d.type === "getCode") { void getCode(id, toStr(d.address)); return; }
    const w = pending[id];
    if (!w) return;
    if (d.type === "ack") w.ack(!!d.hold);
    else if (d.type === "decision") { delete pending[id]; w.done(!!d.allow); }
  };
  const adoptPort = (p: MessagePort) => {
    if (port) return;
    port = p;
    R(portOnMessage, p, [onPortMessage]);
    try { R(portStart, p, []); } catch { /* ignore */ }
    for (let i = 0; i < queued.length; i++) { try { R(portPost, p, [queued[i]]); } catch { /* ignore */ } }
    queued.length = 0;
  };
  // The bridge posts its port as a transferable before any page script can run (both scripts are document_start);
  // the first port wins and the listener goes away, so a later forged "port" message changes nothing.
  const portListener = (e: MessageEvent) => {
    if (e.source !== window) return;
    const d = e.data;
    if (!d || d.source !== TAG + "-ext" || d.type !== "port" || !e.ports || !e.ports[0]) return;
    R(stopImmediate, e, []);
    R(removeListener, window, ["message", portListener, true]);
    adoptPort(e.ports[0]);
  };
  R(addListener, window, ["message", portListener, true]);

  /** Ask the bridge. Resolves to true (let it through) or false (reject with 4001). */
  function inspect(method: string, params: unknown, chain: "evm" | "solana" = "evm", item?: object): Promise<boolean> {
    const id = newId();
    if (item) { const prov = R(weakMapGet, itemProvider, [item]) as object | undefined; if (prov) requestProvider[id] = prov; }
    return new PromiseC<boolean>((resolve) => {
      let acked = false;
      let soft: unknown = null;
      // Until the bridge acknowledges, a dead bridge must not wedge a dapp: after the grace period the request goes
      // through. Acknowledged as "hold": the user's answer is awaited for as long as the modal is on screen.
      // Acknowledged as ordinary: a short wait for the verdict, then through.
      const grace = later(() => { if (!acked) { delete pending[id]; resolve(true); } }, 8000);
      pending[id] = {
        // a later ack(hold=true) (the bridge is about to show the modal) cancels the soft timeout: nothing goes
        // through while a dialog is on screen
        ack: (hold) => { acked = true; cancel(grace); if (hold) { if (soft) { cancel(soft); soft = null; } } else if (!soft) soft = later(() => { if (pending[id]) { delete pending[id]; resolve(true); } }, 8000); },
        done: (allow) => { cancel(grace); if (soft) cancel(soft); resolve(allow); },
      };
      send({ type: "inspect", id, method, params, chain, hadGesture: hadGesture(), msSinceLoad: now() - loadedAt });
    });
  }
  const rejected = () => { const err = new Error("User rejected the request (Web3 Phish Guard)."); (err as unknown as { code: number }).code = 4001; return err; };

  // ---- read-only call on behalf of the bridge (eth_getCode) ----
  let rawRequest: ((args: unknown) => Promise<unknown>) | null = null;
  const requestProvider: Record<string, object> = objectCreate(null);
  async function getCode(id: string, address: string): Promise<void> {
    let code: string | null = null;
    try {
      // answer through the provider the inspected request came in on, not whichever provider was wrapped first
      const prov = requestProvider[id];
      const viaProvider = prov ? (R(weakMapGet, rawRequests, [prov]) as ((a: unknown) => Promise<unknown>) | undefined) : undefined;
      const req = viaProvider ?? rawRequest;
      if (req) {
        const p = req({ method: "eth_getCode", params: [address, "latest"] });
        const v = await new PromiseC<unknown>((res, rej) => { const tm = later(() => rej(new Error("timeout")), 3000); then(p, (x) => { cancel(tm); res(x); }, (e) => { cancel(tm); rej(e); }); });
        if (typeof v === "string") code = v;
      }
    } catch { /* unknown */ }
    send({ type: "code", id, code });
  }

  // ---- provider wrapping: instance + prototype chain -------------------------------------
  const ourFns = new WeakSet<object>();
  const wrappedProviders = new WeakSet<object>();
  const has = (set: WeakSet<object>, o: object): boolean => R(weakSetHas, set, [o]) as boolean;
  const add = (set: WeakSet<object>, o: object) => { R(weakSetAdd, set, [o]); };

  /** Every object in the prototype chain (instance first) that owns `name` as a plain function. */
  function owners(p: object, name: string): object[] {
    const out: object[] = [];
    let o: object | null = p;
    let guard = 0;
    while (o && o !== Object.prototype && o !== Function.prototype && guard++ < 12) {
      const desc = getOwnPropertyDescriptor(o, name);
      if (desc && typeof desc.value === "function") out[out.length] = o;
      o = getPrototypeOf(o);
    }
    return out;
  }
  function patch(owner: object, name: string, make: (orig: (...a: any[]) => any) => (...a: any[]) => any): boolean {
    const desc = getOwnPropertyDescriptor(owner, name);
    if (!desc || typeof desc.value !== "function" || has(ourFns, desc.value)) return false;
    const wrapper = make(desc.value);
    add(ourFns, wrapper);
    try { defineProperty(owner, name, { configurable: true, writable: true, enumerable: desc.enumerable, value: wrapper }); return true; } catch { return false; }
  }
  const asList = (payload: unknown): Array<{ method?: string; params?: unknown } | null> => (isArray(payload) ? (payload as never[]) : [payload as never]);
  /** request objects already approved once (a proxy provider forwarding to the announced one must not ask twice) */
  const approved = new WeakSet<object>();
  const markApproved = (o: unknown) => { if (o && typeof o === "object") add(approved, o); };
  const isApproved = (o: unknown) => !!o && typeof o === "object" && has(approved, o);
  const SIGNING_METHODS: Record<string, true> = objectCreate(null);
  for (const mth of ["eth_sendTransaction", "eth_signTransaction", "wallet_sendCalls", "eth_sign", "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4", "personal_sign"]) SIGNING_METHODS[mth] = true;
  /** Snapshot a request; a signing request that cannot be snapshotted is marked so the bridge holds it. */
  const prepare = (x: { method?: string; params?: unknown } | null) => {
    if (!x || !x.method) return x;
    // already approved on an outer layer (request -> _rpcRequest -> _rpcEngine.handle, or a proxy provider forwarding
    // to the announced one): pass the very same object through, no second snapshot and no second prompt
    if (isApproved(x)) return x;
    const snap = snapshot(x);
    if (snap && typeof snap === "object") return snap;
    return SIGNING_METHODS[toStr(x.method)] ? { method: x.method, params: undefined, w3pgUndecodable: true } : x;
  };
  const all = (ps: Promise<boolean>[]): Promise<boolean> => new PromiseC<boolean>((resolve) => {
    let n = ps.length, ok = true;
    if (!n) { resolve(true); return; }
    for (let i = 0; i < ps.length; i++) then(ps[i], (v) => { if (!v) ok = false; if (--n === 0) resolve(ok); }, () => { if (--n === 0) resolve(ok); });
  });
  const checksFor = (items: Array<{ method?: string; params?: unknown; w3pgUndecodable?: boolean } | null>) => {
    const checks: Promise<boolean>[] = [];
    for (let i = 0; i < items.length; i++) { const x = items[i]; if (x && x.method && !isApproved(x)) checks[checks.length] = inspect(toStr(x.method), x.w3pgUndecodable ? { w3pgUndecodable: true } : x.params, "evm", x); }
    return then(all(checks), (ok) => { if (ok) for (let i = 0; i < items.length; i++) markApproved(items[i]); return ok; }) as Promise<boolean>;
  };
  const rawRequests = new WeakMap<object, (args: unknown) => Promise<unknown>>();

  /** remember which provider a (snapshotted) request belongs to, for the bridge's getCode round trip */
  const itemProvider = new WeakMap<object, object>();
  const requestProviderFor = (item: object, p: object) => { R(weakMapSet, itemProvider, [item, p]); };

  function wrapProvider(p: any) {
    if (!p || typeof p !== "object" || has(wrappedProviders, p)) return;
    add(wrappedProviders, p);
    {
      const o = owners(p, "request")[0];
      const fn = o && (getOwnPropertyDescriptor(o, "request")!.value as (a: unknown) => Promise<unknown>);
      if (fn && !has(ourFns, fn)) { const raw = (args: unknown) => R(fn, p, [args]); R(weakMapSet, rawRequests, [p, raw]); if (!rawRequest) rawRequest = raw; }
    }
    // MetaMask's engine sits below _rpcRequest; a page can call it directly
    const engine = p._rpcEngine;
    if (engine && typeof engine === "object") {
      for (const o of owners(engine, "handle")) {
        patch(o, "handle", (orig) => function (this: unknown, payload: unknown, cb?: unknown) {
          const self = this;
          const items = isArray(payload) ? (payload as unknown[]).map(prepare as never) : [prepare(payload as never)];
          const sendPayload = isArray(payload) ? items : items[0];
          const decided = checksFor(items as never);
          if (typeof cb === "function") { then(decided, (allow) => (allow ? R(orig, self, [sendPayload, cb]) : R(cb, undefined, [rejected()])), () => R(orig, self, [sendPayload, cb])); return undefined; }
          return then(decided, (allow) => (allow ? R(orig, self, [sendPayload]) : reject(rejected())), () => R(orig, self, [sendPayload]));
        });
      }
    }
    // MetaMask-style providers funnel request/send/sendAsync through _rpcRequest: inspect there, once, so a
    // request cannot slip past by calling the lower layer directly and the user is not asked twice. `deep` is only
    // true once that patch actually landed; otherwise the upper layers inspect.
    let deep = false;
    for (const o of owners(p, "_rpcRequest")) {
      const ok = patch(o, "_rpcRequest", (orig) => function (this: unknown, payload: unknown, cb?: unknown) {
        const self = this;
        const items = isArray(payload) ? (payload as unknown[]).map(prepare as never) : [prepare(payload as never)];
        const sendPayload = isArray(payload) ? items : items[0];
        for (let i = 0; i < items.length; i++) { const it = items[i] as { method?: string } | null; if (it && it.method) requestProviderFor(it, p); }
        then(checksFor(items as never), (allow) => {
          if (!allow) { if (typeof cb === "function") R(cb, undefined, [rejected()]); return; }
          R(orig, self, [sendPayload, cb]);
        }, () => { R(orig, self, [sendPayload, cb]); });
        return undefined;
      });
      if (ok) deep = true;
    }
    for (const o of owners(p, "request")) {
      patch(o, "request", (orig) => function (this: unknown, args: { method?: string; params?: unknown }) {
        const self = this ?? p;
        if (deep || !args || !args.method) return R(orig, self, [args]);
        const snap = prepare(args) as { method?: string; params?: unknown } | null;
        const run = () => R(orig, self, [snap ?? args]);
        if (snap) requestProviderFor(snap, p);
        return then(checksFor([snap]), (allow) => (allow ? run() : reject(rejected())), () => run());
      });
    }
    for (const legacy of ["send", "sendAsync"]) {
      for (const o of owners(p, legacy)) {
        patch(o, legacy, (orig) => function (this: unknown, a: any, b: any) {
          const self = this ?? p;
          if (deep) return R(orig, self, [a, b]);
          // legacy synchronous send(method) forms (eth_accounts, net_version) are read-only: pass them straight through
          if (typeof a === "string" && !SIGNING_METHODS[a]) return R(orig, self, [a, b]);
          const items = typeof a === "string" ? [prepare({ method: a, params: b })] : (isArray(a) ? (a as unknown[]).map(prepare as never) : [prepare(a as never)]);
          const sendA = typeof a === "string" ? a : isArray(a) ? items : items[0];
          if (typeof a === "string") b = (items[0] as { params?: unknown } | null)?.params;
          for (let i = 0; i < items.length; i++) { const it = items[i] as { method?: string } | null; if (it && it.method) requestProviderFor(it, p); }
          const invoke = () => R(orig, self, [sendA, b]);
          const decided = checksFor(items as never);
          if (typeof b === "function") { then(decided, (allow) => (allow ? invoke() : R(b, undefined, [rejected()])), invoke); return undefined; }
          return then(decided, (allow) => (allow ? invoke() : reject(rejected())), invoke);
        });
      }
    }
  }

  // window.ethereum: wrap now, on assignment, and keep looking for a while (wallets that inject with
  // Object.defineProperty replace our accessor without triggering the setter)
  const tryWrap = () => { try { wrapProvider((window as any).ethereum); } catch { /* ignore */ } };
  tryWrap();
  let current = (window as any).ethereum;
  try {
    defineProperty(window, "ethereum", { configurable: true, get: () => current, set: (v) => { current = v; wrapProvider(v); } });
  } catch { /* not configurable: polling below covers it */ }
  let polls = 0;
  const poll = () => { tryWrap(); if (++polls < 40) later(poll, 250); };
  later(poll, 250);
  R(addListener, window, ["DOMContentLoaded", tryWrap, { once: true }]);
  R(addListener, window, ["load", tryWrap, { once: true }]);

  // EIP-6963 providers (drainers enumerate these; fake wallets announce wrong identities)
  const KNOWN_RDNS: Record<string, RegExp> = objectCreate(null);
  for (const [k, v] of [["io.metamask", /metamask/i], ["io.metamask.flask", /metamask/i], ["app.phantom", /phantom/i], ["com.coinbase.wallet", /coinbase/i], ["io.rabby", /rabby/i], ["com.okex.wallet", /okx/i], ["com.trustwallet.app", /trust/i], ["com.brave.wallet", /brave/i], ["me.rainbow", /rainbow/i], ["app.backpack", /backpack/i], ["xyz.argent", /argent/i], ["io.zerion.wallet", /zerion/i], ["app.keplr", /keplr/i]] as Array<[string, RegExp]>) KNOWN_RDNS[k] = v;
  R(addListener, window, ["eip6963:announceProvider", (e: any) => {
    const info = (e && e.detail && e.detail.info) || {};
    const provider = e && e.detail && e.detail.provider;
    wrapProvider(provider);
    try {
      const rdns = toStr(info.rdns ?? "");
      const name = toStr(info.name ?? "");
      const claimsMM = !!provider && provider.isMetaMask === true;
      const known = KNOWN_RDNS[rdns];
      const bad = (known && !R(reTest, known, [name])) || (claimsMM && rdns && R(strIndexOf, rdns, ["io.metamask"]) !== 0 && !R(reTest, /metamask/i, [name]));
      if (bad) post({ kind: "fake-wallet", method: "eip6963", detail: "fake_wallet", param: `${name} (${rdns})`, msSinceLoad: now() - loadedAt, hadGesture: false });
    } catch { /* ignore */ }
  }]);

  // ---- Solana: legacy window.solana ----
  const SOL_METHODS = ["signTransaction", "signAllTransactions", "signAndSendTransaction", "signAndSendAllTransactions", "signMessage", "signIn"];
  const isSol = (m: string) => { for (let i = 0; i < SOL_METHODS.length; i++) if (SOL_METHODS[i] === m) return true; return false; };
  void strSplit;
  const guardSolanaCall = (method: string, orig: (...a: any[]) => any, self: unknown, args: IArguments | unknown[]) => {
    const first = (args as unknown[])[0];
    const batch = isArray(first) ? (first as unknown[]).length : 1;
    return then(inspect(method, { batch }, "solana"), (allow) => (allow ? R(orig, self, args as unknown[]) : PromiseC.reject(rejected())), () => R(orig, self, args as unknown[]));
  };
  const wrapSolana = () => {
    const w = window as any;
    const s = w.solana ?? (w.phantom && w.phantom.solana);
    if (!s || typeof s !== "object" || has(wrappedProviders, s)) return;
    add(wrappedProviders, s);
    for (const m of SOL_METHODS) for (const o of owners(s, m)) patch(o, m, (orig) => function (this: unknown) { return guardSolanaCall("solana:" + m, orig, this ?? s, arguments); });
    for (const o of owners(s, "request")) {
      patch(o, "request", (orig) => function (this: unknown, args: { method?: string; params?: unknown }) {
        const m = toStr((args && args.method) ?? "");
        if (!isSol(m)) return R(orig, this ?? s, [args]);
        return then(inspect("solana:" + m, { batch: 1 }, "solana"), (allow) => (allow ? R(orig, this ?? s, [args]) : PromiseC.reject(rejected())), () => R(orig, this ?? s, [args]));
      });
    }
  };
  wrapSolana();
  let sn = 0;
  const spoll = () => { wrapSolana(); if (++sn < 20) later(spoll, 500); };
  later(spoll, 500);

  // ---- Wallet Standard (navigator.wallets, wallet-standard:register-wallet / app-ready) ----
  // The reference implementation exposes `features` through a getter that builds a fresh object on every read, so
  // patching a copy does nothing. An own accessor on the wallet instance shadows it and hands back guarded copies.
  // feature key -> method name, as a literal map: no RegExp or String.prototype call a page could rewrite
  const SIGNING: Record<string, string> = objectCreate(null);
  for (const ns of ["solana", "sui", "aptos", "standard", "experimental"]) for (const mth of ["signTransaction", "signAndSendTransaction", "signAllTransactions", "signMessage", "signIn", "signTransactionBlock", "signAndExecuteTransactionBlock", "signAndExecuteTransaction", "signAndSubmitTransaction", "signPersonalMessage"]) SIGNING[ns + ":" + mth] = mth;
  const guardedFeatures = new WeakMap<object, object>();
  const wrapStandardWallet = (w: any) => {
    if (!w || typeof w !== "object" || has(wrappedProviders, w)) return;
    add(wrappedProviders, w);
    const name = toStr(w.name ?? "wallet");
    let featOwner: object | null = w, featDesc: PropertyDescriptor | undefined;
    let guard = 0;
    while (featOwner && guard++ < 12) { featDesc = getOwnPropertyDescriptor(featOwner, "features"); if (featDesc) break; featOwner = getPrototypeOf(featOwner); }
    if (!featDesc) return;
    const readOriginal = () => (featDesc!.get ? R(featDesc!.get, w, []) : featDesc!.value);
    const build = (orig: any) => {
      if (!orig || typeof orig !== "object") return orig;
      const copy: Record<string, unknown> = objectCreate(null);
      for (const key of objectKeys(orig)) {
        const feat = orig[key];
        const method = SIGNING[key];
        if (!feat || typeof feat !== "object" || !method) { copy[key] = feat; continue; }
        const fcopy: Record<string, unknown> = { ...feat };
        const origFn = feat[method];
        if (typeof origFn === "function") fcopy[method] = function (this: unknown, ...inputs: unknown[]) { return guardSolanaCall(key, origFn, feat, inputs); };
        copy[key] = fcopy;
      }
      return copy;
    };
    let override: unknown = undefined, overridden = false;
    const guardedOf = (o: unknown) => { if (!o || typeof o !== "object") return o; let g = R(weakMapGet, guardedFeatures, [o]); if (!g) { g = build(o); R(weakMapSet, guardedFeatures, [o, g]); } return g; };
    try {
      defineProperty(w, "features", {
        configurable: true, enumerable: true,
        get: () => guardedOf(overridden ? override : readOriginal()),
        set: (v) => { override = v; overridden = true; }, // wallets that reassign this.features keep working
      });
    } catch {
      // The reference wallet template freezes itself in its constructor. The app then gets a Proxy whose `features`
      // are guarded; everything else forwards to the frozen target (methods bound to it, so private fields work).
      const proxy = new Proxy(w, {
        get: (t, k, _r) => { if (k === "features") return guardedOf(Reflect.get(t, k, t)); const v = Reflect.get(t, k, t); return typeof v === "function" ? R(Function.prototype.bind, v, [t]) : v; },
      });
      R(weakMapSet, proxies, [w, proxy]);
      post({ kind: "wallet-standard", method: "register", detail: "frozen", param: name, msSinceLoad: now() - loadedAt, hadGesture: false });
      return;
    }
    post({ kind: "wallet-standard", method: "register", detail: "", param: name, msSinceLoad: now() - loadedAt, hadGesture: false });
  };
  const proxies = new WeakMap<object, object>();
  /** the object the app should receive: the wallet itself once patched, or its guarded Proxy when frozen */
  const guardWallet = (w: any) => { wrapStandardWallet(w); const px = w && typeof w === "object" ? R(weakMapGet, proxies, [w]) : undefined; return px ?? w; };
  const ourApi = { register: (...wallets: any[]) => { for (let i = 0; i < wallets.length; i++) guardWallet(wallets[i]); return () => undefined; } };
  const callWithOurApi = (cb: unknown) => { try { if (typeof cb === "function") R(cb as (...a: unknown[]) => unknown, undefined, [ourApi]); } catch { /* ignore */ } };
  R(addListener, window, ["wallet-standard:register-wallet", (e: any) => callWithOurApi(e && e.detail), true]);
  // The app's side: @wallet-standard/app dispatches a frozen { register } and throws on stopImmediatePropagation from
  // its own event class. Swallow the original event (captured stopImmediatePropagation on the Event prototype still
  // works) and re-dispatch a plain CustomEvent carrying a frozen wrapper that guards each wallet before forwarding.
  let reentry = false;
  R(addListener, window, ["wallet-standard:app-ready", (e: any) => {
    if (reentry) return;
    const api = e && e.detail;
    if (!api || typeof api !== "object" || typeof api.register !== "function") return;
    const orig = api.register;
    const wrapped = freeze({ register: (...wallets: any[]) => { const out: unknown[] = []; for (let i = 0; i < wallets.length; i++) out[i] = guardWallet(wallets[i]); return R(orig, api, out); } });
    try { R(stopImmediate, e, []); } catch { /* their subclass throws: the listener below never sees it either way */ }
    reentry = true;
    try { R(dispatch, window, [createEvent("wallet-standard:app-ready", wrapped)]); } finally { reentry = false; }
  }, true]);
  try {
    const nav = window.navigator as any;
    const existing: any[] = isArray(nav.wallets) ? nav.wallets : [];
    for (let i = 0; i < existing.length; i++) callWithOurApi(existing[i]);
    const arr: any = existing;
    arr.push = (...cbs: any[]) => { for (let i = 0; i < cbs.length; i++) callWithOurApi(cbs[i]); return R(arrayPush, arr, cbs); };
    defineProperty(nav, "wallets", {
      configurable: true,
      get: () => arr,
      set: (v) => {
        // apps assign either an array of callbacks or an object with push(); keep both working
        if (v === arr) return;
        if (isArray(v)) { for (let i = 0; i < v.length; i++) callWithOurApi(v[i]); const copy = [...v]; arr.length = 0; R(arrayPush, arr, copy); }
        else if (v && typeof v === "object" && typeof v.push === "function") { const theirPush = v.push; arr.push = (...cbs: any[]) => { for (let i = 0; i < cbs.length; i++) callWithOurApi(cbs[i]); R(theirPush, v, cbs); return R(arrayPush, arr, cbs); }; }
      },
    });
  } catch { /* navigator.wallets not configurable here */ }

  // ---- clipboard: ClickFix commands and address swapping (text goes to the bridge, which has the patterns) ----
  const selectionText = () => { try { const s = window.getSelection && window.getSelection(); return s ? toStr(s.toString()) : ""; } catch { return ""; } };
  const inspectCopy = (text: unknown) => { if (typeof text === "string" && text) send({ type: "copy", text: R(stringSlice, text, [0, 2000]), selection: selectionText() }); };
  try {
    const proto = (window as any).Clipboard && (window as any).Clipboard.prototype;
    if (proto) {
      patch(proto, "writeText", (orig) => function (this: unknown, tx: string) { inspectCopy(tx); return R(orig, this, [tx]); });
      patch(proto, "write", (orig) => function (this: unknown, items: unknown) {
        try {
          const list = isArray(items) ? (items as Array<{ types?: string[]; getType?: (t: string) => Promise<Blob> }>) : [];
          for (let i = 0; i < list.length; i++) { const it = list[i]; if (it && it.types && it.getType && it.types.indexOf("text/plain") >= 0) then(then(it.getType("text/plain"), (b) => (b as Blob).text()) as Promise<string>, inspectCopy, () => undefined); }
        } catch { /* ignore */ }
        return R(orig, this, [items]);
      });
    }
    const oe = document.execCommand;
    if (typeof oe === "function") {
      document.execCommand = function (cmd: string, ...rest: any[]) {
        if (R(strLower, toStr(cmd), []) === "copy") {
          const active = document.activeElement as HTMLInputElement | null;
          inspectCopy(active && "value" in active ? toStr(active.value ?? "") : selectionText());
        }
        return R(oe, document, [cmd, ...rest]);
      } as typeof document.execCommand;
    }
    R(addListener, window, ["copy", (e: Event) => {
      try {
        const data = (e as ClipboardEvent).clipboardData;
        if (!data || !e.defaultPrevented) return; // not rewritten: the browser copies the selection itself
        inspectCopy(data.getData("text/plain"));
      } catch { /* ignore */ }
    }, false]);
  } catch { /* ignore */ }
})();
