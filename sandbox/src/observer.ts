/**
 * The observer provider, injected into the sandbox page before any page script runs.
 *
 * It is a honeypot, not a wallet: it answers read-only calls so the page's flow proceeds, but it NEVER signs
 * anything and NEVER broadcasts anything. Every state-changing request (a transaction, a permit, any signature)
 * is recorded to `window.__w3pgCaptured` and then rejected with EIP-1193 code 4001, exactly as a user clicking
 * "Reject" would. Nothing here produces a signature or a private key; the address it exposes is a random,
 * empty, throw-away address passed in from the server. The server later simulates each captured request with
 * `eth_simulateV1` to see what signing it would have done.
 */

export interface ObserverConfig {
  /** random throw-away address (0x + 40 hex); it owns nothing */
  address: string;
  /** hex chain id the provider reports, e.g. "0x1" */
  chainId: string;
}

/** Runs inside the page (serialized by Playwright). Keep it self-contained: no imports, no closures over module scope. */
export function observerEntry(cfg: ObserverConfig): void {
  const w = window as unknown as Record<string, unknown> & { dispatchEvent: (e: Event) => boolean };
  const captured: Array<{ method: string; params: unknown; atMs: number; unprompted: boolean; chainId: string }> = [];
  (w as Record<string, unknown>).__w3pgCaptured = captured;
  const t0 = Date.now();
  // the harness sets this to true just before it clicks something, so we can tell "fired on load" from "fired on click"
  (w as Record<string, unknown>).__w3pgClicked = false;

  const addr = cfg.address.toLowerCase();
  const bal = "0x3635c9adc5dea00000"; // 1000 units: enough that a drainer bothers to act; the address is still empty on-chain
  const listeners: Record<string, Array<(x: unknown) => void>> = {};
  const emit = (ev: string, x: unknown) => { for (const fn of listeners[ev] || []) { try { fn(x); } catch { /* ignore */ } } };

  // methods that move or commit assets: recorded, then refused. Nothing below ever answers one of these for real.
  const COMMIT = /^(eth_sendTransaction|eth_signTransaction|eth_sign|personal_sign|eth_signTypedData(_v[134])?|wallet_sendCalls|wallet_sendTransaction)$/;

  function record(method: string, params: unknown) {
    const clicked = (w as Record<string, unknown>).__w3pgClicked === true;
    captured.push({ method, params, atMs: Date.now() - t0, unprompted: !clicked, chainId: cfg.chainId });
  }

  async function handle(method: string, params: unknown[]): Promise<unknown> {
    if (COMMIT.test(method)) {
      record(method, params);
      const err = new Error("User rejected the request.") as Error & { code: number };
      err.code = 4001;
      throw err;
    }
    switch (method) {
      case "eth_requestAccounts":
      case "eth_accounts":
      case "wallet_requestPermissions":
      case "wallet_getPermissions":
        if (method === "wallet_requestPermissions" || method === "wallet_getPermissions") return [{ parentCapability: "eth_accounts" }];
        return [addr];
      case "eth_chainId":
        return cfg.chainId;
      case "net_version":
        return String(parseInt(cfg.chainId, 16));
      case "eth_getBalance":
        return bal;
      case "wallet_switchEthereumChain":
      case "wallet_addEthereumChain": {
        const p = (params[0] || {}) as { chainId?: string };
        if (p && typeof p.chainId === "string") { cfg.chainId = p.chainId; emit("chainChanged", p.chainId); }
        return null;
      }
      case "eth_call": {
        // a dapp often reads balanceOf before offering an action; keep it moving with a funded answer, record the rest
        const call = (params[0] || {}) as { data?: string };
        if (typeof call.data === "string" && call.data.toLowerCase().startsWith("0x70a08231")) return "0x0000000000000000000000000000000000000000000000056bc75e2d63100000";
        return "0x";
      }
      case "eth_blockNumber":
        return "0x1";
      case "eth_estimateGas":
        return "0x5208";
      case "eth_gasPrice":
      case "maxPriorityFeePerGas":
        return "0x3b9aca00";
      case "eth_getTransactionCount":
        return "0x0";
      case "wallet_watchAsset":
        return true;
      default:
        return null;
    }
  }

  const provider = {
    isObserverSandbox: true,
    chainId: cfg.chainId,
    networkVersion: String(parseInt(cfg.chainId, 16)),
    selectedAddress: addr,
    isConnected: () => true,
    request: (args: { method: string; params?: unknown }) => handle(args.method, Array.isArray(args.params) ? args.params : []),
    enable: () => handle("eth_requestAccounts", []),
    send(a: unknown, b?: unknown) {
      if (typeof a === "string") return handle(a, Array.isArray(b) ? (b as unknown[]) : []);
      const req = a as { method: string; params?: unknown[] };
      return handle(req.method, req.params || []);
    },
    sendAsync(req: { method: string; params?: unknown[] }, cb: (e: unknown, r?: unknown) => void) {
      handle(req.method, req.params || []).then((result) => cb(null, { id: (req as { id?: number }).id, jsonrpc: "2.0", result }), (e) => cb(e));
    },
    on(ev: string, fn: (x: unknown) => void) { (listeners[ev] = listeners[ev] || []).push(fn); return provider; },
    once(ev: string, fn: (x: unknown) => void) { const g = (x: unknown) => { fn(x); }; return provider.on(ev, g); },
    removeListener(ev: string, fn: (x: unknown) => void) { listeners[ev] = (listeners[ev] || []).filter((f) => f !== fn); return provider; },
    removeAllListeners() { for (const k of Object.keys(listeners)) delete listeners[k]; return provider; },
  };

  try { Object.defineProperty(w, "ethereum", { value: provider, configurable: true, writable: false }); } catch { (w as Record<string, unknown>).ethereum = provider; }

  // EIP-6963: announce ourselves so modern dapps that use the discovery protocol find the provider
  const info = { uuid: "00000000-0000-4000-8000-00000000w3pg".replace(/w3pg/, "0abc"), name: "Sandbox Observer", icon: "data:image/svg+xml;base64,PHN2Zy8+", rdns: "org.w3pg.sandbox" };
  const announce = () => { try { w.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: Object.freeze({ info, provider }) })); } catch { /* ignore */ } };
  window.addEventListener("eip6963:requestProvider", announce);
  announce();

  setTimeout(() => emit("connect", { chainId: cfg.chainId }), 50);
}
