/**
 * Drives the MAIN-world guard against a fake MetaMask (own-property request -> _rpcRequest -> _rpcEngine.handle)
 * with this test acting as the bridge on the other end of the MessageChannel. Asserts the protocol invariants that
 * review rounds 4 and 5 found broken: one inspection per request, the wallet receives exactly the inspected
 * snapshot, rejections carry code 4001, and approvals are not re-asked on inner layers.
 */
import { describe, it, expect, beforeAll } from "vitest";

type Inspect = { id: string; method: string; params: unknown };
const seen: Inspect[] = [];
const engineCalls: unknown[] = [];
let decide: (m: Inspect) => boolean = () => true;
let port: MessagePort;
const rpcReplies: Array<{ id: string; result: unknown }> = [];

class FakeEngine {
  handle(payload: unknown, cb: (e: unknown, r?: unknown) => void) { engineCalls.push(payload); cb(null, { jsonrpc: "2.0", id: 1, result: "ok" }); }
}
class BaseProvider {
  _rpcEngine = new FakeEngine();
  isMetaMask = true;
  constructor() { Object.defineProperty(this, "request", { value: BaseProvider.prototype.request.bind(this), writable: true, configurable: true, enumerable: false }); } // own-property bound request, like MetaMask
  _rpcRequest(payload: unknown, cb: (e: unknown, r?: unknown) => void) { this._rpcEngine.handle(payload, cb); }
  async request(args: { method: string; params?: unknown }): Promise<unknown> {
    return new Promise((res, rej) => this._rpcRequest(args, (e: unknown, r: unknown) => (e ? rej(e) : res((r as { result: unknown }).result))));
  }
  sendAsync(payload: unknown, cb: (e: unknown, r?: unknown) => void) { this._rpcRequest(payload, cb); }
}

beforeAll(async () => {
  const win = new EventTarget() as EventTarget & Record<string, unknown>;
  win.ethereum = new BaseProvider();
  win.navigator = {};
  win.solana = { signTransaction: async (t: unknown) => t, signMessage: async (m: unknown) => m };
  win.getSelection = () => null;
  (globalThis as unknown as Record<string, unknown>).window = win;
  (globalThis as unknown as Record<string, unknown>).document = { execCommand: undefined, activeElement: null };
  await import("../src/content/provider-guard");
  // the bridge hands over its port before any page script runs
  const ch = new MessageChannel();
  port = ch.port1;
  port.onmessage = (e) => {
    const d = e.data;
    if (d?.type === "rpc") { rpcReplies.push(d); return; }
    if (d?.type !== "inspect") return;
    seen.push({ id: d.id, method: d.method, params: d.params });
    const allow = decide(d);
    port.postMessage({ type: "ack", id: d.id, hold: !allow });
    port.postMessage({ type: "decision", id: d.id, allow });
  };
  const ev = new Event("message") as Event & { data?: unknown; ports?: MessagePort[]; source?: unknown };
  Object.defineProperty(ev, "source", { value: win });
  ev.data = { source: "w3pg-ext", type: "port" };
  ev.ports = [ch.port2];
  win.dispatchEvent(ev);
});

const provider = () => (globalThis as unknown as { window: { ethereum: BaseProvider } }).window.ethereum;
const tx = { to: "0x" + "ab".repeat(20), data: "0x095ea7b3" + "00".repeat(12) + "cd".repeat(20) + "ff".repeat(32) };
// a forwarding provider may re-issue an identical request within one second without a second prompt; every test
// therefore uses its own recipient so one test's approval never covers another's request
let nonce = 0;
const fresh = () => ({ ...tx, to: "0x" + (nonce++).toString(16).padStart(40, "0") });

describe("provider guard protocol (fake MetaMask)", () => {
  it("one inspection per request; the wallet receives the inspected snapshot; result flows back", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    const r = await provider().request({ method: "eth_sendTransaction", params: [tx] });
    expect(r).toBe("ok");
    expect(seen.length).toBe(1);
    expect(engineCalls.length).toBe(1);
    expect((engineCalls[0] as { params: unknown[] }).params[0]).toEqual(tx);
    expect((seen[0].params as unknown[])[0]).toEqual(tx);
  });
  it("a rejection reaches the dapp as EIP-1193 4001 and never reaches the wallet", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => false;
    await expect(provider().request({ method: "eth_sendTransaction", params: [fresh()] })).rejects.toMatchObject({ code: 4001 });
    expect(seen.length).toBe(1);
    expect(engineCalls.length).toBe(0);
  });
  it("read-only methods are not inspected at all", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    await provider().request({ method: "eth_chainId" });
    expect(seen.length).toBe(1); // relayed for observation...
    expect(engineCalls.length).toBe(1);
  });
  it("a sendAsync batch is inspected once per item and delivered once", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    await new Promise<void>((res) => provider().sendAsync([{ method: "eth_sendTransaction", params: [fresh()] }, { method: "personal_sign", params: ["0x01", "0x" + "ab".repeat(20)] }], () => res()));
    expect(seen.length).toBe(2);
    expect(engineCalls.length).toBe(1);
  });
  it("an identical request re-issued a second later is asked again (no replay on an old approval)", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    const t = fresh();
    await provider().request({ method: "eth_sendTransaction", params: [t] });
    await new Promise((r) => setTimeout(r, 1100));
    await provider().request({ method: "eth_sendTransaction", params: [t] });
    expect(seen.length).toBe(2);
  });
  it("a getter that answers differently on the second read cannot smuggle a different tx to the wallet", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    let n = 0;
    const sneaky = { to: fresh().to, get data() { return n++ === 0 ? "0x" : tx.data; } };
    await provider().request({ method: "eth_sendTransaction", params: [sneaky] });
    const inspected = (seen[0].params as Array<{ data: string }>)[0].data;
    const delivered = ((engineCalls[0] as { params: Array<{ data: string }> }).params)[0].data;
    expect(delivered).toBe(inspected);
  });
  it("rpc relay: allowlisted read-only methods go through the provider, anything else answers null untouched", async () => {
    seen.length = 0; engineCalls.length = 0; rpcReplies.length = 0; decide = () => true;
    port.postMessage({ type: "rpc", id: "r1", reqId: "none", method: "eth_getCode", params: ["0x" + "ab".repeat(20), "latest"] });
    port.postMessage({ type: "rpc", id: "r2", reqId: "none", method: "eth_sendTransaction", params: [tx] });
    port.postMessage({ type: "rpc", id: "r3", reqId: "none", method: "personal_sign", params: ["0x01"] });
    for (let i = 0; i < 50 && rpcReplies.length < 3; i++) await new Promise((r) => setTimeout(r, 20));
    const byId = Object.fromEntries(rpcReplies.map((r) => [r.id, r.result]));
    expect(byId.r1).toBe("ok");
    expect(byId.r2).toBeNull();
    expect(byId.r3).toBeNull();
    const methods = engineCalls.map((c) => (c as { method: string }).method);
    expect(methods).toEqual(["eth_getCode"]);
  });
});

describe("provider guard: Solana transactions for the simulation", () => {
  const sol = () => (globalThis as unknown as { window: { solana: { signTransaction: (t: unknown) => Promise<unknown>; signMessage: (m: unknown) => Promise<unknown> } } }).window.solana;
  const bytes = Uint8Array.from([1, 2, 3, 250, 255]);
  const b64 = Buffer.from(bytes).toString("base64");
  // the legacy provider is wrapped by the guard's poll (every 500 ms), so wait until the hook is in place
  const hooked = async () => { decide = () => true; for (let i = 0; i < 40; i++) { seen.length = 0; await sol().signMessage(bytes); if (seen.length) return; await new Promise((r) => setTimeout(r, 100)); } };

  it("sends a legacy Transaction serialized without requiring signatures, as base64", async () => {
    await hooked();
    seen.length = 0; decide = () => true;
    let args: unknown;
    await sol().signTransaction({ serialize(a: unknown) { args = a; return bytes; } });
    expect(args).toEqual({ requireAllSignatures: false, verifySignatures: false });
    expect(seen[0].method).toBe("solana:signTransaction");
    expect(seen[0].params).toEqual({ batch: 1, txs: [b64] });
  });
  it("falls back to serialize() with no arguments (VersionedTransaction)", async () => {
    await hooked();
    seen.length = 0; decide = () => true;
    await sol().signTransaction({ serialize(a?: unknown) { if (a) throw new Error("no options here"); return bytes; } });
    expect((seen[0].params as { txs: string[] }).txs).toEqual([b64]);
  });
  it("a throwing, lying or oversized transaction yields no txs and never changes the outcome", async () => {
    await hooked();
    decide = () => true;
    for (const bad of [{ serialize() { throw new Error("x"); } }, { serialize: "nope" }, { serialize() { return new Uint8Array(1701); } }, { serialize() { return "not bytes"; } }]) {
      seen.length = 0;
      const r = await sol().signTransaction(bad);
      expect(r).toBe(bad);
      expect(seen[0].params).toEqual({ batch: 1 });
    }
    seen.length = 0; decide = () => false;
    await expect(sol().signTransaction({ serialize() { return bytes; } })).rejects.toMatchObject({ code: 4001 });
  });
  it("signMessage carries no transaction", async () => {
    await hooked();
    expect(seen[0].method).toBe("solana:signMessage");
    expect(seen[0].params).toEqual({ batch: 1 });
  });
});
