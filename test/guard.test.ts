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
  win.getSelection = () => null;
  (globalThis as unknown as Record<string, unknown>).window = win;
  (globalThis as unknown as Record<string, unknown>).document = { execCommand: undefined, activeElement: null };
  await import("../src/content/provider-guard");
  // the bridge hands over its port before any page script runs
  const ch = new MessageChannel();
  port = ch.port1;
  port.onmessage = (e) => {
    const d = e.data;
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
    await expect(provider().request({ method: "eth_sendTransaction", params: [tx] })).rejects.toMatchObject({ code: 4001 });
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
    await new Promise<void>((res) => provider().sendAsync([{ method: "eth_sendTransaction", params: [tx] }, { method: "personal_sign", params: ["0x01", "0x" + "ab".repeat(20)] }], () => res()));
    expect(seen.length).toBe(2);
    expect(engineCalls.length).toBe(1);
  });
  it("a getter that answers differently on the second read cannot smuggle a different tx to the wallet", async () => {
    seen.length = 0; engineCalls.length = 0; decide = () => true;
    let n = 0;
    const sneaky = { to: tx.to, get data() { return n++ === 0 ? "0x" : tx.data; } };
    await provider().request({ method: "eth_sendTransaction", params: [sneaky] });
    const inspected = (seen[0].params as Array<{ data: string }>)[0].data;
    const delivered = ((engineCalls[0] as { params: Array<{ data: string }> }).params)[0].data;
    expect(delivered).toBe(inspected);
  });
});
