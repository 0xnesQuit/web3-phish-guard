/** Network side of the simulation: runs eth_simulateV1 on a free public RPC and labels the tokens. Node fetch. */
import { RPC_ENDPOINTS, buildSimulateRequest, parseSimulation, summarizeChanges, type SimTx } from "./lib/simulate.js";
import { SEL, decodeString, decodeUint } from "./lib/impact.js";
import type { SimLine } from "./types.js";

async function rpc(url: string, body: unknown, ms: number): Promise<unknown> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: ctl.signal });
    return r.ok ? await r.json() : null;
  } catch { return null; } finally { clearTimeout(timer); }
}

const labelCache = new Map<string, { symbol?: string; decimals?: number }>();
async function tokenLabels(chainId: number, endpoint: string, tokens: string[]): Promise<Map<string, { symbol?: string; decimals?: number }>> {
  const labels = new Map<string, { symbol?: string; decimals?: number }>();
  const missing: string[] = [];
  for (const tk of tokens) { const hit = labelCache.get(`${chainId}:${tk}`); if (hit) labels.set(tk, hit); else missing.push(tk); }
  if (!missing.length) return labels;
  const batch = missing.flatMap((tk, i) => [
    { jsonrpc: "2.0", id: i * 2, method: "eth_call", params: [{ to: tk, data: SEL.symbol }, "latest"] },
    { jsonrpc: "2.0", id: i * 2 + 1, method: "eth_call", params: [{ to: tk, data: SEL.decimals }, "latest"] },
  ]);
  const res = await rpc(endpoint, batch, 4000);
  if (!Array.isArray(res)) return labels;
  const byId = new Map<number, string>();
  for (const r of res as Array<{ id?: number; result?: unknown }>) if (typeof r?.id === "number" && typeof r.result === "string") byId.set(r.id, r.result);
  missing.forEach((tk, i) => {
    const d = decodeUint(byId.get(i * 2 + 1));
    const meta = { symbol: decodeString(byId.get(i * 2)), decimals: d !== undefined && d <= 77n ? Number(d) : undefined };
    if (meta.symbol === undefined && meta.decimals === undefined) return;
    labelCache.set(`${chainId}:${tk}`, meta);
    labels.set(tk, meta);
  });
  return labels;
}

/** Simulate one transaction (or a batch) on its chain; returns display lines, or undefined when no endpoint can. */
export async function simulate(chainIdHex: string | undefined, from: string, txs: SimTx[]): Promise<SimLine | undefined> {
  const chain = chainIdHex && /^0x[0-9a-f]{1,8}$/i.test(chainIdHex) ? parseInt(chainIdHex, 16) : 1;
  const endpoints = RPC_ENDPOINTS[chain];
  if (!endpoints) return undefined;
  const req = buildSimulateRequest(txs.length === 1 ? { ...txs[0], from } : txs.map((t) => ({ ...t, from })));
  for (const url of endpoints) {
    const res = (await rpc(url, req, 6000)) as { result?: unknown; error?: { code?: number; message?: string } } | null;
    if (!res) continue;
    if (res.error) {
      if (res.error.code === -32601 || /not (found|supported|available)|unsupported|unknown method|does not exist/i.test(String(res.error.message ?? ""))) continue;
      return undefined;
    }
    const parsed = parseSimulation(res.result, from);
    if (!parsed) return undefined;
    const tokens = [...new Set([...parsed.out, ...parsed.in].filter((c) => c.kind !== "native").map((c) => c.token).concat(parsed.approvals.map((a) => a.token)))].slice(0, 20);
    const labels = tokens.length ? await tokenLabels(chain, url, tokens) : new Map();
    const s = summarizeChanges(parsed, labels, chainIdHex);
    return { out: s.out, in: s.in, approvals: s.approvals, reverted: parsed.reverted };
  }
  return undefined;
}
