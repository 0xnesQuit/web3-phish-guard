/**
 * Transaction simulation (pure): builds the `eth_simulateV1` request for a held transaction and turns the returned
 * logs into "what leaves / comes back / gets approved" for the user's address. The network side lives in the
 * background; nothing here touches chrome.* or fetch.
 */
import { formatUnits, isUnlimitedBig, nativeSymbol, shortAddr, tokenLabel, type TokenMeta } from "./impact.js";

/** Public RPCs that serve eth_simulateV1 with traceTransfers and answer with CORS `*` (no host permission needed). Avalanche has none. */
export const RPC_ENDPOINTS: Record<number, string[]> = {
  1: ["https://ethereum-rpc.publicnode.com", "https://1rpc.io/eth", "https://eth.drpc.org", "https://rpc.mevblocker.io"],
  10: ["https://optimism-rpc.publicnode.com"],
  56: ["https://bsc-rpc.publicnode.com", "https://1rpc.io/bnb", "https://bsc.drpc.org"],
  137: ["https://polygon-bor-rpc.publicnode.com", "https://1rpc.io/matic", "https://polygon.drpc.org"],
  8453: ["https://base-rpc.publicnode.com", "https://1rpc.io/base", "https://base.drpc.org"],
  42161: ["https://arbitrum-one-rpc.publicnode.com"],
};

/** With traceTransfers the node reports native value moves as ERC-20-shaped Transfer logs from this pseudo-address. */
export const NATIVE_LOG_ADDRESS = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const T_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const T_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const T_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
const T_APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const T_APPROVAL_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";

export interface SimTx { from?: string; to?: string; data?: string; value?: string }
export interface AssetChange { token: string; kind: "native" | "erc20" | "erc721" | "erc1155"; from: string; to: string; amount?: bigint; tokenId?: bigint }
export interface SimApproval { token: string; spender: string; amount?: bigint; tokenId?: bigint; forAll?: boolean; unlimited: boolean }
export interface SimParsed { reverted: boolean; error?: string; out: AssetChange[]; in: AssetChange[]; approvals: SimApproval[] }

/** One transaction, or a batch (sequential: each call sees the state the previous one left). */
export function buildSimulateRequest(tx: SimTx | SimTx[], id = 1): { jsonrpc: "2.0"; id: number; method: "eth_simulateV1"; params: unknown[] } {
  const calls = (Array.isArray(tx) ? tx : [tx]).map((t) => {
    const call: Record<string, string> = {};
    for (const k of ["from", "to", "data", "value"] as const) if (t[k]) call[k] = t[k]!;
    return call;
  });
  return { jsonrpc: "2.0", id, method: "eth_simulateV1", params: [{ blockStateCalls: [{ calls }], validation: false, traceTransfers: true }, "latest"] };
}

interface RawLog { address?: string; topics?: string[]; data?: string }
const topicAddr = (t: string | undefined) => (typeof t === "string" && /^0x[0-9a-f]{64}$/i.test(t) ? "0x" + t.slice(26).toLowerCase() : undefined);
const topicBig = (t: string | undefined) => (typeof t === "string" && /^0x[0-9a-f]{64}$/i.test(t) ? BigInt(t) : undefined);
/** n-th 32-byte word of a data blob */
const word = (data: string, n: number): bigint | undefined => {
  const h = data.replace(/^0x/, "");
  const w = h.slice(n * 64, n * 64 + 64);
  return w.length === 64 && /^[0-9a-f]{64}$/i.test(w) ? BigInt("0x" + w) : undefined;
};

/** Add to an existing row for the same asset (token+kind; NFTs also by id), or push a new one. */
function addChange(list: AssetChange[], c: AssetChange): void {
  const row = list.find((r) => r.token === c.token && r.kind === c.kind && r.tokenId === c.tokenId);
  if (row) row.amount = (row.amount ?? 0n) + (c.amount ?? 0n);
  else if (list.length < 200) list.push({ ...c });
}

/** `result` is the JSON-RPC result of eth_simulateV1 (an array of blocks); undefined when it does not look like one. */
export function parseSimulation(result: unknown, user: string): SimParsed | undefined {
  const calls = (result as Array<{ calls?: Array<Record<string, unknown>> }> | undefined)?.[0]?.calls;
  if (!Array.isArray(calls) || !calls.length || calls.length > 64 || calls.some((c) => !c || typeof c !== "object")) return undefined;
  const me = user.toLowerCase();
  const out: AssetChange[] = [], inn: AssetChange[] = [], approvals: SimApproval[] = [];
  // a batch fails as soon as one of its calls does
  const bad = calls.find((c) => c.status === "0x0" || c.status === 0);
  if (bad) {
    const e = bad.error as { message?: string } | string | undefined;
    return { reverted: true, error: typeof e === "string" ? e : e?.message, out, in: inn, approvals };
  }
  const push = (c: AssetChange) => { if (c.from === me) addChange(out, c); if (c.to === me) addChange(inn, c); };
  const logs = calls.flatMap((c) => (Array.isArray(c.logs) ? (c.logs as RawLog[]) : [])).slice(0, 500);
  for (const log of logs) {
    const topics = Array.isArray(log.topics) ? log.topics : [];
    const token = typeof log.address === "string" ? log.address.toLowerCase() : "";
    const data = typeof log.data === "string" ? log.data : "0x";
    if (!/^0x[0-9a-f]{40}$/.test(token) || !topics[0]) continue;
    const sig = topics[0].toLowerCase();
    if (sig === T_TRANSFER) {
      const from = topicAddr(topics[1]), to = topicAddr(topics[2]);
      if (!from || !to) continue;
      if (topics.length === 4) { const id = topicBig(topics[3]); if (id !== undefined) push({ token, kind: "erc721", from, to, tokenId: id, amount: 1n }); }
      else if (topics.length === 3) { const amount = word(data, 0); if (amount !== undefined) push({ token, kind: token === NATIVE_LOG_ADDRESS ? "native" : "erc20", from, to, amount }); }
    } else if (sig === T_SINGLE) {
      const from = topicAddr(topics[2]), to = topicAddr(topics[3]), id = word(data, 0), amount = word(data, 1);
      if (from && to && id !== undefined && amount !== undefined) push({ token, kind: "erc1155", from, to, tokenId: id, amount });
    } else if (sig === T_BATCH) {
      const from = topicAddr(topics[2]), to = topicAddr(topics[3]);
      const idsOff = word(data, 0), valsOff = word(data, 1);
      if (!from || !to || idsOff === undefined || valsOff === undefined || idsOff % 32n || valsOff % 32n) continue;
      const io = Number(idsOff / 32n), vo = Number(valsOff / 32n);
      const n = word(data, io), nv = word(data, vo);
      if (n === undefined || n !== nv || n > 64n) continue;
      for (let i = 0; i < Number(n); i++) {
        const id = word(data, io + 1 + i), amount = word(data, vo + 1 + i);
        if (id !== undefined && amount !== undefined) push({ token, kind: "erc1155", from, to, tokenId: id, amount });
      }
    } else if (sig === T_APPROVAL) {
      const owner = topicAddr(topics[1]), spender = topicAddr(topics[2]);
      if (owner !== me || !spender) continue;
      if (topics.length === 4) { const id = topicBig(topics[3]); if (id !== undefined && approvals.length < 50) approvals.push({ token, spender, tokenId: id, unlimited: false }); }
      else {
        const amount = word(data, 0);
        // an allowance of 0 is a revocation, not a new approval
        if (amount !== undefined && amount > 0n && approvals.length < 50) approvals.push({ token, spender, amount, unlimited: isUnlimitedBig(amount) });
      }
    } else if (sig === T_APPROVAL_ALL) {
      const owner = topicAddr(topics[1]), spender = topicAddr(topics[2]);
      if (owner === me && spender && word(data, 0) !== 0n && approvals.length < 50) approvals.push({ token, spender, forAll: true, unlimited: true });
    }
  }
  return { reverted: false, out, in: inn, approvals };
}

export interface SimWords { unlimited: string; all: string }
const EN_WORDS: SimWords = { unlimited: "unlimited", all: "all NFTs" };

/** Display-ready strings (one per asset / approval). Amounts without known decimals are shown in raw units. */
export function summarizeChanges(p: SimParsed, labels: Map<string, { symbol?: string; decimals?: number }>, chainId?: string | number, words: SimWords = EN_WORDS): { out: string[]; in: string[]; approvals: string[] } {
  const native = nativeSymbol(chainId);
  const label = (token: string) => tokenLabel(token, labels.get(token) as TokenMeta | undefined);
  const dec = (token: string) => labels.get(token)?.decimals ?? 0;
  const one = (c: AssetChange): string => {
    if (c.kind === "native") return `${formatUnits(c.amount ?? 0n, 18)} ${native}`;
    if (c.kind === "erc20") return `${formatUnits(c.amount ?? 0n, dec(c.token))} ${label(c.token)}`;
    return `${c.kind === "erc1155" ? formatUnits(c.amount ?? 0n, 0) : "1"} × ${label(c.token)} #${c.tokenId} (NFT)`;
  };
  const approval = (a: SimApproval): string => {
    const to = shortAddr(a.spender);
    if (a.forAll) return `${label(a.token)} ${words.all} → ${to}`;
    if (a.tokenId !== undefined) return `${label(a.token)} #${a.tokenId} → ${to}`;
    return `${a.unlimited ? words.unlimited : formatUnits(a.amount ?? 0n, dec(a.token))} ${label(a.token)} → ${to}`;
  };
  return { out: p.out.map(one), in: p.in.map(one), approvals: p.approvals.map(approval) };
}
