import { describe, it, expect } from "vitest";
import { RPC_ENDPOINTS, buildSimulateRequest, parseSimulation, summarizeChanges, NATIVE_LOG_ADDRESS } from "../src/lib/simulate";

const word = (n: number | bigint) => BigInt(n).toString(16).padStart(64, "0");
const topic = (a: string) => "0x" + a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const USER = "0x" + "aa".repeat(20);
const OTHER = "0x" + "bb".repeat(20);
const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const APE = "0x" + "cc".repeat(20);
const ITEMS = "0x" + "dd".repeat(20);
const SPENDER = "0x" + "11".repeat(20);
const TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62";
const BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb";
const APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const APPROVAL_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";

const sim = (logs: unknown[], status = "0x1", extra: Record<string, unknown> = {}) => [{ calls: [{ status, returnData: "0x", logs, ...extra }] }];

const fixture = sim([
  { address: USDC, topics: [TRANSFER, topic(USER), topic(OTHER)], data: "0x" + word(1_000_000_000) }, // 1,000 USDC out
  { address: USDC, topics: [TRANSFER, topic(USER), topic(OTHER)], data: "0x" + word(500_000_000) }, // aggregated with the first
  { address: NATIVE_LOG_ADDRESS, topics: [TRANSFER, topic(OTHER), topic(USER)], data: "0x" + word(5n * 10n ** 17n) }, // 0.5 native in
  { address: APE, topics: [TRANSFER, topic(USER), topic(OTHER), "0x" + word(1234)], data: "0x" }, // NFT out
  { address: ITEMS, topics: [SINGLE, topic(OTHER), topic(USER), topic(OTHER)], data: "0x" + word(7) + word(3) }, // 3 x id 7 out
  { address: ITEMS, topics: [BATCH, topic(OTHER), topic(OTHER), topic(USER)], data: "0x" + word(64) + word(160) + word(2) + word(1) + word(2) + word(2) + word(10) + word(20) }, // ids 1,2 amounts 10,20 in
  { address: USDC, topics: [APPROVAL, topic(USER), topic(SPENDER)], data: "0x" + "f".repeat(64) }, // unlimited
  { address: ITEMS, topics: [APPROVAL_ALL, topic(USER), topic(SPENDER)], data: "0x" + word(1) },
  { address: USDC, topics: [TRANSFER, topic(OTHER), topic(OTHER)], data: "0x" + word(9) }, // not ours: ignored
  { address: USDC, topics: [APPROVAL, topic(OTHER), topic(SPENDER)], data: "0x" + word(9) }, // someone else's approval: ignored
]);

describe("buildSimulateRequest", () => {
  it("builds the eth_simulateV1 call with traceTransfers and drops absent fields", () => {
    const r = buildSimulateRequest({ from: USER, to: OTHER, data: "0x12", value: undefined });
    expect(r.method).toBe("eth_simulateV1");
    expect(r.params).toEqual([{ blockStateCalls: [{ calls: [{ from: USER, to: OTHER, data: "0x12" }] }], validation: false, traceTransfers: true }, "latest"]);
  });
  it("lists endpoints for the supported chains only", () => {
    expect(Object.keys(RPC_ENDPOINTS).map(Number).sort((a, b) => a - b)).toEqual([1, 10, 56, 137, 8453, 42161]);
    expect(RPC_ENDPOINTS[43114]).toBeUndefined();
  });
});

describe("parseSimulation", () => {
  const p = parseSimulation(fixture, USER)!;
  it("aggregates fungible transfers out and keeps NFTs per id", () => {
    expect(p.reverted).toBe(false);
    expect(p.out.map((c) => [c.kind, c.token, c.tokenId, c.amount])).toEqual([
      ["erc20", USDC, undefined, 1_500_000_000n],
      ["erc721", APE, 1234n, 1n],
      ["erc1155", ITEMS, 7n, 3n],
    ]);
  });
  it("collects what comes back, including native and ERC-1155 batches", () => {
    expect(p.in.map((c) => [c.kind, c.tokenId, c.amount])).toEqual([["native", undefined, 5n * 10n ** 17n], ["erc1155", 1n, 10n], ["erc1155", 2n, 20n]]);
  });
  it("reports only the user's own approvals, flagging unlimited and for-all", () => {
    expect(p.approvals).toEqual([
      { token: USDC, spender: SPENDER, amount: (1n << 256n) - 1n, unlimited: true },
      { token: ITEMS, spender: SPENDER, forAll: true, unlimited: true },
    ]);
  });
  it("handles a reverted call and malformed results", () => {
    const r = parseSimulation(sim([], "0x0", { error: { message: "execution reverted" } }), USER)!;
    expect(r).toMatchObject({ reverted: true, error: "execution reverted", out: [], in: [], approvals: [] });
    expect(parseSimulation(null, USER)).toBeUndefined();
    expect(parseSimulation([], USER)).toBeUndefined();
  });
  it("treats an ERC-721 approval as a limited one and a zero allowance as a revocation", () => {
    const r = parseSimulation(sim([
      { address: APE, topics: [APPROVAL, topic(USER), topic(SPENDER), "0x" + word(5)], data: "0x" },
      { address: USDC, topics: [APPROVAL, topic(USER), topic(SPENDER)], data: "0x" + word(0) },
    ]), USER)!;
    expect(r.approvals).toEqual([{ token: APE, spender: SPENDER, tokenId: 5n, unlimited: false }]);
  });
});

describe("summarizeChanges", () => {
  it("formats amounts with the resolved labels", () => {
    const labels = new Map([[USDC, { symbol: "USDC", decimals: 6 }], [APE, { symbol: "BAYC" }]]);
    const s = summarizeChanges(parseSimulation(fixture, USER)!, labels, "0x1");
    expect(s.out).toEqual(["1,500 USDC", "1 × BAYC #1234 (NFT)", `3 × ${ITEMS.slice(0, 8)}…${ITEMS.slice(-6)} #7 (NFT)`]);
    expect(s.in[0]).toBe("0.5 ETH");
    expect(s.approvals[0]).toBe("unlimited USDC → 0x111111…111111");
    expect(s.approvals[1]).toContain("all NFTs");
  });
  it("uses the chain's native symbol", () => {
    const s = summarizeChanges(parseSimulation(sim([{ address: NATIVE_LOG_ADDRESS, topics: [TRANSFER, topic(USER), topic(OTHER)], data: "0x" + word(10n ** 18n) }]), USER)!, new Map(), 56);
    expect(s.out).toEqual(["1 BNB"]);
  });
});

describe("batches (several calls in one simulation)", () => {
  const two = [
    { status: "0x1", logs: [{ address: USDC, topics: [TRANSFER, topic(USER), topic(OTHER)], data: "0x" + word(1_000_000) }] },
    { status: "0x1", logs: [
      { address: USDC, topics: [TRANSFER, topic(USER), topic(OTHER)], data: "0x" + word(2_000_000) },
      { address: NATIVE_LOG_ADDRESS, topics: [TRANSFER, topic(OTHER), topic(USER)], data: "0x" + word(10n ** 18n) },
    ] },
  ];
  it("puts every call in blockStateCalls[0].calls, in order", () => {
    const r = buildSimulateRequest([{ from: USER, to: OTHER, data: "0x01" }, { from: USER, to: SPENDER, value: "0x5" }]);
    expect(r.params).toEqual([{ blockStateCalls: [{ calls: [{ from: USER, to: OTHER, data: "0x01" }, { from: USER, to: SPENDER, value: "0x5" }] }], validation: false, traceTransfers: true }, "latest"]);
  });
  it("aggregates logs across all calls", () => {
    const p = parseSimulation([{ calls: two }], USER)!;
    expect(p.reverted).toBe(false);
    expect(p.out.map((c) => [c.token, c.amount])).toEqual([[USDC, 3_000_000n]]);
    expect(p.in.map((c) => [c.kind, c.amount])).toEqual([["native", 10n ** 18n]]);
  });
  it("is reverted when any call is, reporting that call's error", () => {
    const p = parseSimulation([{ calls: [two[0], { status: "0x0", error: { message: "execution reverted: nope" }, logs: [] }, two[1]] }], USER)!;
    expect(p).toMatchObject({ reverted: true, error: "execution reverted: nope", out: [], in: [], approvals: [] });
  });
  it("rejects a malformed call list", () => {
    expect(parseSimulation([{ calls: [two[0], null] }], USER)).toBeUndefined();
    expect(parseSimulation([{ calls: [] }], USER)).toBeUndefined();
  });
});
