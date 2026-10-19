import { describe, it, expect } from "vitest";
import { base58Encode, base58Decode, parseMessageAccounts, diffSolana, mergeDiffs, summarizeSolana, KNOWN_MINTS, SOL_ENDPOINTS, type SolAccount } from "../src/lib/solana";

const USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SYSTEM = "11111111111111111111111111111111";
const USER = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
const ATTACKER = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const b64 = (b: Uint8Array) => Buffer.from(b).toString("base64");
const key = (s: string) => base58Decode(s)!;

/** header + keys + blockhash + zero instructions, behind `sigs` empty signatures */
function buildTx(keys: string[], opts: { version?: 0; sigs?: number } = {}): string {
  const sigs = opts.sigs ?? 1;
  const parts: number[] = [sigs]; // compact-u16 under 128
  for (let i = 0; i < sigs * 64; i++) parts.push(0);
  if (opts.version === 0) parts.push(0x80);
  parts.push(sigs, 0, 1); // header
  parts.push(keys.length);
  for (const k of keys) parts.push(...key(k));
  for (let i = 0; i < 32; i++) parts.push(7); // recent blockhash
  parts.push(0); // zero instructions
  if (opts.version === 0) parts.push(0); // zero address-table lookups
  return b64(Uint8Array.from(parts));
}

describe("base58", () => {
  it("matches a published vector", () => {
    expect(base58Encode(new TextEncoder().encode("Hello World!"))).toBe("2NEpo7TZRRrLZSi2U");
    expect(new TextDecoder().decode(base58Decode("2NEpo7TZRRrLZSi2U")!)).toBe("Hello World!");
  });
  it("round trips real public keys, including the all-zero system program id", () => {
    for (const k of [USDC, USER, ATTACKER, TOKEN_PROGRAM, SYSTEM, ...Object.keys(KNOWN_MINTS)]) {
      const raw = base58Decode(k)!;
      expect(raw.length).toBe(32);
      expect(base58Encode(raw)).toBe(k);
    }
    expect(base58Encode(new Uint8Array(32))).toBe(SYSTEM);
  });
  it("rejects characters outside the alphabet", () => {
    expect(base58Decode("0OIl")).toBeUndefined();
  });
});

describe("parseMessageAccounts", () => {
  it("reads a legacy message", () => {
    const m = parseMessageAccounts(buildTx([USER, ATTACKER, SYSTEM]));
    expect(m).toEqual({ version: "legacy", signer: USER, keys: [USER, ATTACKER, SYSTEM] });
  });
  it("reads a v0 message behind the version prefix and several signatures", () => {
    const m = parseMessageAccounts(buildTx([USER, USDC, TOKEN_PROGRAM, SYSTEM], { version: 0, sigs: 2 }));
    expect(m).toEqual({ version: 0, signer: USER, keys: [USER, USDC, TOKEN_PROGRAM, SYSTEM] });
  });
  it("returns undefined for garbage, truncation and unknown versions", () => {
    expect(parseMessageAccounts("")).toBeUndefined();
    expect(parseMessageAccounts("not base64!")).toBeUndefined();
    expect(parseMessageAccounts(buildTx([USER, ATTACKER]).slice(0, 60))).toBeUndefined();
    const v1 = Buffer.from(buildTx([USER], { version: 0 }), "base64");
    v1[65] = 0x81;
    expect(parseMessageAccounts(b64(v1))).toBeUndefined();
  });
});

const tokenAcct = (owner: string, amount: string, o: { mint?: string; decimals?: number; delegate?: string; delegated?: string; programOwner?: string } = {}): SolAccount => ({
  lamports: 2039280,
  owner: o.programOwner ?? TOKEN_PROGRAM,
  data: {
    program: "spl-token",
    parsed: {
      type: "account",
      info: {
        mint: o.mint ?? USDC, owner, state: "initialized",
        tokenAmount: { amount, decimals: o.decimals ?? 6, uiAmount: Number(amount) / 10 ** (o.decimals ?? 6) },
        ...(o.delegate ? { delegate: o.delegate, delegatedAmount: { amount: o.delegated ?? "0", decimals: 6 } } : {}),
      },
    },
  },
});
const sysAcct = (lamports: number, owner = SYSTEM): SolAccount => ({ lamports, owner, data: ["", "base64"] });
const KEYS = [USER, "TokenAcct1", ATTACKER];

describe("diffSolana", () => {
  it("reports SOL and token movements of the user's own accounts only", () => {
    const pre = [sysAcct(20_000_000_000), tokenAcct(USER, "2500000000"), tokenAcct(ATTACKER, "5")];
    const post = [sysAcct(7_500_000_000), tokenAcct(USER, "1500000000"), tokenAcct(ATTACKER, "1000000005")];
    const d = diffSolana(pre, post, USER, KEYS);
    expect(d.lamportsDelta).toBe(-12_500_000_000n);
    expect(d.tokens).toEqual([{ mint: USDC, delta: -1_000_000_000n, decimals: 6 }]);
    expect(d.delegates).toEqual([]);
    expect(d.ownerChanged).toBe(false);
    expect(d.closedAccounts).toBe(0);
  });
  it("flags a new token delegate, but not an unchanged one", () => {
    const pre = [sysAcct(1e9), tokenAcct(USER, "100")];
    const post = [sysAcct(1e9), tokenAcct(USER, "100", { delegate: ATTACKER, delegated: "100" })];
    expect(diffSolana(pre, post, USER, KEYS).delegates).toEqual([{ mint: USDC, delegate: ATTACKER, amount: 100n }]);
    expect(diffSolana(post, post, USER, KEYS).delegates).toEqual([]);
    // a delegate with nothing delegated is not a grant
    expect(diffSolana(pre, [sysAcct(1e9), tokenAcct(USER, "100", { delegate: ATTACKER, delegated: "0" })], USER, KEYS).delegates).toEqual([]);
  });
  it("flags a token account whose owner authority changed, and counts its balance as gone", () => {
    const pre = [sysAcct(1e9), tokenAcct(USER, "42")];
    const post = [sysAcct(1e9), tokenAcct(ATTACKER, "42")];
    const d = diffSolana(pre, post, USER, KEYS);
    expect(d.ownerChanged).toBe(true);
    expect(d.tokens).toEqual([{ mint: USDC, delta: -42n, decimals: 6 }]);
  });
  it("flags an assign of the user's own system account to another program", () => {
    const d = diffSolana([sysAcct(1e9)], [sysAcct(1e9, ATTACKER)], USER, [USER]);
    expect(d.ownerChanged).toBe(true);
  });
  it("counts closed token accounts and handles accounts that do not exist yet", () => {
    const closed = diffSolana([sysAcct(1e9), tokenAcct(USER, "0")], [sysAcct(1e9 + 2039280), null], USER, KEYS);
    expect(closed.closedAccounts).toBe(1);
    expect(closed.lamportsDelta).toBe(2039280n);
    const created = diffSolana([sysAcct(1e9), null], [sysAcct(1e9), tokenAcct(USER, "7")], USER, KEYS);
    expect(created.tokens).toEqual([{ mint: USDC, delta: 7n, decimals: 6 }]);
  });
  it("defaults the user's system account to the first key", () => {
    expect(diffSolana([sysAcct(5)], [sysAcct(9)], USER).lamportsDelta).toBe(4n);
  });
});

describe("mergeDiffs", () => {
  it("sums transactions", () => {
    const a = diffSolana([sysAcct(10_000_000_000), tokenAcct(USER, "10")], [sysAcct(9_000_000_000), tokenAcct(USER, "4")], USER, KEYS);
    const b = diffSolana([sysAcct(9_000_000_000), tokenAcct(USER, "4")], [sysAcct(9_000_000_000), tokenAcct(USER, "9", { delegate: ATTACKER, delegated: "9" })], USER, KEYS);
    const m = mergeDiffs([a, b]);
    expect(m.lamportsDelta).toBe(-1_000_000_000n);
    expect(m.tokens).toEqual([{ mint: USDC, delta: -1n, decimals: 6 }]);
    expect(m.delegates).toHaveLength(1);
  });
});

describe("summarizeSolana", () => {
  it("formats SOL and token amounts, ignoring fee-sized SOL moves", () => {
    const pre = [sysAcct(20_000_000_000), tokenAcct(USER, "2500000000")];
    const post = [sysAcct(7_500_000_000), tokenAcct(USER, "1500000000")];
    const s = summarizeSolana(diffSolana(pre, post, USER, KEYS), new Map());
    expect(s.out).toEqual(["12.5 SOL", "1,000 USDC"]);
    expect(s.in).toEqual([]);
    expect(s.warnings).toEqual([]);
    const fee = summarizeSolana(diffSolana([sysAcct(1e9)], [sysAcct(1e9 - 5000)], USER, [USER]));
    expect(fee.out).toEqual([]);
  });
  it("lists what comes in, uses given labels, and shortens unknown mints", () => {
    const MINT = "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr";
    const pre = [sysAcct(0), tokenAcct(USER, "0", { mint: MINT, decimals: 9 })];
    const post = [sysAcct(3_000_000_000), tokenAcct(USER, "5000000000", { mint: MINT, decimals: 9 })];
    expect(summarizeSolana(diffSolana(pre, post, USER, KEYS), new Map([[MINT, "SOMETHING"]])).in).toEqual(["3 SOL", "5 SOMETHING"]);
    expect(summarizeSolana(diffSolana(pre, post, USER, KEYS), {}).in[1]).toBe("5 Gh9Z…tKJr");
  });
  it("words delegates and ownership changes as warnings", () => {
    const pre = [sysAcct(1e9, SYSTEM), tokenAcct(USER, "100"), tokenAcct(USER, "1")];
    const post = [sysAcct(1e9, ATTACKER), tokenAcct(USER, "100", { delegate: ATTACKER, delegated: "100" }), tokenAcct(USER, "1")];
    const s = summarizeSolana(diffSolana(pre, post, USER, [USER, "A", "B"]));
    expect(s.warnings).toEqual(["Token delegate: USDC → 7xKX…", "Account ownership changes"]);
    const custom = summarizeSolana(diffSolana(pre, post, USER, [USER, "A", "B"]), {}, { delegate: (l) => `D(${l})`, owner: "O" });
    expect(custom.warnings).toEqual(["D(USDC → 7xKX…)", "O"]);
  });
  it("lists the endpoint without the blocked mainnet-beta host", () => {
    expect(SOL_ENDPOINTS).toEqual(["https://solana-rpc.publicnode.com"]);
  });
});
