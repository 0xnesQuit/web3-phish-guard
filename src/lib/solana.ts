/**
 * Solana simulation helpers (pure, no chrome.*): parse the account list out of a serialized transaction, diff the
 * user's balances before / after a simulateTransaction run and turn the diff into dialog strings. The network side
 * lives in the background.
 */
import { formatUnits } from "./impact";

/** Public Solana RPCs that answer extensions with CORS `*`. (api.mainnet-beta.solana.com answers 403: do not use.) More can be added later. */
export const SOL_ENDPOINTS: string[] = ["https://solana-rpc.publicnode.com"];

export const KNOWN_MINTS: Record<string, string> = {
  EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v: "USDC",
  Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB: "USDT",
  So11111111111111111111111111111111111111112: "wSOL",
  JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN: "JUP",
  DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263: "BONK",
  mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So: "mSOL",
  J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn: "JitoSOL",
  "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R": "RAY",
  HZ1JovNiVvGrGNiiYvEozEVjZ58xaU3RKwX8eACQBCt3: "PYTH",
  EKpQGSJtjMFqKZ9KQanSqYXRcF8fBopzLHYxdM65zcjm: "WIF",
};

// ---- base58 ----------------------------------------------------------------------------------
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = []; // little endian base58 digits
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let s = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) s += ALPHABET[digits[i]];
  return s;
}

export function base58Decode(str: string): Uint8Array | undefined {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  const out: number[] = []; // little endian bytes
  for (let i = zeros; i < str.length; i++) {
    const v = ALPHABET.indexOf(str[i]);
    if (v < 0) return undefined;
    let carry = v;
    for (let j = 0; j < out.length; j++) {
      carry += out[j] * 58;
      out[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { out.push(carry & 0xff); carry >>= 8; }
  }
  const res = new Uint8Array(zeros + out.length);
  for (let i = 0; i < out.length; i++) res[res.length - 1 - i] = out[i];
  return res;
}

export function b64Decode(b64: string): Uint8Array | undefined {
  try {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) return undefined;
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return undefined; }
}

// ---- wire format -----------------------------------------------------------------------------
export interface ParsedMessage { version: "legacy" | 0; signer: string; keys: string[] }

/** compact-u16 at `pos`: [value, bytes used] or undefined when truncated / over-long */
function compactU16(b: Uint8Array, pos: number): [number, number] | undefined {
  let v = 0;
  for (let i = 0; i < 3; i++) {
    if (pos + i >= b.length) return undefined;
    const x = b[pos + i];
    v |= (x & 0x7f) << (7 * i);
    if ((x & 0x80) === 0) return v > 0xffff ? undefined : [v, i + 1];
  }
  return undefined;
}

/** Static account keys of a serialized transaction (signatures + message); address-table lookups are not resolved. */
export function parseMessageAccounts(txBase64: string): ParsedMessage | undefined {
  const b = b64Decode(txBase64);
  if (!b || b.length < 4) return undefined;
  const sigs = compactU16(b, 0);
  if (!sigs) return undefined;
  let pos = sigs[1] + sigs[0] * 64;
  if (pos >= b.length) return undefined;
  let version: "legacy" | 0 = "legacy";
  if (b[pos] & 0x80) {
    if ((b[pos] & 0x7f) !== 0) return undefined; // only v0 exists
    version = 0;
    pos++;
  }
  pos += 3; // header: required signatures, readonly signed, readonly unsigned
  const count = compactU16(b, pos);
  if (!count) return undefined;
  pos += count[1];
  const n = count[0];
  if (n < 1 || n > 256 || pos + n * 32 + 32 > b.length) return undefined; // keys + recent blockhash must fit
  const keys: string[] = [];
  for (let i = 0; i < n; i++) keys.push(base58Encode(b.subarray(pos + i * 32, pos + i * 32 + 32)));
  return { version, signer: keys[0], keys };
}

// ---- balance diff ----------------------------------------------------------------------------
/** A jsonParsed account as returned by getMultipleAccounts / simulateTransaction (null: does not exist) */
export type SolAccount = { lamports?: number | string; owner?: string; data?: unknown } | null | undefined;

export interface SolDiff {
  lamportsDelta: bigint;
  tokens: Array<{ mint: string; delta: bigint; decimals: number }>;
  delegates: Array<{ mint: string; delegate: string; amount: bigint }>;
  ownerChanged: boolean;
  closedAccounts: number;
}

interface TokenInfo { mint: string; owner?: string; delegate?: string; amount: bigint; decimals: number; delegated: bigint }
const big = (v: unknown): bigint => {
  try { return typeof v === "bigint" ? v : typeof v === "number" ? BigInt(Math.trunc(v)) : typeof v === "string" && /^[0-9]+$/.test(v) ? BigInt(v) : 0n; } catch { return 0n; }
};

/** the spl-token account fields, or undefined when this is not a parsed token account */
function tokenInfo(a: SolAccount): TokenInfo | undefined {
  const d = a?.data as { parsed?: { info?: Record<string, unknown> } } | undefined;
  const info = d && !Array.isArray(d) && typeof d === "object" ? d.parsed?.info : undefined;
  if (!info || typeof info !== "object" || typeof info.mint !== "string" || !info.tokenAmount) return undefined;
  const ta = info.tokenAmount as { amount?: unknown; decimals?: unknown };
  const da = info.delegatedAmount as { amount?: unknown } | undefined;
  return {
    mint: info.mint,
    owner: typeof info.owner === "string" ? info.owner : undefined,
    delegate: typeof info.delegate === "string" ? info.delegate : undefined,
    amount: big(ta.amount),
    decimals: typeof ta.decimals === "number" ? ta.decimals : 0,
    delegated: big(da?.amount),
  };
}

/**
 * What a simulated transaction does to `user`: SOL, tokens held in token accounts the user owns, delegates and
 * ownership changes. `pre` / `post` are in the same order as `keys`; the user's own system account is `keys.indexOf(user)`
 * (the first account, the fee payer, when `keys` is not given).
 */
export function diffSolana(pre: SolAccount[], post: SolAccount[], user: string, keys?: string[]): SolDiff {
  const diff: SolDiff = { lamportsDelta: 0n, tokens: [], delegates: [], ownerChanged: false, closedAccounts: 0 };
  const userIdx = keys ? keys.indexOf(user) : 0;
  const n = Math.max(pre.length, post.length);
  for (let i = 0; i < n; i++) {
    const a = pre[i] ?? null, z = post[i] ?? null;
    if (i === userIdx && (a || z)) {
      diff.lamportsDelta += big(z?.lamports) - big(a?.lamports);
      if (a && z && a.owner && z.owner && a.owner !== z.owner) diff.ownerChanged = true;
    }
    const ta = tokenInfo(a), tz = tokenInfo(z);
    const wasMine = ta?.owner === user, isMine = tz?.owner === user;
    if (!wasMine && !isMine) continue; // only token accounts the user owns
    if (wasMine && z && (!isMine || (a?.owner && z.owner && a.owner !== z.owner))) diff.ownerChanged = true;
    if (wasMine && !z) diff.closedAccounts++;
    const mint = (tz ?? ta)!.mint, decimals = (tz ?? ta)!.decimals;
    // an account that changed hands is no longer the user's: its whole balance left
    const delta = (isMine ? tz!.amount : 0n) - (wasMine ? ta!.amount : 0n);
    if (delta !== 0n) {
      const row = diff.tokens.find((r) => r.mint === mint);
      if (row) row.delta += delta; else diff.tokens.push({ mint, delta, decimals });
    }
    if (isMine && tz!.delegate && tz!.delegated > 0n && (ta?.delegate !== tz!.delegate || ta?.delegated !== tz!.delegated)) {
      diff.delegates.push({ mint, delegate: tz!.delegate, amount: tz!.delegated });
    }
  }
  diff.tokens = diff.tokens.filter((r) => r.delta !== 0n);
  return diff;
}

/** Sum the diffs of several transactions (each simulated on its own). */
export function mergeDiffs(list: SolDiff[]): SolDiff {
  const out: SolDiff = { lamportsDelta: 0n, tokens: [], delegates: [], ownerChanged: false, closedAccounts: 0 };
  for (const d of list) {
    out.lamportsDelta += d.lamportsDelta;
    out.ownerChanged = out.ownerChanged || d.ownerChanged;
    out.closedAccounts += d.closedAccounts;
    out.delegates.push(...d.delegates);
    for (const t of d.tokens) {
      const row = out.tokens.find((r) => r.mint === t.mint);
      if (row) row.delta += t.delta; else out.tokens.push({ ...t });
    }
  }
  out.tokens = out.tokens.filter((r) => r.delta !== 0n);
  return out;
}

export interface SolWords { delegate: (label: string) => string; owner: string }
const EN_SOL_WORDS: SolWords = { delegate: (l) => `Token delegate: ${l}`, owner: "Account ownership changes" };
/** SOL moves smaller than this are fees and priority fees, not a transfer worth a line */
const DUST_LAMPORTS = 100_000n;

/** Display strings; `labels` maps mint -> symbol (KNOWN_MINTS fills the rest, unknown mints show shortened). */
export function summarizeSolana(diff: SolDiff, labels: Map<string, string> | Record<string, string> = {}, words: SolWords = EN_SOL_WORDS): { out: string[]; in: string[]; warnings: string[] } {
  const label = (mint: string) => (labels instanceof Map ? labels.get(mint) : labels[mint]) ?? KNOWN_MINTS[mint] ?? `${mint.slice(0, 4)}…${mint.slice(-4)}`;
  const out: string[] = [], inn: string[] = [], warnings: string[] = [];
  const add = (delta: bigint, text: (abs: bigint) => string) => (delta < 0n ? out : inn).push(text(delta < 0n ? -delta : delta));
  const l = diff.lamportsDelta;
  if (l >= DUST_LAMPORTS || l <= -DUST_LAMPORTS) add(l, (a) => `${formatUnits(a, 9)} SOL`);
  for (const t of diff.tokens) add(t.delta, (a) => `${formatUnits(a, t.decimals)} ${label(t.mint)}`);
  for (const d of diff.delegates) warnings.push(words.delegate(`${label(d.mint)} → ${d.delegate.slice(0, 4)}…`));
  if (diff.ownerChanged) warnings.push(words.owner);
  return { out, in: inn, warnings };
}
