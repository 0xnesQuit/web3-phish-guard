/**
 * "What does this request mean for my wallet": pure helpers that turn decoded intents plus a few on-chain reads
 * (token symbol / decimals / balance, counterparty code) into the lines the gate dialog shows. No network here;
 * the bridge fetches the reads through the page's own provider and feeds them in.
 */

/** Well-known counterparties (same address on every chain where they are deployed). Lowercase. */
export const KNOWN_CONTRACTS: Record<string, string> = {
  "0x000000000022d473030f116ddee9f6b43ac78ba3": "Uniswap Permit2",
  "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router",
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router",
  "0x7a250d5630b4cf539739df2c9bf9c2c12ab1a2f9": "Uniswap V2 Router",
  "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 Router",
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 Router 2",
  "0x0000000000000068f116a894984e2db1123eb395": "OpenSea Seaport 1.6",
  "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "OpenSea Seaport 1.5",
  "0x1e0049783f008a0085193e00003d00cd54003c71": "OpenSea conduit",
  "0x000000000000ad05ccc4f10045630fb830b95127": "Blur Marketplace",
  "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch v5",
  "0x111111125421ca6dc452d289314280a0f8842a65": "1inch v6",
  "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x Exchange Proxy",
  "0x881d40237659c251811cec9c364ef91dc08d300c": "MetaMask Swaps",
  "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3",
  "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap Router",
  "0x1231deb6f5749ef6ce6943a275a1d3e7486f4eae": "LI.FI Diamond",
  "0x3a23f943181408eac424116af7b7790c94cb97a5": "Socket Gateway",
  "0xc36442b4a4522e871399cd717abdd847ab11fe88": "Uniswap V3 Positions",
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
  "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
  "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": "MetaMask smart account (7702)",
};

/** Native coin symbol by chain id (hex or decimal); unknown chains fall back to "ETH"-style wording via "native". */
const NATIVE: Record<number, string> = { 1: "ETH", 10: "ETH", 56: "BNB", 100: "xDAI", 137: "POL", 250: "FTM", 324: "ETH", 8453: "ETH", 42161: "ETH", 43114: "AVAX", 59144: "ETH", 81457: "ETH", 534352: "ETH", 11155111: "SepoliaETH" };
export function nativeSymbol(chainId: string | number | undefined): string {
  const n = typeof chainId === "string" ? parseInt(chainId, 16) : chainId;
  return (n && NATIVE[n]) || "native coin";
}

const UINT_MAX = BigInt("0x" + "f".repeat(64));
/** 2^255 or more, or the "max uint" idioms: treated as unlimited */
export function isUnlimitedBig(v: bigint): boolean { return v >= UINT_MAX / 2n; }

/** Hex or decimal integer string to bigint; undefined when unparsable. */
export function toBig(v: string | number | bigint | undefined): bigint | undefined {
  if (v === undefined || v === null) return undefined;
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number") return BigInt(Math.trunc(v));
    const s = v.trim();
    if (!s) return undefined;
    if (/^0x[0-9a-f]*$/i.test(s)) return s.length > 2 ? BigInt(s) : 0n;
    if (/^[0-9]+$/.test(s)) return BigInt(s);
    if (/^[0-9a-f]{64}$/i.test(s)) return BigInt("0x" + s); // a raw 32-byte word
  } catch { /* fall through */ }
  return undefined;
}

/** 1234500000 with 6 decimals -> "1,234.5"; keeps at most 4 fractional digits, drops trailing zeros. */
export function formatUnits(v: bigint, decimals: number): string {
  const neg = v < 0n;
  if (neg) v = -v;
  const d = Math.max(0, Math.min(36, decimals | 0));
  const base = 10n ** BigInt(d);
  const whole = v / base;
  let frac = (v % base).toString().padStart(d, "0").slice(0, 4).replace(/0+$/, "");
  const w = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  if (!frac && whole === 0n && v > 0n) frac = "0001"; // dust, but not nothing
  return (neg ? "-" : "") + w + (frac ? "." + frac : "");
}

/** A deadline / expiry (unix seconds or ms, hex or decimal) relative to now; "" when absent or unparsable. */
export function deadlineText(v: string | number | undefined, now = Date.now()): { never: boolean; text: string } | undefined {
  const b = toBig(v);
  if (b === undefined) return undefined;
  if (b === 0n) return undefined;
  // 2^32 - 1 and max uint idioms, or more than 20 years out: effectively forever
  let secs = b;
  if (secs > 10_000_000_000n) secs = secs / 1000n; // milliseconds
  const nowS = BigInt(Math.floor(now / 1000));
  if (b >= UINT_MAX / 2n || b === 4294967295n || secs - nowS > 20n * 365n * 86400n) return { never: true, text: "" };
  const diff = Number(secs - nowS);
  if (diff <= 0) return { never: false, text: "expired" };
  const days = Math.floor(diff / 86400);
  if (days >= 365) return { never: false, text: `${(days / 365).toFixed(1)} y` };
  if (days >= 1) return { never: false, text: `${days} d` };
  const hours = Math.floor(diff / 3600);
  if (hours >= 1) return { never: false, text: `${hours} h` };
  return { never: false, text: `${Math.max(1, Math.floor(diff / 60))} min` };
}

/** Decode a `string` ABI return (symbol()/name()); also tolerates the bytes32 variants (MKR-style). */
export function decodeString(hex: string | null | undefined): string | undefined {
  if (!hex || typeof hex !== "string") return undefined;
  const h = hex.toLowerCase().replace(/^0x/, "");
  if (h.length < 64) return undefined;
  let bytes: string;
  if (h.length === 64) bytes = h.replace(/(00)+$/, ""); // bytes32
  else {
    const off = Number(BigInt("0x" + h.slice(0, 64))) * 2;
    const len = Number(BigInt("0x" + h.slice(off, off + 64))) * 2;
    if (!len || off + 64 + len > h.length) return undefined;
    bytes = h.slice(off + 64, off + 64 + len);
  }
  let s = "";
  for (let i = 0; i + 2 <= bytes.length; i += 2) s += String.fromCharCode(parseInt(bytes.slice(i, i + 2), 16));
  try { s = decodeURIComponent(escape(s)); } catch { /* keep raw */ }
  s = s.replace(/[^\x20-\x7e -￿]/g, "").trim();
  return s && s.length <= 32 ? s : undefined;
}

export function decodeUint(hex: string | null | undefined): bigint | undefined {
  if (!hex || typeof hex !== "string" || !/^0x[0-9a-f]*$/i.test(hex) || hex.length < 66) return undefined;
  return BigInt(hex.slice(0, 66));
}

/** ABI-encode a single address argument call. */
export const callData = (selector: string, address?: string) => selector + (address ? address.toLowerCase().replace(/^0x/, "").padStart(64, "0") : "");
export const SEL = { symbol: "0x95d89b41", name: "0x06fdde03", decimals: "0x313ce567", balanceOf: "0x70a08231" };

export interface TokenMeta { symbol?: string; name?: string; decimals?: number; balance?: bigint; /** balanceOf worked but decimals() did not: an NFT collection */ nft?: boolean }

/** Human label for a token: "USDC" / "Bored Ape Yacht Club" / "0x1234…abcd". */
export function tokenLabel(address: string | undefined, meta: TokenMeta | undefined): string {
  const known = address ? KNOWN_CONTRACTS[address.toLowerCase()] : undefined;
  return meta?.symbol || meta?.name || known || shortAddr(address);
}
export const shortAddr = (a?: string) => (a ? `${a.slice(0, 8)}…${a.slice(-6)}` : "");

/** Seaport order summary: what the signer gives and what comes back to them. */
export interface SeaportSummary { give: Array<{ token: string; count: number; amount: bigint; kind: "native" | "erc20" | "nft" }>; get: Array<{ token: string; amount: bigint; kind: "native" | "erc20" | "nft" }> }
export function summarizeSeaport(message: Record<string, unknown>): SeaportSummary | undefined {
  const offer = message.offer as Array<Record<string, unknown>> | undefined;
  const consideration = message.consideration as Array<Record<string, unknown>> | undefined;
  if (!Array.isArray(offer)) return undefined;
  const offerer = String(message.offerer ?? "").toLowerCase();
  const kindOf = (t: unknown): "native" | "erc20" | "nft" => { const n = Number(t); return n === 0 ? "native" : n === 1 ? "erc20" : "nft"; };
  const give: SeaportSummary["give"] = [];
  for (const it of offer.slice(0, 50)) {
    const token = String(it.token ?? "").toLowerCase();
    const kind = kindOf(it.itemType);
    const amount = toBig(it.startAmount as string) ?? 0n;
    const row = give.find((g) => g.token === token && g.kind === kind);
    if (row) { row.count++; row.amount += amount; } else give.push({ token, count: 1, amount, kind });
  }
  const get: SeaportSummary["get"] = [];
  for (const it of (Array.isArray(consideration) ? consideration : []).slice(0, 50)) {
    if (String(it.recipient ?? "").toLowerCase() !== offerer) continue;
    const token = String(it.token ?? "").toLowerCase();
    const kind = kindOf(it.itemType);
    const amount = toBig(it.startAmount as string) ?? 0n;
    const row = get.find((g) => g.token === token && g.kind === kind);
    if (row) row.amount += amount; else get.push({ token, amount, kind });
  }
  return { give, get };
}
