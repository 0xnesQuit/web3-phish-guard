/**
 * Pure decoders for wallet RPC payloads. Runs in the MAIN world (no chrome.*) and in tests.
 * Goal: name the *intent* of a request (unlimited approval, operator approval, permit, delegation, transfer)
 * and extract the counterparty so the gate can decide whether to hold it.
 */

export interface TxIntent {
  /** canonical kind used by scoring/i18n */
  kind: "approve" | "approve-unlimited" | "setApprovalForAll" | "permit2" | "transfer" | "transferFrom" | "multicall" | "eth-send" | "delegation-7702" | "unknown-payable" | "none";
  selector?: string;
  /** spender / operator / recipient / delegate, lowercase */
  counterparty?: string;
  token?: string;
  amountHex?: string;
  unlimited?: boolean;
  /** nested intents for multicall / sendCalls */
  inner?: TxIntent[];
}

export interface SignIntent {
  kind: "permit" | "permit2" | "permit-batch" | "permit-for-all" | "seaport-order" | "blur-order" | "delegation" | "transfer-auth" | "safe-delegatecall" | "agent-approval" | "eth_sign" | "other";
  primaryType?: string;
  /** spender/operator/offerer when present */
  counterparty?: string;
  deadline?: string;
}

const UINT_MAX = "f".repeat(64);
export const SELECTORS: Record<string, string> = {
  "0x095ea7b3": "approve",
  "0x39509351": "increaseAllowance",
  "0xa22cb465": "setApprovalForAll",
  "0xd505accf": "permit",
  "0x2b67b570": "permit2",            // Permit2.permit(PermitSingle)
  "0x2a2d80d1": "permit2",            // Permit2.permit(PermitBatch)
  "0x87517c45": "permit2-approve",    // Permit2.approve(token, spender, amount, expiration)
  "0x30f28b7a": "permit2-transfer",   // permitTransferFrom
  "0x23b872dd": "transferFrom",
  "0x42842e0e": "safeTransferFrom",
  "0xb88d4fde": "safeTransferFrom",
  "0xa9059cbb": "transfer",
  "0xf242432a": "safeTransferFrom",   // ERC-1155 safeTransferFrom(from, to, id, amount, data)
  "0x2eb2c2d6": "safeBatchTransferFrom", // ERC-1155
  "0xac9650d8": "multicall",
  "0x5ae401dc": "multicall",          // Uniswap v3 router multicall(deadline, data[])
  "0x1f0464d1": "multicall",          // multicall(bytes32 previousBlockhash, bytes[])
  "0x82ad56cb": "multicall",          // Multicall3.aggregate3
  "0x252dba42": "multicall",          // Multicall3.aggregate
  "0xbce38bd7": "multicall",          // Multicall3.tryAggregate
  "0x174dea71": "multicall",          // Multicall3.aggregate3Value
  "0x8d80ff0a": "multicall",          // Safe MultiSend.multiSend(bytes)
  "0x3593564c": "universal-router",   // Uniswap UniversalRouter.execute(commands, inputs, deadline)
  "0x24856bc3": "universal-router",   // UniversalRouter.execute(commands, inputs)
};
const MULTICALL_SELECTORS = new Set(Object.entries(SELECTORS).filter(([, n]) => n === "multicall").map(([s]) => s));

const word = (data: string, i: number) => data.slice(10 + i * 64, 10 + (i + 1) * 64);
const addr = (w: string) => ("0x" + w.slice(24)).toLowerCase();
const isUnlimited = (w: string) => w === UINT_MAX || /^f{40,}/.test(w) || /^[8-9a-f]/.test(w);

/** Decode one calldata blob (hex, 0x-prefixed). */
export function decodeCalldata(data: string | undefined, to?: string): TxIntent {
  const d = (data ?? "").toLowerCase();
  if (d.length < 10) return { kind: "none" };
  const sel = d.slice(0, 10);
  const name = SELECTORS[sel];
  switch (name) {
    case "approve":
    case "increaseAllowance": {
      const amount = word(d, 1);
      return { kind: isUnlimited(amount) ? "approve-unlimited" : "approve", selector: sel, counterparty: addr(word(d, 0)), token: to?.toLowerCase(), amountHex: amount, unlimited: isUnlimited(amount) };
    }
    case "setApprovalForAll": {
      const approved = word(d, 1).endsWith("1");
      return { kind: approved ? "setApprovalForAll" : "none", selector: sel, counterparty: addr(word(d, 0)), token: to?.toLowerCase() };
    }
    case "permit2-approve":
      return { kind: "permit2", selector: sel, token: addr(word(d, 0)), counterparty: addr(word(d, 1)), amountHex: word(d, 2), unlimited: isUnlimited(word(d, 2)) };
    case "permit":
    case "permit2":
    case "permit2-transfer":
      return { kind: "permit2", selector: sel, token: to?.toLowerCase() };
    case "transfer":
      return { kind: "transfer", selector: sel, counterparty: addr(word(d, 0)), token: to?.toLowerCase(), amountHex: word(d, 1) };
    case "transferFrom":
    case "safeTransferFrom":
    case "safeBatchTransferFrom":
      return { kind: "transferFrom", selector: sel, counterparty: addr(word(d, 1)), token: to?.toLowerCase() };
    case "universal-router": {
      // Universal Router command bytes (low 6 bits): 0x0a PERMIT2_PERMIT, 0x03 PERMIT2_PERMIT_BATCH (signature-based
      // allowances, held), 0x02 PERMIT2_TRANSFER_FROM, 0x0d PERMIT2_TRANSFER_FROM_BATCH (moves tokens, reported).
      // 0x0b is WRAP_ETH and 0x00/0x01/0x08/0x09 are swaps: ordinary.
      const off = parseInt(word(d, 0), 16) * 2;
      const len = parseInt(d.slice(10 + off, 10 + off + 64), 16);
      const cmds = d.slice(10 + off + 64, 10 + off + 64 + len * 2);
      const inner: TxIntent[] = [];
      for (let i = 0; i + 2 <= cmds.length; i += 2) {
        const c = parseInt(cmds.slice(i, i + 2), 16) & 0x3f;
        if (c === 0x0a || c === 0x03) inner.push({ kind: "permit2", selector: sel, token: to?.toLowerCase() });
        if (c === 0x02 || c === 0x0d) inner.push({ kind: "transferFrom", selector: sel, token: to?.toLowerCase() });
      }
      return { kind: "multicall", selector: sel, inner };
    }
    case "multicall": {
      // scan the blob for nested known selectors: cheap and good enough to spot an approve wrapped in a multicall
      const inner: TxIntent[] = [];
      for (const s of Object.keys(SELECTORS)) {
        if (MULTICALL_SELECTORS.has(s)) continue;
        let i = d.indexOf(s.slice(2), 10);
        while (i !== -1 && inner.length < 8) {
          if (i % 2 === 0) inner.push(decodeCalldata("0x" + d.slice(i), to));
          i = d.indexOf(s.slice(2), i + 8);
        }
      }
      return { kind: "multicall", selector: sel, inner };
    }
    default:
      return { kind: "none", selector: sel };
  }
}

export interface TxLike { to?: string; data?: string; value?: string; authorizationList?: unknown[]; type?: string | number }

/** Decode an eth_sendTransaction / eth_signTransaction params[0]. */
export function decodeTx(tx: TxLike | undefined): TxIntent {
  if (!tx) return { kind: "none" };
  const type = typeof tx.type === "string" ? parseInt(tx.type, 16) : tx.type;
  if ((Array.isArray(tx.authorizationList) && tx.authorizationList.length) || type === 4) {
    const first = tx.authorizationList?.[0] as { address?: string } | undefined;
    return { kind: "delegation-7702", counterparty: first?.address?.toLowerCase() };
  }
  const intent = decodeCalldata(tx.data, tx.to);
  if (intent.kind !== "none") return intent;
  const hasValue = !!tx.value && /^0x0*[1-9a-f]/i.test(tx.value);
  if (hasValue && (!tx.data || tx.data === "0x")) return { kind: "eth-send", counterparty: tx.to?.toLowerCase() };
  if (hasValue) return { kind: "unknown-payable", selector: (tx.data ?? "").slice(0, 10), counterparty: tx.to?.toLowerCase() };
  return { kind: "none", selector: (tx.data ?? "").slice(0, 10) };
}

/** EIP-5792 wallet_sendCalls params[0].calls[] */
export function decodeSendCalls(p: { calls?: TxLike[] } | undefined): TxIntent {
  const calls = p?.calls ?? [];
  const inner = calls.slice(0, 64).map(decodeTx).filter((i) => i.kind !== "none");
  return { kind: "multicall", inner };
}

/** eth_signTypedData_v4 params[1] (JSON string or object). */
export function decodeTypedData(raw: unknown): SignIntent {
  let td: { primaryType?: string; message?: Record<string, unknown>; domain?: { name?: string } } | null = null;
  try { td = typeof raw === "string" ? JSON.parse(raw) : (raw as typeof td); } catch { return { kind: "other" }; }
  if (!td || typeof td !== "object") return { kind: "other" };
  const pt = String(td.primaryType ?? "");
  const m = (td.message ?? {}) as Record<string, unknown>;
  const pick = (...keys: string[]) => {
    for (const k of keys) {
      const v = m[k] ?? (m.details as Record<string, unknown> | undefined)?.[k] ?? (m.spender as unknown);
      if (typeof v === "string" && /^0x[0-9a-f]{40}$/i.test(v)) return v.toLowerCase();
    }
    return undefined;
  };
  const deadline = ["deadline", "sigDeadline", "expiry", "expiration", "endTime"].map((k) => m[k]).find((v) => v !== undefined);
  if (/^PermitBatch(TransferFrom|WitnessTransferFrom)?$/.test(pt)) return { kind: "permit-batch", primaryType: pt, counterparty: pick("spender"), deadline: String(deadline ?? "") };
  if (/^Permit(Single|TransferFrom|WitnessTransferFrom)$/.test(pt)) return { kind: "permit2", primaryType: pt, counterparty: pick("spender"), deadline: String(deadline ?? "") };
  if (pt === "PermitForAll") return { kind: "permit-for-all", primaryType: pt, counterparty: pick("operator", "spender") };
  if (pt === "Permit") return { kind: "permit", primaryType: pt, counterparty: pick("spender"), deadline: String(deadline ?? "") };
  if (/^(OrderComponents|Order|BulkOrder|SeaportOrder)$/.test(pt)) return { kind: "seaport-order", primaryType: pt, counterparty: pick("offerer") };
  if (/^(Root|Order|Listing)$/.test(pt) && /blur/i.test(String(td.domain?.name ?? ""))) return { kind: "blur-order", primaryType: pt };
  if (/^Delegation$/.test(pt) || /^(SetDelegate|Delegate)/.test(pt)) return { kind: "delegation", primaryType: pt, counterparty: pick("delegate") };
  // Safe: a delegatecall transaction can replace the Safe's own logic (the Bybit-style attack)
  if (pt === "SafeTx") {
    const op = Number(m.operation ?? 0);
    return op === 1 ? { kind: "safe-delegatecall", primaryType: pt, counterparty: pick("to") } : { kind: "other", primaryType: pt };
  }
  // Hyperliquid-style: approving an agent key or a withdrawal is a signature that hands over trading / funds
  if (/ApproveAgent|ApproveBuilderFee|Withdraw|UsdSend|SpotSend|UsdClassTransfer/i.test(pt) || /hyperliquid/i.test(String(td.domain?.name ?? ""))) {
    if (/ApproveAgent|Withdraw|UsdSend|SpotSend|ApproveBuilderFee/i.test(pt)) return { kind: "agent-approval", primaryType: pt, counterparty: pick("agentAddress", "destination", "builder") };
  }
  // EIP-3009 (USDC and friends): a signature that lets the relayer move the tokens
  if (/^(TransferWithAuthorization|ReceiveWithAuthorization|CancelAuthorization)$/.test(pt) && pt !== "CancelAuthorization") return { kind: "transfer-auth", primaryType: pt, counterparty: pick("to"), deadline: String(m.validBefore ?? "") };
  return { kind: "other", primaryType: pt };
}

/** Address poisoning: same first 4 and last 4 hex chars as a known recipient, but a different address. */
export function looksPoisoned(candidate: string, known: string[]): string | undefined {
  const c = candidate.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(c)) return undefined;
  for (const k of known) {
    const kk = k.toLowerCase();
    if (kk === c) return undefined;
    if (kk.slice(2, 6) === c.slice(2, 6) && kk.slice(-4) === c.slice(-4)) return kk;
  }
  return undefined;
}

/** ClickFix / clipboard hijack: text that would run a command when pasted into a terminal or Run dialog. */
export const CLICKFIX_RE = /\b(powershell|pwsh|mshta|cmd(\.exe)?\s*\/c|certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|Invoke-(Expression|WebRequest|RestMethod)|iex\s*\(|curl\s+[^|]*\|\s*(ba)?sh\b|wget\s+[^|]*\|\s*(ba)?sh\b|osascript|xattr\s+-d|base64\s+(-d|--decode))\b/i;

export const CRYPTO_ADDR_RE = /\b(0x[0-9a-fA-F]{40}|[1-9A-HJ-NP-Za-km-z]{32,44}|bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[A-Za-z1-9]{33}|r[1-9A-HJ-NP-Za-km-z]{24,34})\b/;
