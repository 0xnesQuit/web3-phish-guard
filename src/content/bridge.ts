/**
 * Isolated-world side of the wallet gate (document_start, every frame).
 *
 * The MAIN-world guard (provider-guard.ts) only hooks and relays; everything that decides lives here, in a JavaScript
 * realm the page cannot reach: decoding calldata and typed data, the EOA-spender and address-poisoning checks,
 * ClickFix / clipboard patterns, the gate decision (via the background) and the confirmation modal (rendered in the
 * top frame, re-mounted if removed, trusted clicks only). Answers travel back over a MessageChannel port the guard
 * received before any page script ran.
 */
import { t } from "../lib/i18n";
import { KNOWN_CONTRACTS, nativeSymbol, toBig, isUnlimitedBig, formatUnits, deadlineText, decodeString, decodeUint, callData, SEL, tokenLabel, shortAddr, summarizeSeaport, type TokenMeta } from "../lib/impact";
import { screenTargets, flagLabelKey, type Counterparty } from "../lib/addrscreen";
import { decodeTx, decodeSendCalls, decodeTypedData, looksPoisoned, CLICKFIX_RE, CRYPTO_ADDR_RE, type TxIntent, type SignIntent } from "../lib/txdecode";

const TAG = "w3pg";

/** One translated "asset impact" line for the gate dialog. */
interface ImpactLine { text: string; bad?: boolean; muted?: boolean }
interface GateDetails { id: string; method: string; kind: string; counterparty?: string; counterpartyEoa?: boolean; unlimited?: boolean; token?: string; poisonedTwin?: string; batch?: string[]; primaryType?: string; deadline?: string; impact?: ImpactLine[]; sim?: ImpactLine[]; warn?: ImpactLine[]; hadGesture: boolean }
/** What the decoders found; only used locally to compute the impact lines (never sent to the background). */
interface ImpactIntent {
  tx?: TxIntent; sign?: SignIntent;
  /** the raw calls to simulate: the held eth_sendTransaction / eth_signTransaction, or every call of a wallet_sendCalls batch (in order) */
  simCalls?: SimTx[];
  /** the decoded calls of a batch, for the per-call lines */
  calls?: TxIntent[];
  /** serialized Solana transactions (base64) the guard captured, to simulate */
  solTxs?: string[];
}
interface SimTx { from?: string; to?: string; data?: string; value?: string }
interface SimReply { ok?: boolean; reason?: string; reverted?: boolean; failed?: boolean; error?: string; out?: string[]; in?: string[]; approvals?: string[]; warnings?: string[] }
type Decision = { ask: boolean; reason?: string; score?: number };
interface InspectMsg { type: "inspect"; id: string; method: string; params: unknown; chain: "evm" | "solana"; hadGesture: boolean; msSinceLoad: number }

const RISKY_KINDS = ["approve-unlimited", "approve", "setApprovalForAll", "permit2", "transfer", "transferFrom", "delegation-7702", "unknown-payable", "eth-send"];
const ALWAYS_HOLD = new Set(["setApprovalForAll", "approve-unlimited", "permit2", "permit", "permit-batch", "permit-for-all", "delegation", "delegation-7702", "eth_sign", "seaport-order", "blur-order", "transfer-auth", "safe-delegatecall", "agent-approval", "undecodable"]);

// ---- private channel -------------------------------------------------------------------
const channel = new MessageChannel();
const port = channel.port1;
const rpcWaiters = new Map<string, (result: unknown) => void>();
port.onmessage = (e) => {
  const d = e.data;
  if (!d || typeof d !== "object") return;
  if (d.type === "event" && d.event) void safeSend({ type: "w3pg:provider", event: d.event });
  else if (d.type === "inspect") void handleInspect(d as InspectMsg);
  else if (d.type === "rpc") { const w = rpcWaiters.get(String(d.id)); if (w) { rpcWaiters.delete(String(d.id)); w(d.result ?? null); } }
  else if (d.type === "copy") inspectCopy(String(d.text ?? ""), String(d.selection ?? ""));
};
try { window.postMessage({ source: TAG + "-ext", type: "port" }, "*", [channel.port2]); } catch { /* ignore */ }

/** runtime calls throw synchronously once the extension context is invalidated (after an update); never let that escape */
const safeSend = (msg: unknown): Promise<unknown> => { try { return chrome.runtime.sendMessage(msg).catch(() => undefined); } catch { return Promise.resolve(undefined); } };
const post = (event: Record<string, unknown>) => safeSend({ type: "w3pg:provider", event });

/**
 * Read-only JSON-RPC through the page's own provider: the guard relays it (allowlist: eth_getCode, eth_call,
 * eth_chainId, eth_accounts, eth_getBalance) on the provider the inspected request `reqId` came in on.
 * Resolves to the raw result, or null on error / timeout.
 */
function rpc(reqId: string, method: string, params: unknown[], ms = 3500): Promise<unknown> {
  const id = Math.random().toString(36).slice(2);
  return new Promise((resolve) => {
    const timer = setTimeout(() => { rpcWaiters.delete(id); resolve(null); }, ms);
    rpcWaiters.set(id, (result) => { clearTimeout(timer); resolve(result); });
    try { port.postMessage({ type: "rpc", id, reqId, method, params }); } catch { clearTimeout(timer); rpcWaiters.delete(id); resolve(null); }
  });
}

/** eth_getCode: a 7702-delegated EOA counts as an EOA. */
async function isEoa(address: string | undefined, reqId: string): Promise<boolean | undefined> {
  if (!address || !/^0x[0-9a-f]{40}$/.test(address)) return undefined;
  const code = await rpc(reqId, "eth_getCode", [address, "latest"]);
  if (typeof code !== "string") return undefined;
  const c = code.toLowerCase();
  return c === "0x" || c === "0x0" || c === "" || c.startsWith("0xef0100");
}

// ---- asset impact (display only): on-chain reads through the page's provider ----
const IMPACT_CAP_MS = 4000;
let ctxCache: { at: number; user?: string; chainId?: string } | undefined;
/** user address (eth_accounts[0]) and chain id, cached for 30 s */
async function walletContext(reqId: string): Promise<{ user?: string; chainId?: string }> {
  if (ctxCache && Date.now() - ctxCache.at < 30_000) return ctxCache;
  const [accs, chain] = await Promise.all([rpc(reqId, "eth_accounts", []), rpc(reqId, "eth_chainId", [])]);
  const a = Array.isArray(accs) ? accs[0] : undefined;
  const user = typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a) ? a.toLowerCase() : undefined;
  const chainId = typeof chain === "string" && /^0x[0-9a-fA-F]{1,16}$/.test(chain) ? chain : undefined;
  if (user || chainId) ctxCache = { at: Date.now(), user, chainId };
  return { user, chainId };
}

const ethCall = async (reqId: string, to: string, data: string): Promise<string | null> => {
  const r = await rpc(reqId, "eth_call", [{ to, data }, "latest"]);
  return typeof r === "string" ? r : null;
};
/** symbol / decimals / nft-ness are cached per token for the page lifetime; the balance is always read fresh */
const metaCache = new Map<string, TokenMeta>();
async function tokenMeta(reqId: string, token: string | undefined, user: string | undefined, wantBalance = true): Promise<TokenMeta | undefined> {
  if (!token || !/^0x[0-9a-f]{40}$/.test(token)) return undefined;
  let base = metaCache.get(token);
  const balP = wantBalance && user ? ethCall(reqId, token, callData(SEL.balanceOf, user)) : Promise.resolve(null);
  if (!base) {
    const [sym, dec] = await Promise.all([ethCall(reqId, token, SEL.symbol), ethCall(reqId, token, SEL.decimals)]);
    const decimals = decodeUint(dec);
    base = { symbol: decodeString(sym), decimals: decimals !== undefined && decimals <= 77n ? Number(decimals) : undefined };
  }
  const balance = decodeUint(await balP);
  if (base.decimals === undefined && balance !== undefined) base = { ...base, nft: true };
  if (base.symbol || base.decimals !== undefined || base.nft) metaCache.set(token, base);
  const meta: TokenMeta = { ...base, balance };
  return meta.symbol || meta.decimals !== undefined || meta.balance !== undefined ? meta : undefined;
}

const fmtAmt = (v: bigint, meta?: TokenMeta) => formatUnits(v, meta?.decimals ?? 0);

/** Token lines shared by approvals and permits. */
function tokenLines(token: string, meta: TokenMeta | undefined, o: { unlimited: boolean; amount?: bigint; forAll?: boolean }): ImpactLine[] {
  if (!meta) return [];
  const label = tokenLabel(token, meta);
  if (meta.nft || o.forAll) {
    if (meta.balance === undefined) return [];
    return [{ text: t("gate_impact_nfts", [label, meta.balance.toString()]), bad: true }];
  }
  if (o.unlimited) {
    return meta.balance !== undefined && meta.balance > 0n
      ? [{ text: t("gate_impact_all", [label, fmtAmt(meta.balance, meta)]), bad: true }]
      : [{ text: t("gate_impact_all_zero", [label]), bad: true }];
  }
  const out: ImpactLine[] = [];
  if (o.amount !== undefined) out.push({ text: t("gate_impact_amount", [fmtAmt(o.amount, meta), label]) });
  if (meta.balance !== undefined) out.push({ text: t("gate_impact_balance", [fmtAmt(meta.balance, meta), label]) });
  return out;
}

async function seaportLines(reqId: string, message: Record<string, unknown>, chainId: string | undefined): Promise<ImpactLine[]> {
  const sum = summarizeSeaport(message);
  if (!sum) return [];
  const tokens = [...new Set([...sum.give, ...sum.get].filter((i) => i.kind !== "native").map((i) => i.token))].slice(0, 8);
  const metas = new Map<string, TokenMeta | undefined>();
  await Promise.all(tokens.map(async (tk) => { metas.set(tk, await tokenMeta(reqId, tk, undefined, false)); }));
  const native = nativeSymbol(chainId);
  const text = (i: { token: string; amount: bigint; kind: "native" | "erc20" | "nft"; count?: number }) => {
    if (i.kind === "native") return `${formatUnits(i.amount, 18)} ${native}`;
    const m = metas.get(i.token);
    const label = tokenLabel(i.token, m);
    return i.kind === "nft" ? `${i.count ?? 1} × ${label} (NFT)` : `${fmtAmt(i.amount, m)} ${label}`;
  };
  const out: ImpactLine[] = [];
  if (sum.give.length) out.push({ text: t("gate_impact_give", [sum.give.slice(0, 6).map(text).join(", ")]), bad: true });
  const nothing = sum.get.length === 0 || sum.get.every((i) => i.amount === 0n);
  if (nothing) out.push({ text: t("gate_impact_get_nothing"), bad: true });
  else out.push({ text: t("gate_impact_get", [sum.get.slice(0, 6).map((i) => text({ ...i, count: 1 })).join(", ")]) });
  return out;
}

const CALL_BAD = new Set(["approve-unlimited", "setApprovalForAll", "permit2", "delegation-7702"]);
/** "Call 2: Token transfer: 100 USDC" for the first 6 calls of a batch; at most 4 distinct tokens are read. */
async function callLines(reqId: string, calls: TxIntent[], user: string | undefined, chainId: string | undefined): Promise<ImpactLine[]> {
  const shown = calls.slice(0, 6);
  const tokens = [...new Set(shown.map((c) => c.token).filter((x): x is string => !!x))].slice(0, 4);
  const metas = new Map<string, TokenMeta | undefined>();
  await Promise.all(tokens.map(async (tk) => { metas.set(tk, await tokenMeta(reqId, tk, user, false)); }));
  return shown.map((c, i) => {
    const kindText = t(`gate_kind_${c.kind.replace(/-/g, "_")}`) || c.kind;
    let detail = "";
    if (c.kind === "eth-send" || c.kind === "unknown-payable") {
      const v = toBig(c.valueHex);
      if (v !== undefined) detail = `${formatUnits(v, 18)} ${nativeSymbol(chainId)}`;
    } else if (c.token) {
      const m = metas.get(c.token);
      const label = tokenLabel(c.token, m);
      const amount = c.unlimited || m?.nft ? undefined : toBig(c.amountHex);
      detail = amount !== undefined && m?.decimals !== undefined ? `${fmtAmt(amount, m)} ${label}` : label;
    }
    return { text: t("gate_impact_call", [String(i + 1), detail ? `${kindText}: ${detail}` : kindText]), bad: CALL_BAD.has(c.kind) };
  });
}

/** Every read is optional: whatever fails is simply left out. */
async function describeImpactLines(g: GateDetails, intent: ImpactIntent | undefined): Promise<ImpactLine[]> {
  if (!intent || (!intent.tx && !intent.sign)) return [];
  const reqId = g.id;
  const { user, chainId } = await walletContext(reqId);
  const lines: ImpactLine[] = [];
  const guarded = async (fn: () => Promise<ImpactLine[]> | ImpactLine[]) => { try { lines.push(...(await fn())); } catch { /* optional */ } };
  const tx = intent.tx, sg = intent.sign;
  if (tx) {
    await guarded(async () => {
      switch (tx.kind) {
        case "approve": case "approve-unlimited": case "permit2": {
          const meta = await tokenMeta(reqId, tx.token, user);
          const amount = toBig(tx.amountHex);
          return tokenLines(tx.token!, meta, { unlimited: !!tx.unlimited || (amount !== undefined && isUnlimitedBig(amount)), amount });
        }
        case "setApprovalForAll": return tokenLines(tx.token!, await tokenMeta(reqId, tx.token, user), { unlimited: true, forAll: true });
        case "transfer": case "transferFrom": {
          const meta = await tokenMeta(reqId, tx.token, user);
          const amount = toBig(tx.amountHex);
          if (!meta || meta.nft || amount === undefined) return [];
          return [{ text: t("gate_impact_sends", [fmtAmt(amount, meta), tokenLabel(tx.token, meta), shortAddr(tx.counterparty)]) }];
        }
        case "eth-send": case "unknown-payable": {
          const v = toBig(tx.valueHex);
          return v === undefined ? [] : [{ text: t("gate_impact_sends", [formatUnits(v, 18), nativeSymbol(chainId), shortAddr(tx.counterparty)]) }];
        }
        case "delegation-7702": {
          let who = tx.counterparty ? KNOWN_CONTRACTS[tx.counterparty] : undefined;
          if (!who) who = t((await isEoa(tx.counterparty, reqId)) === true ? "gate_word_plain_wallet" : "gate_word_unknown_contract");
          return [{ text: t("gate_impact_delegate", [who]), bad: true }];
        }
        default: return [];
      }
    });
  }
  if (sg) {
    await guarded(async () => {
      if (sg.kind === "seaport-order") return sg.message ? seaportLines(reqId, sg.message, chainId) : [];
      if (sg.kind !== "permit" && sg.kind !== "permit2" && sg.kind !== "permit-batch") return [];
      const out: ImpactLine[] = [];
      const meta = await tokenMeta(reqId, sg.token, user);
      const amount = toBig(sg.amountHex);
      if (sg.token) out.push(...tokenLines(sg.token, meta, { unlimited: amount !== undefined && isUnlimitedBig(amount), amount }));
      if (sg.kind === "permit-batch" && sg.tokens && sg.tokens.length) {
        const list = [...new Set(sg.tokens)].slice(0, 6);
        const names = await Promise.all(list.map(async (tk) => tokenLabel(tk, await tokenMeta(reqId, tk, undefined, false))));
        out.push({ text: t("gate_impact_tokens", [names.join(", ")]) });
      }
      const dl = deadlineText(sg.deadline);
      if (dl?.never) out.push({ text: t("gate_impact_no_expiry"), bad: true });
      else if (dl?.text) out.push({ text: t("gate_impact_deadline", [dl.text]) });
      return out;
    });
  }
  if (intent.calls && intent.calls.length > 1) await guarded(() => callLines(reqId, intent.calls!, user, chainId));
  if (g.counterparty && tx?.kind !== "delegation-7702") {
    const known = KNOWN_CONTRACTS[g.counterparty.toLowerCase()];
    if (known) lines.push({ text: t("gate_known", [known]) });
    else if (g.counterpartyEoa === false) lines.push({ text: t("gate_unknown_contract") });
  }
  return lines;
}

/** describeImpactLines capped at 4 s overall; never rejects, resolves to [] on timeout or failure. */
function describeImpact(g: GateDetails, intent: ImpactIntent | undefined): Promise<ImpactLine[]> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve([]), IMPACT_CAP_MS);
    describeImpactLines(g, intent).then((l) => { clearTimeout(timer); resolve(l); }, () => { clearTimeout(timer); resolve([]); });
  });
}

// ---- transaction simulation (public RPC via the background; off switch in the options page) ----
const SIM_CAP_MS = 8000;
const joinList = (l: string[]) => l.slice(0, 6).join(", ") + (l.length > 6 ? ` +${l.length - 6}` : "");
/** Turn the background's formatted reply into dialog rows; any failure is a single muted "not available" row. */
function simLines(r: SimReply | undefined): ImpactLine[] {
  if (!r || !r.ok) return [{ text: t("gate_sim_unavailable"), muted: true }];
  if (r.reverted) return [{ text: t("gate_sim_reverted") }];
  if (r.failed) return [{ text: t("gate_sim_sol_failed") }];
  const out = r.out ?? [], inn = r.in ?? [], ap = r.approvals ?? [], warn = r.warnings ?? [];
  const lines: ImpactLine[] = [];
  if (out.length) lines.push({ text: t("gate_sim_out", [joinList(out)]), bad: true });
  if (inn.length) lines.push({ text: t("gate_sim_in", [joinList(inn)]) });
  else if (out.length) lines.push({ text: t("gate_sim_nothing_back"), bad: true });
  for (const a of ap.slice(0, 6)) lines.push({ text: t("gate_sim_approval", [a]), bad: true });
  for (const w of warn.slice(0, 4)) lines.push({ text: w, bad: true });
  if (!lines.length) lines.push({ text: t("gate_sim_no_changes") });
  return lines;
}

/** Start the simulation for a held transaction; never rejects, capped at SIM_CAP_MS. */
function simulate(g: GateDetails, calls: SimTx[]): Promise<ImpactLine[]> {
  return new Promise((resolve) => {
    const fail = () => resolve(simLines(undefined));
    const timer = setTimeout(fail, SIM_CAP_MS);
    (async () => {
      const { user, chainId } = await walletContext(g.id);
      const filled: SimTx[] = [];
      for (const tx of calls.slice(0, 16)) {
        const from = tx.from && /^0x[0-9a-fA-F]{40}$/.test(tx.from) ? tx.from : user;
        if (!from || !tx.to) return fail();
        filled.push({ ...tx, from });
      }
      if (!chainId || !filled.length) return fail();
      // a single transaction goes as `tx` (unchanged); a batch as `calls`, simulated in order
      const r = (await safeSend(filled.length === 1 ? { type: "w3pg:simulate", chainId, tx: filled[0] } : { type: "w3pg:simulate", chainId, calls: filled })) as SimReply | undefined;
      clearTimeout(timer);
      resolve(simLines(r));
    })().catch(() => { clearTimeout(timer); fail(); });
  });
}

/** Solana: the background simulates the transactions the guard captured (no wallet context needed). */
function simulateSol(txs: string[]): Promise<ImpactLine[]> {
  return new Promise((resolve) => {
    const fail = () => resolve(simLines(undefined));
    const timer = setTimeout(fail, SIM_CAP_MS);
    safeSend({ type: "w3pg:simulateSol", txs }).then((r) => { clearTimeout(timer); resolve(simLines(r as SimReply | undefined)); }, () => { clearTimeout(timer); fail(); });
  });
}

// ---- counterparty screen (known malicious address): runs only at the gate, never blocks the dialog ----
const ADDR_CAP_MS = 5000;
type AddrReply = { bad: boolean; flags: string[] };
/** per-address, for the page lifetime (the Worker also caches 6-24 h) */
const addrCache = new Map<string, Promise<AddrReply>>();
function screenAddr(address: string, chain: number): Promise<AddrReply> {
  const key = chain + ":" + address;
  let p = addrCache.get(key);
  if (!p) {
    p = safeSend({ type: "w3pg:addr", address, chain }).then((r) => {
      const o = (r ?? {}) as { bad?: unknown; flags?: unknown };
      return { bad: o.bad === true, flags: Array.isArray(o.flags) ? o.flags.filter((f): f is string => typeof f === "string") : [] };
    }, () => ({ bad: false, flags: [] }));
    addrCache.set(key, p);
  }
  return p;
}

/** Warning rows for flagged counterparties; [] when nothing is flagged, nothing is screenable or anything fails (fail open). */
function addrWarnLines(g: GateDetails, intent: ImpactIntent | undefined): Promise<ImpactLine[]> {
  return new Promise((resolve) => {
    if (!intent) return resolve([]);
    const timer = setTimeout(() => resolve([]), ADDR_CAP_MS);
    (async () => {
      const items: Array<{ kind: string; counterparty?: string }> = [];
      if (intent.tx) items.push(intent.tx);
      for (const c of intent.calls ?? []) items.push(c);
      if (intent.sign) items.push(intent.sign);
      if (!items.length) return [];
      const { user, chainId } = await walletContext(g.id);
      const targets: Counterparty[] = screenTargets(items, user);
      if (!targets.length) return [];
      const chain = chainId ? parseInt(chainId, 16) || 1 : 1;
      const lines: ImpactLine[] = [];
      await Promise.all(targets.map(async (c) => {
        const r = await screenAddr(c.address, chain);
        if (r.bad && r.flags.length) lines.push({ text: t(c.role === "recipient" ? "gate_addr_bad_recipient" : "gate_addr_bad_spender", [short(c.address), t(flagLabelKey(r.flags))]), bad: true });
      }));
      return lines;
    })().then((l) => { clearTimeout(timer); resolve(l); }, () => { clearTimeout(timer); resolve([]); });
  });
}

// ---- recipients seen on this origin (address poisoning) ----
const knownRecipients: string[] = [];
function checkPoison(to: string | undefined): string | undefined {
  if (!to || !/^0x[0-9a-fA-F]{40}$/.test(to)) return undefined;
  const twin = looksPoisoned(to, knownRecipients);
  if (!twin && !knownRecipients.includes(to.toLowerCase())) knownRecipients.push(to.toLowerCase());
  return twin;
}

async function handleInspect(m: InspectMsg): Promise<void> {
  let allow = true;
  try {
    const r = await inspect(m);
    allow = r;
  } catch { allow = true; }
  port.postMessage({ type: "decision", id: m.id, allow });
}

/** Mirrors the former MAIN-world logic: name the intent, report it, and hold what needs holding. */
async function inspect(m: InspectMsg): Promise<boolean> {
  const { method, params, hadGesture: g, msSinceLoad } = m;
  const p = Array.isArray(params) ? params : [];
  const ack = (hold: boolean) => port.postMessage({ type: "ack", id: m.id, hold });

  if (m.chain === "solana") {
    const batch = typeof (params as { batch?: number })?.batch === "number" ? (params as { batch: number }).batch : 1;
    post({ kind: "risky-tx", method, detail: batch > 1 ? "solana_batch" : "solana", param: method, msSinceLoad, hadGesture: g });
    ack(false);
    // the guard's display-only copy of the transactions (base64): simulated for the dialog, never used for any decision
    const rawTxs = (params as { txs?: unknown })?.txs;
    const solTxs = Array.isArray(rawTxs) ? rawTxs.filter((x): x is string => typeof x === "string" && x.length <= 2400 && /^[A-Za-z0-9+/]+={0,2}$/.test(x)).slice(0, 4) : [];
    return gate({ id: m.id, method, kind: "solana-sign", batch: batch > 1 ? Array(batch).fill("sign") : undefined, hadGesture: g }, solTxs.length ? { solTxs } : undefined);
  }
  if (method === "eth_requestAccounts" || method === "wallet_requestPermissions" || method === "enable") {
    if (!g && msSinceLoad < 5000) post({ kind: "auto-connect", method, detail: "", msSinceLoad, hadGesture: g });
    ack(false); return true;
  }
  if (method === "wallet_switchEthereumChain" || method === "wallet_addEthereumChain") {
    if (!g) post({ kind: "chain-switch", method, detail: "", msSinceLoad, hadGesture: g });
    ack(false); return true;
  }
  // the guard could not snapshot a signing request (a page broke structuredClone, or params carry live getters):
  // never let an undecodable signing request through unseen
  if ((params as { w3pgUndecodable?: boolean } | null)?.w3pgUndecodable) {
    post({ kind: "risky-sign", method, detail: "undecodable", msSinceLoad, hadGesture: g });
    ack(true);
    return gate({ id: m.id, method, kind: "undecodable", hadGesture: g });
  }
  if (method === "eth_sign") {
    post({ kind: "risky-sign", method, detail: "eth_sign", msSinceLoad, hadGesture: g });
    ack(true);
    return gate({ id: m.id, method, kind: "eth_sign", hadGesture: g });
  }
  if (/^eth_signTypedData(_v[34])?$/.test(method)) {
    const td = p.find((x) => typeof x === "string" && x.includes("primaryType")) ?? p[1] ?? p[0];
    const s: SignIntent = decodeTypedData(td);
    if (s.kind === "other") { ack(false); return true; }
    ack(ALWAYS_HOLD.has(s.kind));
    post({ kind: "risky-sign", method, detail: "typed", param: s.primaryType, msSinceLoad, hadGesture: g });
    const eoa = await isEoa(s.counterparty, m.id);
    if (eoa) post({ kind: "risky-sign", method, detail: "eoa-spender", param: s.counterparty, msSinceLoad, hadGesture: g });
    return gate({ id: m.id, method, kind: s.kind, primaryType: s.primaryType, counterparty: s.counterparty, counterpartyEoa: eoa, deadline: s.deadline, hadGesture: g }, { sign: s });
  }
  if (method === "eth_sendTransaction" || method === "eth_signTransaction" || method === "wallet_sendCalls") {
    const intent: TxIntent = method === "wallet_sendCalls" ? decodeSendCalls(p[0] as { calls?: never[] }) : decodeTx(p[0] as never);
    const flat = intent.kind === "multicall" ? intent.inner ?? [] : [intent];
    const risky = flat.filter((i) => RISKY_KINDS.includes(i.kind));
    if (intent.kind === "multicall" && (intent.inner?.length ?? 0) === 0 && method === "wallet_sendCalls" && ((p[0] as { calls?: unknown[] })?.calls?.length ?? 0) > 20) {
      // more calls than the decoder reads: hold rather than wave through
      ack(true);
      return gate({ id: m.id, method, kind: "undecodable", batch: ["calls>20"], hadGesture: g });
    }
    if (!risky.length) { ack(false); return true; }
    const top = risky.find((i) => i.kind === "delegation-7702") ?? risky.find((i) => i.kind === "setApprovalForAll") ?? risky.find((i) => i.kind === "approve-unlimited") ?? risky[0];
    ack(ALWAYS_HOLD.has(top.kind));
    const detailCode = top.kind === "approve-unlimited" ? "approve" : top.kind === "delegation-7702" ? "delegation" : top.kind === "unknown-payable" ? "payable_unknown" : top.kind === "eth-send" ? "eth_send" : top.kind;
    post({ kind: "risky-tx", method, detail: detailCode, param: top.counterparty, msSinceLoad, hadGesture: g });
    const twin = checkPoison(top.counterparty);
    const eoa = ["approve-unlimited", "approve", "setApprovalForAll", "permit2"].includes(top.kind) ? await isEoa(top.counterparty, m.id) : undefined;
    if (eoa) post({ kind: "risky-tx", method, detail: "eoa-spender", param: top.counterparty, msSinceLoad, hadGesture: g });
    if (twin) post({ kind: "risky-tx", method, detail: "poisoning", param: top.counterparty, msSinceLoad, hadGesture: g });
    return gate({ id: m.id, method, kind: top.kind, counterparty: top.counterparty, counterpartyEoa: eoa, unlimited: top.unlimited, token: top.token, poisonedTwin: twin, batch: flat.length > 1 ? flat.map((i) => i.kind) : undefined, hadGesture: g }, { tx: top, simCalls: simCallsOf(method, p[0]), calls: flat.length > 1 ? flat.slice(0, 6) : undefined });
  }
  ack(false);
  return true;
}

/**
 * The raw calls worth simulating: the transaction itself, or every call of a wallet_sendCalls batch (at most 16, in
 * order, so each sees the state the previous one left). None when any call is a 7702 delegation (nothing to replay)
 * or lacks a plain `to`, and none for a batch longer than 16 (a partial simulation would mislead).
 */
function simCallsOf(method: string, p0: unknown): SimTx[] | undefined {
  const o = (p0 && typeof p0 === "object" ? p0 : {}) as Record<string, unknown> & { calls?: Array<Record<string, unknown>> };
  const str = (v: unknown) => (typeof v === "string" ? v : undefined);
  const list = method === "wallet_sendCalls" ? (Array.isArray(o.calls) ? o.calls : []) : [o];
  if (!list.length || list.length > 16) return undefined;
  const out: SimTx[] = [];
  for (const c of list) {
    if (!c || typeof c !== "object" || c.authorizationList || typeof c.to !== "string") return undefined;
    if (decodeTx(c as never).kind === "delegation-7702") return undefined;
    out.push({ from: str(c.from) ?? str(o.from), to: c.to, data: str(c.data) ?? str(c.input), value: str(c.value) });
  }
  return out;
}

/** Ask the background whether to hold; if so, show the modal (in the top frame) and return the user's answer. */
async function gate(g: GateDetails, intent?: ImpactIntent): Promise<boolean> {
  let decision: Decision = { ask: false };
  const fallback = { ask: ALWAYS_HOLD.has(g.kind) || g.counterpartyEoa === true || !!g.poisonedTwin };
  try {
    // background unavailable (or the context invalidated by an update): the kinds no legitimate flow needs fail
    // closed, everything else proceeds
    const r = (await safeSend({ type: "w3pg:gate", details: g })) as Decision | undefined;
    decision = r ?? fallback;
  } catch {
    decision = fallback;
  }
  if (!decision.ask) return true;
  // the modal is about to open: tell the guard to hold the request for as long as it takes
  port.postMessage({ type: "ack", id: g.id, hold: true });
  let allow: boolean;
  // reads start now; the top frame shows the dialog at once and fills the rows in, an iframe waits (one-shot message)
  const impactP = describeImpact(g, intent);
  const simP = intent?.simCalls?.length ? simulate(g, intent.simCalls) : intent?.solTxs?.length ? simulateSol(intent.solTxs) : undefined;
  const warn = { p: addrWarnLines(g, intent), shown: false };
  if (window.top !== window) {
    try { const [lines, sim, w] = await Promise.all([impactP, simP, warn.p]); if (lines.length) g.impact = lines; if (sim?.length) g.sim = sim; if (w.length) g.warn = w; } catch { /* display only */ }
    try {
      const r = (await safeSend({ type: "w3pg:gateTop", details: g, decision, frameHost: location.hostname })) as { allow?: boolean } | undefined;
      allow = typeof r?.allow === "boolean" ? r.allow : await modal(g, decision, location.hostname);
    } catch { allow = await modal(g, decision, location.hostname); }
  } else {
    allow = await modal(g, decision, location.hostname, impactP, simP, warn);
  }
  // Late screen result: the user answered before the lookup finished and the address turned out to be flagged. Show the
  // warning and ask again (top frame); an iframe cannot, so it rejects.
  if (allow && !warn.shown && !g.warn?.length) {
    try {
      const w = await warn.p;
      if (w.length) {
        g.warn = w;
        allow = window.top === window ? await modal(g, { reason: w[0].text, score: decision.score }, location.hostname, impactP, simP) : false;
      }
    } catch { /* screen is best effort */ }
  }
  // Simulation-spoofing guard: a drainer can show a harmless preview, then flip the contract state so the SAME signed
  // transaction drains on execution (the gap between simulation and signing). If the user proceeds on a preview that
  // showed no loss, re-simulate right now; if the effect has turned into a loss, re-confirm with the real result
  // (top frame) or reject outright (iframe) instead of letting it through blind.
  if (allow && intent?.simCalls?.length && simP) {
    try {
      const before = await simP;
      if (!before.some((l) => l.bad)) {
        const fresh = await simulate(g, intent.simCalls);
        if (fresh.some((l) => l.bad)) {
          allow = window.top === window
            ? await modal(g, { reason: t("gate_sim_changed"), score: decision.score }, location.hostname, impactP, Promise.resolve(fresh))
            : false;
        }
      }
    } catch { /* re-sim is best effort: fall back to the user's original choice */ }
  }
  if (!allow) void safeSend({ type: "w3pg:gateRejected", details: g });
  return allow;
}

// the top frame renders modals for its iframes
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "w3pg:showGate" || window.top !== window) return;
  modal(msg.details as GateDetails, (msg.decision as Decision) ?? { ask: true }, String(msg.frameHost ?? location.hostname)).then((allow) => sendResponse({ allow }));
  return true;
});

// ---- clipboard patterns (text arrives from the guard) ----
function inspectCopy(text: string, selection: string) {
  if (!text) return;
  const now = performance.now();
  if (CLICKFIX_RE.test(text)) { post({ kind: "clickfix", method: "clipboard", detail: "clickfix", param: text.slice(0, 80), msSinceLoad: now, hadGesture: true }); return; }
  const copied = text.match(CRYPTO_ADDR_RE)?.[1];
  if (!copied) return;
  const selected = selection.match(CRYPTO_ADDR_RE)?.[1];
  if (selected && selected !== copied) post({ kind: "clipboard-swap", method: "clipboard", detail: "clipboard_swap", param: `${selected.slice(0, 8)}… → ${copied.slice(0, 8)}…`, msSinceLoad: now, hadGesture: true });
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
const short = (a?: string) => (a ? `${a.slice(0, 8)}…${a.slice(-6)}` : "");

/** heading + rows; with no lines and no pending reads nothing at all (no heading) */
function impactHtml(lines: ImpactLine[] | undefined, checking: boolean): string {
  if (checking) return `<li class="chk">${esc(t("gate_checking"))}</li>`;
  if (!lines || !lines.length) return "";
  return `<li class="h">${esc(t("gate_impact_title"))}</li>` + lines.map((l) => `<li${l.bad ? ' class="bad"' : ""}>${esc(l.text)}</li>`).join("");
}

/** simulation rows: heading + rows; the muted "not available" row stands alone */
function simHtml(lines: ImpactLine[] | undefined, checking: boolean): string {
  if (checking) return `<li class="chk">${esc(t("gate_simulating"))}</li>`;
  if (!lines || !lines.length) return "";
  const head = lines[0].muted ? "" : `<li class="h">${esc(t("gate_sim_title"))}</li>`;
  return head + lines.map((l) => `<li${l.muted ? ' class="chk"' : l.bad ? ' class="bad"' : ""}>${esc(l.text)}</li>`).join("");
}

function modal(g: GateDetails, d: { reason?: string; score?: number }, hostLabel: string, impactP?: Promise<ImpactLine[]>, simP?: Promise<ImpactLine[]>, warn?: { p: Promise<ImpactLine[]>; shown: boolean }): Promise<boolean> {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.id = "w3pg-gate";
    host.style.cssText = "all:initial !important;position:fixed !important;inset:0 !important;z-index:2147483647 !important;display:block !important;";
    const root = host.attachShadow({ mode: "closed" });
    const rows: string[] = [];
    const kindText = t(`gate_kind_${g.kind.replace(/-/g, "_")}`) || g.kind;
    rows.push(`<li>${esc(t("gate_request"))}: <b>${esc(kindText)}</b>${g.primaryType ? ` (${esc(g.primaryType)})` : ""}</li>`);
    if (g.counterparty) rows.push(`<li>${esc(t("gate_counterparty"))}: <code>${esc(short(g.counterparty))}</code>${g.counterpartyEoa ? ` <b class="bad">${esc(t("gate_eoa"))}</b>` : ""}</li>`);
    if (g.unlimited) rows.push(`<li class="bad">${esc(t("gate_unlimited"))}</li>`);
    if (g.poisonedTwin) rows.push(`<li class="bad">${esc(t("gate_poison", [short(g.poisonedTwin)]))}</li>`);
    if (g.batch) rows.push(`<li>${esc(t("gate_batch", [g.batch.join(", ")]))}</li>`);
    if (!g.hadGesture) rows.push(`<li class="bad">${esc(t("gate_no_click"))}</li>`);
    if (d.reason) rows.push(`<li>${esc(d.reason)}</li>`);
    root.innerHTML = `
      <style>
        .bg{position:fixed;inset:0;background:rgba(6,8,14,.78);display:flex;align-items:center;justify-content:center;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
        .card{box-sizing:border-box;max-width:520px;width:calc(100% - 32px);max-height:calc(100vh - 32px);overflow:auto;background:#141926;color:#e8ecf6;border:1px solid #222a3a;border-top:3px solid #ff5b6e;border-radius:14px;padding:22px 24px;box-shadow:0 24px 70px rgba(0,0,0,.65)}
        h1{font-size:18px;line-height:1.3;font-weight:700;margin:0 0 6px;color:#ff5b6e}
        .sub{color:#9aa6c0;margin-bottom:14px}
        ul{margin:0 0 14px;padding-left:18px}
        li{margin:5px 0;color:#e8ecf6}
        li b{color:#e8ecf6}
        .bad,li b.bad{color:#ff7d8c}
        .imp:empty{display:none}
        .imp{border-top:1px solid #222a3a;padding-top:8px}
        .imp .h{list-style:none;margin-left:-18px;font-weight:600;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:#9aa6c0}
        .warn{background:rgba(255,91,110,.1);border:1px solid rgba(255,91,110,.35);border-radius:10px;padding:8px 12px 8px 30px}
        .warn li{font-weight:700;color:#ff5b6e}
        .imp .chk{color:#9aa6c0;font-style:italic}
        code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;background:#0e121c;border:1px solid #222a3a;color:#e8ecf6;padding:1px 6px;border-radius:6px}
        .row{display:flex;gap:10px;flex-wrap:wrap}
        button{font:inherit;font-weight:600;padding:10px 18px;border-radius:10px;border:1px solid transparent;cursor:pointer}
        button:focus-visible{outline:2px solid #5b8cff;outline-offset:2px}
        .rej{background:#5b8cff;color:#0b1020}
        .rej:hover{background:#7aa0ff}
        .ok{background:transparent;color:#ff9aa6;border-color:#4a2a33}
        .ok:hover{background:rgba(255,91,110,.12);border-color:#ff5b6e}
        .host{font-size:12px;color:#9aa6c0;margin-top:12px;word-break:break-all}
      </style>
      <div class="bg" role="dialog" aria-modal="true" aria-labelledby="w3pg-t">
        <div class="card">
          <h1 id="w3pg-t">${esc(t("gate_title"))}</h1>
          <div class="sub">${esc(t("gate_sub", [String(d.score ?? "")]))}</div>
          <ul id="warn" class="imp warn">${g.warn?.length ? g.warn.map((l) => `<li class="bad">${esc(l.text)}</li>`).join("") : ""}</ul>
          <ul>${rows.join("")}</ul>
          <ul id="imp" class="imp">${impactHtml(g.impact, !g.impact?.length && !!impactP)}</ul>
          <ul id="sim" class="imp">${simHtml(g.sim, !g.sim?.length && !!simP)}</ul>
          <div class="row">
            <button class="rej" id="rej">${esc(t("gate_reject"))}</button>
            <button class="ok" id="ok">${esc(t("gate_allow"))}</button>
          </div>
          <div class="host">${esc(hostLabel)}</div>
        </div>
      </div>`;
    let settled = false;
    const mount = () => (document.documentElement || document.body).appendChild(host);
    // a page that removes the dialog node gets it straight back; only the user's click settles the request.
    // (A page can still cover it with its own top layer; the request stays held until this dialog is answered.)
    const keep = new MutationObserver(() => { if (!settled && !host.isConnected) mount(); });
    keep.observe(document.documentElement, { childList: true, subtree: false });
    const done = (allow: boolean) => { settled = true; keep.disconnect(); host.remove(); resolve(allow); };
    root.getElementById("rej")!.addEventListener("click", (e) => { if (e.isTrusted) done(false); });
    root.getElementById("ok")!.addEventListener("click", (e) => { if (e.isTrusted) done(true); });
    root.addEventListener("keydown", (e) => { if (e.isTrusted && (e as KeyboardEvent).key === "Escape") done(false); });
    mount();
    if (warn && !g.warn?.length) {
      // the counterparty screen fills its rows in when it returns (addrWarnLines caps itself); a settled dialog ignores it
      warn.p.then((lines) => {
        const ul = root.getElementById("warn");
        if (ul && !settled && lines.length) { ul.innerHTML = lines.map((l) => `<li class="bad">${esc(l.text)}</li>`).join(""); warn.shown = true; }
      }, () => undefined);
    }
    if (impactP && !g.impact?.length) {
      // the placeholder is already in the dialog; fill it when the reads finish (describeImpact caps itself at 4 s)
      impactP.then((lines) => {
        const ul = root.getElementById("imp");
        if (ul && !settled) ul.innerHTML = impactHtml(lines, false);
      }, () => { const ul = root.getElementById("imp"); if (ul) ul.innerHTML = ""; });
    }
    if (simP && !g.sim?.length) {
      // same pattern for the simulation (simulate() caps itself at SIM_CAP_MS); a settled dialog ignores a late result
      simP.then((lines) => {
        const ul = root.getElementById("sim");
        if (ul && !settled) ul.innerHTML = simHtml(lines, false);
      }, () => { const ul = root.getElementById("sim"); if (ul && !settled) ul.innerHTML = simHtml(simLines(undefined), false); });
    }
    setTimeout(() => (root.getElementById("rej") as HTMLButtonElement | null)?.focus(), 0);
  });
}
