/**
 * Best-effort WalletConnect v2 "mobile wallet" for the sandbox. Pairs with a WC URI exposed by the page, approves the
 * session with the throw-away address, then records every request and rejects it with 4001 (like the injected
 * observer). Off unless WC_PROJECT_ID is set. Never throws.
 */
import type { Page } from "playwright";
import { SignClient } from "@walletconnect/sign-client";
import { buildApprovedNamespaces } from "@walletconnect/utils";

export interface WcCapture { method: string; params: unknown; atMs: number; unprompted: boolean; chainId: string }

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function findUri(page: Page): Promise<string | undefined> {
  return page.evaluate(async () => {
    const re = /wc:[0-9a-fA-F]{64}@2\?[^"'\s<>]+/;
    const pick = (s: string | null | undefined): string | undefined => {
      if (!s) return undefined;
      let m = s.match(re);
      if (m) return m[0];
      if (/wc%3A/i.test(s)) {
        try { m = decodeURIComponent(s.replace(/&amp;/g, "&")).match(re); if (m) return m[0]; } catch { /* ignore */ }
      }
      return undefined;
    };
    let r = pick(document.documentElement.outerHTML);
    if (r) return r;
    for (const a of Array.from(document.querySelectorAll('a[href^="wc:"]'))) { r = pick(a.getAttribute("href")); if (r) return r; }
    for (const el of Array.from(document.querySelectorAll("*")).slice(0, 5000)) {
      for (const at of Array.from(el.attributes)) { r = pick(at.value); if (r) return r; }
    }
    try { r = pick(await navigator.clipboard?.readText?.()); if (r) return r; } catch { /* ignore */ }
    return undefined;
  }).catch(() => undefined);
}

export async function tryWalletConnect(page: Page, address: string, chainId: string, startedAt: number, deadline: number): Promise<WcCapture[]> {
  const captured: WcCapture[] = [];
  const projectId = process.env.WC_PROJECT_ID;
  if (!projectId) return captured;
  let client: Awaited<ReturnType<typeof SignClient.init>> | undefined;
  try {
    try {
      const el = page.locator("button, a, [role=button], div").filter({ hasText: /walletconnect/i }).first();
      await el.click({ timeout: 1200, noWaitAfter: true });
    } catch { /* best effort */ }

    let uri: string | undefined;
    for (let i = 0; i < 4 && Date.now() < deadline; i++) {
      uri = await findUri(page);
      if (uri) break;
      await sleep(600);
    }
    if (!uri) return captured;

    client = await SignClient.init({
      projectId,
      relayUrl: process.env.WC_RELAY_URL || "wss://relay.walletconnect.com",
      metadata: { name: "Sandbox Observer", description: "analysis", url: "https://w3pg.sandbox", icons: [] },
    });
    const c = client;

    c.on("session_proposal", async ({ id, params }) => {
      try {
        const ns = { ...(params.requiredNamespaces ?? {}), ...(params.optionalNamespaces ?? {}) } as Record<string, { chains?: string[] }>;
        const set = new Set<string>();
        for (const k of Object.keys(params.requiredNamespaces ?? {})) if (k.startsWith("eip155:")) set.add(k);
        for (const k of Object.keys(ns)) {
          if (k === "eip155") for (const ch of ns[k].chains ?? []) set.add(ch);
          else if (k.startsWith("eip155:")) set.add(k);
        }
        const chains = set.size ? [...set] : ["eip155:1"];
        const approved = buildApprovedNamespaces({
          proposal: params,
          supportedNamespaces: {
            eip155: {
              chains,
              methods: ["eth_sendTransaction", "eth_signTransaction", "eth_sign", "personal_sign", "eth_signTypedData", "eth_signTypedData_v4", "wallet_sendCalls"],
              events: ["accountsChanged", "chainChanged"],
              accounts: chains.map((x) => `${x}:${address}`),
            },
          },
        });
        await c.approve({ id, namespaces: approved });
      } catch {
        await c.reject({ id, reason: { code: 1, message: "unsupported" } }).catch(() => undefined);
      }
    });

    c.on("session_request", async ({ id, topic, params }) => {
      const m = /^eip155:(\d+)$/.exec(params.chainId ?? "");
      captured.push({
        method: params.request.method,
        params: params.request.params,
        atMs: Date.now() - startedAt,
        unprompted: false,
        chainId: m ? "0x" + Number(m[1]).toString(16) : chainId,
      });
      await c.respond({ topic, response: { id, jsonrpc: "2.0", error: { code: 4001, message: "User rejected the request." } } }).catch(() => undefined);
    });

    await c.pair({ uri });
    const end = Math.min(deadline, Date.now() + 8000);
    while (Date.now() < end) await sleep(500);
  } catch { /* best effort: return whatever was captured */ }
  finally {
    try {
      const c = client;
      if (c) {
        for (const s of c.session.getAll()) await c.disconnect({ topic: s.topic, reason: { code: 6000, message: "done" } }).catch(() => undefined);
        c.removeAllListeners?.("session_proposal");
        c.removeAllListeners?.("session_request");
        await (c.core.relayer as unknown as { transportClose?: () => Promise<void> }).transportClose?.().catch(() => undefined);
      }
    } catch { /* never throw from cleanup */ }
  }
  return captured;
}
