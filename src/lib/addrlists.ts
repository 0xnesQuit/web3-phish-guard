// Offline copy of the OFAC sanctioned and MyEtherWallet darklist address lists (both MIT, public raw files, about 835 addresses).
// The gate checks the counterparty against these with a storage read plus Set lookups, never a network call. The only network is
// the periodic background fetch. Every failure keeps the last cached set (fail open).
const OFAC_URL = "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json";
const MEW_DARKLIST_URL = "https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json";

export const ADDR_LIST_TTL_MS = 24 * 60 * 60 * 1000;
export const ADDR_LIST_REFRESH_MINUTES = 60 * 24;

const ADDR_RE = /^0x[0-9a-f]{40}$/;

interface AddrFeed { name: "ofac" | "mew"; url: string; flag: string; pick: (item: unknown) => unknown }
const FEEDS: AddrFeed[] = [
  { name: "ofac", url: OFAC_URL, flag: "sanctioned", pick: (x) => x },
  { name: "mew", url: MEW_DARKLIST_URL, flag: "phishing_activities", pick: (x) => (x && typeof x === "object" ? (x as { address?: unknown }).address : undefined) },
];

interface StoredAddrList { addrs: string[]; at: number }
const mem = new Map<string, { set: Set<string>; at: number }>();

/** Parse a raw feed JSON into lowercase, validated addresses; [] on any other shape. */
export function parseAddrFeed(raw: unknown, pick: (item: unknown) => unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out = new Set<string>();
  for (const item of raw) {
    const a = pick(item);
    if (typeof a !== "string") continue;
    const l = a.toLowerCase();
    if (ADDR_RE.test(l)) out.add(l);
  }
  return [...out];
}

async function readStored(name: string): Promise<StoredAddrList | undefined> {
  const key = `addrlist:${name}`;
  try {
    const v = (await chrome.storage.local.get(key))[key] as StoredAddrList | undefined;
    return v && Array.isArray(v.addrs) ? v : undefined;
  } catch { return undefined; }
}

async function loadSet(name: string): Promise<Set<string>> {
  const m = mem.get(name);
  if (m) return m.set;
  const s = await readStored(name);
  const set = new Set(s?.addrs ?? []);
  if (s) mem.set(name, { set, at: s.at });
  return set;
}

/** Fetch both feeds now. A failed or empty fetch keeps the previous cached set. Never throws. */
export async function refreshAddrLists(): Promise<void> {
  for (const f of FEEDS) {
    try {
      const res = await fetch(f.url, { signal: AbortSignal.timeout(10_000), credentials: "omit" });
      if (!res.ok) continue;
      const addrs = parseAddrFeed(await res.json(), f.pick);
      if (addrs.length === 0) continue;
      const at = Date.now();
      await chrome.storage.local.set({ [`addrlist:${f.name}`]: { addrs, at } satisfies StoredAddrList });
      mem.set(f.name, { set: new Set(addrs), at });
    } catch { /* keep the last cached set */ }
  }
}

/** Refresh only when a set is missing or older than the TTL (used at startup so the offline list fills without waiting for the alarm). */
export async function refreshAddrListsIfStale(): Promise<void> {
  try {
    const now = Date.now();
    for (const f of FEEDS) {
      const s = await readStored(f.name);
      if (!s || now - s.at > ADDR_LIST_TTL_MS) { await refreshAddrLists(); return; }
    }
  } catch { /* ignore */ }
}

/** Offline flags for a lowercase address: "sanctioned" (OFAC), "phishing_activities" (MEW darklist); [] on a miss or nothing cached. Never throws, no network. */
export async function localAddrFlags(address: string): Promise<string[]> {
  try {
    const a = address.toLowerCase();
    if (!ADDR_RE.test(a)) return [];
    const flags: string[] = [];
    for (const f of FEEDS) if ((await loadSet(f.name)).has(a)) flags.push(f.flag);
    return flags;
  } catch { return []; }
}

export function resetAddrListsForTests(): void { mem.clear(); }
