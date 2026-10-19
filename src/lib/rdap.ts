/**
 * Domain age via RDAP. Uses the IANA bootstrap file (data.iana.org/rdap/dns.json)
 * to find the authoritative registry server per TLD, then queries it directly.
 * rdap.org is only a fallback (it returned 403 to non-browser clients in testing).
 *
 * Only called for domains the local heuristics already consider suspicious, so a
 * user's ordinary browsing never leaves the machine. Only the registrable domain is
 * sent, never the full URL.
 */

interface AgeCache {
  registeredAt?: number; // ms epoch
  checkedAt: number;
  failed?: boolean;
}
interface Bootstrap {
  services: Array<[string[], string[]]>;
  fetchedAt: number;
}

const OK_TTL = 7 * 24 * 3600 * 1000;
const FAIL_TTL = 6 * 3600 * 1000;
const BOOT_TTL = 7 * 24 * 3600 * 1000;
const MIN_INTERVAL = 600;
let lastCall = 0;
let bootMem: Bootstrap | null = null;

/**
 * One registry call at a time, spaced MIN_INTERVAL apart. The page the user actually opened (priority) jumps ahead
 * of the X timeline badges, so a busy feed never delays the verdict for the current navigation.
 */
interface Job { run: () => Promise<unknown>; priority: boolean }
const jobs: Job[] = [];
let draining = false;
async function drain(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    while (jobs.length) {
      const i = jobs.findIndex((j) => j.priority);
      const job = jobs.splice(i >= 0 ? i : 0, 1)[0];
      const wait = lastCall + MIN_INTERVAL - Date.now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      lastCall = Date.now();
      try { await job.run(); } catch { /* reported through the job's own promise */ }
    }
  } finally { draining = false; }
}
function queued<T>(fn: () => Promise<T>, priority: boolean): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    jobs.push({ priority, run: () => fn().then(resolve, reject) });
    void drain();
  });
}

export async function domainAgeDays(registrable: string, opts: { priority?: boolean } = {}): Promise<number | undefined> {
  const key = `rdap:${registrable}`;
  const cached = (await chrome.storage.local.get(key))[key] as AgeCache | undefined;
  const now = Date.now();
  if (cached) {
    if (cached.registeredAt && now - cached.checkedAt < OK_TTL) return (now - cached.registeredAt) / 86400000;
    if (cached.failed && now - cached.checkedAt < FAIL_TTL) return undefined;
  }
  const registeredAt = await queued(() => fetchRegistration(registrable), opts.priority !== false);
  await chrome.storage.local.set({ [key]: { registeredAt, checkedAt: now, failed: registeredAt === undefined } satisfies AgeCache });
  return registeredAt ? (now - registeredAt) / 86400000 : undefined;
}

async function bootstrap(): Promise<Bootstrap | null> {
  if (bootMem && Date.now() - bootMem.fetchedAt < BOOT_TTL) return bootMem;
  const stored = (await chrome.storage.local.get("rdap:bootstrap"))["rdap:bootstrap"] as Bootstrap | undefined;
  if (stored && Date.now() - stored.fetchedAt < BOOT_TTL) return (bootMem = stored);
  try {
    const res = await fetchWithTimeout("https://data.iana.org/rdap/dns.json", 8000);
    if (!res.ok) return stored ?? null;
    const json = (await res.json()) as { services: Array<[string[], string[]]> };
    bootMem = { services: json.services, fetchedAt: Date.now() };
    await chrome.storage.local.set({ "rdap:bootstrap": bootMem });
    return bootMem;
  } catch {
    return stored ?? null;
  }
}

export function serverForTld(boot: Bootstrap | null, tld: string): string | null {
  if (!boot) return null;
  for (const [tlds, urls] of boot.services) {
    if (tlds.includes(tld)) {
      const u = urls.find((x) => x.startsWith("https://")) ?? urls[0];
      return u ? u.replace(/\/?$/, "/") : null;
    }
  }
  return null;
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { headers: { accept: "application/rdap+json, application/json" }, redirect: "follow", signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function fetchRegistration(registrable: string): Promise<number | undefined> {
  const tld = registrable.split(".").pop() ?? "";
  const boot = await bootstrap();
  const base = serverForTld(boot, tld);
  const candidates = [base ? `${base}domain/${registrable}` : null, `https://rdap.org/domain/${encodeURIComponent(registrable)}`].filter(Boolean) as string[];
  for (const url of candidates) {
    try {
      const res = await fetchWithTimeout(url, 8000);
      if (!res.ok) continue;
      if (!(res.headers.get("content-type") ?? "").includes("json")) continue;
      const ms = parseRegistration((await res.json()) as RdapDoc);
      if (ms !== undefined) return ms;
    } catch {
      /* try next */
    }
  }
  return undefined;
}

type RdapDoc = { events?: Array<{ eventAction?: string; eventDate?: string }> };

export function parseRegistration(json: RdapDoc): number | undefined {
  const ev = json.events?.find((e) => e.eventAction === "registration");
  if (!ev?.eventDate) return undefined;
  const ms = Date.parse(ev.eventDate);
  return Number.isFinite(ms) ? ms : undefined;
}
