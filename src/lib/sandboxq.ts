/**
 * Sandbox queue client: install id, queue/poll/cancel calls and the persisted pending-job store.
 * Shared by the popup (live polling while open) and the background (alarm polling while closed);
 * it only uses fetch + chrome.storage, which exist in both contexts.
 */
import type { SandboxReport } from "./types";
import { API_BASE } from "./deepscan";

export interface PendingJob { url: string; host: string; enqueuedAt: number; lastState: string; eta?: number; tabTitle?: string }
export interface DoneJob { url: string; host: string; at: number; report: SandboxReport }

export type QueueResp =
  | { state: "cache_hit" | "blocklist"; report: SandboxReport }
  | { state: "queued"; jobId: string; position?: number; etaSeconds?: number; nextPollMs?: number }
  | { state: "running"; jobId: string; nextPollMs?: number }
  | { state: "done"; jobId: string; report: SandboxReport }
  | { state: "queue_full"; reason?: string; retryAfter?: number }
  | { state: "error"; error: string };

export type JobResp =
  | { state: "queued"; position?: number; etaSeconds?: number; nextPollMs?: number }
  | { state: "running"; nextPollMs?: number }
  | { state: "done"; report: SandboxReport }
  | { state: "expired" }
  | { state: "error"; error: string };

export const SBX_DONE_TTL = 10 * 60_000;
export const SBX_JOB_MAX_AGE = 30 * 60_000;
export const SBX_ALARM = "sbxPoll";

let cachedId: string | undefined;
/** Random per-install id (a-f0-9, 24 chars), created on first use. Sent only to the sandbox queue routes. */
export async function getInstallId(): Promise<string> {
  if (cachedId) return cachedId;
  try {
    const got = (await chrome.storage.local.get("installId")).installId;
    if (typeof got === "string" && /^[A-Za-z0-9-]{8,64}$/.test(got)) return (cachedId = got);
  } catch { /* storage unavailable: fall through to an in-memory id */ }
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 24);
  cachedId = id;
  try { await chrome.storage.local.set({ installId: id }); } catch { /* keep the in-memory id */ }
  return id;
}

async function call<T>(path: string, init: RequestInit, timeoutMs = 15_000): Promise<{ status: number; body: T } | { error: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${API_BASE}${path}`, { ...init, signal: ctrl.signal, credentials: "omit" });
    clearTimeout(timer);
    const body = (await res.json().catch(() => ({}))) as T;
    return { status: res.status, body };
  } catch {
    clearTimeout(timer);
    return { error: "unreachable" };
  }
}

const strip = (u: string) => u.replace(/[?#].*$/, "");

export async function queueSandbox(url: string, force = false): Promise<QueueResp> {
  const installId = await getInstallId();
  const r = await call<Record<string, unknown>>("/v1/sandbox/queue", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: strip(url), installId, ...(force ? { force: true } : {}) }) });
  if ("error" in r) return { state: "error", error: r.error };
  if (typeof r.body.state !== "string") return { state: "error", error: `http_${r.status}` };
  return r.body as unknown as QueueResp;
}

export async function pollJob(jobId: string): Promise<JobResp> {
  const installId = await getInstallId();
  const r = await call<Record<string, unknown>>(`/v1/sandbox/job?id=${encodeURIComponent(jobId)}&installId=${encodeURIComponent(installId)}`, { method: "GET" });
  if ("error" in r) return { state: "error", error: r.error };
  if (typeof r.body.state !== "string") return { state: "error", error: `http_${r.status}` };
  return r.body as unknown as JobResp;
}

export async function cancelJob(jobId: string): Promise<{ ok: boolean }> {
  const installId = await getInstallId();
  const r = await call<{ ok?: boolean }>("/v1/sandbox/job/cancel", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jobId, installId }) });
  return { ok: !("error" in r) && r.body.ok === true };
}

/** Normalise a server report into the popup's SandboxReport shape. */
export function asReport(raw: unknown, state: string): SandboxReport {
  const r = (raw && typeof raw === "object" ? raw : {}) as Partial<SandboxReport>;
  return { ...r, ok: r.ok !== false && typeof r.score === "number", score: typeof r.score === "number" ? r.score : 0, verdict: r.verdict ?? "unknown", flags: r.flags ?? [], findings: r.findings ?? [], state };
}

// ---- persisted pending jobs / finished reports (survive popup close and service-worker death) ----
export async function getJobs(): Promise<Record<string, PendingJob>> {
  try { return ((await chrome.storage.local.get("sbxJobs")).sbxJobs as Record<string, PendingJob> | undefined) ?? {}; } catch { return {}; }
}
export async function setJobs(jobs: Record<string, PendingJob>): Promise<void> {
  try {
    await chrome.storage.local.set({ sbxJobs: jobs });
    if (Object.keys(jobs).length) await ensureSbxAlarm(); else await chrome.alarms.clear(SBX_ALARM);
  } catch { /* extension context invalidated */ }
}
export async function addJob(jobId: string, job: PendingJob): Promise<void> {
  const jobs = await getJobs();
  jobs[jobId] = job;
  await setJobs(jobs);
}
export async function removeJob(jobId: string): Promise<void> {
  const jobs = await getJobs();
  if (!(jobId in jobs)) return;
  delete jobs[jobId];
  await setJobs(jobs);
}
export async function ensureSbxAlarm(): Promise<void> {
  try {
    if (!(await chrome.alarms.get(SBX_ALARM))) chrome.alarms.create(SBX_ALARM, { periodInMinutes: 1, delayInMinutes: 1 }); // 1 min is the minimum on released extensions
  } catch { /* ignore */ }
}
export async function getDone(): Promise<Record<string, DoneJob>> {
  try {
    const all = ((await chrome.storage.local.get("sbxDone")).sbxDone as Record<string, DoneJob> | undefined) ?? {};
    const now = Date.now();
    return Object.fromEntries(Object.entries(all).filter(([, d]) => now - d.at < SBX_DONE_TTL));
  } catch { return {}; }
}
export async function putDone(jobId: string, d: DoneJob): Promise<void> {
  try {
    const all = await getDone();
    all[jobId] = d;
    await chrome.storage.local.set({ sbxDone: all });
  } catch { /* ignore */ }
}
export const sameUrl = (a: string, b: string) => strip(a) === strip(b);

/** Background alarm path: poll every pending job once; notify and store finished ones. */
export async function pollPendingJobs(onDone: (jobId: string, job: PendingJob, report: SandboxReport) => Promise<void>): Promise<void> {
  const jobs = await getJobs();
  const ids = Object.keys(jobs);
  if (!ids.length) { await chrome.alarms.clear(SBX_ALARM).catch(() => undefined); return; }
  const now = Date.now();
  for (const id of ids) {
    const job = jobs[id];
    if (now - job.enqueuedAt > SBX_JOB_MAX_AGE) { delete jobs[id]; continue; }
    const r = await pollJob(id);
    if (r.state === "done") {
      const report = asReport(r.report, "queued_done");
      delete jobs[id];
      await putDone(id, { url: job.url, host: job.host, at: Date.now(), report });
      await onDone(id, job, report).catch(() => undefined);
    } else if (r.state === "expired") {
      delete jobs[id];
    } else if (r.state === "queued" || r.state === "running") {
      jobs[id] = { ...job, lastState: r.state, eta: r.state === "queued" ? r.etaSeconds : undefined };
    }
  }
  await setJobs(jobs);
}
