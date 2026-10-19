/**
 * Durable Object holding everything that must change atomically: rate-limit counters, scan cooldowns, the
 * community blocklist and the moderation queue. A Durable Object runs single-threaded per instance and its storage
 * is transactional, so two concurrent scans cannot both pass a budget check and two moderators cannot overwrite
 * each other's decision. KV remains the cache and bulk store (reports, verdict cache, RDAP, X lookups).
 */
import { DurableObject } from "cloudflare:workers";

export interface CommunityList { updatedAt: number; domains: string[]; auto: string[]; v?: number }
interface Counter { n: number; exp: number }

const DAY = 86_400_000;
const JOB_LEASE = 45_000, JOB_QUEUED_TTL = 120_000, JOB_DONE_TTL = 90_000;

export interface QCfg { max: number; concurrency: number; avgSec: number; throughput: number; installConc: number }
interface SbxJob {
  jobId: string; url: string; host: string; enqueuedAt: number; state: "queued" | "running" | "done";
  refcount: number; interestedInstalls: string[]; leaseExpiry?: number; result?: Record<string, unknown>; doneAt?: number;
}

export class W3pgState extends DurableObject {
  /** Atomic check-and-increment: true when the key had fewer than `limit` hits; the bucket expires after ttlSec. */
  /** Sandbox stats: plain names are top-level counters, `day:<x>` -> days[x], `backend:<x>` -> backends[x]. Single-threaded DO, so race-free. */
  async bumpStats(fields: string[]): Promise<void> {
    const s = (await this.ctx.storage.get<Record<string, any>>("stat:sbx")) ?? {};
    const days: Record<string, number> = s.days ?? {}, backends: Record<string, number> = s.backends ?? {};
    for (const f of fields) {
      if (f.startsWith("day:")) { const k = f.slice(4); days[k] = (days[k] ?? 0) + 1; }
      else if (f.startsWith("backend:")) { const k = f.slice(8); backends[k] = (backends[k] ?? 0) + 1; }
      else s[f] = (Number(s[f]) || 0) + 1;
    }
    s.days = Object.fromEntries(Object.entries(days).sort(([a], [b]) => (a < b ? -1 : 1)).slice(-31));
    s.backends = Object.fromEntries(Object.entries(backends).sort(([, a], [, b]) => b - a).slice(0, 20));
    await this.ctx.storage.put("stat:sbx", s);
  }
  /** Recent sandbox requests: last 50, host only. */
  async logEvent(entry: Record<string, unknown>): Promise<void> {
    const l = (await this.ctx.storage.get<Record<string, unknown>[]>("log:sbx")) ?? [];
    l.push(entry);
    await this.ctx.storage.put("log:sbx", l.slice(-50));
  }
  async getLog(): Promise<Record<string, unknown>[]> {
    return ((await this.ctx.storage.get<Record<string, unknown>[]>("log:sbx")) ?? []).slice().reverse();
  }
  async getStats(): Promise<Record<string, unknown>> {
    return (await this.ctx.storage.get<Record<string, unknown>>("stat:sbx")) ?? {};
  }

  async incr(key: string, limit: number, ttlSec: number): Promise<boolean> {
    const now = Date.now();
    const cur = (await this.ctx.storage.get<Counter>(`c:${key}`)) ?? { n: 0, exp: now + ttlSec * 1000 };
    if (cur.exp <= now) { cur.n = 0; cur.exp = now + ttlSec * 1000; }
    if (cur.n >= limit) return false;
    cur.n++;
    await this.ctx.storage.put(`c:${key}`, cur);
    await this.ensureAlarm();
    return true;
  }

  /** Scan admission in one transaction: per-caller day budget, per-caller-per-host cooldown, per-host and global day budgets. */
  async admitScan(p: { ip: string; host: string; ipLimit: number; hostLimit: number; globalLimit: number; cooldownSec: number }): Promise<{ ok: true } | { ok: false; error: string }> {
    const now = Date.now();
    const cd = await this.ctx.storage.get<number>(`cd:${p.ip}:${p.host}`);
    if (cd && cd > now) return { ok: false, error: "host_cooldown" };
    // peek every budget first so a refused request consumes nothing
    const day = Math.floor(now / DAY);
    const keys = [`scan:${p.ip}`, `scan:host:${p.host}`, "scan:global"].map((k) => `c:${day}:${k}`);
    const limits = [p.ipLimit, p.hostLimit, p.globalLimit];
    const errors = ["rate_limited", "host_capacity_reached", "daily_capacity_reached"];
    const vals = await this.ctx.storage.get<Counter>(keys);
    for (let i = 0; i < keys.length; i++) {
      const c = vals.get(keys[i]);
      if (c && c.exp > now && c.n >= limits[i]) return { ok: false, error: errors[i] };
    }
    const puts: Record<string, unknown> = {};
    for (let i = 0; i < keys.length; i++) {
      const c = vals.get(keys[i]);
      puts[keys[i]] = c && c.exp > now ? { n: c.n + 1, exp: c.exp } : { n: 1, exp: (day + 2) * DAY };
    }
    puts[`cd:${p.ip}:${p.host}`] = now + p.cooldownSec * 1000;
    await this.ctx.storage.put(puts);
    await this.ensureAlarm();
    return { ok: true };
  }

  // ---- single-flight lock for sandbox scans: the DO is single-threaded, so exactly one caller becomes leader ----
  /** Leader if no live scan holds `key`; the marker self-expires (ttlSec) so a crashed leader cannot wedge the key. */
  async beginScan(key: string, ttlSec = 60): Promise<{ leader: boolean }> {
    const now = Date.now();
    const exp = await this.ctx.storage.get<number>(`sf:${key}`);
    if (exp && exp > now) return { leader: false };
    await this.ctx.storage.put(`sf:${key}`, now + ttlSec * 1000);
    await this.ensureAlarm();
    return { leader: true };
  }
  async endScan(key: string): Promise<void> {
    await this.ctx.storage.delete(`sf:${key}`);
  }

  // ---- community list (versioned so a stale read cannot overwrite a newer decision) ----
  async getList(): Promise<CommunityList | null> {
    return (await this.ctx.storage.get<CommunityList>("list")) ?? null;
  }
  /** Replace the list if the caller saw the current version; returns the stored list either way. */
  async setList(list: CommunityList, expectV: number): Promise<{ ok: boolean; list: CommunityList }> {
    const cur = (await this.ctx.storage.get<CommunityList>("list")) ?? { updatedAt: 0, domains: [], auto: [], v: 0 };
    if ((cur.v ?? 0) !== expectV) return { ok: false, list: cur };
    const next: CommunityList = { updatedAt: list.updatedAt, domains: [...new Set(list.domains)], auto: [...new Set(list.auto)], v: expectV + 1 };
    await this.ctx.storage.put("list", next);
    return { ok: true, list: next };
  }

  // ---- moderation queue (ids, newest first) ----
  async queuePush(id: string, max = 2000): Promise<void> {
    const idx = (await this.ctx.storage.get<string[]>("queue")) ?? [];
    idx.unshift(id);
    if (idx.length > max) idx.length = max; // the oldest waiting report gives way (it stays readable by id)
    await this.ctx.storage.put("queue", idx);
  }
  async queueRemove(id: string): Promise<void> {
    const idx = (await this.ctx.storage.get<string[]>("queue")) ?? [];
    await this.ctx.storage.put("queue", idx.filter((x) => x !== id));
  }
  async queueList(): Promise<string[]> {
    return (await this.ctx.storage.get<string[]>("queue")) ?? [];
  }
  async queueSeed(ids: string[]): Promise<void> {
    if (!(await this.ctx.storage.get("queue"))) await this.ctx.storage.put("queue", ids);
  }

  // ---- verdict store for /v1/sandbox: the authoritative, cross-colo-consistent copy (the Cache API is per-colo, only a fast secondary) ----
  // One DO instance is plenty at this scale (a few hundred scans/day); shard by key prefix if it ever is not.
  private async vk(prefix: string, k: string): Promise<string> {
    const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(k)); // DO keys are length-limited
    return prefix + [...new Uint8Array(h)].slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async putVerdict(urlKey: string, report: Record<string, unknown>, ttlSec: number): Promise<void> {
    if (ttlSec > 0) { await this.ctx.storage.put(await this.vk("v:", urlKey), { exp: Date.now() + ttlSec * 1000, d: report }); await this.ensureAlarm(); }
  }
  async getVerdict(urlKey: string): Promise<Record<string, unknown> | null> {
    const e = await this.ctx.storage.get<{ exp: number; d: Record<string, unknown> }>(await this.vk("v:", urlKey));
    return e && e.exp > Date.now() ? e.d : null;
  }
  async putHostVerdict(host: string, data: Record<string, unknown>, ttlSec: number): Promise<void> {
    if (ttlSec > 0) { await this.ctx.storage.put(await this.vk("hv:", host), { exp: Date.now() + ttlSec * 1000, d: data }); await this.ensureAlarm(); }
  }
  async getHostVerdict(host: string): Promise<Record<string, unknown> | null> {
    const e = await this.ctx.storage.get<{ exp: number; d: Record<string, unknown> }>(await this.vk("hv:", host));
    return e && e.exp > Date.now() ? e.d : null;
  }

  // ---- sandbox job queue ("Queue it"): FIFO in one storage key (<= 36 small records). No dedicated worker: a request that
  // touches the queue (enqueue / poll) gets a `dispatch` directive when a slot is free and runs the scan inline in the Worker;
  // the alarm (every 5s while non-empty) only re-queues expired leases and reaps, the next request then re-dispatches. ----
  private async jobsGet(): Promise<SbxJob[]> { return (await this.ctx.storage.get<SbxJob[]>("jobs")) ?? []; }
  /** Reap expired jobs/leases in place; true when anything changed. */
  private reap(jobs: SbxJob[], now: number): boolean {
    let ch = false;
    for (let i = jobs.length - 1; i >= 0; i--) {
      const j = jobs[i];
      if (j.state === "running" && (j.leaseExpiry ?? 0) <= now) { j.state = "queued"; j.leaseExpiry = undefined; ch = true; } // crashed leader: content-addressed, a re-run is safe
      if ((j.state === "queued" && now - j.enqueuedAt > JOB_QUEUED_TTL) || (j.state === "done" && now - (j.doneAt ?? 0) > JOB_DONE_TTL)) { jobs.splice(i, 1); ch = true; }
    }
    return ch;
  }
  /** Lease the next queued job if a slot is free. */
  private lease(jobs: SbxJob[], now: number, concurrency: number): { jobId: string; url: string } | undefined {
    if (jobs.filter((j) => j.state === "running").length >= concurrency) return undefined;
    const j = jobs.find((x) => x.state === "queued");
    if (!j) return undefined;
    j.state = "running"; j.leaseExpiry = now + JOB_LEASE;
    return { jobId: j.jobId, url: j.url };
  }
  private view(jobs: SbxJob[], j: SbxJob, c: QCfg): Record<string, unknown> {
    if (j.state === "done") return { state: "done", report: j.result };
    if (j.state === "running") return { state: "running", nextPollMs: 2000 };
    const position = jobs.filter((x) => x.state === "queued").indexOf(j) + 1;
    return { state: "queued", position, etaSeconds: Math.ceil(position / c.concurrency) * c.avgSec, nextPollMs: 3000 };
  }
  private async save(jobs: SbxJob[]): Promise<void> {
    await this.ctx.storage.put("jobs", jobs);
    if (jobs.length) await this.qAlarm();
  }
  /** Per-install token bucket: capacity `cap`, one token back every 20s. Returns 0 when a token was taken, else seconds to wait. */
  private async take(iid: string, cap: number, now: number): Promise<number> {
    const b = (await this.ctx.storage.get<{ t: number; at: number }>(`ib:${iid}`)) ?? { t: cap, at: now };
    const t = Math.min(cap, b.t + (now - b.at) / 20_000);
    if (t < 1) { await this.ctx.storage.put(`ib:${iid}`, { t, at: now }); return Math.ceil((1 - t) * 20); }
    await this.ctx.storage.put(`ib:${iid}`, { t: t - 1, at: now });
    return 0;
  }
  async enqueueJob(p: { jobId: string; url: string; host: string; installId: string; cfg: QCfg }): Promise<Record<string, unknown>> {
    const now = Date.now(), c = p.cfg, jobs = await this.jobsGet();
    this.reap(jobs, now);
    let j = jobs.find((x) => x.jobId === p.jobId);
    if (j?.state === "done") return this.view(jobs, j, c);
    if (!j || !j.interestedInstalls.includes(p.installId)) {
      const depth = jobs.filter((x) => x.state !== "done").length;
      if (!j && depth >= Math.min(c.max, 36)) return { state: "queue_full", retryAfter: Math.ceil((depth / Math.max(1, c.throughput)) * 60) };
      const wait = await this.take(p.installId, c.installConc, now);
      if (wait) return { state: "queue_full", reason: "install_limit", retryAfter: wait };
      if (!j) { j = { jobId: p.jobId, url: p.url, host: p.host, enqueuedAt: now, state: "queued", refcount: 0, interestedInstalls: [] }; jobs.push(j); }
      j.interestedInstalls.push(p.installId); j.refcount = j.interestedInstalls.length;
    }
    const dispatch = this.lease(jobs, now, c.concurrency);
    await this.save(jobs);
    return { ...this.view(jobs, j, c), ...(dispatch ? { dispatch } : {}) };
  }
  /** Poll: also the second dispatch trigger. Unknown / reaped ids are "expired". */
  async getJob(jobId: string, cfg: QCfg, doLease = true): Promise<Record<string, unknown>> {
    const now = Date.now(), jobs = await this.jobsGet();
    const ch = this.reap(jobs, now);
    const j = jobs.find((x) => x.jobId === jobId);
    if (!j) { if (ch) await this.save(jobs); return { state: "expired" }; }
    const dispatch = doLease ? this.lease(jobs, now, cfg.concurrency) : undefined;
    if (ch || dispatch) await this.save(jobs);
    return { ...this.view(jobs, j, cfg), ...(dispatch ? { dispatch } : {}) };
  }
  /** Drop this install's interest; the job goes only if still queued and nobody else wants it. A running scan is left to finish. */
  async cancelJob(jobId: string, installId: string, cap: number): Promise<void> {
    const jobs = await this.jobsGet(), j = jobs.find((x) => x.jobId === jobId);
    if (!j || !j.interestedInstalls.includes(installId)) return;
    j.interestedInstalls = j.interestedInstalls.filter((x) => x !== installId); j.refcount = j.interestedInstalls.length;
    if (j.state === "queued") {
      const b = await this.ctx.storage.get<{ t: number; at: number }>(`ib:${installId}`);
      if (b) await this.ctx.storage.put(`ib:${installId}`, { t: Math.min(cap, b.t + 1), at: b.at }); // refund the unused slot
      if (!j.refcount) jobs.splice(jobs.indexOf(j), 1);
    }
    await this.save(jobs);
  }
  /** Leader finished (any outcome): keep the result for late pollers. Accepted even if the lease lapsed meanwhile. */
  async completeJob(jobId: string, report: Record<string, unknown>): Promise<void> {
    const jobs = await this.jobsGet(), j = jobs.find((x) => x.jobId === jobId);
    if (!j) return;
    j.state = "done"; j.result = report; j.doneAt = Date.now(); j.leaseExpiry = undefined;
    await this.save(jobs);
  }

  // ---- housekeeping: daily sweep of expired counters/cooldowns/verdicts; every 5s while the job queue is non-empty ----
  private async ensureAlarm(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + DAY);
  }
  private async qAlarm(): Promise<void> {
    const cur = await this.ctx.storage.getAlarm(), at = Date.now() + 5000;
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }
  async alarm(): Promise<void> {
    const now = Date.now();
    let hk = (await this.ctx.storage.get<number>("hk")) ?? 0;
    if (hk <= now) {
      const all = await this.ctx.storage.list<unknown>();
      const drop: string[] = [];
      for (const [k, v] of all) {
        if (k.startsWith("c:") && typeof v === "object" && v && (v as Counter).exp <= now) drop.push(k);
        else if ((k.startsWith("cd:") || k.startsWith("sf:")) && typeof v === "number" && v <= now) drop.push(k);
        else if ((k.startsWith("v:") || k.startsWith("hv:")) && (v as { exp: number }).exp <= now) drop.push(k);
        else if (k.startsWith("ib:") && (v as { at: number }).at < now - 3_600_000) drop.push(k);
      }
      for (let i = 0; i < drop.length; i += 128) await this.ctx.storage.delete(drop.slice(i, i + 128));
      hk = now + DAY;
      await this.ctx.storage.put("hk", hk);
    }
    const jobs = await this.jobsGet();
    if (this.reap(jobs, now)) await this.ctx.storage.put("jobs", jobs); // expired leases back to queued; the next poll re-dispatches
    await this.ctx.storage.setAlarm(jobs.length ? Math.min(hk, now + 5000) : hk);
  }
}
