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

export class W3pgState extends DurableObject {
  /** Atomic check-and-increment: true when the key had fewer than `limit` hits; the bucket expires after ttlSec. */
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

  // ---- housekeeping: drop expired counters and cooldowns once a day ----
  private async ensureAlarm(): Promise<void> {
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(Date.now() + DAY);
  }
  async alarm(): Promise<void> {
    const now = Date.now();
    const all = await this.ctx.storage.list<Counter | number>();
    const drop: string[] = [];
    for (const [k, v] of all) {
      if (k.startsWith("c:") && typeof v === "object" && v && (v as Counter).exp <= now) drop.push(k);
      else if ((k.startsWith("cd:") || k.startsWith("sf:")) && typeof v === "number" && v <= now) drop.push(k);
    }
    for (let i = 0; i < drop.length; i += 128) await this.ctx.storage.delete(drop.slice(i, i + 128));
    await this.ctx.storage.setAlarm(now + DAY);
  }
}
