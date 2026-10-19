/**
 * The ~50k most visited registrable domains (Tranco), used as a popularity guard: a single feed entry or a heuristic
 * score never blocks one of these outright. Output: data/top-sites.json { updatedAt, hosts }.
 *   node scripts/build-top-sites.mjs [count]
 */
import { writeFileSync } from "node:fs";

const count = Number(process.argv[2] || 50_000);
const id = (await (await fetch("https://tranco-list.eu/top-1m-id")).text()).trim();
if (!/^[A-Z0-9]{4,8}$/.test(id)) { console.error("unexpected Tranco list id", id); process.exit(1); }
const csv = await (await fetch(`https://tranco-list.eu/download/${id}/${count}`)).text();
const hosts = csv.split("\n").map((l) => l.split(",")[1]?.trim().toLowerCase()).filter((h) => h && /^[a-z0-9.-]+\.[a-z0-9-]+$/.test(h));
if (hosts.length < count * 0.9) { console.error(`only ${hosts.length} hosts parsed`); process.exit(1); }
writeFileSync("data/top-sites.json", JSON.stringify({ updatedAt: Date.now(), source: `tranco ${id}`, hosts }));
console.log(`top-sites: ${hosts.length} hosts (tranco ${id})`);
