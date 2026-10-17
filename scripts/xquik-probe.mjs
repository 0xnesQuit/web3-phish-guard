// Probe Xquik with the key from the XQUIK_KEY env var (never written to disk).
// Usage: XQUIK_KEY=xq_... node scripts/xquik-probe.mjs axisrobotics yieldfields
const key = process.env.XQUIK_KEY;
if (!key) throw new Error("XQUIK_KEY env var missing");
const BASE = "https://xquik.com/api/v1";
const h = { "x-api-key": key, accept: "application/json" };

for (const token of process.argv.slice(2)) {
  const r = await fetch(`${BASE}/x/users/search?q=${encodeURIComponent(token)}&pageSize=20&hasWebsite=true&minFollowers=200`, { headers: h });
  console.log(`\n== ${token} -> ${r.status} credits-left=${r.headers.get("x-xquik-credits-remaining") ?? r.headers.get("x-credits-remaining") ?? "?"}`);
  if (!r.ok) { console.log(await r.text()); continue; }
  const j = await r.json();
  for (const u of j.users ?? []) {
    console.log(`  @${u.username.padEnd(20)} ${String(u.followers ?? 0).padStart(9)}  ${u.verifiedType ?? (u.isBlueVerified ? "blue" : "-")}  ${u.createdAt?.slice(0, 10) ?? "-"}  ${u.url ?? ""}  links=${(u.contactInfo?.links ?? []).map((l) => l.url).join(",")}`);
  }
}
