import { it, expect, vi } from "vitest";
const BL = "../src/lib/blocklist";

const store: Record<string, unknown> = {};
(globalThis as any).chrome = {
  storage: { local: {
    get: async (k: string | string[] | null) => { if (k === null) return { ...store }; const ks = Array.isArray(k) ? k : [k]; const o: Record<string, unknown> = {}; for (const x of ks) if (x in store) o[x] = store[x]; return o; },
    set: async (o: Record<string, unknown>) => { Object.assign(store, JSON.parse(JSON.stringify(o, (_k, v) => (typeof v === "bigint" ? v.toString() : v)))); },
    remove: async (k: string | string[]) => { for (const x of Array.isArray(k) ? k : [k]) delete store[x]; },
  } },
};

it("an index written under another salt is rebuilt from the tail on the next warm, so hotlist additions and removals survive", async () => {
  // 1) a warm worker: salt created, MetaMask list stored with the salt
  let m = await import(BL);
  await m.warmLists(["vercel.app"], []);
  const salt = store.hsalt as string;
  m.setHashSalt(salt);
  // emulate storeSource for metamask (salted)
  store["hidx:metamask"] = m.encodeIndex(m.buildIndex(["old-drainer.xyz", "drop-onsolana.vercel.app"]));
  store["meta:metamask"] = { count: 2, updatedAt: 1, mmLastUpdated: 100 };
  store["tail:metamask"] = ["old-drainer.xyz", "drop-onsolana.vercel.app"];
  store["didx:metamask"] = { sibling: [[".vercel.app", [["onsolana", "drop-onsolana.vercel.app"]]]], attack: [] };
  // 2) the worker sleeps; an alarm wakes a fresh one: refreshMetaMaskDiffs() runs before any warmLists()
  vi.resetModules();
  m = await import(BL);
  (globalThis as any).fetch = async () => ({ ok: true, json: async () => ({ data: [{ url: "fresh-drainer.xyz", targetList: "eth_phishing_detect_config.blocklist", timestamp: 200 }, { url: "old-drainer.xyz", targetList: "eth_phishing_detect_config.blocklist", timestamp: 201, isRemoval: true }] }) });
  await m.refreshMetaMaskDiffs();
  // 3) the next real wake warms normally
  vi.resetModules();
  m = await import(BL);
  await m.warmLists(["vercel.app"], []);
  const res = {
    fresh: m.blocklistHit("fresh-drainer.xyz"),
    removedStillListed: m.blocklistHit("old-drainer.xyz"),
    old: m.blocklistHit("drop-onsolana.vercel.app"),
    sibling: m.siblingHit("drop-onsolana2.vercel.app"),
    didx: JSON.stringify(store["didx:metamask"]),
  };
  expect(res.fresh).toBe("metamask"); // the hotlist addition is found
  expect(res.removedStillListed).toBeUndefined(); // the removal was applied
  expect(res.old).toBe("metamask");
  expect(res.sibling).toBe("drop-onsolana.vercel.app");
});
