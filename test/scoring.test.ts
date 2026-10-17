import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { parseHost, tokenize, levenshtein } from "../src/lib/hostname";
import { score, BLOCK_THRESHOLD, WARN_THRESHOLD } from "../src/lib/scoring";
import { extractDomains, normalizeDomain, parentDomains } from "../src/lib/blocklist";
import { parseRegistration } from "../src/lib/rdap";
import { mergeBrands } from "../src/lib/lists";
import type { Brand, SignalLists } from "../src/lib/types";

const brands = JSON.parse(readFileSync("data/brands.seed.json", "utf8")) as Brand[];
const actions = JSON.parse(readFileSync("data/action-words.json", "utf8"));
const hosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const tlds = JSON.parse(readFileSync("data/tlds.json", "utf8"));
const lists: SignalLists = {
  actionStrong: actions.strong, actionMedium: actions.medium,
  freeHostsStrong: hosts.strong, freeHostsWeak: hosts.weak,
  tldStrong: tlds.strong, tldWeak: tlds.weak,
};
const freeHosts = [...hosts.strong, ...hosts.weak];

function run(url: string, extra: Partial<Parameters<typeof score>[2]> = {}) {
  const p = parseHost(url, freeHosts)!;
  return score(url, p, { brands, lists, ...extra });
}

describe("parseHost", () => {
  it("splits registrable domain and sub labels", () => {
    const p = parseHost("https://claims.eigenfoundation.org/x", freeHosts)!;
    expect(p.registrable).toBe("eigenfoundation.org");
    expect(p.subLabels).toEqual(["claims"]);
    expect(p.domainLabel).toBe("eigenfoundation");
    expect(p.tld).toBe("org");
  });
  it("treats free hosts as the suffix", () => {
    const p = parseHost("https://pancakeswapclaim6754.vercel.app/", freeHosts)!;
    expect(p.freeHost).toBe("vercel.app");
    expect(p.registrable).toBe("pancakeswapclaim6754.vercel.app");
    expect(p.domainLabel).toBe("pancakeswapclaim6754");
  });
  it("handles multi-part public suffixes", () => {
    const p = parseHost("https://foo.bar.co.uk", freeHosts)!;
    expect(p.registrable).toBe("bar.co.uk");
    expect(p.tld).toBe("co.uk");
  });
  it("tokenizes hyphens and digit boundaries", () => {
    expect(tokenize(["rewards-axisrobotics"])).toEqual(["rewards", "axisrobotics"]);
    expect(tokenize(["pancakeswapclaim6754"])).toEqual(["pancakeswapclaim"]);
    expect(tokenize(["claim", "arb2"])).toEqual(["claim", "arb"]);
  });
  it("levenshtein", () => {
    expect(levenshtein("uniswap", "unlswap")).toBe(1);
    expect(levenshtein("metamask", "metamsk")).toBe(1);
    expect(levenshtein("abc", "xyz")).toBe(3);
  });
});

describe("scam examples", () => {
  it("rewards-axisrobotics.xyz is at least a warning without age, blocked with fresh age", () => {
    const v = run("https://rewards-axisrobotics.xyz/");
    expect(v.band).toBe("warn");
    expect(v.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["action-strong", "brand-unverified", "tld-weak"]));
    expect(v.needsAgeCheck).toBe(true);
    const v2 = run("https://rewards-axisrobotics.xyz/", { ageDays: 3 });
    expect(v2.band).toBe("block");
  });
  it("checker-axisrobotics.live", () => {
    expect(run("https://checker-axisrobotics.live/").band).toBe("warn");
    expect(run("https://checker-axisrobotics.live/", { ageDays: 10 }).band).toBe("block");
  });
  it("known brand + action on free host is blocked outright", () => {
    const v = run("https://pancakeswapclaim6754.vercel.app/");
    expect(v.band).toBe("block");
    expect(v.brand).toBe("PancakeSwap");
  });
  it("claim-zama.pages.dev is blocked", () => {
    expect(run("https://claim-zama.pages.dev/").band).toBe("block");
  });
  it("brand impersonation on a plain .com warns", () => {
    const v = run("https://uniswap-rewards.com/");
    expect(v.band).toBe("warn");
    expect(v.signals.some((s) => s.id === "brand-impersonation")).toBe(true);
  });
  it("users-ethena.xyz warns even though ethena.fi is a .fi brand", () => {
    const v = run("https://users-ethena.xyz/");
    expect(v.score).toBeGreaterThanOrEqual(WARN_THRESHOLD);
  });
  it("typosquat is caught", () => {
    const v = run("https://metamsk-wallet.io/");
    expect(v.signals.some((s) => s.id === "brand-typo")).toBe(true);
  });
  it("blocklist hit is always a block", () => {
    expect(run("https://totally-normal.com/", { blocklistHit: "metamask" }).band).toBe("block");
  });
  it("wallet provider weights push a warn into block", () => {
    const v = run("https://airdrop-claim-portal.top/");
    expect(v.score).toBeGreaterThanOrEqual(WARN_THRESHOLD);
  });
});

describe("legitimate examples must not be flagged", () => {
  const legit = [
    "https://uniswap.org/",
    "https://app.uniswap.org/swap",
    "https://claims.eigenfoundation.org/",
    "https://provisions.starknet.io/",
    "https://claim.zknation.io/",
    "https://sophon.xyz/",
    "https://ethena.fi/",
    "https://hyperliquid.xyz/",
    "https://opensea.io/collection/x",
    "https://zora.co/",
    "https://pudgypenguins.com/",
    "https://galxe.com/quest",
    "https://app.layer3.xyz/",
    "https://database.xyz/", // contains 'base' but is not Base
    "https://github.com/",
    "https://google.com/",
    "https://news.ycombinator.com/",
  ];
  for (const u of legit) {
    it(u, () => {
      const v = run(u);
      expect(v.band, `${u} -> ${JSON.stringify(v.signals)}`).toBe("none");
    });
  }
  it("brand-new legit project with a plain name only gets a weak score", () => {
    // unknown brand, no action word, .xyz, 3 days old: 5 + 25 = 30 -> below warn
    const v = run("https://newcoolproject.xyz/", { ageDays: 3 });
    expect(v.band).toBe("none");
  });
  it("old domain with an action word is not flagged", () => {
    const v = run("https://claim-your-refund-advice.com/", { ageDays: 3000 });
    expect(v.band).toBe("none");
  });
  it("user allowlist beats everything", () => {
    const v = run("https://rewards-axisrobotics.xyz/", { userAllowed: true, blocklistHit: "x" });
    expect(v.band).toBe("none");
  });
  it("MetaMask allowlist beats heuristics but not official-brand check", () => {
    expect(run("https://claim-something.xyz/", { allowlistHit: true }).band).toBe("none");
  });
});

describe("generated (DefiLlama) brands are lower confidence", () => {
  const gen: Brand[] = [
    { name: "Kamino Lend", tokens: ["kamino"], domains: ["kamino.com"] },
    { name: "Rainbow Wallet", tokens: ["rainbow"], domains: ["rainbow.me"] },
  ];
  const merged = mergeBrands(brands, gen);
  const runG = (url: string, extra: Partial<Parameters<typeof score>[2]> = {}) => score(url, parseHost(url, freeHosts)!, { brands: merged, lists, ...extra });
  it("domain drift of a generated brand is not flagged on its own", () => {
    expect(runG("https://kamino.finance/").band).toBe("none");
    expect(runG("https://rainbow-six.com/").band).toBe("none");
  });
  it("generated brand + action word still warns", () => {
    const v = runG("https://kamino-airdrop.xyz/");
    expect(v.band).toBe("warn");
    expect(v.signals.some((s) => s.id === "brand-impersonation-weak")).toBe(true);
  });
  it("generated brand + action word on free host blocks", () => {
    expect(runG("https://kamino-claim.vercel.app/").band).toBe("block");
  });
  it("seed entries keep their tier after merge", () => {
    expect(merged.find((b) => b.name === "Uniswap")?.tier).toBe("seed");
    expect(merged.find((b) => b.name === "Kamino Lend")?.tier).toBe("generated");
  });
});

describe("social origin context", () => {
  it("coming from X raises the score and forces the age check", () => {
    const plain = run("https://rewards-axisrobotics.xyz/");
    const fromX = run("https://rewards-axisrobotics.xyz/", { origin: { source: "x", at: 0 } });
    expect(fromX.score).toBeGreaterThan(plain.score);
    expect(fromX.needsAgeCheck).toBe(true);
  });
  it("poster is not the brand's official handle", () => {
    const v = run("https://uniswap-rewards.com/", { origin: { source: "x", at: 0, poster: "Uniswap_Claims", isReply: true } });
    expect(v.band).toBe("block");
    expect(v.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["poster-mismatch", "poster-reply", "origin-social"]));
  });
  it("official handle posting its own domain stays clean", () => {
    const v = run("https://app.uniswap.org/", { origin: { source: "x", at: 0, poster: "Uniswap" } });
    expect(v.band).toBe("none");
  });
  it("origin never allowlists: official poster + lookalike domain still warns", () => {
    const v = run("https://uniswap-rewards.com/", { origin: { source: "x", at: 0, poster: "Uniswap", posterVerified: true } });
    expect(v.band).not.toBe("none");
    expect(v.signals.some((s) => s.id === "poster-mismatch")).toBe(false);
  });
  it("suspicious poster name for a brand without a known handle", () => {
    const v = run("https://claim-axisrobotics.xyz/", { origin: { source: "x", at: 0, poster: "AxisRobotics_Airdrop", isReply: true } });
    expect(v.band).toBe("block");
    expect(v.signals.some((s) => s.id === "poster-name")).toBe(true);
  });
  it("ordinary site shared on X with no other signal stays silent", () => {
    expect(run("https://github.com/", { origin: { source: "x", at: 0, poster: "someone", isReply: true } }).band).toBe("none");
  });
});

describe("blocklist helpers", () => {
  it("extractDomains handles plain arrays and nested configs", () => {
    expect(extractDomains(["a.com", "https://b.com/x"], ["blocklist"])).toEqual(["a.com", "b.com"]);
    const mm = { data: { eth_phishing_detect_config: { blocklist: ["evil.xyz"], allowlist: ["good.io"] } } };
    expect(extractDomains(mm, ["blocklist"])).toEqual(["evil.xyz"]);
    expect(extractDomains(mm, ["allowlist"])).toEqual(["good.io"]);
  });
  it("normalizeDomain", () => {
    expect(normalizeDomain("*.Evil.XYZ/")).toBe("evil.xyz");
    expect(normalizeDomain("https://www.evil.xyz/path")).toBe("evil.xyz");
  });
  it("parentDomains", () => {
    expect(parentDomains("a.b.c.com")).toEqual(["a.b.c.com", "b.c.com", "c.com"]);
  });
  it("rdap registration parse", () => {
    const ms = parseRegistration({ events: [{ eventAction: "registration", eventDate: "2026-10-10T00:00:00Z" }] });
    expect(ms).toBe(Date.parse("2026-10-10T00:00:00Z"));
  });
  it("thresholds are sane", () => {
    expect(BLOCK_THRESHOLD).toBeGreaterThan(WARN_THRESHOLD);
  });
});

describe("rdap bootstrap", () => {
  it("resolves a registry server for a TLD and normalizes the trailing slash", async () => {
    const { serverForTld } = await import("../src/lib/rdap");
    const boot = { services: [[["xyz"], ["https://rdap.centralnic.com/xyz"]], [["com", "net"], ["https://rdap.verisign.com/com/v1/"]]] as Array<[string[], string[]]>, fetchedAt: 0 };
    expect(serverForTld(boot, "xyz")).toBe("https://rdap.centralnic.com/xyz/");
    expect(serverForTld(boot, "net")).toBe("https://rdap.verisign.com/com/v1/");
    expect(serverForTld(boot, "io")).toBeNull();
    expect(serverForTld(null, "com")).toBeNull();
  });
});
