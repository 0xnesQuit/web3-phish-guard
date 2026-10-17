import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { parseHost, tokenize, levenshtein } from "../src/lib/hostname";
import { score, BLOCK_THRESHOLD, WARN_THRESHOLD } from "../src/lib/scoring";
import { extractDomains, normalizeDomain, parentDomains } from "../src/lib/blocklist";
import { parseRegistration } from "../src/lib/rdap";
import { mergeBrands, flattenTrusted } from "../src/lib/lists";
import type { Brand, SignalLists } from "../src/lib/types";

const brands = JSON.parse(readFileSync("data/brands.seed.json", "utf8")) as Brand[];
const actions = JSON.parse(readFileSync("data/action-words.json", "utf8"));
const hosts = JSON.parse(readFileSync("data/free-hosts.json", "utf8"));
const tlds = JSON.parse(readFileSync("data/tlds.json", "utf8"));
const trustedJson = JSON.parse(readFileSync("data/trusted.json", "utf8"));
const lists: SignalLists = {
  trusted: flattenTrusted(trustedJson),
  actionStrong: actions.strong, actionMedium: actions.medium,
  freeHostsStrong: hosts.strong, freeHostsWeak: hosts.weak,
  tldStrong: tlds.strong, tldWeak: tlds.weak,
};
const freeHosts = [...hosts.strong, ...hosts.weak];

function run(url: string, extra: Partial<Parameters<typeof score>[2]> = {}) {
  const p = parseHost(url, freeHosts)!;
  return score(url, p, { brands, lists, ...extra });
}
/** Same seed list but Axis Robotics' official domain unknown: models a pre-token project nobody has verified yet. */
const brandsUnverified: Brand[] = brands.map((b) => (b.name === "Axis Robotics" ? { ...b, domains: [], x: "" } : b));
function runU(url: string, extra: Partial<Parameters<typeof score>[2]> = {}) {
  const p = parseHost(url, freeHosts)!;
  return score(url, p, { brands: brandsUnverified, lists, ...extra });
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
  it("rewards-axisrobotics.xyz with the official domain known: impersonation, warn -> block with age", () => {
    const v = run("https://rewards-axisrobotics.xyz/");
    expect(v.band).toBe("warn");
    expect(v.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["action-strong", "brand-impersonation"]));
    expect(v.needsAgeCheck).toBe(true);
    expect(run("https://rewards-axisrobotics.xyz/", { ageDays: 3 }).band).toBe("block");
  });
  it("rewards-axisrobotics.xyz with the official domain unknown: unverified brand, still warn -> block with age", () => {
    const v = runU("https://rewards-axisrobotics.xyz/");
    expect(v.band).toBe("warn");
    expect(v.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["action-strong", "brand-unverified"]));
    expect(v.needsAgeCheck).toBe(true);
    expect(runU("https://rewards-axisrobotics.xyz/", { ageDays: 3 }).band).toBe("block");
  });
  it("checker-axisrobotics.live", () => {
    expect(runU("https://checker-axisrobotics.live/").band).toBe("warn");
    expect(runU("https://checker-axisrobotics.live/", { ageDays: 10 }).band).toBe("block");
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
    const plain = runU("https://rewards-axisrobotics.xyz/");
    const fromX = runU("https://rewards-axisrobotics.xyz/", { origin: { source: "x", at: 0 } });
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
    const v = runU("https://claim-axisrobotics.xyz/", { origin: { source: "x", at: 0, poster: "AxisRobotics_Airdrop", isReply: true } });
    expect(v.band).toBe("block");
    expect(v.signals.some((s) => s.id === "poster-name")).toBe(true);
    // with the official handle known, the same post is a plain poster mismatch
    const w = run("https://claim-axisrobotics.xyz/", { origin: { source: "x", at: 0, poster: "AxisRobotics_Airdrop", isReply: true } });
    expect(w.signals.some((s) => s.id === "poster-mismatch")).toBe(true);
    expect(w.band).toBe("block");
  });
  it("ordinary site shared on X with no other signal stays silent", () => {
    expect(run("https://github.com/", { origin: { source: "x", at: 0, poster: "someone", isReply: true } }).band).toBe("none");
  });
});

describe("false positives reported from the field", () => {
  const gen: Brand[] = [{ name: "YieldFi", tokens: ["yieldfi"], domains: ["yield.fi"], x: "getyieldfi" }];
  const merged = mergeBrands(brands, gen);
  const runG = (url: string, extra: Partial<Parameters<typeof score>[2]> = {}) => score(url, parseHost(url, freeHosts)!, { brands: merged, lists, ...extra });
  it("yieldfields.fun posted by @YieldFields_RH is not YieldFi", () => {
    const v = runG("https://yieldfields.fun/whitelist", { origin: { source: "x", at: 0, poster: "YieldFields_RH", posterVerified: true } });
    expect(v.signals.some((s) => s.id === "poster-mismatch")).toBe(false);
    expect(v.signals.some((s) => s.id.startsWith("brand-"))).toBe(false);
    expect(v.band).toBe("none");
  });
  it("substring of a generated brand token never matches", () => {
    expect(runG("https://yieldfields-claim.xyz/").signals.some((s) => s.id.startsWith("brand-"))).toBe(false);
  });
  it("whole-token match of a generated brand still works with an action word", () => {
    const v = runG("https://yieldfi-claim.xyz/", { origin: { source: "x", at: 0, poster: "yieldfi_rewards" } });
    expect(v.signals.some((s) => s.id === "brand-impersonation-weak")).toBe(true);
    expect(v.signals.some((s) => s.id === "poster-mismatch")).toBe(true);
    expect(v.band).toBe("block");
  });
  it("poster mismatch needs a flagged brand, not just a token hit", () => {
    const v = run("https://uniswap-blog.com/", { origin: { source: "x", at: 0, poster: "someone" } });
    // seed brand impersonation (+40) is flagged, so mismatch applies
    expect(v.signals.some((s) => s.id === "poster-mismatch")).toBe(true);
    const w = run("https://kamino.finance/", { brands: mergeBrands(brands, [{ name: "Kamino Lend", tokens: ["kamino"], domains: ["kamino.com"], x: "Kamino" }]), origin: { source: "x", at: 0, poster: "someone" } });
    expect(w.signals.some((s) => s.id === "poster-mismatch")).toBe(false);
  });
});

describe("trusted infrastructure and blocklist confidence", () => {
  it("basescan.org listed by PhishDestroy is still clean", () => {
    const v = run("https://basescan.org/tx/0x1", { blocklistHit: "phishdestroy" });
    expect(v.band).toBe("none");
    expect(v.signals[0].id).toBe("trusted");
  });
  it("goerli.basescan.org listed by ScamSniffer is still clean (subdomain of trusted)", () => {
    expect(run("https://goerli.basescan.org/", { blocklistHit: "scamsniffer" }).band).toBe("none");
  });
  it("explorers, exchanges and wallets are never flagged by heuristics", () => {
    for (const u of ["https://arbiscan.io/", "https://app.hyperliquid.xyz/", "https://btcturk.com/", "https://phantom.app/", "https://claim-rewards.etherscan.io/"]) {
      expect(run(u, { origin: { source: "x", at: 0, poster: "someone", isReply: true } }).band, u).toBe("none");
    }
  });
  it("PhishDestroy alone warns; with a local signal it blocks", () => {
    expect(run("https://random-site.com/", { blocklistHit: "phishdestroy" }).band).toBe("warn");
    expect(run("https://claim-random.com/", { blocklistHit: "phishdestroy" }).band).toBe("block");
  });
  it("MetaMask / ScamSniffer hits block outright", () => {
    expect(run("https://random-site.com/", { blocklistHit: "metamask" }).band).toBe("block");
    expect(run("https://random-site.com/", { blocklistHit: "scamsniffer" }).band).toBe("block");
  });
  it("user allowlist still wins over trusted/blocklist ordering", () => {
    expect(run("https://basescan.org/", { userAllowed: true, blocklistHit: "metamask" }).band).toBe("none");
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

describe("X resolver signals", () => {
  const official = { handle: "yieldfields_rh", domains: ["yieldfields.fun"], followers: 27768 };
  it("project's own X account linking the domain clears a suspicious host", () => {
    const v = run("https://yieldfields.fun/whitelist", { origin: { source: "x", at: 0, poster: "YieldFields_RH" }, x: { token: "yieldfields", confidence: 0.6, official } });
    expect(v.signals.some((s) => s.id === "x-domain-match")).toBe(true);
    expect(v.band).toBe("none");
  });
  it("official account links elsewhere -> mismatch on a bait domain", () => {
    const v = run("https://yieldfields-claim.xyz/", { origin: { source: "x", at: 0, poster: "yf_claims" }, x: { token: "yieldfields", confidence: 0.6, official } });
    expect(v.signals.map((s) => s.id)).toEqual(expect.arrayContaining(["x-domain-mismatch", "poster-mismatch"]));
    expect(v.band).toBe("block");
  });
  it("weak poster account adds a signal only on bait hosts", () => {
    const x = { token: "foo", confidence: 0, poster: { handle: "foo_claims", followers: 12, ageDays: 3, domains: [] } };
    expect(run("https://foo-claim.xyz/", { origin: { source: "x", at: 0, poster: "foo_claims" }, x }).signals.some((s) => s.id === "x-poster-weak")).toBe(true);
    expect(run("https://github.com/", { origin: { source: "x", at: 0, poster: "foo_claims" }, x }).signals.some((s) => s.id === "x-poster-weak")).toBe(false);
  });
  it("low-confidence resolution is ignored", () => {
    const v = run("https://yieldfields.fun/", { x: { token: "yieldfields", confidence: 0.2, official } });
    expect(v.signals.some((s) => s.id.startsWith("x-"))).toBe(false);
  });
  it("xToken is set for suspicious hosts and names the brand-like token", () => {
    expect(run("https://rewards-axisrobotics.xyz/").xToken).toBe("axisrobotics");
    expect(run("https://claim-newcoolproj.xyz/").xToken).toBe("newcoolproj");
    expect(run("https://uniswap.org/").xToken).toBeUndefined();
  });
});

describe("TLD never scores alone", () => {
  for (const u of ["https://something.xyz/", "https://project.fun/", "https://brand.top/", "https://coolnft.bond/", "https://x.live/"]) {
    it(u, () => {
      const v = run(u);
      expect(v.score).toBe(0);
    });
  }
  it("abused TLD still adds weight next to a bait word", () => {
    const v = run("https://claim-portal.top/");
    expect(v.signals.some((s) => s.id === "tld-strong")).toBe(true);
  });
  it("weak TLD list is informational only", () => {
    expect(run("https://claim-portal.xyz/").signals.some((s) => s.id === "tld-weak")).toBe(false);
  });
});

describe("trusted list must not cover shared hosting", () => {
  it("foo.notion.site / foo.gitbook.io are still scored as free hosts", () => {
    for (const u of ["https://claim-axis.notion.site/", "https://axisrobotics-claim.gitbook.io/", "https://airdrop.mirror.xyz/"]) {
      const v = run(u);
      expect(v.signals.some((s) => s.id === "trusted"), u).toBe(false);
    }
  });
});
