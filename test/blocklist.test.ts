import { describe, it, expect } from "vitest";
import { isSharedEntry, ingestDomains, applyMetaMaskDiff, normalizePath, buildPathIndex, pathHit, setSharedHosts } from "../src/lib/blocklist";
import { buildRules, RULE_PATH_BASE, RULE_BLOCK_BASE } from "../src/lib/dnr";

describe("feed ingestion keeps platforms out of the blocklist", () => {
  it("drops bare shared hosts, public suffixes and TLDs; keeps real phishing hosts", () => {
    // live ScamSniffer shapes
    expect(isSharedEntry("sites.google.com")).toBe(true);
    expect(isSharedEntry("storage.googleapis.com")).toBe(true);
    expect(isSharedEntry("r2.dev")).toBe(true);
    expect(isSharedEntry("github.io")).toBe(true);
    expect(isSharedEntry("co.uk")).toBe(true);
    expect(isSharedEntry("xyz")).toBe(true);
    expect(isSharedEntry("claim-uniswap.xyz")).toBe(false);
    expect(isSharedEntry("evil.sites.google.com")).toBe(false);
    expect(isSharedEntry("drop-onsolana.netlify.app")).toBe(false);
    setSharedHosts(["my-host.example"]);
    expect(isSharedEntry("my-host.example")).toBe(true);
    expect(ingestDomains(["sites.google.com", "claim-uniswap.xyz", "", "r2.dev"])).toEqual(["claim-uniswap.xyz"]);
  });

  it("MetaMask diffs: only the blocklist target adds hosts; blocklistPaths keep their path", () => {
    const hosts = new Set<string>(["old.xyz"]);
    const paths = new Set<string>();
    const last = applyMetaMaskDiff(hosts, paths, [
      { url: "sites.google.com/view/robinhoodacconthold", targetList: "eth_phishing_detect_config.blocklistPaths", timestamp: 10 },
      { url: "fresh-drainer.xyz", targetList: "eth_phishing_detect_config.blocklist", timestamp: 11 },
      { url: "old.xyz", targetList: "eth_phishing_detect_config.blocklist", timestamp: 12, isRemoval: true },
      { url: "uniswap.org", targetList: "eth_phishing_detect_config.allowlist", timestamp: 13 },
      { url: "sites.google.com", targetList: "eth_phishing_detect_config.blocklist", timestamp: 14 },
    ], 5);
    expect([...hosts]).toEqual(["fresh-drainer.xyz"]);
    expect([...paths]).toEqual(["sites.google.com/view/robinhoodacconthold"]);
    expect(last).toBe(14);
  });

  it("path index matches at segment boundaries only", () => {
    expect(normalizePath("https://sites.google.com/view/Foo/")).toBe("sites.google.com/view/foo");
    expect(normalizePath("sites.google.com")).toBe("");
    const idx = buildPathIndex(["sites.google.com/view/foo", "sites.google.com/kryptowallets.app/ledger"]);
    expect(pathHit(idx, "sites.google.com", "/view/foo")).toBe(true);
    expect(pathHit(idx, "sites.google.com", "/view/foo/home")).toBe(true);
    expect(pathHit(idx, "sites.google.com", "/view/foobar")).toBe(false);
    expect(pathHit(idx, "sites.google.com", "/view/other")).toBe(false);
    expect(pathHit(idx, "docs.google.com", "/view/foo")).toBe(false);
  });

  it("DNR gets urlFilter rules for paths, covering sub-frames too", () => {
    const rules = buildRules(["evil.xyz"], ["uniswap.org"], ["sites.google.com/view/foo", "uniswap.org/x"]);
    const pathRules = rules.filter((r) => r.id >= RULE_PATH_BASE);
    expect(pathRules.map((r) => r.condition.urlFilter)).toEqual(["||sites.google.com/view/foo"]);
    expect(rules.find((r) => r.id === RULE_BLOCK_BASE)?.condition.resourceTypes).toEqual(["main_frame", "sub_frame"]);
  });
});
