import { describe, it, expect } from "vitest";
import { buildRules, CHUNK, RULE_ALLOW, RULE_BLOCK_BASE } from "../src/lib/dnr";

describe("DNR rules", () => {
  it("chunks block domains, dedupes, drops allowed ones, adds an allow rule", () => {
    const block = Array.from({ length: CHUNK * 2 + 10 }, (_, i) => `evil${i}.xyz`).concat(["evil1.xyz", "uniswap.org"]);
    const rules = buildRules(block, ["uniswap.org", "basescan.org"]);
    const blockRules = rules.filter((r) => r.id >= RULE_BLOCK_BASE);
    expect(blockRules.length).toBe(3);
    expect(blockRules.flatMap((r) => r.condition.requestDomains ?? [])).not.toContain("uniswap.org");
    expect(rules.find((r) => r.id === RULE_ALLOW)?.condition.requestDomains).toEqual(["uniswap.org", "basescan.org"]);
  });
  it("ignores malformed entries", () => {
    const rules = buildRules(["ok.com", "bad domain", "", "ÿ.com"], []);
    expect(rules[0].condition.requestDomains).toEqual(["ok.com"]);
  });
});
