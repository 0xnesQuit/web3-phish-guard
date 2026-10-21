import { describe, it, expect } from "vitest";
import { screenTargets, flagLabelKey, parseAddrReply, ADDR_ALLOWLIST } from "../src/lib/addrscreen";

const BAD = "0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c";
const PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3";

describe("screenTargets", () => {
  it("keeps an unknown spender and labels the role", () => {
    expect(screenTargets([{ kind: "approve", counterparty: BAD }, { kind: "transfer", counterparty: "0x" + "ab".repeat(20) }])).toEqual([
      { address: BAD, role: "spender" },
      { address: "0x" + "ab".repeat(20), role: "recipient" },
    ]);
  });
  it("drops allowlisted, own, zero and duplicate addresses", () => {
    const me = "0x" + "11".repeat(20);
    const out = screenTargets([
      { kind: "permit2", counterparty: PERMIT2 },
      { kind: "approve", counterparty: me },
      { kind: "transfer", counterparty: "0x" + "0".repeat(40) },
      { kind: "approve", counterparty: BAD },
      { kind: "setApprovalForAll", counterparty: BAD },
    ], me);
    expect(out).toEqual([{ address: BAD, role: "spender" }]);
  });
  it("ignores kinds that are not screened and malformed addresses", () => {
    expect(screenTargets([{ kind: "delegation-7702", counterparty: BAD }, { kind: "approve", counterparty: "0x12" }])).toEqual([]);
  });
  it("allowlist covers Permit2 and both Seaport versions", () => {
    for (const a of [PERMIT2, "0x0000000000000068f116a894984e2db1123eb395", "0x00000000000000adc04c56bf30ac9d3c0aaf14dc"]) expect(ADDR_ALLOWLIST.has(a)).toBe(true);
  });
});

describe("labels and reply parsing", () => {
  it("maps flags to a label key", () => {
    expect(flagLabelKey(["stealing_attack", "sanctioned"])).toBe("gate_addr_l_phish");
    expect(flagLabelKey(["sanctioned"])).toBe("gate_addr_l_sanction");
    expect(flagLabelKey(["cybercrime"])).toBe("gate_addr_l_crime");
  });
  it("treats malformed replies as not flagged", () => {
    expect(parseAddrReply(null)).toEqual({ bad: false, flags: [] });
    expect(parseAddrReply({ bad: true, flags: [] })).toEqual({ bad: false, flags: [] });
    expect(parseAddrReply({ bad: true, flags: ["sanctioned"] })).toEqual({ bad: true, flags: ["sanctioned"] });
  });
});
