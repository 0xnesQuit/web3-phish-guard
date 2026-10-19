import { describe, it, expect } from "vitest";
import { formatUnits, deadlineText, decodeString, decodeUint, summarizeSeaport, toBig, isUnlimitedBig, callData, SEL, nativeSymbol, tokenLabel, shortAddr } from "../src/lib/impact";

const word = (n: number | bigint) => BigInt(n).toString(16).padStart(64, "0");
const A = (c: string) => "0x" + c.repeat(40);

describe("toBig", () => {
  it("parses hex, decimal, raw words, numbers; rejects junk", () => {
    expect(toBig("0x10")).toBe(16n);
    expect(toBig("0x")).toBe(0n);
    expect(toBig("1000")).toBe(1000n);
    expect(toBig("0".repeat(62) + "ff")).toBe(255n);
    expect(toBig(42)).toBe(42n);
    expect(toBig(7n)).toBe(7n);
    expect(toBig("")).toBeUndefined();
    expect(toBig("nope")).toBeUndefined();
    expect(toBig(undefined)).toBeUndefined();
  });
  it("unlimited detection", () => {
    expect(isUnlimitedBig(toBig("0x" + "f".repeat(64))!)).toBe(true);
    expect(isUnlimitedBig(1000n)).toBe(false);
  });
});

describe("formatUnits", () => {
  it("scales, groups and trims", () => {
    expect(formatUnits(1234500000n, 6)).toBe("1,234.5");
    expect(formatUnits(1000000000000000000n, 18)).toBe("1");
    expect(formatUnits(500000000000000000n, 18)).toBe("0.5");
    expect(formatUnits(0n, 18)).toBe("0");
    expect(formatUnits(12345678n, 0)).toBe("12,345,678");
  });
  it("dust is not shown as zero", () => { expect(formatUnits(1n, 18)).toBe("0.0001"); });
  it("keeps at most four fractional digits", () => { expect(formatUnits(123456789n, 8)).toBe("1.2345"); });
});

describe("deadlineText", () => {
  const now = Date.UTC(2026, 0, 1);
  const s = Math.floor(now / 1000);
  it("absent or zero", () => {
    expect(deadlineText(undefined, now)).toBeUndefined();
    expect(deadlineText("0", now)).toBeUndefined();
    expect(deadlineText("junk", now)).toBeUndefined();
  });
  it("relative units", () => {
    expect(deadlineText(String(s + 30 * 60), now)).toEqual({ never: false, text: "30 min" });
    expect(deadlineText(String(s + 5 * 3600), now)).toEqual({ never: false, text: "5 h" });
    expect(deadlineText(String(s + 3 * 86400 + 5), now)).toEqual({ never: false, text: "3 d" });
    expect(deadlineText(String(s + 400 * 86400), now)?.text).toMatch(/y$/);
  });
  it("milliseconds are understood", () => {
    expect(deadlineText(String(now + 2 * 86400 * 1000 + 5000), now)).toEqual({ never: false, text: "2 d" });
  });
  it("expired", () => { expect(deadlineText(String(s - 100), now)).toEqual({ never: false, text: "expired" }); });
  it("never", () => {
    expect(deadlineText("0x" + "f".repeat(64), now)?.never).toBe(true);
    expect(deadlineText("4294967295", now)?.never).toBe(true);
    expect(deadlineText(String(s + 50 * 365 * 86400), now)?.never).toBe(true);
  });
});

describe("decodeString / decodeUint", () => {
  const hexOf = (str: string) => Array.from(str).map((c) => c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  it("dynamic string", () => {
    expect(decodeString("0x" + word(32) + word(4) + hexOf("USDC").padEnd(64, "0"))).toBe("USDC");
  });
  it("bytes32 (MKR style)", () => {
    expect(decodeString("0x" + hexOf("MKR").padEnd(64, "0"))).toBe("MKR");
  });
  it("garbage and empty", () => {
    expect(decodeString(null)).toBeUndefined();
    expect(decodeString("0x")).toBeUndefined();
    expect(decodeString("0x" + word(32) + word(500))).toBeUndefined();
  });
  it("uint", () => {
    expect(decodeUint("0x" + word(1234))).toBe(1234n);
    expect(decodeUint("0x")).toBeUndefined();
    expect(decodeUint(null)).toBeUndefined();
  });
});

describe("misc helpers", () => {
  it("callData pads the address", () => {
    expect(callData(SEL.balanceOf, A("a"))).toBe("0x70a08231" + "0".repeat(24) + "a".repeat(40));
    expect(callData(SEL.symbol)).toBe("0x95d89b41");
  });
  it("nativeSymbol and tokenLabel", () => {
    expect(nativeSymbol("0x1")).toBe("ETH");
    expect(nativeSymbol("0x38")).toBe("BNB");
    expect(nativeSymbol(undefined)).toBe("native coin");
    expect(tokenLabel("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", undefined)).toBe("WETH");
    expect(tokenLabel(A("1"), { symbol: "FOO" })).toBe("FOO");
    expect(tokenLabel(A("1"), undefined)).toBe(shortAddr(A("1")));
  });
});

describe("summarizeSeaport", () => {
  const me = A("a"), other = A("b");
  it("give and get with the recipient filter", () => {
    const s = summarizeSeaport({
      offerer: me.toUpperCase().replace("0X", "0x"),
      offer: [{ itemType: 2, token: A("c"), startAmount: "1" }, { itemType: 2, token: A("c"), startAmount: "1" }, { itemType: 1, token: A("d"), startAmount: "500" }],
      consideration: [
        { itemType: 0, token: A("0"), startAmount: "1000", recipient: me },
        { itemType: 0, token: A("0"), startAmount: "250", recipient: me },
        { itemType: 0, token: A("0"), startAmount: "999", recipient: other }, // fee to someone else: not ours
      ],
    })!;
    expect(s.give).toEqual([{ token: A("c"), count: 2, amount: 2n, kind: "nft" }, { token: A("d"), count: 1, amount: 500n, kind: "erc20" }]);
    expect(s.get).toEqual([{ token: A("0"), amount: 1250n, kind: "native" }]);
  });
  it("free listing: nothing comes back to the offerer", () => {
    const s = summarizeSeaport({ offerer: me, offer: [{ itemType: 3, token: A("c"), startAmount: "1" }], consideration: [{ itemType: 0, token: A("0"), startAmount: "1", recipient: other }] })!;
    expect(s.get).toEqual([]);
  });
  it("not an order", () => { expect(summarizeSeaport({ foo: 1 })).toBeUndefined(); });
});
