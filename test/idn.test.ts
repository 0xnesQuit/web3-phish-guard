import { describe, it, expect } from "vitest";
import { decodePunycode, skeleton, homographHost } from "../src/lib/idn";

describe("IDN homograph", () => {
  it("decodes punycode", () => {
    expect(decodePunycode("xn--mnchen-3ya")).toBe("münchen");
    expect(decodePunycode("xn--80ak6aa92e")).toBe("аррӏе"); // Cyrillic apple
    expect(decodePunycode("plain")).toBe("plain");
  });
  it("skeleton maps confusables", () => {
    expect(skeleton("metаmask")).toBe("metamask"); // Cyrillic а
    expect(skeleton("ραypal")).toBe("paypal");
  });
  it("homographHost only for xn-- hosts", () => {
    expect(homographHost("uniswap.org")).toBeNull();
    expect(homographHost(new URL("https://metаmask.io/").hostname)).toBe("metamask.io");
  });
});
