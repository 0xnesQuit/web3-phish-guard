import { describe, it, expect, vi } from "vitest";

vi.stubGlobal("chrome", { runtime: { sendMessage: () => Promise.resolve(), getManifest: () => ({}) }, i18n: { getMessage: (k: string) => k, getUILanguage: () => "en" } });
vi.stubGlobal("document", { addEventListener: () => undefined, querySelectorAll: () => [] });
vi.stubGlobal("window", { setTimeout: globalThis.setTimeout.bind(globalThis) });

const { looksLikeSeed } = await import("../src/content/seed-guard");

describe("seed phrase detection", () => {
  it("12-word BIP39 mnemonic", () => {
    expect(looksLikeSeed("abandon ability able about above absent absorb abstract absurd abuse access accident")).toBe("mnemonic");
  });
  it("24 words with one typo still counts", () => {
    const w = "legal winner thank year wave sausage worth useful legal winner thank yellow legal winner thank year wave sausage worth useful legal winner thank zzzz";
    expect(looksLikeSeed(w)).toBe("mnemonic");
  });
  it("ordinary sentences do not", () => {
    expect(looksLikeSeed("please connect your wallet to claim the airdrop before the countdown ends today ok")).toBeNull();
    expect(looksLikeSeed("hello")).toBeNull();
  });
  it("private keys", () => {
    expect(looksLikeSeed("0x" + "a1".repeat(32))).toBe("private-key");
    expect(looksLikeSeed("4" + "A".repeat(87))).toBe("private-key");
    expect(looksLikeSeed("0x" + "a".repeat(40))).toBeNull(); // an address is not a key
  });
});
