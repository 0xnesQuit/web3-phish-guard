import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";

vi.stubGlobal("chrome", { runtime: { getURL: (p: string) => p }, storage: { local: { get: async () => ({}), set: async () => undefined } } });

describe("signed list manifests", () => {
  it("round-trips a manifest signature between node:crypto and WebCrypto", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const files = { "trusted.json": { bytes: 10, sha256: "ab" }, "action-words.json": { bytes: 5, sha256: "cd" } };
    const canon = JSON.stringify({ updatedAt: 123, files: Object.fromEntries(Object.keys(files).sort().map((k) => [k, files[k as keyof typeof files]])) });
    const sig = sign("sha256", Buffer.from(canon), { key: privateKey, dsaEncoding: "ieee-p1363" }).toString("base64");
    const key = await crypto.subtle.importKey("jwk", publicKey.export({ format: "jwk" }) as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Uint8Array.from(atob(sig), (c) => c.charCodeAt(0)), new TextEncoder().encode(canon));
    expect(ok).toBe(true);
    const tampered = canon.replace("123", "124");
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Uint8Array.from(atob(sig), (c) => c.charCodeAt(0)), new TextEncoder().encode(tampered))).toBe(false);
  });
  it("the extension rejects an unsigned manifest", async () => {
    const { verifyManifest } = await import("../src/lib/lists");
    expect(await verifyManifest({ updatedAt: 1, files: {} })).toBe(false);
    expect(await verifyManifest({ updatedAt: 1, files: {}, sig: "AAAA" })).toBe(false);
  });
});
