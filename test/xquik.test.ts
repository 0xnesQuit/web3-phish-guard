import { describe, it, expect } from "vitest";
import { pickOfficial, toAccount, domainsFromLinkPage, registrableOf } from "../src/lib/xquik";

// Canned from a live Xquik search on 2026-10-17 (trimmed).
const AXIS = [
  { username: "axisrobotics", name: "Axis Robotics", followers: 64587, verifiedType: "Business", createdAt: "Wed Nov 26 10:00:00 +0000 2014", url: "https://linktr.ee/axisrobotics" },
  { username: "axisroboticsPh", name: "Axis Robotics PH", followers: 1099, isBlueVerified: true, createdAt: "Wed May 06 10:00:00 +0000 2026", url: "https://t.me/axisrobotics_ph" },
  { username: "axisrobotcs", name: "Axis Robotics", followers: 1479, createdAt: "Wed Dec 23 10:00:00 +0000 2025", url: "https://linktr.ee/axisrobotics" },
  { username: "AxisRoboticsBD", name: "Axis Robotics BD", followers: 356, isBlueVerified: true, createdAt: "Thu Jul 30 10:00:00 +0000 2026", url: "https://discord.com/channels/1/2" },
];
const YIELD = [
  { username: "yieldfields", name: "YieldFields", followers: 938, createdAt: "Fri May 07 10:00:00 +0000 2021", url: "https://yieldfields.finance" },
  { username: "YieldFields_RH", name: "Yield Fields (🧑‍🌾,🧑‍🌾)", followers: 27768, isBlueVerified: true, createdAt: "Fri Aug 28 10:00:00 +0000 2020", url: "https://yieldfields.fun/", contactInfo: { links: [{ url: "https://yieldfields.fun/" }, { url: "https://opensea.io/collection/yield-field-deeds" }] } },
];
const UNI = [
  { username: "Uniswap", name: "Uniswap 🦄", followers: 1483936, verifiedType: "Business", createdAt: "Wed Apr 11 10:00:00 +0000 2018", url: "http://app.uniswap.org" },
  { username: "uniswap_gem", name: "Uniswap Gems", followers: 193360, isBlueVerified: true, createdAt: "Sun Dec 02 10:00:00 +0000 2018", url: "http://t.me/teamfvc" },
  { username: "uniswap12", name: "Uniswap Airdrop", followers: 65790, isBlueVerified: true, createdAt: "Sun Dec 13 10:00:00 +0000 2020", url: "https://weex.com/zh-CN/register?vipCode=7vc6" },
  { username: "UniswapFND", name: "Uniswap Foundation", followers: 20356, isBlueVerified: true, createdAt: "Thu May 19 10:00:00 +0000 2022", url: "http://www.uniswapfoundation.org" },
];

describe("pickOfficial", () => {
  it("Axis Robotics: the 64k Business account wins over regional and typo clones", () => {
    const r = pickOfficial("axisrobotics", AXIS);
    expect(r.official?.handle).toBe("axisrobotics");
    expect(r.confidence).toBeGreaterThanOrEqual(0.5);
    expect(r.official?.domains).toEqual([]); // linktree only; resolved separately
  });
  it("YieldFields: the 27k account linking yieldfields.fun wins", () => {
    const r = pickOfficial("yieldfields", YIELD);
    expect(r.official?.handle).toBe("yieldfields_rh");
    expect(r.official?.domains).toContain("yieldfields.fun");
    expect(r.official?.domains).not.toContain("opensea.io");
  });
  it("Uniswap: Business account with app.uniswap.org, not the 'Uniswap Airdrop' clone", () => {
    const r = pickOfficial("uniswap", UNI);
    expect(r.official?.handle).toBe("uniswap");
    expect(r.official?.domains).toEqual(["uniswap.org"]);
    expect(r.confidence).toBeGreaterThan(0.8);
  });
  it("no plausible account -> confidence 0", () => {
    expect(pickOfficial("zzzunknownproject", UNI).official).toBeUndefined();
  });
  it("Twitter-style createdAt parses to an age", () => {
    expect(toAccount(UNI[0]).ageDays).toBeGreaterThan(365 * 5);
  });
});

describe("link page parsing", () => {
  it("reads the owner's links from __NEXT_DATA__ and ignores Linktree's promoted links", () => {
    const html = `<a href="https://hellofresh.com/promo">ad</a><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"links":[{"url":"https://axisrobotics.ai/"},{"url":"https://x.com/axisrobotics"},{"url":"https://discord.gg/abc"},{"url":"https://app.axisrobotics.ai/claim"}]}}}</script><img src="https://lnkimg.com/x.png">`;
    expect(domainsFromLinkPage(html, "axisrobotics")).toEqual(["axisrobotics.ai"]);
  });
  it("regex fallback without JSON keeps only domains carrying the token", () => {
    const html = `<a href="https://hellofresh.com/promo">ad</a><a href="https://axisrobotics.ai/">site</a>`;
    expect(domainsFromLinkPage(html, "axisrobotics")).toEqual(["axisrobotics.ai"]);
  });
  it("registrableOf keeps private suffix hosts whole", () => {
    expect(registrableOf("https://foo.vercel.app/x")).toBe("foo.vercel.app");
    expect(registrableOf("app.uniswap.org")).toBe("uniswap.org");
    expect(registrableOf(undefined)).toBeNull();
  });
});
