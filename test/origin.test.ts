import { describe, it, expect } from "vitest";
import { sourceFromHost } from "../src/lib/origin";

describe("sourceFromHost", () => {
  it("maps redirectors and social hosts", () => {
    expect(sourceFromHost("t.co")).toBe("x");
    expect(sourceFromHost("x.com")).toBe("x");
    expect(sourceFromHost("mobile.twitter.com")).toBe("x");
    expect(sourceFromHost("discord.com")).toBe("discord");
    expect(sourceFromHost("web.telegram.org")).toBe("telegram");
    expect(sourceFromHost("out.reddit.com")).toBe("reddit");
    expect(sourceFromHost("google.com")).toBeNull();
    expect(sourceFromHost("notx.com")).toBeNull();
  });
});
