import { describe, it, expect } from "vitest";
import { decodeCalldata, decodeTx, decodeTypedData } from "../src/lib/txdecode";

const T = (c: string) => "0x" + c.repeat(40);

describe("typed data / tx impact fields", () => {
  it("eth-send and unknown-payable keep the value", () => {
    expect(decodeTx({ to: "0x1", value: "0x5af3107a4000" }).valueHex).toBe("0x5af3107a4000");
    expect(decodeTx({ to: "0x1", value: "0x5af3107a4000", data: "0xdeadbeef" + "0".repeat(64) }).valueHex).toBe("0x5af3107a4000");
  });
  it("Permit: token from verifyingContract, amount from value", () => {
    const s = decodeTypedData({ primaryType: "Permit", domain: { name: "USDC", verifyingContract: T("A") }, message: { spender: T("b"), value: "1000000", deadline: "123" } });
    expect(s.token).toBe(T("a"));
    expect(s.amountHex).toBe("1000000");
    expect(s.deadline).toBe("123");
  });
  it("PermitSingle: details.token and details.amount", () => {
    const s = decodeTypedData({ primaryType: "PermitSingle", message: { details: { token: T("A"), amount: "5", expiration: "9" }, spender: T("b"), sigDeadline: "99" } });
    expect(s.token).toBe(T("a"));
    expect(s.amountHex).toBe("5");
    expect(s.deadline).toBe("99");
  });
  it("PermitTransferFrom: permitted.token and permitted.amount", () => {
    const s = decodeTypedData({ primaryType: "PermitTransferFrom", message: { permitted: { token: T("c"), amount: "7" }, spender: T("b"), nonce: "1", deadline: "50" } });
    expect(s.kind).toBe("permit2");
    expect(s.token).toBe(T("c"));
    expect(s.amountHex).toBe("7");
  });
  it("PermitBatch: first token plus the full list", () => {
    const s = decodeTypedData({ primaryType: "PermitBatch", message: { details: [{ token: T("1"), amount: "1" }, { token: T("2"), amount: "2" }], spender: T("b"), sigDeadline: "1" } });
    expect(s.kind).toBe("permit-batch");
    expect(s.token).toBe(T("1"));
    expect(s.tokens).toEqual([T("1"), T("2")]);
  });
  it("seaport exposes the raw message, other kinds do not", () => {
    const msg = { offerer: T("a"), offer: [] };
    expect(decodeTypedData({ primaryType: "OrderComponents", message: msg }).message).toEqual(msg);
    expect(decodeTypedData({ primaryType: "Permit", message: { spender: T("b") } }).message).toBeUndefined();
  });
  it("ERC-20 transferFrom carries the amount word", () => {
    const d = "0x23b872dd" + "0".repeat(24) + "11".repeat(20) + "0".repeat(24) + "22".repeat(20) + "0".repeat(62) + "ff";
    expect(decodeCalldata(d, "0x" + "33".repeat(20)).amountHex).toBe("0".repeat(62) + "ff");
  });
});
