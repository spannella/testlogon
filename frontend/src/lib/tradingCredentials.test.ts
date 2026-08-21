import { describe, expect, it } from "vitest";

import {
  ALL_PROTOCOLS,
  buildFixSessionConfig,
  fixConfigFilename,
  protocolLabel,
  protocolRequiresScopes,
  validateProtocolScopes,
  wsSubscribeChannels,
  wsSubscribePayload,
} from "./tradingCredentials";

describe("tradingCredentials", () => {
  it("labels protocols", () => {
    expect(protocolLabel("rest")).toBe("REST");
    expect(protocolLabel("ws")).toBe("WebSocket");
    expect(protocolLabel("fix")).toBe("FIX");
    expect(protocolLabel("binary")).toBe("Binary");
  });

  it("exposes all four protocols", () => {
    expect(ALL_PROTOCOLS).toEqual(["rest", "ws", "fix", "binary"]);
  });

  it("protocolRequiresScopes: rest has no requirement, fix/binary need trading+custody", () => {
    expect(protocolRequiresScopes("rest")).toEqual([]);
    expect(protocolRequiresScopes("fix")).toContain("trading:orders");
    expect(protocolRequiresScopes("fix")).toContain("custody:transfer");
    expect(protocolRequiresScopes("binary")).toContain("trading:read");
    expect(protocolRequiresScopes("ws")).toContain("marketdata:stream");
  });

  it("validate: fix/binary require a trading-or-custody scope", () => {
    const errsNone = validateProtocolScopes(["fix"], ["marketdata:read"]);
    expect(errsNone).toHaveLength(1);
    expect(errsNone[0]!.protocol).toBe("fix");

    const errsOk = validateProtocolScopes(["fix", "binary"], ["trading:orders"]);
    expect(errsOk).toHaveLength(0);

    const custodyOk = validateProtocolScopes(["binary"], ["custody:withdraw"]);
    expect(custodyOk).toHaveLength(0);
  });

  it("validate: ws accepts marketdata scope", () => {
    expect(validateProtocolScopes(["ws"], ["marketdata:stream"])).toHaveLength(0);
    expect(validateProtocolScopes(["ws"], [])).toHaveLength(1);
  });

  it("validate: rest never errors", () => {
    expect(validateProtocolScopes(["rest"], [])).toHaveLength(0);
  });

  it("builds a QuickFIX config with required fields", () => {
    const cfg = buildFixSessionConfig({
      senderCompId: "CLIENT1",
      targetCompId: "EXCH",
      host: "fix.example.com",
      port: 5001,
      username: "user1",
      password: "secret",
      msgTypes: ["D", "F", "CU"],
    });
    expect(cfg).toContain("ConnectionType=initiator");
    expect(cfg).toContain("SenderCompID=CLIENT1");
    expect(cfg).toContain("TargetCompID=EXCH");
    expect(cfg).toContain("SocketConnectHost=fix.example.com");
    expect(cfg).toContain("SocketConnectPort=5001");
    expect(cfg).toContain("Username=user1");
    expect(cfg).toContain("Password=secret");
    expect(cfg).toContain("D, F, CU");
    expect(cfg).toContain("BeginString=FIX.4.4");
  });

  it("builds a config without optional fields", () => {
    const cfg = buildFixSessionConfig({
      senderCompId: "A",
      targetCompId: "B",
      host: "h",
      port: "9000",
    });
    expect(cfg).not.toContain("Username=");
    expect(cfg).not.toContain("Password=");
    expect(cfg).toContain("SocketConnectPort=9000");
  });

  it("respects custom beginString/heartBtInt", () => {
    const cfg = buildFixSessionConfig({
      senderCompId: "A",
      targetCompId: "B",
      host: "h",
      port: 1,
      beginString: "FIXT.1.1",
      heartBtInt: 15,
    });
    expect(cfg).toContain("BeginString=FIXT.1.1");
    expect(cfg).toContain("HeartBtInt=15");
  });

  it("sanitizes fix config filename", () => {
    expect(fixConfigFilename("CLIENT/1 X")).toBe("fix-CLIENT_1_X.cfg");
    expect(fixConfigFilename("")).toBe("fix-session.cfg");
  });

  it("ws helpers", () => {
    expect(wsSubscribePayload("events")).toBe(JSON.stringify({ sub: "events" }));
    expect(wsSubscribePayload("custody")).toBe(JSON.stringify({ sub: "custody" }));
    expect(wsSubscribeChannels()).toEqual(["events", "custody"]);
    expect(wsSubscribeChannels(["events"])).toEqual(["events"]);
  });
});
