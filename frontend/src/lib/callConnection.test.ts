import { describe, expect, it } from "vitest";

import {
  TURN_REFRESH_LEAD_SEC,
  mapConnectionStatus,
  connectionBadge,
  shouldIceRestart,
  isTurnExpired,
  shouldRefreshTurn,
  type CallConnectionStatus,
} from "./callConnection";

describe("mapConnectionStatus", () => {
  it("returns 'new' when both states are unknown", () => {
    expect(mapConnectionStatus(null, null)).toEqual({ status: "new", label: "Starting…" });
    expect(mapConnectionStatus("new", "new").status).toBe("new");
    expect(mapConnectionStatus(undefined, undefined).status).toBe("new");
  });

  it("maps connecting/checking to 'connecting'", () => {
    expect(mapConnectionStatus("connecting", null).status).toBe("connecting");
    expect(mapConnectionStatus(null, "checking").status).toBe("connecting");
    expect(mapConnectionStatus("connecting", "checking").label).toBe("Connecting…");
  });

  it("maps connected/completed to 'connected'", () => {
    expect(mapConnectionStatus("connected", "connected").status).toBe("connected");
    expect(mapConnectionStatus(null, "completed").status).toBe("connected");
    expect(mapConnectionStatus("connected", null).label).toBe("Connected");
  });

  it("maps disconnected to 'reconnecting'", () => {
    expect(mapConnectionStatus("disconnected", "disconnected").status).toBe("reconnecting");
    expect(mapConnectionStatus(null, "disconnected").status).toBe("reconnecting");
    expect(mapConnectionStatus("disconnected", "disconnected").label).toBe("Reconnecting…");
  });

  it("maps failed to 'failed'", () => {
    expect(mapConnectionStatus("failed", null).status).toBe("failed");
    expect(mapConnectionStatus(null, "failed").status).toBe("failed");
    expect(mapConnectionStatus("failed", "failed").label).toBe("Connection failed");
  });

  it("maps closed to 'closed'", () => {
    expect(mapConnectionStatus("closed", null).status).toBe("closed");
    expect(mapConnectionStatus("closed", "closed").label).toBe("Call ended");
  });

  describe("precedence: failed > connected > reconnecting > connecting > new", () => {
    it("failed beats connected", () => {
      expect(mapConnectionStatus("failed", "connected").status).toBe("failed");
      expect(mapConnectionStatus("connected", "failed").status).toBe("failed");
    });

    it("failed beats closed", () => {
      expect(mapConnectionStatus("closed", "failed").status).toBe("failed");
    });

    it("connected beats reconnecting(disconnected) when pc is connected", () => {
      // pc connected but ice disconnected -> connected wins per precedence
      expect(mapConnectionStatus("connected", "disconnected").status).toBe("connected");
    });

    it("reconnecting beats connecting", () => {
      expect(mapConnectionStatus("disconnected", "checking").status).toBe("reconnecting");
    });

    it("connecting beats new", () => {
      expect(mapConnectionStatus("connecting", "new").status).toBe("connecting");
    });
  });
});

describe("connectionBadge", () => {
  it("returns label + tone for every status", () => {
    const expected: Record<CallConnectionStatus, string> = {
      new: "neutral",
      connecting: "info",
      connected: "success",
      reconnecting: "warning",
      failed: "danger",
      closed: "neutral",
    };
    (Object.keys(expected) as CallConnectionStatus[]).forEach((status) => {
      const badge = connectionBadge(status);
      expect(badge.tone).toBe(expected[status]);
      expect(badge.label.length).toBeGreaterThan(0);
    });
  });

  it("label matches mapConnectionStatus label for connected", () => {
    expect(connectionBadge("connected").label).toBe(mapConnectionStatus("connected", null).label);
  });
});

describe("shouldIceRestart", () => {
  it("always restarts on failed", () => {
    expect(shouldIceRestart("failed")).toBe(true);
    expect(shouldIceRestart("failed", false)).toBe(true);
  });

  it("restarts on disconnected only past grace", () => {
    expect(shouldIceRestart("disconnected")).toBe(false);
    expect(shouldIceRestart("disconnected", false)).toBe(false);
    expect(shouldIceRestart("disconnected", true)).toBe(true);
  });

  it("does not restart on healthy/other states", () => {
    expect(shouldIceRestart("connected", true)).toBe(false);
    expect(shouldIceRestart("checking", true)).toBe(false);
    expect(shouldIceRestart("completed", true)).toBe(false);
    expect(shouldIceRestart("new", true)).toBe(false);
    expect(shouldIceRestart(null, true)).toBe(false);
    expect(shouldIceRestart(undefined, true)).toBe(false);
  });
});

describe("isTurnExpired", () => {
  it("is false strictly before expiry", () => {
    expect(isTurnExpired(1000, 999)).toBe(false);
  });

  it("is true at and after expiry", () => {
    expect(isTurnExpired(1000, 1000)).toBe(true);
    expect(isTurnExpired(1000, 1001)).toBe(true);
  });
});

describe("shouldRefreshTurn", () => {
  it("does not refresh when comfortably before the lead window", () => {
    // expires at 1000, lead 60 -> refresh boundary is 940
    expect(shouldRefreshTurn(1000, 939, 60)).toBe(false);
  });

  it("refreshes once within the lead window", () => {
    expect(shouldRefreshTurn(1000, 940, 60)).toBe(true);
    expect(shouldRefreshTurn(1000, 970, 60)).toBe(true);
  });

  it("refreshes when already expired", () => {
    expect(shouldRefreshTurn(1000, 1001, 60)).toBe(true);
  });

  it("uses TURN_REFRESH_LEAD_SEC as the default lead", () => {
    const expires = 5000;
    const boundary = expires - TURN_REFRESH_LEAD_SEC;
    expect(shouldRefreshTurn(expires, boundary - 1)).toBe(false);
    expect(shouldRefreshTurn(expires, boundary)).toBe(true);
  });

  it("has a positive default lead", () => {
    expect(TURN_REFRESH_LEAD_SEC).toBeGreaterThan(0);
  });
});
