import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import { getFillsFees, getLiquidations, getFundingPayments } from "@/api/endpoints/trading";

describe("trading feed endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("getFillsFees GETs /me/fills/fees and returns parsed body", async () => {
    const body = { fills: [], count: 0 };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getFillsFees();
    expect(spy).toHaveBeenCalledWith("/me/fills/fees");
    expect(out).toEqual(body);
  });

  it("getLiquidations GETs /me/liquidations", async () => {
    const body = { liquidations: [], count: 0 };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getLiquidations();
    expect(spy).toHaveBeenCalledWith("/me/liquidations");
    expect(out).toEqual(body);
  });

  it("getFundingPayments GETs /me/funding/payments", async () => {
    const body = { payments: [], count: 0 };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getFundingPayments();
    expect(spy).toHaveBeenCalledWith("/me/funding/payments");
    expect(out).toEqual(body);
  });
});
