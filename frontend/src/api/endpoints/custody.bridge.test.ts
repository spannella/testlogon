import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import {
  fundSpot,
  settleSpot,
  fundMargin,
  settleMargin,
  getSubaccounts,
  createSubaccount,
  transferBetweenSubaccounts,
  getDeposits,
  getFeeSchedule,
} from "@/api/endpoints/custody";

describe("custody bridge + subaccount + fee endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  // ─── custody <-> trading bridge (4 real POST routes) ────────────
  it("fundSpot POSTs {token,amount} to /me/custody/fund-spot and returns body", async () => {
    const body = { funded: true, token: "ETH", asset_id: 1, amount: "1", me_amount: "1", spot: {} };
    const spy = vi.spyOn(api, "post").mockResolvedValue(body as never);
    const out = await fundSpot({ token: "ETH", amount: "1.5" });
    expect(spy).toHaveBeenCalledWith("/me/custody/fund-spot", { token: "ETH", amount: "1.5" });
    expect(out).toEqual(body);
  });

  it("settleSpot POSTs {token,amount} to /me/custody/settle-spot and returns body", async () => {
    const body = { settled: true, token: "USDC", amount: "10" };
    const spy = vi.spyOn(api, "post").mockResolvedValue(body as never);
    const out = await settleSpot({ token: "USDC", amount: "10" });
    expect(spy).toHaveBeenCalledWith("/me/custody/settle-spot", { token: "USDC", amount: "10" });
    expect(out).toEqual(body);
  });

  it("fundMargin POSTs {token,amount} to /me/custody/fund-margin", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({ funded: true } as never);
    await fundMargin({ token: "BNB", amount: "2" });
    expect(spy).toHaveBeenCalledWith("/me/custody/fund-margin", { token: "BNB", amount: "2" });
  });

  it("settleMargin POSTs {token,amount} to /me/custody/settle-margin", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({ settled: false, reason: "insufficient" } as never);
    const out = await settleMargin({ token: "POL", amount: "3" });
    expect(spy).toHaveBeenCalledWith("/me/custody/settle-margin", { token: "POL", amount: "3" });
    expect(out).toMatchObject({ settled: false, reason: "insufficient" });
  });

  // ─── sub-accounts ───────────────────────────────────────────────
  it("getSubaccounts GETs /me/custody/subaccounts", async () => {
    const body = { subaccounts: [{ label: "trading", vault: "v_trading" }] };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getSubaccounts();
    expect(spy).toHaveBeenCalledWith("/me/custody/subaccounts");
    expect(out).toEqual(body);
  });

  it("createSubaccount POSTs {label} to /me/custody/subaccounts", async () => {
    const spy = vi.spyOn(api, "post").mockResolvedValue({ created: true } as never);
    await createSubaccount("savings");
    expect(spy).toHaveBeenCalledWith("/me/custody/subaccounts", { label: "savings" });
  });

  it("transferBetweenSubaccounts POSTs the request to /me/custody/subaccounts/transfer", async () => {
    const req = { from_label: "a", to_label: "b", asset: "ETH", amount: "0.25" };
    const spy = vi.spyOn(api, "post").mockResolvedValue({ transferred: true } as never);
    await transferBetweenSubaccounts(req);
    expect(spy).toHaveBeenCalledWith("/me/custody/subaccounts/transfer", req);
  });

  // ─── deposits ───────────────────────────────────────────────────
  it("getDeposits GETs /me/custody/deposits", async () => {
    const body = { vault: "v1", deposits: [], count: 0 };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getDeposits();
    expect(spy).toHaveBeenCalledWith("/me/custody/deposits");
    expect(out).toEqual(body);
  });

  // ─── fee schedule (symbolid query) ──────────────────────────────
  it("getFeeSchedule GETs /me/fees/schedule with stringified symbolid query", async () => {
    const body = {
      status: "ok",
      symbolid: 42,
      maker_fee_bps: 1,
      taker_fee_bps: 2,
      liquidation_fee_bps: 3,
      source: "engine",
      configured: true,
    };
    const spy = vi.spyOn(api, "get").mockResolvedValue(body as never);
    const out = await getFeeSchedule(42);
    expect(spy).toHaveBeenCalledWith("/me/fees/schedule", { symbolid: "42" });
    expect(out).toEqual(body);
  });
});
