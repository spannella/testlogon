import { describe, expect, it, vi, beforeEach } from "vitest";
import { api } from "@/api/client";
import {
  getDevtoolsBillingLedger,
  getDevtoolsBillingSummary,
  getDevtoolsEmailMessages,
  getDevtoolsSmsConversations,
} from "@/api/endpoints/devtools";

describe("devtools endpoints", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("maps email request params to backend contract", async () => {
    const spy = vi.spyOn(api, "get").mockResolvedValue({} as never);
    await getDevtoolsEmailMessages({ mailbox: "a@x.com", thread_id: "t1", q: "code", state: "all", limit: 10, cursor: "abc" });
    expect(spy).toHaveBeenCalledWith("/internal/dev-tools/email/messages", {
      mailbox: "a@x.com",
      thread_id: "t1",
      q: "code",
      state: "all",
      limit: "10",
      cursor: "abc",
    });
  });

  it("maps sms request params to backend contract", async () => {
    const spy = vi.spyOn(api, "get").mockResolvedValue({} as never);
    await getDevtoolsSmsConversations({ participant: "+14155550123", q: "hello", limit: 25, cursor: "c1" });
    expect(spy).toHaveBeenCalledWith("/internal/dev-tools/sms/conversations", {
      participant: "+14155550123",
      q: "hello",
      limit: "25",
      cursor: "c1",
    });
  });

  it("maps billing ledger and summary params to backend contract", async () => {
    const spy = vi.spyOn(api, "get").mockResolvedValue({} as never);
    await getDevtoolsBillingLedger({ provider: "paypal", status: "completed", from: "2026-01-01", to: "2026-01-02", limit: 50, cursor: "n1" });
    expect(spy).toHaveBeenNthCalledWith(1, "/internal/dev-tools/billing/ledger", {
      provider: "paypal",
      status: "completed",
      from: "2026-01-01",
      to: "2026-01-02",
      limit: "50",
      cursor: "n1",
    });

    await getDevtoolsBillingSummary({ provider: "stripe", status: "failed", from: "2026-01-01", to: "2026-01-02" });
    expect(spy).toHaveBeenNthCalledWith(2, "/internal/dev-tools/billing/summary", {
      provider: "stripe",
      status: "failed",
      from: "2026-01-01",
      to: "2026-01-02",
    });
  });
});
