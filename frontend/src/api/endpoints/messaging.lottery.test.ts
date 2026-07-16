import { beforeEach, describe, expect, it, vi } from "vitest";

import * as client from "@/api/client";
import { createLotteryMessage } from "@/api/endpoints/messaging";
import type { CreateLotteryMessageReq } from "@/api/types";
import * as featureFlags from "@/lib/featureFlags";

describe("lottery create endpoint", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects when lottery feature flag is disabled", async () => {
    vi.spyOn(featureFlags, "isMessagingDmLotteryEnabled").mockReturnValue(false);

    await expect(
      createLotteryMessage({
        message_type: "lottery_dm",
        conversation_id: "c1",
        lottery_config: {
          version: "v1",
          outcomes: [
            { payload_type: "text", weight_bps: 6000, text_content: "A" },
            { payload_type: "text", weight_bps: 4000, text_content: "B" },
          ],
        },
      }),
    ).rejects.toThrow("Lottery messages are disabled");
  });

  it("sends Idempotency-Key header for lottery create", async () => {
    vi.spyOn(featureFlags, "isMessagingDmLotteryEnabled").mockReturnValue(true);
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue("uuid-123" as ReturnType<typeof globalThis.crypto.randomUUID>);
    const apiSpy = vi.spyOn(client, "api").mockResolvedValue({} as never);

    const body: CreateLotteryMessageReq = {
      message_type: "lottery_dm",
      conversation_id: "c42",
      lottery_config: {
        version: "v1",
        outcomes: [
          { payload_type: "text", weight_bps: 6000, text_content: "A" },
          { payload_type: "text", weight_bps: 4000, text_content: "B" },
        ],
      },
    };

    await createLotteryMessage(body);

    expect(apiSpy).toHaveBeenCalledWith("/messaging/messages/lottery", {
      method: "POST",
      headers: {
        "Idempotency-Key": "lottery_create:c42_b2f2e7e0:uuid-123",
      },
      body: JSON.stringify(body),
    });
  });

  it("uses deterministic fallback idempotency key when randomUUID is unavailable", async () => {
    vi.spyOn(featureFlags, "isMessagingDmLotteryEnabled").mockReturnValue(true);
    const apiSpy = vi.spyOn(client, "api").mockResolvedValue({} as never);
    const nowSpy = vi.spyOn(Date, "now").mockReturnValue(1700000000000);
    const randSpy = vi.spyOn(Math, "random").mockReturnValue(0.123456789);
    const originalCrypto = globalThis.crypto;
    vi.stubGlobal("crypto", {} as Crypto);

    const body: CreateLotteryMessageReq = {
      message_type: "lottery_dm",
      conversation_id: "c99",
      lottery_config: {
        version: "v1",
        outcomes: [
          { payload_type: "text", weight_bps: 5000, text_content: "A" },
          { payload_type: "text", weight_bps: 5000, text_content: "B" },
        ],
      },
    };

    try {
      await createLotteryMessage(body);
    } finally {
      vi.unstubAllGlobals();
      if (originalCrypto) {
        vi.stubGlobal("crypto", originalCrypto);
      }
      nowSpy.mockRestore();
      randSpy.mockRestore();
    }

    expect(apiSpy).toHaveBeenCalledWith("/messaging/messages/lottery", {
      method: "POST",
      headers: {
        "Idempotency-Key": "lottery_create:c99_39fef558:1700000000000_4fzzzxjy",
      },
      body: JSON.stringify(body),
    });
  });

  it("caps conversation segment in idempotency key to stay within backend length limits", async () => {
    vi.spyOn(featureFlags, "isMessagingDmLotteryEnabled").mockReturnValue(true);
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue("uuid-123" as ReturnType<typeof globalThis.crypto.randomUUID>);
    const apiSpy = vi.spyOn(client, "api").mockResolvedValue({} as never);

    const body: CreateLotteryMessageReq = {
      message_type: "lottery_dm",
      conversation_id: "c".repeat(200),
      lottery_config: {
        version: "v1",
        outcomes: [
          { payload_type: "text", weight_bps: 5000, text_content: "A" },
          { payload_type: "text", weight_bps: 5000, text_content: "B" },
        ],
      },
    };

    await createLotteryMessage(body);

    const [[, requestInit]] = apiSpy.mock.calls as [[string, { headers: Record<string, string> }]];
    const key = requestInit.headers["Idempotency-Key"] ?? "";
    expect(key).toBe("lottery_create:cccccccccccccccc_9d757fad:uuid-123");
    expect(key.length).toBeLessThanOrEqual(128);
  });
});
