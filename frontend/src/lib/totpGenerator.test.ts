import { describe, expect, it } from "vitest";

import { generateTotpCode } from "@/lib/totpGenerator";

const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("generateTotpCode", () => {
  it("matches RFC6238 SHA1 test vectors with 8 digits", async () => {
    const config = {
      mode: "raw" as const,
      secret: rfcSecret,
      algorithm: "SHA1" as const,
      digits: 8 as const,
      period: 30,
    };

    const v1 = await generateTotpCode(config, 59_000);
    const v2 = await generateTotpCode(config, 1_111_111_109_000);
    const v3 = await generateTotpCode(config, 1_234_567_890_000);

    expect(v1.code).toBe("94287082");
    expect(v2.code).toBe("07081804");
    expect(v3.code).toBe("89005924");
  });

  it("returns countdown and counter for cadence handling", async () => {
    const result = await generateTotpCode(
      {
        mode: "raw",
        secret: rfcSecret,
        algorithm: "SHA1",
        digits: 6,
        period: 30,
      },
      61_000,
    );

    expect(result.counter).toBe(2);
    expect(result.periodSeconds).toBe(30);
    expect(result.secondsRemaining).toBe(29);
    expect(result.code).toHaveLength(6);
  });
});
