import { describe, expect, it } from "vitest";

import { parseTotpConfigInput } from "@/lib/totpConfigParser";

describe("parseTotpConfigInput", () => {
  it("normalizes a valid otpauth URI into canonical config", () => {
    const result = parseTotpConfigInput(
      "otpauth://totp/TestLogon:alice@example.com?secret=JBSW-Y3DP EHPK3PXP&issuer=TestLogon&algorithm=SHA256&digits=8&period=45",
    );

    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
    expect(result.config).toEqual({
      mode: "otpauth",
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "TestLogon",
      accountName: "alice@example.com",
      label: "TestLogon:alice@example.com",
      algorithm: "SHA256",
      digits: 8,
      period: 45,
    });
  });

  it("supports raw Base32 mode without network calls", () => {
    const result = parseTotpConfigInput("jbsw y3dp ehpk 3pxp");

    expect(result.ok).toBe(true);
    expect(result.config?.mode).toBe("raw");
    expect(result.config?.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(result.config?.algorithm).toBe("SHA1");
    expect(result.config?.digits).toBe(6);
    expect(result.config?.period).toBe(30);
  });

  it("returns clear validation errors for invalid secret", () => {
    const result = parseTotpConfigInput("otpauth://totp/Example:user?secret=INVALID$SECRET");

    expect(result.ok).toBe(false);
    expect(result.errors).toContain("TOTP secret must be valid Base32 characters (A-Z and 2-7).");
  });

  it("returns non-blocking warnings for unsupported parameters", () => {
    const result = parseTotpConfigInput(
      "otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&algorithm=md5&digits=7&period=0&counter=1&foo=bar",
    );

    expect(result.ok).toBe(true);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        "Unsupported algorithm 'MD5'. Falling back to SHA1.",
        "Unsupported digits '7'. Falling back to 6.",
        "Invalid period '0'. Falling back to 30 seconds.",
        "Unsupported parameter 'counter' ignored.",
        "HOTP counter parameter is ignored for TOTP.",
        "Unsupported parameter 'foo' ignored.",
      ]),
    );
    expect(result.config?.algorithm).toBe("SHA1");
    expect(result.config?.digits).toBe(6);
    expect(result.config?.period).toBe(30);
  });

  it("fails for non-TOTP otpauth types", () => {
    const result = parseTotpConfigInput("otpauth://hotp/Test:user?secret=JBSWY3DPEHPK3PXP");
    expect(result.ok).toBe(false);
    expect(result.errors).toContain("Unsupported OTP type 'hotp'. Only TOTP is supported.");
  });
});
