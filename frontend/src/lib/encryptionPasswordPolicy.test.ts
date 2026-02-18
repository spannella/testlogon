import { describe, expect, it } from "vitest";
import { evaluateEncryptionPassword } from "./encryptionPasswordPolicy";

describe("evaluateEncryptionPassword", () => {
  it("marks strong passwords as strong", () => {
    const res = evaluateEncryptionPassword("S3cure!Passphrase");
    expect(res.isStrong).toBe(true);
    expect(res.score).toBeGreaterThanOrEqual(5);
  });

  it("rejects common weak patterns", () => {
    const res = evaluateEncryptionPassword("Password1234!");
    const common = res.checks.find((c) => c.id === "common");
    expect(common?.met).toBe(false);
    expect(res.isStrong).toBe(false);
  });
});
