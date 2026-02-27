import { describe, expect, it } from "vitest";
import {
  MessageCryptoError,
  decodeEnvelope,
  decryptMessage,
  encodeEnvelope,
  encryptMessage,
} from "./messageEncryption";

describe("messageEncryption", () => {
  it("roundtrips small and representative medium messages", async () => {
    const samples = [
      "hello world",
      "A".repeat(3200),
      "Line 1\nLine 2\n🚀 encrypted payload",
    ];

    for (const sample of samples) {
      const envelope = await encryptMessage(sample, "Str0ng!Password");
      const decrypted = await decryptMessage(envelope, "Str0ng!Password");
      expect(decrypted).toBe(sample);
    }
  });

  it("supports envelope encode/decode helpers", async () => {
    const envelope = await encryptMessage("encode me", "Str0ng!Password");
    const packed = encodeEnvelope(envelope);
    const unpacked = decodeEnvelope(packed);

    expect(unpacked.alg).toBe("AES-256-GCM");
    expect(unpacked.kdf).toBe("PBKDF2-SHA256");

    const decrypted = await decryptMessage(unpacked, "Str0ng!Password");
    expect(decrypted).toBe("encode me");
  });

  it("classifies wrong password safely", async () => {
    const envelope = await encryptMessage("super secret", "Str0ng!Password");

    await expect(decryptMessage(envelope, "WrongPassword123")).rejects.toMatchObject({
      code: "wrong_password",
    });
  });

  it("classifies tampered payload via checksum mismatch", async () => {
    const envelope = await encryptMessage("tamper check", "Str0ng!Password");

    const bytes = Uint8Array.from(atob(envelope.ciphertext_b64!), (ch) => ch.charCodeAt(0));
    expect(bytes.length).toBeGreaterThan(0);
    const first = bytes[0];
    if (first === undefined) throw new Error("Expected ciphertext bytes");
    bytes[0] = first ^ 0xff;
    const tamperedB64 = btoa(String.fromCharCode(...bytes));

    const tampered = {
      ...envelope,
      ciphertext_b64: tamperedB64,
    };

    await expect(decryptMessage(tampered, "Str0ng!Password")).rejects.toMatchObject({
      code: "tampered_payload",
    });
  });

  it("rejects malformed envelope decode", () => {
    expect(() => decodeEnvelope("{not-json}")).toThrow(MessageCryptoError);
  });
});
