import type { TotpConfig } from "@/lib/totpConfigParser";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const base32ToBytes = (input: string): Uint8Array => {
  const normalized = input.replace(/=+$/g, "").toUpperCase();
  let bits = "";
  for (const char of normalized) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx < 0) throw new Error("Invalid Base32 secret.");
    bits += idx.toString(2).padStart(5, "0");
  }

  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
};

const counterToBytes = (counter: number): Uint8Array => {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(value & BigInt(0xff));
    value >>= BigInt(8);
  }
  return bytes;
};

const hashName = (algorithm: TotpConfig["algorithm"]) => {
  if (algorithm === "SHA1") return "SHA-1";
  if (algorithm === "SHA256") return "SHA-256";
  return "SHA-512";
};

export interface TotpCodeResult {
  code: string;
  counter: number;
  periodSeconds: number;
  secondsRemaining: number;
}

export const generateTotpCode = async (config: TotpConfig, nowMs = Date.now()): Promise<TotpCodeResult> => {
  const periodSeconds = config.period;
  const counter = Math.floor(nowMs / 1000 / periodSeconds);
  const secondsRemaining = periodSeconds - (Math.floor(nowMs / 1000) % periodSeconds);

  const secretBytes = base32ToBytes(config.secret);
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: { name: hashName(config.algorithm) } },
    false,
    ["sign"],
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "HMAC" }, key, counterToBytes(counter)),
  );

  const offset = (signature[signature.length - 1] ?? 0) & 0x0f;
  const b0 = signature[offset] ?? 0;
  const b1 = signature[offset + 1] ?? 0;
  const b2 = signature[offset + 2] ?? 0;
  const b3 = signature[offset + 3] ?? 0;
  const binary =
    ((b0 & 0x7f) << 24)
    | ((b1 & 0xff) << 16)
    | ((b2 & 0xff) << 8)
    | (b3 & 0xff);

  const code = String(binary % 10 ** config.digits).padStart(config.digits, "0");

  return {
    code,
    counter,
    periodSeconds,
    secondsRemaining,
  };
};
