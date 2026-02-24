/**
 * Message encryption helpers.
 *
 * Primary path:  Web Crypto API (AES-256-GCM + PBKDF2-SHA256) — requires HTTPS/localhost.
 * Fallback path: @noble/ciphers + @noble/hashes — pure-JS, identical algorithms,
 *                works over plain HTTP so dev environments can still exercise the feature.
 *
 * Both paths produce and consume the same MessageEncryptionEnvelope wire format,
 * so envelopes are fully cross-compatible between the two paths.
 */

export interface MessageEncryptionEnvelope {
  version: 1;
  alg: "AES-256-GCM";
  kdf: "PBKDF2-SHA256";
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  ciphertext_b64: string;
  ciphertext_sha256_b64?: string;
}

export type MessageCryptoErrorCode =
  | "crypto_unavailable"
  | "invalid_envelope"
  | "unsupported_envelope"
  | "wrong_password"
  | "tampered_payload"
  | "crypto_error";

export class MessageCryptoError extends Error {
  code: MessageCryptoErrorCode;

  constructor(code: MessageCryptoErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "MessageCryptoError";
  }
}

const DEFAULT_ITERATIONS = 600_000;

// ─── Capability detection ────────────────────────────────────────────────────

function hasWebCrypto(): boolean {
  return typeof window !== "undefined" && Boolean(window.crypto?.subtle);
}

/**
 * Returns true if encryption is supported.
 * Always true because we have a pure-JS fallback.
 */
export function isMessageCryptoSupported(): boolean {
  return true;
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] ?? 0);
  return btoa(binary);
}

function fromB64(value: string): Uint8Array {
  try {
    const binary = atob(value || "");
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) ?? 0;
    return out;
  } catch {
    throw new MessageCryptoError("invalid_envelope", "Invalid base64 in encryption envelope.");
  }
}

function randomBytes(n: number): Uint8Array {
  // getRandomValues is available in non-secure contexts (unlike crypto.subtle).
  const buf = new Uint8Array(n);
  window.crypto.getRandomValues(buf);
  return buf;
}

function assertEnvelopeShape(value: unknown): asserts value is MessageEncryptionEnvelope {
  if (!value || typeof value !== "object") {
    throw new MessageCryptoError("invalid_envelope", "Encryption envelope must be an object.");
  }
  const env = value as Partial<MessageEncryptionEnvelope>;
  if (env.version !== 1 || env.alg !== "AES-256-GCM" || env.kdf !== "PBKDF2-SHA256") {
    throw new MessageCryptoError("unsupported_envelope", "Unsupported encryption envelope version or algorithm.");
  }
  if (!env.iterations || Number.isNaN(env.iterations) || env.iterations < 100_000) {
    throw new MessageCryptoError("invalid_envelope", "Invalid PBKDF2 iteration count.");
  }
  for (const field of ["salt_b64", "iv_b64", "ciphertext_b64"] as const) {
    if (!env[field] || typeof env[field] !== "string") {
      throw new MessageCryptoError("invalid_envelope", `Missing encryption envelope field: ${field}`);
    }
  }
}

// ─── WebCrypto path ──────────────────────────────────────────────────────────

async function webcryptoDeriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<CryptoKey> {
  const subtle = window.crypto.subtle;
  const enc = new TextEncoder();
  const base = await subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function webcryptoSha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await window.crypto.subtle.digest("SHA-256", bytes));
}

async function webcryptoEncrypt(
  plaintext: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await webcryptoDeriveKey(password, salt, iterations);
  const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return new Uint8Array(cipher);
}

async function webcryptoDecrypt(
  cipherBytes: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await webcryptoDeriveKey(password, salt, iterations);
  try {
    const plain = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
    return new Uint8Array(plain);
  } catch {
    throw new MessageCryptoError("wrong_password", "Unable to decrypt message with provided password.");
  }
}

// ─── Noble (pure-JS) fallback path ───────────────────────────────────────────
//
// @noble/ciphers gcm() produces identical output to WebCrypto AES-GCM:
//   encrypt(plaintext) → ciphertext ‖ 16-byte auth tag
//   decrypt(ciphertext) → plaintext (throws if auth tag is wrong)
//
// @noble/hashes pbkdf2() is a spec-compliant PBKDF2-SHA256 implementation.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type NobleImport = Promise<any>;

function importPbkdf2(): NobleImport { return import("@noble/hashes/pbkdf2.js"); }
function importSha2(): NobleImport { return import("@noble/hashes/sha2.js"); }
function importAes(): NobleImport { return import("@noble/ciphers/aes.js"); }

async function nobleDeriveKey(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const [{ pbkdf2Async }, { sha256 }] = await Promise.all([importPbkdf2(), importSha2()]);
  const enc = new TextEncoder();
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  return pbkdf2Async(sha256, enc.encode(password), salt, { c: iterations, dkLen: 32 }) as Promise<Uint8Array>;
}

async function nobleSha256(bytes: Uint8Array): Promise<Uint8Array> {
  const { sha256 } = await importSha2();
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  return sha256(bytes) as Uint8Array;
}

async function nobleEncrypt(
  plaintext: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const [{ gcm }, keyBytes] = await Promise.all([importAes(), nobleDeriveKey(password, salt, iterations)]);
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  return (gcm(keyBytes, iv) as { encrypt(p: Uint8Array): Uint8Array }).encrypt(plaintext);
}

async function nobleDecrypt(
  cipherBytes: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const [{ gcm }, keyBytes] = await Promise.all([importAes(), nobleDeriveKey(password, salt, iterations)]);
  try {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-call
    return (gcm(keyBytes, iv) as { decrypt(c: Uint8Array): Uint8Array }).decrypt(cipherBytes);
  } catch {
    throw new MessageCryptoError("wrong_password", "Unable to decrypt message with provided password.");
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function encodeEnvelope(envelope: MessageEncryptionEnvelope): string {
  assertEnvelopeShape(envelope);
  return JSON.stringify(envelope);
}

export function decodeEnvelope(value: string): MessageEncryptionEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new MessageCryptoError("invalid_envelope", "Envelope payload must be valid JSON.");
  }
  assertEnvelopeShape(parsed);
  return parsed;
}

export async function encryptMessage(
  plaintext: string,
  password: string,
  options?: { iterations?: number },
): Promise<MessageEncryptionEnvelope> {
  const iterations = Math.max(100_000, options?.iterations ?? DEFAULT_ITERATIONS);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const encoded = new TextEncoder().encode(plaintext);

  const cipherBytes = hasWebCrypto()
    ? await webcryptoEncrypt(encoded, password, salt, iv, iterations)
    : await nobleEncrypt(encoded, password, salt, iv, iterations);

  const checksum = hasWebCrypto()
    ? await webcryptoSha256(cipherBytes)
    : await nobleSha256(cipherBytes);

  return {
    version: 1,
    alg: "AES-256-GCM",
    kdf: "PBKDF2-SHA256",
    iterations,
    salt_b64: toB64(salt),
    iv_b64: toB64(iv),
    ciphertext_b64: toB64(cipherBytes),
    ciphertext_sha256_b64: toB64(checksum),
  };
}

export async function decryptMessage(
  envelope: MessageEncryptionEnvelope,
  password: string,
): Promise<string> {
  assertEnvelopeShape(envelope);

  const salt = fromB64(envelope.salt_b64);
  const iv = fromB64(envelope.iv_b64);
  const cipherBytes = fromB64(envelope.ciphertext_b64);

  if (salt.byteLength !== 16 || iv.byteLength !== 12 || cipherBytes.byteLength <= 16) {
    throw new MessageCryptoError("invalid_envelope", "Encryption envelope failed basic length validation.");
  }

  if (envelope.ciphertext_sha256_b64) {
    const expected = envelope.ciphertext_sha256_b64;
    const actual = toB64(
      hasWebCrypto()
        ? await webcryptoSha256(cipherBytes)
        : await nobleSha256(cipherBytes),
    );
    if (expected !== actual) {
      throw new MessageCryptoError("tampered_payload", "Encrypted message payload failed integrity verification.");
    }
  }

  const plainBytes = hasWebCrypto()
    ? await webcryptoDecrypt(cipherBytes, password, salt, iv, envelope.iterations)
    : await nobleDecrypt(cipherBytes, password, salt, iv, envelope.iterations);

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plainBytes);
  } catch {
    throw new MessageCryptoError("tampered_payload", "Decrypted message contained invalid UTF-8 content.");
  }
}

// Keep for backwards compat — now unused internally but may be imported elsewhere.
export async function deriveMessageKey(
  password: string,
  saltBytes: Uint8Array,
  iterations = DEFAULT_ITERATIONS,
): Promise<CryptoKey> {
  if (!hasWebCrypto()) {
    throw new MessageCryptoError("crypto_unavailable", "deriveMessageKey requires WebCrypto.");
  }
  return webcryptoDeriveKey(password, saltBytes, iterations);
}
