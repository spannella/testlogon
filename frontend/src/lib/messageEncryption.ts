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

function ensureWebCrypto(): SubtleCrypto {
  if (!window.crypto?.subtle) {
    throw new MessageCryptoError("crypto_unavailable", "WebCrypto is not available in this browser.");
  }
  return window.crypto.subtle;
}

export function isMessageCryptoSupported(): boolean {
  return typeof window !== "undefined" && Boolean(window.crypto?.subtle);
}

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

async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = ensureWebCrypto();
  const digest = await subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

export async function deriveMessageKey(
  password: string,
  saltBytes: Uint8Array,
  iterations = DEFAULT_ITERATIONS,
): Promise<CryptoKey> {
  const subtle = ensureWebCrypto();
  const enc = new TextEncoder();
  const baseKey = await subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

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
  const subtle = ensureWebCrypto();
  const iterations = Math.max(100_000, options?.iterations ?? DEFAULT_ITERATIONS);
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveMessageKey(password, salt, iterations);
  const encoded = new TextEncoder().encode(plaintext);

  const cipher = await subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  const cipherBytes = new Uint8Array(cipher);
  const checksum = await digestSha256(cipherBytes);

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

export async function decryptMessage(envelope: MessageEncryptionEnvelope, password: string): Promise<string> {
  assertEnvelopeShape(envelope);
  const subtle = ensureWebCrypto();

  const salt = fromB64(envelope.salt_b64);
  const iv = fromB64(envelope.iv_b64);
  const cipherBytes = fromB64(envelope.ciphertext_b64);

  if (salt.byteLength !== 16 || iv.byteLength !== 12 || cipherBytes.byteLength <= 16) {
    throw new MessageCryptoError("invalid_envelope", "Encryption envelope failed basic length validation.");
  }

  if (envelope.ciphertext_sha256_b64) {
    const expected = envelope.ciphertext_sha256_b64;
    const actual = toB64(await digestSha256(cipherBytes));
    if (expected !== actual) {
      throw new MessageCryptoError("tampered_payload", "Encrypted message payload failed integrity verification.");
    }
  }

  const key = await deriveMessageKey(password, salt, envelope.iterations);

  let plainBuffer: ArrayBuffer;
  try {
    plainBuffer = await subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBytes);
  } catch {
    // In browser runtimes this is typically DOMException(OperationError), but
    // test/runtime implementations may throw different error classes.
    throw new MessageCryptoError("wrong_password", "Unable to decrypt message with provided password.");
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plainBuffer);
  } catch {
    throw new MessageCryptoError("tampered_payload", "Decrypted message contained invalid UTF-8 content.");
  }
}
