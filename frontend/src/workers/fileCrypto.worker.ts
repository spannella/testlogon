/// <reference lib="webworker" />

import type { CryptoOptions, EncryptionMetadata, CryptoProgress } from "@/lib/fileEncryption";

const DEFAULT_ITERATIONS = 600_000;
const DEFAULT_CHUNK_SIZE = 1024 * 1024;

declare const self: DedicatedWorkerGlobalScope;

function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i] ?? 0);
  return btoa(binary);
}

function fromB64(value: string): Uint8Array {
  const binary = atob(value || "");
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i) ?? 0;
  return out;
}


function packEncryptedChunk(chunk: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + chunk.byteLength);
  const view = new DataView(out.buffer);
  view.setUint32(0, chunk.byteLength, false);
  out.set(chunk, 4);
  return out;
}

function unpackEncryptedChunks(buffer: Uint8Array): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < buffer.byteLength) {
    if (offset + 4 > buffer.byteLength) throw new Error("Corrupted encrypted payload");
    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 4);
    const length = view.getUint32(0, false);
    offset += 4;
    if (offset + length > buffer.byteLength) throw new Error("Corrupted encrypted payload");
    chunks.push(buffer.slice(offset, offset + length));
    offset += length;
  }
  return chunks;
}

function mergeArrayBuffers(parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, p) => sum + p.byteLength, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.byteLength;
  }
  return out;
}

async function deriveKey(password: string, saltBytes: Uint8Array, iterations = DEFAULT_ITERATIONS): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await self.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return self.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function postProgress(progress: CryptoProgress) {
  self.postMessage({ type: "progress", progress });
}

self.onmessage = async (event: MessageEvent) => {
  try {
    const { type, payload } = event.data as { type: "encrypt" | "decrypt"; payload: any };

    if (type === "encrypt") {
      const opts: CryptoOptions | undefined = payload.options;
      const chunkSize = Math.max(64 * 1024, opts?.chunkSize ?? DEFAULT_CHUNK_SIZE);
      const iterations = opts?.iterations ?? DEFAULT_ITERATIONS;
      const plain = new Uint8Array(payload.fileBuffer as ArrayBuffer);
      const salt = self.crypto.getRandomValues(new Uint8Array(16));
      const iv = self.crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(payload.password, salt, iterations);
      const chunks: Uint8Array[] = [];

      for (let start = 0; start < plain.byteLength; start += chunkSize) {
        const end = Math.min(plain.byteLength, start + chunkSize);
        const chunk = plain.slice(start, end);
        const encrypted = await self.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, chunk);
        chunks.push(packEncryptedChunk(new Uint8Array(encrypted)));
        postProgress({
          phase: "encrypt",
          processedBytes: end,
          totalBytes: plain.byteLength,
          percent: Math.min(100, Math.round((end / plain.byteLength) * 100)),
        });
      }

      const metadata: EncryptionMetadata = {
        version: 1,
        alg: "AES-256-GCM",
        kdf: "PBKDF2-SHA256",
        iterations,
        salt_b64: toB64(salt),
        iv_b64: toB64(iv),
        orig_name: payload.fileName,
        orig_size: plain.byteLength,
        mime: payload.fileType || "application/octet-stream",
        chunk_size: chunkSize,
      };
      const out = mergeArrayBuffers(chunks);
      self.postMessage({ type: "done", payload: { encryptedBuffer: out.buffer, metadata } }, [out.buffer]);
      return;
    }

    const metadata = (payload.metadata ?? {}) as Partial<EncryptionMetadata>;
    const cipher = new Uint8Array(payload.encryptedBuffer as ArrayBuffer);
    const salt = fromB64(String(metadata.salt_b64 || ""));
    const iv = fromB64(String(metadata.iv_b64 || ""));
    const iterations = Number(metadata.iterations || DEFAULT_ITERATIONS);
    const key = await deriveKey(payload.password, salt, iterations);
    const chunks: Uint8Array[] = [];

    const packedChunks = unpackEncryptedChunks(cipher);
    let processed = 0;
    for (const chunk of packedChunks) {
      const plain = await self.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, chunk);
      chunks.push(new Uint8Array(plain));
      processed += chunk.byteLength + 4;
      postProgress({
        phase: "decrypt",
        processedBytes: processed,
        totalBytes: cipher.byteLength,
        percent: Math.min(100, Math.round((processed / cipher.byteLength) * 100)),
      });
    }

    const out = mergeArrayBuffers(chunks);
    self.postMessage(
      { type: "done", payload: { plainBuffer: out.buffer, mime: metadata.mime || "application/octet-stream" } },
      [out.buffer],
    );
  } catch (err) {
    self.postMessage({ type: "error", error: err instanceof Error ? err.message : "Crypto worker failure" });
  }
};

export {};
