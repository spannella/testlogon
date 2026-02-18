export interface EncryptionMetadata {
  version: number;
  alg: string;
  kdf: string;
  iterations: number;
  salt_b64: string;
  iv_b64: string;
  orig_name: string;
  orig_size: number;
  mime: string;
  chunk_size?: number;
}

export interface CryptoProgress {
  phase: "encrypt" | "decrypt";
  processedBytes: number;
  totalBytes: number;
  percent: number;
}

export interface CryptoOptions {
  iterations?: number;
  chunkSize?: number;
  onProgress?: (progress: CryptoProgress) => void;
  useWorker?: boolean;
}

const DEFAULT_ITERATIONS = 600_000;
const DEFAULT_CHUNK_SIZE = 1024 * 1024; // 1 MiB

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

export async function deriveKey(password: string, saltBytes: Uint8Array, iterations = DEFAULT_ITERATIONS): Promise<CryptoKey> {
  if (!window.crypto?.subtle) {
    throw new Error("WebCrypto is not available in this browser.");
  }
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function emitProgress(
  phase: "encrypt" | "decrypt",
  processedBytes: number,
  totalBytes: number,
  onProgress?: (progress: CryptoProgress) => void,
) {
  if (!onProgress) return;
  const percent = totalBytes > 0 ? Math.min(100, Math.round((processedBytes / totalBytes) * 100)) : 100;
  onProgress({ phase, processedBytes, totalBytes, percent });
}


async function readBlobArrayBuffer(blob: Blob): Promise<ArrayBuffer> {
  const candidate = blob as Blob & { arrayBuffer?: () => Promise<ArrayBuffer> };
  if (typeof candidate.arrayBuffer === "function") {
    return candidate.arrayBuffer();
  }
  return new Response(blob).arrayBuffer();
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
    if (offset + 4 > buffer.byteLength) {
      throw new Error("Corrupted encrypted payload");
    }
    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, 4);
    const length = view.getUint32(0, false);
    offset += 4;
    if (offset + length > buffer.byteLength) {
      throw new Error("Corrupted encrypted payload");
    }
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

async function encryptChunkedInMainThread(
  file: File,
  password: string,
  options?: CryptoOptions,
): Promise<{ blob: Blob; metadata: EncryptionMetadata }> {
  const chunkSize = Math.max(64 * 1024, options?.chunkSize ?? DEFAULT_CHUNK_SIZE);
  const iterations = options?.iterations ?? DEFAULT_ITERATIONS;
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, iterations);
  const chunks: Uint8Array[] = [];
  let processed = 0;

  for (let start = 0; start < file.size; start += chunkSize) {
    const end = Math.min(file.size, start + chunkSize);
    const plainChunk = await readBlobArrayBuffer(file.slice(start, end));
    const encryptedChunk = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainChunk);
    chunks.push(packEncryptedChunk(new Uint8Array(encryptedChunk)));
    processed = end;
    emitProgress("encrypt", processed, file.size, options?.onProgress);
  }

  const merged = mergeArrayBuffers(chunks);
  const blob = new Blob([merged.buffer.slice(merged.byteOffset, merged.byteOffset + merged.byteLength)], { type: "application/octet-stream" });
  return {
    blob,
    metadata: {
      version: 1,
      alg: "AES-256-GCM",
      kdf: "PBKDF2-SHA256",
      iterations,
      salt_b64: toB64(salt),
      iv_b64: toB64(iv),
      orig_name: file.name,
      orig_size: file.size,
      mime: file.type || "application/octet-stream",
      chunk_size: chunkSize,
    },
  };
}

async function decryptChunkedInMainThread(
  blob: Blob,
  password: string,
  metadata?: Partial<EncryptionMetadata>,
  options?: CryptoOptions,
): Promise<Blob> {
  const salt = fromB64(String(metadata?.salt_b64 || ""));
  const iv = fromB64(String(metadata?.iv_b64 || ""));
  const iterations = Number(metadata?.iterations || DEFAULT_ITERATIONS);
  const key = await deriveKey(password, salt, iterations);
  const chunks: Uint8Array[] = [];
  let processed = 0;

  const encryptedBytes = new Uint8Array(await readBlobArrayBuffer(blob));
  const packedChunks = unpackEncryptedChunks(encryptedBytes);

  for (const encryptedChunk of packedChunks) {
    const plainChunk = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedChunk);
    chunks.push(new Uint8Array(plainChunk));
    processed += encryptedChunk.byteLength + 4;
    emitProgress("decrypt", processed, blob.size, options?.onProgress);
  }

  const merged = mergeArrayBuffers(chunks);
  return new Blob([merged.buffer.slice(merged.byteOffset, merged.byteOffset + merged.byteLength)], { type: metadata?.mime || "application/octet-stream" });
}

function canUseWorker(useWorker?: boolean): boolean {
  return !!useWorker && typeof Worker !== "undefined";
}

async function runWorkerJob<TPayload, TResult>(
  type: "encrypt" | "decrypt",
  payload: TPayload,
  onProgress?: (progress: CryptoProgress) => void,
): Promise<TResult> {
  const worker = new Worker(new URL("../workers/fileCrypto.worker.ts", import.meta.url), { type: "module" });

  return new Promise<TResult>((resolve, reject) => {
    worker.onmessage = (event: MessageEvent) => {
      const msg = event.data as { type: string; payload?: TResult; error?: string; progress?: CryptoProgress };
      if (msg.type === "progress" && msg.progress) {
        onProgress?.(msg.progress);
        return;
      }
      if (msg.type === "done" && msg.payload) {
        resolve(msg.payload);
        worker.terminate();
        return;
      }
      if (msg.type === "error") {
        reject(new Error(msg.error || "Crypto worker failed"));
        worker.terminate();
      }
    };
    worker.onerror = () => {
      reject(new Error("Crypto worker failed"));
      worker.terminate();
    };
    worker.postMessage({ type, payload });
  });
}

export async function encryptFile(file: File, password: string): Promise<{ blob: Blob; metadata: EncryptionMetadata }> {
  return encryptFileChunked(file, password);
}

export async function decryptFile(blob: Blob, password: string, metadata?: Partial<EncryptionMetadata>): Promise<Blob> {
  return decryptFileChunked(blob, password, metadata);
}

export async function encryptFileChunked(
  file: File,
  password: string,
  options?: CryptoOptions,
): Promise<{ blob: Blob; metadata: EncryptionMetadata }> {
  if (canUseWorker(options?.useWorker)) {
    const ab = await file.arrayBuffer();
    const result = await runWorkerJob<
      {
        fileBuffer: ArrayBuffer;
        fileName: string;
        fileType: string;
        password: string;
        options?: CryptoOptions;
      },
      { encryptedBuffer: ArrayBuffer; metadata: EncryptionMetadata }
    >(
      "encrypt",
      {
        fileBuffer: ab,
        fileName: file.name,
        fileType: file.type || "application/octet-stream",
        password,
        options,
      },
      options?.onProgress,
    );

    return {
      blob: new Blob([result.encryptedBuffer], { type: "application/octet-stream" }),
      metadata: result.metadata,
    };
  }
  return encryptChunkedInMainThread(file, password, options);
}

export async function decryptFileChunked(
  blob: Blob,
  password: string,
  metadata?: Partial<EncryptionMetadata>,
  options?: CryptoOptions,
): Promise<Blob> {
  if (canUseWorker(options?.useWorker)) {
    const ab = await blob.arrayBuffer();
    const result = await runWorkerJob<
      {
        encryptedBuffer: ArrayBuffer;
        password: string;
        metadata?: Partial<EncryptionMetadata>;
        options?: CryptoOptions;
      },
      { plainBuffer: ArrayBuffer; mime: string }
    >(
      "decrypt",
      {
        encryptedBuffer: ab,
        password,
        metadata,
        options,
      },
      options?.onProgress,
    );
    return new Blob([result.plainBuffer], { type: result.mime || metadata?.mime || "application/octet-stream" });
  }
  return decryptChunkedInMainThread(blob, password, metadata, options);
}
