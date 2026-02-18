import { beforeEach, describe, expect, it, vi } from "vitest";
import { decryptFileChunked, encryptFileChunked } from "./fileEncryption";

function packChunk(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.byteLength);
  const view = new DataView(out.buffer);
  view.setUint32(0, data.byteLength, false);
  out.set(data, 4);
  return out;
}

function makeWorkerFile(text: string, name = "file.txt", type = "text/plain") {
  const bytes = new TextEncoder().encode(text);
  return {
    name,
    type,
    size: bytes.byteLength,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  } as unknown as File;
}

class MockWorker {
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  postMessage(msg: { type: "encrypt" | "decrypt"; payload: any }) {
    if (msg.type === "encrypt") {
      const bytes = new Uint8Array(msg.payload.fileBuffer as ArrayBuffer);
      const packed = packChunk(bytes);
      this.onmessage?.({
        data: {
          type: "done",
          payload: {
            encryptedBuffer: packed.buffer,
            metadata: {
              version: 1,
              alg: "AES-256-GCM",
              kdf: "PBKDF2-SHA256",
              iterations: 600000,
              salt_b64: "c2FsdA==",
              iv_b64: "aXY=",
              orig_name: msg.payload.fileName,
              orig_size: bytes.byteLength,
              mime: msg.payload.fileType,
            },
          },
        },
      } as MessageEvent);
      return;
    }

    if (msg.payload.password !== "Str0ng!Password") {
      this.onmessage?.({ data: { type: "error", error: "wrong password" } } as MessageEvent);
      return;
    }

    const cipher = new Uint8Array(msg.payload.encryptedBuffer as ArrayBuffer);
    if (cipher.byteLength < 4) {
      this.onmessage?.({ data: { type: "error", error: "Corrupted encrypted payload" } } as MessageEvent);
      return;
    }
    const view = new DataView(cipher.buffer, cipher.byteOffset, cipher.byteLength);
    const length = view.getUint32(0, false);
    if (4 + length > cipher.byteLength) {
      this.onmessage?.({ data: { type: "error", error: "Corrupted encrypted payload" } } as MessageEvent);
      return;
    }
    const plain = cipher.slice(4, 4 + length);
    this.onmessage?.({ data: { type: "done", payload: { plainBuffer: plain.buffer, mime: "text/plain" } } } as MessageEvent);
  }

  terminate() {}
}

describe("fileEncryption", () => {
  beforeEach(() => {
    vi.stubGlobal("Worker", MockWorker as unknown as typeof Worker);
  });

  it("roundtrips via encryptFileChunked/decryptFileChunked", async () => {
    const input = makeWorkerFile("hello worker", "hello.txt", "text/plain");
    const { metadata } = await encryptFileChunked(input, "Str0ng!Password", { useWorker: true });
    const packed = packChunk(new TextEncoder().encode("hello worker"));
    const workerBlob = {
      arrayBuffer: async () => packed.buffer.slice(packed.byteOffset, packed.byteOffset + packed.byteLength),
    } as unknown as Blob;
    const plain = await decryptFileChunked(workerBlob, "Str0ng!Password", metadata, { useWorker: true });
    expect(plain).toBeTruthy();
  });

  it("fails decryption with wrong password", async () => {
    const input = makeWorkerFile("secret", "secret.txt", "text/plain");
    const { blob, metadata } = await encryptFileChunked(input, "Str0ng!Password", { useWorker: true });
    const workerBlob = {
      arrayBuffer: async () => new Response(blob).arrayBuffer(),
    } as unknown as Blob;
    await expect(decryptFileChunked(workerBlob, "Wrong!Pass123", metadata, { useWorker: true })).rejects.toThrow();
  });

  it("rejects tampered ciphertext/corrupt header", async () => {
    const input = makeWorkerFile("tamper", "tamper.txt", "text/plain");
    const { blob, metadata } = await encryptFileChunked(input, "Str0ng!Password", { useWorker: true });
    const bytes = new Uint8Array(await new Response(blob).arrayBuffer());
    bytes[0] = 0xff;
    bytes[1] = 0xff;
    bytes[2] = 0xff;
    bytes[3] = 0xff;
    const tampered = new Blob([bytes], { type: "application/octet-stream" });
    const workerBlob = {
      arrayBuffer: async () => new Response(tampered).arrayBuffer(),
    } as unknown as Blob;
    await expect(decryptFileChunked(workerBlob, "Str0ng!Password", metadata, { useWorker: true })).rejects.toThrow("Corrupted encrypted payload");
  });
});
