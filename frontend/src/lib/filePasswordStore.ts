import type { EncryptionMetadata } from "@/lib/fileEncryption";

const DB_NAME = "filemgr-crypto";
const DB_VERSION = 2;
const STORE_KEYS = "keys";
const STORE_PASSWORDS = "passwords";
const MASTER_KEY_ID = "device-master-key";

const REMEMBER_TTL_DAYS = 90;
const REMEMBER_ROTATE_AFTER_DAYS = 30;
const DAY_MS = 24 * 60 * 60 * 1000;

interface RememberedPasswordRecord {
  fileId: string;
  ivB64: string;
  cipherB64: string;
  createdAt: string;
  updatedAt?: string;
  expiresAt?: string;
  path?: string;
  displayName?: string;
}

export interface RememberedPasswordInfo {
  fileId: string;
  path?: string;
  displayName?: string;
  createdAt: string;
  updatedAt?: string;
  expiresAt: string;
}

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

function nowIso(): string {
  return new Date().toISOString();
}

function ttlIso(start = Date.now(), ttlDays = REMEMBER_TTL_DAYS): string {
  return new Date(start + ttlDays * DAY_MS).toISOString();
}

function isExpired(expiresAt?: string): boolean {
  if (!expiresAt) return false;
  const ts = Date.parse(expiresAt);
  if (Number.isNaN(ts)) return true;
  return ts <= Date.now();
}

function shouldRotate(updatedAt?: string): boolean {
  if (!updatedAt) return true;
  const ts = Date.parse(updatedAt);
  if (Number.isNaN(ts)) return true;
  return Date.now() - ts >= REMEMBER_ROTATE_AFTER_DAYS * DAY_MS;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onerror = () => reject(req.error ?? new Error("Failed to open IndexedDB"));
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_KEYS)) db.createObjectStore(STORE_KEYS);
      if (!db.objectStoreNames.contains(STORE_PASSWORDS)) db.createObjectStore(STORE_PASSWORDS, { keyPath: "fileId" });
    };
    req.onsuccess = () => resolve(req.result);
  });
}

function txRequest<T = unknown>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

async function getMasterKey(): Promise<CryptoKey> {
  const db = await openDb();
  const tx = db.transaction(STORE_KEYS, "readwrite");
  const store = tx.objectStore(STORE_KEYS);
  const existing = await txRequest<CryptoKey | undefined>(store.get(MASTER_KEY_ID));
  if (existing) return existing;

  const key = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  await txRequest(store.put(key, MASTER_KEY_ID));
  return key;
}

async function getRecord(fileId: string): Promise<RememberedPasswordRecord | null> {
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readonly");
  const store = tx.objectStore(STORE_PASSWORDS);
  const rec = await txRequest<RememberedPasswordRecord | undefined>(store.get(fileId));
  return rec ?? null;
}

async function putRecord(rec: RememberedPasswordRecord): Promise<void> {
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readwrite");
  const store = tx.objectStore(STORE_PASSWORDS);
  await txRequest(store.put(rec));
}

export function canRememberPasswords(): boolean {
  return typeof window !== "undefined" && !!window.crypto?.subtle && typeof indexedDB !== "undefined";
}

export async function buildRememberedFileId(path: string, metadata?: Partial<EncryptionMetadata>): Promise<string> {
  const base = [path, metadata?.salt_b64 || "", metadata?.orig_name || "", String(metadata?.orig_size || "")].join("|");
  const bytes = new TextEncoder().encode(base);
  const hash = await window.crypto.subtle.digest("SHA-256", bytes);
  return toB64(new Uint8Array(hash));
}

export async function saveRememberedPassword(
  fileId: string,
  password: string,
  context?: { path?: string; displayName?: string },
): Promise<void> {
  if (!canRememberPasswords()) return;
  const key = await getMasterKey();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(password);
  const cipher = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);

  const now = nowIso();
  await putRecord({
    fileId,
    ivB64: toB64(iv),
    cipherB64: toB64(new Uint8Array(cipher)),
    createdAt: now,
    updatedAt: now,
    expiresAt: ttlIso(),
    path: context?.path,
    displayName: context?.displayName,
  });
}

async function rotateRememberedPasswordLease(rec: RememberedPasswordRecord): Promise<void> {
  if (!shouldRotate(rec.updatedAt ?? rec.createdAt)) return;
  await putRecord({
    ...rec,
    updatedAt: nowIso(),
    expiresAt: ttlIso(),
  });
}

export async function loadRememberedPassword(fileId: string): Promise<string | null> {
  if (!canRememberPasswords()) return null;
  const rec = await getRecord(fileId);
  if (!rec) return null;

  if (isExpired(rec.expiresAt)) {
    await clearRememberedPassword(fileId);
    return null;
  }

  try {
    const key = await getMasterKey();
    const plain = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(rec.ivB64) },
      key,
      fromB64(rec.cipherB64),
    );
    await rotateRememberedPasswordLease(rec);
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

export async function listRememberedPasswords(): Promise<RememberedPasswordInfo[]> {
  if (!canRememberPasswords()) return [];
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readonly");
  const store = tx.objectStore(STORE_PASSWORDS);
  const rows = await txRequest<RememberedPasswordRecord[]>(store.getAll());
  const activeRows = rows.filter((r) => !isExpired(r.expiresAt));
  activeRows.sort((a, b) => (b.updatedAt || b.createdAt).localeCompare(a.updatedAt || a.createdAt));
  return activeRows.map((r) => ({
    fileId: r.fileId,
    path: r.path,
    displayName: r.displayName,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
    expiresAt: r.expiresAt || ttlIso(Date.parse(r.createdAt)),
  }));
}

export async function purgeExpiredRememberedPasswords(): Promise<number> {
  if (!canRememberPasswords()) return 0;
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readwrite");
  const store = tx.objectStore(STORE_PASSWORDS);
  const rows = await txRequest<RememberedPasswordRecord[]>(store.getAll());
  let removed = 0;
  for (const row of rows) {
    if (isExpired(row.expiresAt)) {
      await txRequest(store.delete(row.fileId));
      removed += 1;
    }
  }
  return removed;
}

export async function clearRememberedPassword(fileId: string): Promise<void> {
  if (!canRememberPasswords()) return;
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readwrite");
  const store = tx.objectStore(STORE_PASSWORDS);
  await txRequest(store.delete(fileId));
}

export async function clearAllRememberedPasswords(): Promise<number> {
  if (!canRememberPasswords()) return 0;
  const db = await openDb();
  const tx = db.transaction(STORE_PASSWORDS, "readwrite");
  const store = tx.objectStore(STORE_PASSWORDS);
  const rows = await txRequest<RememberedPasswordRecord[]>(store.getAll());
  await txRequest(store.clear());
  return rows.length;
}
