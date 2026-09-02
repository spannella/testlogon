// Pure, framework-free helpers for generic file-mount provider management.
// No React / no network — safe to unit-test in isolation (vitest).
//
// Mirrors the backend filemanager mount contracts:
//   • S3-style FileMount CRUD           (POST/PATCH/DELETE /v1/fs/mounts,
//                                         POST /v1/fs/mounts/{id}/validate)
//   • generic provider mounts (SFTP…)   (POST /v1/fs/mounts/{id}/test,
//                                         POST /v1/fs/mounts/{id}/rotate-credential)
//
// The validation rules below intentionally match the backend Pydantic field
// constraints so the UI can fail fast BEFORE issuing a request.

export type MountProvider = "sftp" | "drive" | "onedrive" | "s3";

/** Provider display metadata (no icon dependency — the UI maps iconKey). */
export interface ProviderMeta {
  label: string;
  iconKey: "sftp" | "drive" | "onedrive" | "s3";
  /** Whether this provider is a remote-host transport (needs host/port). */
  hostBased: boolean;
}

export function providerMeta(
  provider: MountProvider | string | null | undefined,
): ProviderMeta {
  switch (provider) {
    case "sftp":
      return { label: "SFTP / SCP / FTP", iconKey: "sftp", hostBased: true };
    case "drive":
      return { label: "Google Drive", iconKey: "drive", hostBased: false };
    case "onedrive":
      return { label: "Microsoft OneDrive", iconKey: "onedrive", hostBased: false };
    case "s3":
      return { label: "S3 bucket", iconKey: "s3", hostBased: false };
    default:
      return { label: "Mount", iconKey: "s3", hostBased: false };
  }
}

export const SUPPORTED_PROVIDERS: MountProvider[] = ["sftp", "drive", "onedrive", "s3"];

// ── Status badge mapping ───────────────────────────────────────────
// Backend SFTP status enum: healthy|degraded|auth_failed|unreachable|disabled
// Backend FileMount status enum: active|degraded|error|disabled
export type BadgeSeverity = "success" | "warning" | "danger" | "neutral";

export interface StatusBadge {
  label: string;
  severity: BadgeSeverity;
}

export function mountStatusBadge(
  status: string | null | undefined,
): StatusBadge {
  switch (status) {
    case "healthy":
    case "active":
      return { label: status === "active" ? "Active" : "Healthy", severity: "success" };
    case "degraded":
      return { label: "Degraded", severity: "warning" };
    case "auth_failed":
      return { label: "Auth failed", severity: "danger" };
    case "unreachable":
      return { label: "Unreachable", severity: "danger" };
    case "error":
      return { label: "Error", severity: "danger" };
    case "disabled":
      return { label: "Disabled", severity: "neutral" };
    default:
      return { label: status ? String(status) : "Unknown", severity: "neutral" };
  }
}

// ── Draft config validation ────────────────────────────────────────

/** A cross-provider mount config draft as edited in the UI. */
export interface MountConfigDraft {
  provider: MountProvider | string;
  mount_path?: string;
  // host-based (sftp)
  protocol?: string;
  host?: string;
  port?: number | string;
  remote_root?: string;
  read_only?: boolean;
  auth_credential_ref?: string;
  // s3 / cloud object providers
  bucket?: string;
  prefix?: string;
  mode?: string;
  auth_ref?: string;
}

export interface FieldError {
  field: string;
  message: string;
}

export interface ValidationResult {
  ok: boolean;
  errors: FieldError[];
}

const SFTP_PROTOCOLS = ["sftp", "scp", "ftp"];

function toPort(v: number | string | undefined): number | null {
  if (v === undefined || v === null || v === "") return null;
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n) || !Number.isInteger(n)) return null;
  return n;
}

/**
 * Validate a mount config draft against the backend field constraints for its
 * provider. Returns every field error (not just the first) so a form can show
 * them all at once.
 */
export function validateMountConfig(draft: MountConfigDraft): ValidationResult {
  const errors: FieldError[] = [];
  const provider = draft.provider;

  if (!provider || !SUPPORTED_PROVIDERS.includes(provider as MountProvider)) {
    errors.push({ field: "provider", message: "Choose a supported provider." });
  }

  if (provider === "sftp") {
    // mirrors CreateSftpMountIn
    if (draft.protocol && !SFTP_PROTOCOLS.includes(draft.protocol)) {
      errors.push({ field: "protocol", message: "Protocol must be sftp, scp, or ftp." });
    }
    if (!draft.host || !draft.host.trim()) {
      errors.push({ field: "host", message: "Host is required." });
    }
    const port = toPort(draft.port);
    if (port === null) {
      errors.push({ field: "port", message: "Port is required." });
    } else if (port < 1 || port > 65535) {
      errors.push({ field: "port", message: "Port must be between 1 and 65535." });
    }
    if (!draft.remote_root || !draft.remote_root.trim()) {
      errors.push({ field: "remote_root", message: "Remote root path is required." });
    }
    if (!draft.auth_credential_ref || !draft.auth_credential_ref.trim()) {
      errors.push({ field: "auth_credential_ref", message: "A credential reference is required." });
    }
  } else if (provider === "s3" || provider === "drive" || provider === "onedrive") {
    // mirrors FileMountCreateIn (bucket/prefix/mode/auth_ref/mount_path)
    if (!draft.mount_path || draft.mount_path.trim().length < 1) {
      errors.push({ field: "mount_path", message: "Mount path is required." });
    } else if (draft.mount_path.length > 2048) {
      errors.push({ field: "mount_path", message: "Mount path is too long." });
    }
    const bucket = (draft.bucket ?? "").trim();
    if (bucket.length < 3 || bucket.length > 255) {
      errors.push({ field: "bucket", message: "Bucket/container must be 3–255 characters." });
    }
    if (draft.prefix && draft.prefix.length > 2048) {
      errors.push({ field: "prefix", message: "Prefix is too long." });
    }
    if (draft.mode && !["read_only", "read_write"].includes(draft.mode)) {
      errors.push({ field: "mode", message: "Mode must be read_only or read_write." });
    }
    const authRef = (draft.auth_ref ?? "").trim();
    if (authRef.length < 1 || authRef.length > 256) {
      errors.push({ field: "auth_ref", message: "A credential reference is required." });
    }
  }

  return { ok: errors.length === 0, errors };
}

/** Build the create-request body for the backend from a validated draft. */
export function buildCreateBody(
  draft: MountConfigDraft,
): Record<string, unknown> {
  if (draft.provider === "sftp") {
    return {
      protocol: draft.protocol || "sftp",
      host: (draft.host ?? "").trim(),
      port: toPort(draft.port) ?? 22,
      auth_credential_ref: (draft.auth_credential_ref ?? "").trim(),
      remote_root: (draft.remote_root ?? "").trim(),
      read_only: !!draft.read_only,
    };
  }
  // s3 / drive / onedrive
  return {
    mount_path: (draft.mount_path ?? "").trim(),
    bucket: (draft.bucket ?? "").trim(),
    prefix: draft.prefix ? draft.prefix.trim() : null,
    mode: draft.mode || (draft.read_only ? "read_only" : "read_write"),
    auth_ref: (draft.auth_ref ?? "").trim(),
    status: "active",
  };
}

// ── Credential rotation validation (SFTP-style rotate-credential) ───
// mirrors RotateSftpMountCredentialIn
export interface RotateCredentialDraft {
  auth_mode: string;
  username?: string;
  password?: string;
  private_key?: string;
  private_key_passphrase?: string;
  auth_credential_ref?: string;
}

export function validateRotateCredential(
  draft: RotateCredentialDraft,
): ValidationResult {
  const errors: FieldError[] = [];
  if (!["password", "private_key"].includes(draft.auth_mode)) {
    errors.push({ field: "auth_mode", message: "Auth mode must be password or private_key." });
  }
  if (!draft.username || !draft.username.trim()) {
    errors.push({ field: "username", message: "Username is required." });
  }
  if (draft.auth_mode === "password" && !(draft.password && draft.password.length > 0)) {
    errors.push({ field: "password", message: "Password is required." });
  }
  if (draft.auth_mode === "private_key" && !(draft.private_key && draft.private_key.trim())) {
    errors.push({ field: "private_key", message: "Private key is required." });
  }
  return { ok: errors.length === 0, errors };
}

/** Convenience: is a mount actionable for the given control? */
export function canTestMount(provider: string | null | undefined): boolean {
  // The backend exposes /test + /rotate-credential on the host-based (SFTP)
  // family; S3/cloud object mounts use /validate instead.
  return provider === "sftp";
}
