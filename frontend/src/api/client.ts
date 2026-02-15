import { toast } from "sonner";
import { useAuthStore } from "@/stores/authStore";

// ─── Helpers ─────────────────────────────────────────────────────

const API_BASE_URL = ((import.meta as any).env?.VITE_API_BASE_URL ?? "").toString().replace(/\/$/, "");

function withApiBase(path: string): string {
  if (!API_BASE_URL || /^https?:\/\//.test(path)) {
    return path;
  }
  return `${API_BASE_URL}${path.startsWith("/") ? "" : "/"}${path}`;
}

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]!) : null;
}

function normalizeErrorDetail(detail: unknown, fallback: string): string {
  if (typeof detail === "string") {
    return detail;
  }
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }
        if (item && typeof item === "object" && "msg" in item) {
          const message = (item as { msg?: unknown }).msg;
          if (typeof message === "string") {
            return message;
          }
        }
        return null;
      })
      .filter(Boolean);
    if (messages.length > 0) {
      return messages.join(", ");
    }
  }
  if (detail && typeof detail === "object" && "msg" in detail) {
    const message = (detail as { msg?: unknown }).msg;
    if (typeof message === "string") {
      return message;
    }
  }
  return fallback;
}

// ─── Error class ─────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
    public body?: unknown,
  ) {
    super(detail);
    this.name = "ApiError";
  }
}

// ─── Core request function ───────────────────────────────────────

let refreshPromise: Promise<void> | null = null;

async function refreshSession(): Promise<void> {
  const res = await fetch(withApiBase("/ui/session/refresh"), {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) {
    useAuthStore.getState().logout();
    throw new ApiError(res.status, "Session refresh failed");
  }
}

/**
 * Typed fetch wrapper that handles:
 * - Authorization header from auth store
 * - CSRF token from `ui_csrf` cookie
 * - Automatic token refresh on 401
 * - JSON serialization/deserialization
 * - Typed error handling
 */
export async function api<T>(
  path: string,
  options: RequestInit & { params?: Record<string, string> } = {},
): Promise<T> {
  const { params, ...init } = options;

  // Build URL with query params
  let url = withApiBase(path);
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url = `${withApiBase(path)}?${qs}`;
  }

  // Build headers
  const headers = new Headers(init.headers);

  // Auth token
  const { accessToken } = useAuthStore.getState();
  if (accessToken && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  // CSRF token
  const csrf = getCookie("ui_csrf");
  if (csrf) {
    headers.set("X-CSRF-Token", csrf);
  }

  // Default content type for JSON bodies
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers,
      credentials: "include",
    });
  } catch (err) {
    // Network error (offline, DNS failure, etc.)
    toast.error("Network error — check your connection and try again");
    throw new ApiError(0, "Network error", err);
  }

  // Handle 401 — try refreshing the session once
  if (res.status === 401) {
    if (!refreshPromise) {
      refreshPromise = refreshSession().finally(() => {
        refreshPromise = null;
      });
    }

    try {
      await refreshPromise;
    } catch {
      throw new ApiError(401, "Authentication required");
    }

    // Retry original request with fresh session
    const retryRes = await fetch(url, {
      ...init,
      headers,
      credentials: "include",
    });

    if (!retryRes.ok) {
      const body = await retryRes.json().catch(() => null);
      throw new ApiError(
        retryRes.status,
        normalizeErrorDetail((body as Record<string, unknown>)?.detail, retryRes.statusText),
        body,
      );
    }

    return retryRes.json() as Promise<T>;
  }

  // Handle 403 — permission denied
  if (res.status === 403) {
    const body = await res.json().catch(() => null);
    const detail = normalizeErrorDetail(
      (body as Record<string, unknown>)?.detail,
      "Permission denied",
    );
    toast.error(detail);
    throw new ApiError(403, detail, body);
  }

  // Handle non-2xx responses
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new ApiError(
      res.status,
      normalizeErrorDetail((body as Record<string, unknown>)?.detail, res.statusText),
      body,
    );
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

// ─── Convenience methods ─────────────────────────────────────────

api.get = <T>(path: string, params?: Record<string, string>) =>
  api<T>(path, { method: "GET", params });

api.post = <T>(path: string, body?: unknown) =>
  api<T>(path, {
    method: "POST",
    body: body != null ? JSON.stringify(body) : undefined,
  });

api.put = <T>(path: string, body?: unknown) =>
  api<T>(path, {
    method: "PUT",
    body: body != null ? JSON.stringify(body) : undefined,
  });

api.patch = <T>(path: string, body?: unknown) =>
  api<T>(path, {
    method: "PATCH",
    body: body != null ? JSON.stringify(body) : undefined,
  });

api.del = <T>(path: string, params?: Record<string, string>) =>
  api<T>(path, { method: "DELETE", params });

/**
 * Upload a file via multipart form data.
 * Does NOT set Content-Type — the browser adds the boundary automatically.
 */
api.upload = <T>(path: string, formData: FormData, params?: Record<string, string>) =>
  api<T>(path, { method: "POST", body: formData, params });
