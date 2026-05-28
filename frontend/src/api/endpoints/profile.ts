import { ApiError, api } from "@/api/client";
import type { CrossUserProfileResp, Profile, Address, AddressIn, AddressValidateReq, AddressValidateResp, PublicProfileData, ProfilePostsResponse } from "@/api/types";
import { useAuthStore } from "@/stores/authStore";
import { useImpersonationStore } from "@/stores/impersonationStore";

// ─── Profile ─────────────────────────────────────────────────────

export const getProfile = () =>
  api.get<{ profile: Profile }>("/ui/profile");

export const patchProfile = async (body: Partial<Profile>) => {
  const out = await api.patch<{ profile: Profile }>("/ui/profile", body);
  clearProfileLookupCache();
  return out;
};

export const replaceProfile = async (body: Profile) => {
  const out = await api.put<{ profile: Profile }>("/ui/profile", body);
  clearProfileLookupCache();
  return out;
};

export const getProfileAudit = () =>
  api.get<{ audit: Record<string, unknown>[] }>("/ui/profile/audit");

export const uploadProfilePhoto = (kind: "profile" | "cover", file: File) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<{ profile: Profile; url: string }>(
    `/ui/profile/photos/${kind}/upload`,
    formData,
  ).then((out) => {
    clearProfileLookupCache();
    return out;
  });
};

export type ProfileLookupErrorCode =
  | "not_found_or_suppressed"
  | "rate_limited"
  | "unknown";

export class ProfileLookupError extends Error {
  constructor(
    public code: ProfileLookupErrorCode,
    message: string,
    public status: number,
    public detail: string,
    public body?: unknown,
    public retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = "ProfileLookupError";
  }
}

type ProfileLookupCacheEntry = {
  etag: string;
  data: CrossUserProfileResp;
};

const profileLookupCache = new Map<string, ProfileLookupCacheEntry>();
const API_BASE_URL = ((import.meta as any).env?.VITE_API_BASE_URL ?? "").toString().replace(/\/$/, "");

function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]!) : null;
}

function withApiBase(path: string): string {
  if (!API_BASE_URL || /^https?:\/\//.test(path)) return path;
  return `${API_BASE_URL}${path.startsWith("/") ? "" : "/"}${path}`;
}

export function clearProfileLookupCache(): void {
  profileLookupCache.clear();
}

function mapProfileLookupError(err: unknown): ProfileLookupError {
  if (err instanceof ProfileLookupError) {
    return err;
  }
  if (!(err instanceof ApiError)) {
    return new ProfileLookupError("unknown", "Unexpected profile lookup error", 0, "Unexpected profile lookup error", err);
  }
  if (err.status === 404) {
    return new ProfileLookupError(
      "not_found_or_suppressed",
      "Profile not available",
      err.status,
      err.detail,
      err.body,
    );
  }
  if (err.status === 429) {
    return new ProfileLookupError(
      "rate_limited",
      "Too many profile lookups. Please try again shortly.",
      err.status,
      err.detail,
      err.body,
    );
  }
  return new ProfileLookupError("unknown", err.detail || "Profile lookup failed", err.status, err.detail, err.body);
}

function parseRetryAfterSeconds(value: string | null): number | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const asInt = Number.parseInt(trimmed, 10);
  if (Number.isFinite(asInt) && asInt > 0) {
    return asInt;
  }
  const asDate = Date.parse(trimmed);
  if (Number.isNaN(asDate)) {
    return undefined;
  }
  const deltaSeconds = Math.ceil((asDate - Date.now()) / 1000);
  return deltaSeconds > 0 ? deltaSeconds : undefined;
}

function parseRetryAfterSecondsFromBody(body: unknown): number | undefined {
  if (!body || typeof body !== "object") return undefined;
  const detail = (body as { detail?: unknown }).detail;
  if (!detail || typeof detail !== "object") return undefined;
  const raw = (detail as { retry_after_seconds?: unknown }).retry_after_seconds;
  const parsed = Number.parseInt(String(raw), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

/**
 * Cross-user profile read endpoint.
 * - Public/Member/Owner audience is inferred by backend from auth/session context.
 * - Raises ProfileLookupError with normalized codes for UI-level mapping.
 */
export async function getProfileByIdentifier(identifier: string): Promise<CrossUserProfileResp> {
  const normalized = identifier.trim();
  if (!normalized) {
    throw new ProfileLookupError("not_found_or_suppressed", "Profile not available", 404, "Profile identifier is required");
  }

  const cacheKey = normalized.toLowerCase();
  const cached = profileLookupCache.get(cacheKey);
  const headers = new Headers();
  if (cached?.etag) {
    headers.set("If-None-Match", cached.etag);
  }
  const { accessToken } = useAuthStore.getState();
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  const imp = useImpersonationStore.getState();
  if (imp.isActive() && imp.token) {
    headers.set("X-IMPERSONATION-TOKEN", imp.token);
  }
  const csrf = getCookie("ui_csrf");
  if (csrf) {
    headers.set("X-CSRF-Token", csrf);
  }
  const path = `/ui/profiles/${encodeURIComponent(normalized)}`;
  const url = withApiBase(path);

  try {
    const response = await fetch(url, {
      method: "GET",
      credentials: "include",
      headers,
    });
    if (response.status === 304 && cached) {
      return cached.data;
    }
    if (response.status === 304 && !cached) {
      // Cache entry was evicted/missing; retry once without If-None-Match.
      headers.delete("If-None-Match");
      const retry = await fetch(url, {
        method: "GET",
        credentials: "include",
        headers,
      });
      if (retry.ok) {
        const payload = await retry.json() as CrossUserProfileResp;
        const etag = retry.headers.get("etag");
        if (etag) {
          profileLookupCache.set(cacheKey, { etag, data: payload });
        }
        return payload;
      }
      if (retry.status === 429) {
        const retryBody = await retry.json().catch(() => null);
        const retryAfterFromHeader = parseRetryAfterSeconds(retry.headers.get("retry-after"));
        throw new ProfileLookupError(
          "rate_limited",
          "Too many profile lookups. Please try again shortly.",
          429,
          (retryBody && typeof retryBody === "object" && "detail" in retryBody && typeof (retryBody as { detail?: unknown }).detail === "string")
            ? (retryBody as { detail: string }).detail
            : "Profile lookup rate limited",
          retryBody,
          retryAfterFromHeader ?? parseRetryAfterSecondsFromBody(retryBody),
        );
      }
      const retryBody = await retry.json().catch(() => null);
      throw new ApiError(
        retry.status,
        (retryBody && typeof retryBody === "object" && "detail" in retryBody && typeof (retryBody as { detail?: unknown }).detail === "string")
          ? (retryBody as { detail: string }).detail
          : retry.statusText || "Profile lookup failed",
        retryBody,
      );
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null);
      if (response.status === 429) {
        const retryAfterFromHeader = parseRetryAfterSeconds(response.headers.get("retry-after"));
        throw new ProfileLookupError(
          "rate_limited",
          "Too many profile lookups. Please try again shortly.",
          429,
          (body && typeof body === "object" && "detail" in body && typeof (body as { detail?: unknown }).detail === "string")
            ? (body as { detail: string }).detail
            : response.statusText || "Profile lookup rate limited",
          body,
          retryAfterFromHeader ?? parseRetryAfterSecondsFromBody(body),
        );
      }
      throw new ApiError(
        response.status,
        (body && typeof body === "object" && "detail" in body && typeof (body as { detail?: unknown }).detail === "string")
          ? (body as { detail: string }).detail
          : response.statusText || "Profile lookup failed",
        body,
      );
    }

    const payload = await response.json() as CrossUserProfileResp;
    const etag = response.headers.get("etag");
    if (etag) {
      profileLookupCache.set(cacheKey, { etag, data: payload });
    }
    return payload;
  } catch (err) {
    throw mapProfileLookupError(err);
  }
}

// ─── Public Profile (SOC-006 Storefront) ────────────────────────

export const getPublicProfile = (identifier: string) =>
  api.get<PublicProfileData>(`/ui/profile/public/${encodeURIComponent(identifier)}`);

export const getProfilePosts = (
  identifier: string,
  params?: {
    limit?: number;
    cursor?: string;
    filter?: "all" | "text" | "image" | "video" | "locked";
  },
) => {
  const qs: Record<string, string> = {};
  if (params?.limit) qs.limit = String(params.limit);
  if (params?.cursor) qs.cursor = params.cursor;
  if (params?.filter && params.filter !== "all") qs.filter = params.filter;
  return api.get<ProfilePostsResponse>(
    `/ui/profile/public/${encodeURIComponent(identifier)}/posts`,
    Object.keys(qs).length > 0 ? qs : undefined,
  );
};

// ─── Addresses ───────────────────────────────────────────────────

export const getAddresses = () =>
  api.get<Address[]>("/ui/addresses");

export const createAddress = (body: AddressIn) =>
  api.post<Address>("/ui/addresses", body);

export const updateAddress = (addressId: string, body: AddressIn) =>
  api.patch<Address>(`/ui/addresses/${addressId}`, body);

export const deleteAddress = (addressId: string) =>
  api.del<{ deleted: boolean }>(`/ui/addresses/${addressId}`);

export const searchAddresses = (query: string) =>
  api.post<{ query: string; matches: Address[] }>("/ui/addresses/search", { query });

export const setPrimaryAddress = (addressId: string) =>
  api.put<Address>("/ui/addresses/primary", { address_id: addressId });

export const validateAddress = (body: AddressValidateReq) =>
  api.post<AddressValidateResp>("/api/ups/address-validate", body);
