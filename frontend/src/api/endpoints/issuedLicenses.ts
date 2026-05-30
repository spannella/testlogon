import { api } from "@/api/client";
import type {
  IssuedLicenseOut,
  HeldLicenseOut,
  LibraryItemOut,
  LicenseCheckOut,
  IssuedLicenseIndexItem,
} from "@/api/types";

// -- Issue a new license --

export interface IssueLicenseBody {
  content_id: string;
  content_type: string;
  license_mode: "per_user" | "blanket";
  licensee_id?: string | null;
  profit_share_pct?: number;
  fixed_cost_cents?: number;
  revenue_share_pct?: number;
  currency?: string;
  title?: string;
  thumbnail_url?: string;
  expires_at?: number | null;
}

export const issueLicense = (body: IssueLicenseBody) =>
  api.post<IssuedLicenseOut>("/ui/licenses/issued", body);

// -- List licenses I've issued --

export const listIssuedLicenses = (opts?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<{ items: IssuedLicenseIndexItem[]; next_cursor?: string | null }>(
    "/ui/licenses/issued",
    params,
  );
};

// -- Get issued license detail --

export const getIssuedLicense = (issuedLicenseId: string, contentId: string) =>
  api.get<IssuedLicenseOut>(
    `/ui/licenses/issued/${issuedLicenseId}`,
    { content_id: contentId },
  );

// -- Update license terms --

export interface UpdateLicenseTermsBody {
  profit_share_pct?: number | null;
  fixed_cost_cents?: number | null;
  revenue_share_pct?: number | null;
  expires_at?: number | null;
}

export const updateLicenseTerms = (
  issuedLicenseId: string,
  contentId: string,
  body: UpdateLicenseTermsBody,
) =>
  api.patch<IssuedLicenseOut>(
    `/ui/licenses/issued/${issuedLicenseId}?content_id=${encodeURIComponent(contentId)}`,
    body,
  );

// -- Revoke license --

export const revokeLicense = (
  issuedLicenseId: string,
  contentId: string,
  reason?: string,
) =>
  api.post<IssuedLicenseOut>(
    `/ui/licenses/issued/${issuedLicenseId}/revoke`,
    { reason: reason || "" },
    { content_id: contentId },
  );

// -- List licenses I hold --

export const listHeldLicenses = (opts?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<{ items: HeldLicenseOut[]; next_cursor?: string | null }>(
    "/ui/licenses/held",
    params,
  );
};

// -- Content license queries --

export const listContentLicenses = (contentId: string, opts?: { status?: string }) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  return api.get<{ items: IssuedLicenseOut[] }>(
    `/ui/licenses/content/${contentId}`,
    params,
  );
};

export const checkLicense = (contentId: string) =>
  api.get<LicenseCheckOut>(`/ui/licenses/content/${contentId}/check`);

// -- Licensed Content Library --

export const browseLibrary = (opts?: {
  content_type?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.content_type) params["content_type"] = opts.content_type;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<{ items: LibraryItemOut[]; next_cursor?: string | null }>(
    "/ui/licenses/library",
    params,
  );
};

export const browseCreatorLibrary = (
  licensorId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<{ items: LibraryItemOut[]; next_cursor?: string | null }>(
    `/ui/licenses/library/creator/${licensorId}`,
    params,
  );
};
