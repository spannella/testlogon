import { api } from "@/api/client";
import type {
  LicenseAgreementOut,
  LicenseAgreementListOut,
  LicenseAgreementContentLinkOut,
  LicenseAgreementDownloadOut,
  LicenseAgreementReviewQueueOut,
} from "@/api/types";

export const LICENSE_TYPES = [
  "royalty_free",
  "creative_commons",
  "commercial",
  "custom",
  "editorial",
  "public_domain",
] as const;

export const CONTENT_TYPES = ["video", "post", "broadcast"] as const;

export interface CreateLicenseAgreementBody {
  title: string;
  licensor_name: string;
  license_type: string;
  territory?: string;
  expires_at?: number | null;
  notes?: string;
  file: File;
}

export const createLicenseAgreement = (body: CreateLicenseAgreementBody) => {
  const fd = new FormData();
  fd.append("title", body.title);
  fd.append("licensor_name", body.licensor_name);
  fd.append("license_type", body.license_type);
  fd.append("territory", body.territory ?? "worldwide");
  if (body.expires_at != null) fd.append("expires_at", String(body.expires_at));
  fd.append("notes", body.notes ?? "");
  fd.append("file", body.file);
  return api.upload<LicenseAgreementOut>("/ui/licenses/agreements", fd);
};

export const listLicenseAgreements = (params?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.status) q.status = params.status;
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<LicenseAgreementListOut>("/ui/licenses/agreements", q);
};

export const getLicenseAgreement = (licenseId: string) =>
  api.get<LicenseAgreementOut>(`/ui/licenses/agreements/${licenseId}`);

export interface UpdateLicenseAgreementBody {
  title?: string;
  licensor_name?: string;
  license_type?: string;
  territory?: string;
  expires_at?: number | null;
  notes?: string;
}

export const updateLicenseAgreement = (
  licenseId: string,
  body: UpdateLicenseAgreementBody,
) => api.patch<LicenseAgreementOut>(`/ui/licenses/agreements/${licenseId}`, body);

export const setLicenseAgreementStatus = (
  licenseId: string,
  status: "active" | "archived",
) =>
  api.post<LicenseAgreementOut>(`/ui/licenses/agreements/${licenseId}/status`, {
    status,
  });

export const deleteLicenseAgreement = (licenseId: string) =>
  api.del<{ ok: boolean }>(`/ui/licenses/agreements/${licenseId}`);

export const downloadLicenseAgreement = (licenseId: string) =>
  api.get<LicenseAgreementDownloadOut>(
    `/ui/licenses/agreements/${licenseId}/download`,
  );

export const linkLicenseAgreementContent = (
  licenseId: string,
  body: { content_id: string; content_type: string },
) =>
  api.post<LicenseAgreementContentLinkOut>(
    `/ui/licenses/agreements/${licenseId}/link`,
    body,
  );

export const unlinkLicenseAgreementContent = (
  licenseId: string,
  contentId: string,
) =>
  api.del<{ ok: boolean }>(
    `/ui/licenses/agreements/${licenseId}/link/${contentId}`,
  );

export const listLicenseAgreementContent = (licenseId: string) =>
  api.get<{ items: LicenseAgreementContentLinkOut[] }>(
    `/ui/licenses/agreements/${licenseId}/content`,
  );

export const listAgreementsForContent = (contentId: string) =>
  api.get<{ items: LicenseAgreementContentLinkOut[] }>(
    `/ui/licenses/agreements/content/${contentId}/licenses`,
  );

// -- Admin --

export const adminListLicenseReviewQueue = (params?: {
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.limit) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<LicenseAgreementReviewQueueOut>(
    "/ui/admin/licenses/review",
    q,
  );
};

export const adminReviewLicenseAgreement = (
  licenseId: string,
  body: { verified: boolean; rejection_reason?: string },
) =>
  api.post<LicenseAgreementOut>(
    `/ui/admin/licenses/review/${licenseId}`,
    body,
  );
