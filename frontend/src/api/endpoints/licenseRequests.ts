import { api } from "@/api/client";
import type {
  LicenseRequestOut,
  LicenseRequestListOut,
  LicenseRequestApprovalOut,
  LicenseTerms,
} from "@/api/types";

// -- Create a new license request --

export interface CreateLicenseRequestBody {
  content_id: string;
  content_type: string;
  owner_id: string;
  proposed_terms: LicenseTerms;
  message?: string;
}

export const createLicenseRequest = (body: CreateLicenseRequestBody) =>
  api.post<LicenseRequestOut>("/ui/licenses/requests", body);

// -- List sent requests --

export const listSentRequests = (opts?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<LicenseRequestListOut>("/ui/licenses/requests/sent", params);
};

// -- List received requests (inbox) --

export const listReceivedRequests = (opts?: {
  status?: string;
  limit?: number;
  cursor?: string;
}) => {
  const params: Record<string, string> = {};
  if (opts?.status) params["status"] = opts.status;
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<LicenseRequestListOut>(
    "/ui/licenses/requests/received",
    params,
  );
};

// -- Get request detail --

export const getLicenseRequest = (requestId: string, contentId: string) =>
  api.get<LicenseRequestOut>(`/ui/licenses/requests/${requestId}`, {
    content_id: contentId,
  });

// -- Approve request --

export const approveRequest = (requestId: string, contentId: string) =>
  api.post<LicenseRequestApprovalOut>(
    `/ui/licenses/requests/${requestId}/approve`,
    {},
    { content_id: contentId },
  );

// -- Deny request --

export const denyRequest = (
  requestId: string,
  contentId: string,
  reason?: string,
) =>
  api.post<LicenseRequestOut>(
    `/ui/licenses/requests/${requestId}/deny`,
    { reason: reason || "" },
    { content_id: contentId },
  );

// -- Counter-offer --

export const counterOffer = (
  requestId: string,
  contentId: string,
  counterTerms: LicenseTerms,
) =>
  api.post<LicenseRequestOut>(
    `/ui/licenses/requests/${requestId}/counter`,
    { counter_terms: counterTerms },
    { content_id: contentId },
  );

// -- Accept counter-offer --

export const acceptCounter = (requestId: string, contentId: string) =>
  api.post<LicenseRequestApprovalOut>(
    `/ui/licenses/requests/${requestId}/accept-counter`,
    {},
    { content_id: contentId },
  );

// -- Reject counter-offer --

export const rejectCounter = (requestId: string, contentId: string) =>
  api.post<LicenseRequestOut>(
    `/ui/licenses/requests/${requestId}/reject-counter`,
    {},
    { content_id: contentId },
  );

// -- Withdraw request --

export const withdrawRequest = (requestId: string, contentId: string) =>
  api.post<LicenseRequestOut>(
    `/ui/licenses/requests/${requestId}/withdraw`,
    {},
    { content_id: contentId },
  );
