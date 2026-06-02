import { api, withApiBase } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import type {
  KycAuditTrail,
  KycDeadlineReport,
  KycProcessingTimeReport,
  KycReportExportRequest,
  KycRetentionReport,
  KycSar,
  KycSarRequest,
  KycScreeningComplianceReport,
  KycVolumeReport,
} from "@/api/types";

const BASE = "/v1/kyc/compliance";

function rangeParams(start?: number, end?: number): Record<string, string> | undefined {
  const params: Record<string, string> = {};
  if (start != null) params.start_date = String(start);
  if (end != null) params.end_date = String(end);
  return Object.keys(params).length ? params : undefined;
}

export const getKycVolumeReport = (start?: number, end?: number) =>
  api.get<KycVolumeReport>(`${BASE}/reports/volume`, rangeParams(start, end));

export const getKycScreeningReport = (start?: number, end?: number) =>
  api.get<KycScreeningComplianceReport>(`${BASE}/reports/screening`, rangeParams(start, end));

export const getKycProcessingTimeReport = (start?: number, end?: number) =>
  api.get<KycProcessingTimeReport>(`${BASE}/reports/processing-time`, rangeParams(start, end));

export const getKycDeadlineReport = (warnAfterHours?: number, criticalAfterHours?: number) => {
  const params: Record<string, string> = {};
  if (warnAfterHours != null) params.warn_after_hours = String(warnAfterHours);
  if (criticalAfterHours != null) params.critical_after_hours = String(criticalAfterHours);
  return api.get<KycDeadlineReport>(
    `${BASE}/reports/deadlines`,
    Object.keys(params).length ? params : undefined,
  );
};

export const getKycRetentionReport = () =>
  api.get<KycRetentionReport>(`${BASE}/reports/retention`);

export const getKycAuditTrail = (userSub: string) =>
  api.get<KycAuditTrail>(`${BASE}/reports/audit-trail/${encodeURIComponent(userSub)}`);

export const generateKycSar = (body: KycSarRequest) =>
  api.post<KycSar>(`${BASE}/sar`, body);

/**
 * Export a report as CSV or PDF. Fetches the binary response and triggers a
 * browser download via a Blob URL.
 */
export async function downloadKycReportExport(
  reportType: string,
  body: KycReportExportRequest,
): Promise<void> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const { accessToken } = useAuthStore.getState();
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const csrf = document.cookie
    .split("; ")
    .find((c) => c.startsWith("ui_csrf="))
    ?.split("=")[1];
  if (csrf) headers["X-CSRF-Token"] = decodeURIComponent(csrf);

  const res = await fetch(withApiBase(`${BASE}/reports/${reportType}/export`), {
    method: "POST",
    credentials: "include",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw new Error(`Export failed: ${res.status}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `kyc_${reportType}.${body.format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
