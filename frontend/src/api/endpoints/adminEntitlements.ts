import { api } from "@/api/client";

export type EntitlementReasonCode =
  | "customer_support"
  | "fraud_review"
  | "billing_correction"
  | "incident_remediation"
  | "goodwill";

export const revokeEntitlement = (
  entitlementId: string,
  body: { reason_code: EntitlementReasonCode; audit_comment: string },
) => api.post<Record<string, unknown>>(`/v1/admin/entitlements/${encodeURIComponent(entitlementId)}/revoke`, body);

export const extendEntitlement = (
  entitlementId: string,
  body: { reason_code: EntitlementReasonCode; audit_comment: string; extend_hours: number },
) => api.post<Record<string, unknown>>(`/v1/admin/entitlements/${encodeURIComponent(entitlementId)}/extend`, body);

export const creditAdjustEntitlement = (
  entitlementId: string,
  body: { reason_code: EntitlementReasonCode; audit_comment: string; credit_units: number },
) => api.post<Record<string, unknown>>(`/v1/admin/entitlements/${encodeURIComponent(entitlementId)}/credits`, body);
