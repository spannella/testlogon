import { api } from "@/api/client";

export type PaymentIncidentKind = "dispute" | "chargeback" | "payment_failure";

export interface PaymentIncident {
  incident_id: string;
  provider: string;
  incident_type: PaymentIncidentKind | string;
  status: string;
  amount?: string;
  currency?: string;
  customer_id?: string;
  response_due_at?: string;
  updated_at?: string;
}

export interface PaymentIncidentEvent {
  event_id?: string;
  event_type: string;
  created_at?: string;
  payload?: Record<string, unknown>;
}

export interface PaymentIncidentEvidenceVersion {
  version: string;
  created_at?: string;
  payload?: Record<string, unknown>;
}

export interface PaymentIncidentDetail extends PaymentIncident {
  events: PaymentIncidentEvent[];
  evidence_versions: PaymentIncidentEvidenceVersion[];
  ticket_link?: {
    ticket_id: string;
    linked_at?: string;
    linked_by?: string;
  } | null;
}

export function listPaymentIncidents(params: {
  incident_type?: string;
  due_before_ts?: number;
  status?: string;
  limit?: number;
}) {
  return api.get<{ items: PaymentIncident[]; count: number }>("/api/admin/payment-incidents", {
    ...(params.incident_type ? { incident_type: params.incident_type } : {}),
    ...(params.due_before_ts ? { due_before_ts: String(params.due_before_ts) } : {}),
    ...(params.status ? { status: params.status } : {}),
    ...(params.limit ? { limit: String(params.limit) } : {}),
  });
}

export function getPaymentIncidentDetail(incidentId: string) {
  return api.get<PaymentIncidentDetail>(`/api/admin/payment-incidents/${incidentId}`);
}

export function uploadPaymentIncidentEvidence(
  incidentId: string,
  body: { summary?: string; file_refs?: string[]; evidence_items?: Record<string, unknown>[] },
) {
  return api.post<{ version: number }>(`/api/admin/payment-incidents/${incidentId}/evidence`, body);
}

export function submitPaymentIncidentResponse(
  incidentId: string,
  body: { response_summary: string; rationale?: string },
) {
  return api.post<{ ok: boolean }>(`/api/admin/payment-incidents/${incidentId}/submit-response`, body);
}
