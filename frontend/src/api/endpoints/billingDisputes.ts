import { api } from "@/api/client";
import type {
  DisputeFileIn,
  DisputeOut,
  DisputeRespondIn,
  DisputeResolveIn,
} from "@/api/types";

// Customer endpoints
export const fileDispute = (body: DisputeFileIn) =>
  api.post<DisputeOut>("/ui/billing/disputes", body);

export const listMyDisputes = (limit = 50) =>
  api.get<{ items: DisputeOut[] }>("/ui/billing/disputes", { limit: String(limit) });

export const getDispute = (id: string) =>
  api.get<DisputeOut>(`/ui/billing/disputes/${id}`);

// Admin endpoints
export const adminListDisputes = (status = "open", limit = 50) =>
  api.get<{ items: DisputeOut[] }>("/ui/admin/disputes", { status, limit: String(limit) });

export const adminRespondDispute = (id: string, body: DisputeRespondIn) =>
  api.post<{ ok: boolean; dispute_id: string; evidence_submitted: boolean; status: string }>(
    `/ui/admin/disputes/${id}/respond`,
    body,
  );

export const adminResolveDispute = (id: string, body: DisputeResolveIn) =>
  api.post<{ ok: boolean; dispute_id: string; status: string; resolution: string }>(
    `/ui/admin/disputes/${id}/resolve`,
    body,
  );
