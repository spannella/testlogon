import { api } from "@/api/client";
import type {
  CreatorDisputeRespondIn,
  DisputeFileIn,
  DisputeOut,
  DisputeRespondIn,
  DisputeResolveIn,
} from "@/api/types";

// ---- Customer (payer) endpoints — DISP-020 ----
export const fileDispute = (body: DisputeFileIn) =>
  api.post<DisputeOut>("/ui/billing/disputes", body);

export const listMyDisputes = (limit = 50) =>
  api.get<{ items: DisputeOut[] }>("/ui/billing/disputes", { limit: String(limit) });

export const getDispute = (id: string) =>
  api.get<DisputeOut>(`/ui/billing/disputes/${id}`);

export const withdrawDispute = (id: string) =>
  api.post<{ ok: boolean; dispute_id: string; status: string }>(
    `/ui/billing/disputes/${id}/withdraw`,
    {},
  );

// ---- Creator/seller endpoints — DISP-021 ----
export const listCreatorDisputes = (limit = 50) =>
  api.get<{ items: DisputeOut[] }>("/ui/creator/disputes", { limit: String(limit) });

export const getCreatorDispute = (id: string) =>
  api.get<DisputeOut>(`/ui/creator/disputes/${id}`);

export const creatorRespondDispute = (id: string, body: CreatorDisputeRespondIn) =>
  api.post<{ ok: boolean; dispute_id: string; status: string; creator_response: string | null }>(
    `/ui/creator/disputes/${id}/respond`,
    body,
  );

// ---- Admin endpoints — DISP-022 (AdminScope.PAYMENT_DISPUTES) ----
export const adminListDisputes = (status = "open", limit = 50) =>
  api.get<{ items: DisputeOut[] }>("/ui/admin/disputes", { status, limit: String(limit) });

export const adminGetDispute = (id: string) =>
  api.get<DisputeOut>(`/ui/admin/disputes/${id}`);

export const adminRespondDispute = (id: string, body: DisputeRespondIn) =>
  api.post<{ ok: boolean; dispute_id: string; evidence_submitted: boolean; status: string }>(
    `/ui/admin/disputes/${id}/respond`,
    body,
  );

export const adminResolveDispute = (id: string, body: DisputeResolveIn) =>
  api.post<{ ok: boolean; dispute_id: string; status: string; resolution: string; moved_cents: number }>(
    `/ui/admin/disputes/${id}/resolve`,
    body,
  );

export const adminSweepDisputes = (limit = 200) =>
  api.post<{ swept: number; escalated: number }>(
    `/ui/admin/disputes/sweep?limit=${limit}`,
    {},
  );
