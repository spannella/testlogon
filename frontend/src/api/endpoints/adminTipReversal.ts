import { api } from "@/api/client";

export interface TipReverseResult {
  ok: boolean;
  tip_payment_id: string;
  refunded_cents: number;
  clawback_cents: number;
  reversal_entry_id: string;
  refund_entry_id: string;
  idempotent_replay: boolean;
}

export const reverseTip = (
  tipPaymentId: string,
  body: { tipper_id: string; recipient_id?: string; reason?: string },
) => api.post<TipReverseResult>(`/v1/admin/tips/${encodeURIComponent(tipPaymentId)}/reverse`, body);
