import { api } from "@/api/client";
import type {
  CarrierTrackingView,
  CarrierPollTransactionOut,
  CarrierPollNowOut,
} from "@/api/types";

// ─── SHOP-004: Carrier Tracking ─────────────────────────────────

/** Read the constructed tracking view (carrier, tracking URL, status, events). */
export const getCarrierTracking = (txnId: string) =>
  api.get<CarrierTrackingView>(
    `/ui/purchase-history/transactions/${txnId}/tracking`,
  );

/** Poll the carrier for a single order; applies any status change. */
export const pollCarrierTracking = (txnId: string) =>
  api.post<CarrierPollTransactionOut>(
    `/ui/shop/tracking/transactions/${txnId}/poll`,
  );

/** Admin/root: poll a batch of in-flight orders against the carrier API. */
export const pollCarrierTrackingNow = (limit?: number) =>
  api.post<CarrierPollNowOut>(
    `/ui/shop/tracking/poll-now`,
    undefined,
    limit ? { limit: String(limit) } : undefined,
  );
