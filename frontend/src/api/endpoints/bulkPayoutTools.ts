import { api } from "@/api/client";
import type {
  BulkKind,
  BulkEligibleItem,
  BulkBatchOut,
  BulkPreviewIn,
  BulkExecuteIn,
} from "@/api/types";

const BASE = "/ui/admin/bulk-payouts";

export const bulkPayoutTools = {
  listEligible: (kind: BulkKind): Promise<BulkEligibleItem[]> =>
    api.get<BulkEligibleItem[]>(`${BASE}/eligible`, { kind }),

  preview: (body: BulkPreviewIn): Promise<BulkBatchOut> =>
    api.post<BulkBatchOut>(`${BASE}/preview`, body),

  execute: (body: BulkExecuteIn): Promise<BulkBatchOut> =>
    api.post<BulkBatchOut>(`${BASE}/execute`, body),

  listBatches: (): Promise<BulkBatchOut[]> =>
    api.get<BulkBatchOut[]>(`${BASE}/batches`),

  getBatch: (batchId: string): Promise<BulkBatchOut> =>
    api.get<BulkBatchOut>(`${BASE}/batches/${batchId}`),
};
