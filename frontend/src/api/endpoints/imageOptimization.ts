import { api } from "@/api/client";
import type {
  ImageOptimizationRecord,
  ImageOptimizeRequest,
} from "@/api/types";

const BASE = "/ui/images/optimize";

// Request on-demand optimization of an already-uploaded image.
export const requestImageOptimization = (body: ImageOptimizeRequest) =>
  api.post<ImageOptimizationRecord>(BASE, body);

// Fetch a previously generated optimization record by id.
export const fetchImageOptimization = (optimizationId: string) =>
  api.get<ImageOptimizationRecord>(`${BASE}/${optimizationId}`);
