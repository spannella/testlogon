import { api } from "@/api/client";
import type {
  InstanceHealthOut,
  InstanceMetricIngestIn,
  InstanceMetricLatestOut,
  InstanceMetricSeriesOut,
  InstanceMonitoringIngestOut,
  InstanceMonitoringSeedIn,
} from "@/api/types";

const BASE = "/ui/compute/monitoring";

export const ingestInstanceMetric = (instanceId: string, body: InstanceMetricIngestIn) =>
  api.post<InstanceMonitoringIngestOut>(`${BASE}/instances/${instanceId}/metrics`, body);

export const seedInstanceMetrics = (instanceId: string, body: InstanceMonitoringSeedIn) =>
  api.post<{ instance_id: string; written: number }>(
    `${BASE}/instances/${instanceId}/seed`,
    body,
  );

export const getLatestInstanceMetric = (instanceId: string) =>
  api.get<InstanceMetricLatestOut>(`${BASE}/instances/${instanceId}/metrics/latest`);

export const getInstanceMetricSeries = (
  instanceId: string,
  params?: { limit?: number; since?: number },
) =>
  api.get<InstanceMetricSeriesOut>(
    `${BASE}/instances/${instanceId}/metrics`,
    params
      ? Object.fromEntries(
          Object.entries(params)
            .filter(([, v]) => v !== undefined)
            .map(([k, v]) => [k, String(v)]),
        )
      : undefined,
  );

export const getInstanceHealth = (instanceId: string) =>
  api.get<InstanceHealthOut>(`${BASE}/instances/${instanceId}/health`);
