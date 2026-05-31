import { api } from "@/api/client";
import type {
  K8sLaunchPodIn,
  K8sPodOut,
  K8sPodListOut,
  K8sPodLogsOut,
  K8sImageListOut,
  K8sPresetListOut,
} from "@/api/types";

const BASE = "/ui/remote/k8s";

export const listImages = () =>
  api.get<K8sImageListOut>(`${BASE}/images`);

export const listPresets = () =>
  api.get<K8sPresetListOut>(`${BASE}/presets`);

export const launchPod = (body: K8sLaunchPodIn) =>
  api.post<K8sPodOut>(`${BASE}/launch`, body);

export const listPods = (status?: string) =>
  api.get<K8sPodListOut>(`${BASE}/pods`, status ? { status } : undefined);

export const getPod = (podId: string) =>
  api.get<K8sPodOut>(`${BASE}/pods/${podId}`);

export const getPodLogs = (podId: string, tail?: number) =>
  api.get<K8sPodLogsOut>(`${BASE}/pods/${podId}/logs`, tail ? { tail: String(tail) } : undefined);

export const terminatePod = (podId: string) =>
  api.del<K8sPodOut>(`${BASE}/pods/${podId}`);
