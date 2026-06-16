import { api } from "@/api/client";

// RDP browser transport (ADR-004 / CTI-005, Phase 1 fallback).
// Phase 1 ships only the fallback metadata surface; native in-browser RDP is a
// future milestone behind RDP_REMOTE_DESKTOP_ENABLED.

export interface RdpFallbackResponse {
  available: boolean;
  host_id: string;
  label: string;
  hostname: string;
  port: number;
  username: string;
  address: string;
  instructions: string;
  native_clients: string[];
}

export const rdpApi = {
  // Owner-scoped fallback connection details for a Windows/RDP host.
  fallback: (hostId: string) =>
    api.get<RdpFallbackResponse>("/api/rdp/fallback", { host_id: hostId }),
};
