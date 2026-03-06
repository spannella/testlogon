import { api } from "@/api/client";

export interface VncCapabilities {
  clipboard: boolean;
  file_transfer: boolean;
  drag_drop_upload: boolean;
}

export interface CreateVncSessionRequest {
  target_id: string;
}

export interface VncTimeoutPolicy {
  idle_timeout_seconds: number;
  max_session_duration_seconds: number;
  warning_seconds: number;
}

export interface CreateVncSessionResponse {
  session_id: string;
  ws_url: string;
  connect_params: Record<string, string>;
  created_at: number;
  expires_at: number;
  capabilities: VncCapabilities;
  timeout_policy: VncTimeoutPolicy;
}

export interface DeleteVncSessionResponse {
  session_id: string;
  status: "closed" | "already_closed";
  closed_at?: number | null;
}

export interface VncTransferFallbackResponse {
  session_id: string;
  method: string;
  label: string;
  instructions: string;
  url: string;
  expires_at: number;
}

const DEFAULT_VNC_CAPABILITIES: VncCapabilities = {
  clipboard: false,
  file_transfer: false,
  drag_drop_upload: false,
};

const DEFAULT_TIMEOUT_POLICY: VncTimeoutPolicy = {
  idle_timeout_seconds: 300,
  max_session_duration_seconds: 3600,
  warning_seconds: 60,
};

function normalizeTimeoutPolicy(input: unknown): VncTimeoutPolicy {
  if (!input || typeof input !== "object") {
    return { ...DEFAULT_TIMEOUT_POLICY };
  }
  const raw = input as Partial<Record<keyof VncTimeoutPolicy, unknown>>;
  const idle = Number(raw.idle_timeout_seconds);
  const maxDuration = Number(raw.max_session_duration_seconds);
  const warning = Number(raw.warning_seconds);
  return {
    idle_timeout_seconds: Number.isFinite(idle) && idle > 0 ? Math.floor(idle) : DEFAULT_TIMEOUT_POLICY.idle_timeout_seconds,
    max_session_duration_seconds: Number.isFinite(maxDuration) && maxDuration > 0 ? Math.floor(maxDuration) : DEFAULT_TIMEOUT_POLICY.max_session_duration_seconds,
    warning_seconds: Number.isFinite(warning) && warning > 0 ? Math.floor(warning) : DEFAULT_TIMEOUT_POLICY.warning_seconds,
  };
}

function normalizeVncCapabilities(input: unknown): VncCapabilities {
  if (!input || typeof input !== "object") {
    return { ...DEFAULT_VNC_CAPABILITIES };
  }
  const raw = input as Partial<Record<keyof VncCapabilities, unknown>>;
  return {
    clipboard: Boolean(raw.clipboard),
    file_transfer: Boolean(raw.file_transfer),
    drag_drop_upload: Boolean(raw.drag_drop_upload),
  };
}

export const createVncSession = async (payload: CreateVncSessionRequest): Promise<CreateVncSessionResponse> => {
  const resp = await api.post<CreateVncSessionResponse>("/api/vnc/session", payload);
  return {
    ...resp,
    capabilities: normalizeVncCapabilities(resp.capabilities),
    timeout_policy: normalizeTimeoutPolicy(resp.timeout_policy),
  };
};

export const deleteVncSession = (sessionId: string) =>
  api.del<DeleteVncSessionResponse>(`/api/vnc/session/${encodeURIComponent(sessionId)}`);

export const getVncTransferFallback = (sessionId: string) =>
  api.get<VncTransferFallbackResponse>(`/api/vnc/session/${encodeURIComponent(sessionId)}/transfer-fallback`);
