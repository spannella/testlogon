import { useAuthStore } from "@/stores/authStore";
import { api, normalizeErrorDetail } from "@/api/client";

export type SignatureOriginChannel = "share" | "message";
export type SignatureFieldType = "signature" | "initials" | "date" | "text" | "notary_stamp";

export type SignaturePacketStatus =
  | "draft"
  | "sent"
  | "partially_signed"
  | "completed"
  | "cancelled"
  | "expired";

export interface SignaturePacketSigner {
  signer_id: string;
  status: "pending" | "completed";
  [key: string]: unknown;
}

export type SignatureInputMode = "typed" | "drawn";

export interface SignaturePacketField {
  field_id: string;
  page: number;
  x: number;
  y: number;
  width: number;
  height: number;
  field_type: SignatureFieldType;
  required: boolean;
  assigned_signer_id?: string;
  is_assigned_to_viewer?: boolean;
  filled_at?: string;
  value?: string;
  capture_mode?: SignatureInputMode;
  render_payload?: Record<string, unknown>;
}

export interface SignaturePacketDetail {
  packet_id: string;
  status: SignaturePacketStatus;
  owner_user_id: string;
  source_path: string;
  role: "sender" | "signer";
  signer_status?: "pending" | "completed";
  created_at?: string;
  sent_at?: string;
  completed_at?: string;
  signers: SignaturePacketSigner[];
  fields: SignaturePacketField[];
  capabilities: {
    can_edit_fields: boolean;
    can_send: boolean;
    can_fill_fields: boolean;
  };
  legal_notice?: {
    required: boolean;
    accepted: boolean;
    version: string;
    text: string;
  };
  [key: string]: unknown;
}

export interface CreateSignaturePacketReq {
  source_path: string;
  origin_channel: SignatureOriginChannel;
  origin_ref?: string;
}

export interface CreateSignaturePacketResp {
  packet_id: string;
  status: SignaturePacketStatus;
  owner_user_id: string;
  source_path: string;
  origin_channel: SignatureOriginChannel;
  origin_ref?: string;
  created_at: string;
}

export const createSignaturePacket = (body: CreateSignaturePacketReq) =>
  api.post<CreateSignaturePacketResp>("/v1/signature-packets", body);

export const getSignaturePacketDetail = (packetId: string) =>
  api.get<SignaturePacketDetail>(`/v1/signature-packets/${encodeURIComponent(packetId)}`);

export const createSignaturePacketField = (
  packetId: string,
  body: {
    action: "create";
    page: number;
    x: number;
    y: number;
    width: number;
    height: number;
    field_type: SignatureFieldType;
    assigned_signer_id?: string;
    required: boolean;
  },
) => api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/fields`, body);

export const deleteSignaturePacketField = (packetId: string, fieldId: string) =>
  api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/fields`, {
    action: "delete",
    field_id: fieldId,
  });

export const sendSignaturePacket = (packetId: string) =>
  api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/send`, {});

export const fillSignaturePacketField = (
  packetId: string,
  fieldId: string,
  body: {
    value?: string;
    input_mode?: SignatureInputMode;
    drawn_strokes?: number[][];
  },
) => api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/fields/${encodeURIComponent(fieldId)}/fill`, body);

export const markSignaturePacketDone = (packetId: string) =>
  api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/mark-done`, {});

export const acknowledgeSignaturePacketLegalNotice = (packetId: string) =>
  api.post(`/v1/signature-packets/${encodeURIComponent(packetId)}/acknowledge-legal-notice`, {});

export const downloadSignaturePacketFinalPdf = async (packetId: string): Promise<void> => {
  const accessToken = useAuthStore.getState().accessToken;
  const headers = new Headers();
  if (accessToken) headers.set("Authorization", `Bearer ${accessToken}`);

  const response = await fetch(`/v1/signature-packets/${encodeURIComponent(packetId)}/final-pdf`, {
    method: "GET",
    credentials: "include",
    headers,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(normalizeErrorDetail((body as { detail?: unknown } | null)?.detail, response.statusText));
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `signature-packet-${packetId}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
};
