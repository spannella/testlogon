import { useAuthStore } from "@/stores/authStore";
import { api, normalizeErrorDetail } from "@/api/client";

export type SignatureOriginChannel = "share" | "message" | "file_manager" | "kyc";
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

// ─── SUX-008: "Awaiting my signature" / sent / completed inbox ───────────────

export interface SigningInboxItem {
  packet_id: string;
  owner_user_id?: string | null;
  source_name?: string | null;
  status: SignaturePacketStatus | string;
  status_chip?: string | null;
  status_text?: string | null;
  role?: string | null;
  created_at?: string | null;
  sent_at?: string | null;
  completed_at?: string | null;
}

export interface SigningInboxList {
  items: SigningInboxItem[];
  count: number;
}

export const listAwaitingSignature = (limit = 100) =>
  api.get<SigningInboxList>("/v1/signature-packets/awaiting", { limit: String(limit) });

export const listSentPackets = (limit = 100) =>
  api.get<SigningInboxList>("/v1/signature-packets/sent", { limit: String(limit) });

export const listCompletedForMe = (limit = 100) =>
  api.get<SigningInboxList>("/v1/signature-packets/completed-for-me", { limit: String(limit) });

export const listDraftPackets = (limit = 100) =>
  api.get<SigningInboxList>("/v1/signature-packets/drafts", { limit: String(limit) });

// ─── SUX-005: owner mint/revoke per-signer public signing link ───────────────

export interface CreateSigningLinkResp {
  packet_id: string;
  signer_id: string;
  url: string;
  expires_at: number;
}

export interface RevokeSigningLinkResp {
  packet_id: string;
  signer_id: string;
  jti: string;
  revoked: boolean;
}

export const createSignerSigningLink = (packetId: string, signerId: string) =>
  api.post<CreateSigningLinkResp>(
    `/v1/signature-packets/${encodeURIComponent(packetId)}/signers/${encodeURIComponent(signerId)}/link`,
    {},
  );

export const revokeSignerSigningLink = (packetId: string, signerId: string, jti: string) =>
  api.post<RevokeSigningLinkResp>(
    `/v1/signature-packets/${encodeURIComponent(packetId)}/signers/${encodeURIComponent(signerId)}/link/revoke`,
    { jti },
  );

// ─── SUX-006: public (login-free) signing endpoints (token-scoped) ───────────
// These hit /ui/sign/{token}; the token binds packet_id + signer_id server-side.
// `silent403` keeps invalid/expired/used tokens from firing a global toast — the
// PublicSigningPage renders a friendly terminal state from the thrown ApiError.

export const getPublicSigningDetail = (token: string) =>
  api<SignaturePacketDetail>(`/ui/sign/${encodeURIComponent(token)}`, {
    method: "GET",
    silent403: true,
  });

export const fillPublicSigningField = (
  token: string,
  fieldId: string,
  body: {
    value?: string;
    input_mode?: SignatureInputMode;
    drawn_strokes?: number[][];
  },
) =>
  api(`/ui/sign/${encodeURIComponent(token)}/fields/${encodeURIComponent(fieldId)}/fill`, {
    method: "POST",
    body: JSON.stringify(body),
    silent403: true,
  });

export const acknowledgePublicSigningLegalNotice = (token: string) =>
  api(`/ui/sign/${encodeURIComponent(token)}/acknowledge-legal-notice`, {
    method: "POST",
    body: JSON.stringify({}),
    silent403: true,
  });

export const markPublicSigningDone = (token: string) =>
  api(`/ui/sign/${encodeURIComponent(token)}/mark-done`, {
    method: "POST",
    body: JSON.stringify({}),
    silent403: true,
  });

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
