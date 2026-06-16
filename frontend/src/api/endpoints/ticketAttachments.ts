import { api, withApiBase } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// Ticket attachments (TKA). Upload flow mirrors the messaging image presign:
//   1. POST /tickets/{id}/attachments/presign  → { attachment_id, upload_url, … }
//   2. PUT the bytes to upload_url (relative /mock/s3/... in dev)
//   3. POST /tickets/{id}/attachments          → TicketAttachmentOut (confirm)
//
// Feature-gated: 404 when ticket_attachments_enabled is off — callers handle it.
// ─────────────────────────────────────────────────────────────────────────────

export interface TicketAttachmentOut {
  attachment_id: string;
  ticket_id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: string;
  created_at: number;
  sha256?: string | null;
}

export interface TicketAttachmentPresignOut {
  attachment_id: string;
  upload_url: string;
  bucket: string;
  key: string;
  content_type: string;
}

export interface TicketAttachmentListOut {
  attachments: TicketAttachmentOut[];
}

export const presignTicketAttachment = (
  ticketId: string,
  body: { filename: string; content_type: string },
) =>
  api.post<TicketAttachmentPresignOut>(
    `/tickets/${encodeURIComponent(ticketId)}/attachments/presign`,
    body,
  );

export const confirmTicketAttachment = (
  ticketId: string,
  body: {
    attachment_id: string;
    filename: string;
    content_type: string;
    size_bytes: number;
    sha256?: string;
  },
) =>
  api.post<TicketAttachmentOut>(
    `/tickets/${encodeURIComponent(ticketId)}/attachments`,
    body,
  );

export const listTicketAttachments = (ticketId: string) =>
  api.get<TicketAttachmentListOut>(
    `/tickets/${encodeURIComponent(ticketId)}/attachments`,
  );

export const getTicketAttachmentDownloadUrl = (
  ticketId: string,
  attachmentId: string,
) =>
  api.get<{ download_url: string }>(
    `/tickets/${encodeURIComponent(ticketId)}/attachments/${encodeURIComponent(attachmentId)}/download`,
  );

export const deleteTicketAttachment = (ticketId: string, attachmentId: string) =>
  api.del<void>(
    `/tickets/${encodeURIComponent(ticketId)}/attachments/${encodeURIComponent(attachmentId)}`,
  );

/** PUT raw file bytes to the presigned upload URL (relative in dev). */
export const uploadTicketAttachmentBytes = async (
  uploadUrl: string,
  file: File,
  contentType: string,
) => {
  const resp = await fetch(withApiBase(uploadUrl), {
    method: "PUT",
    body: file,
    headers: { "Content-Type": contentType },
  });
  if (!resp.ok) {
    throw new Error("Failed to upload attachment");
  }
};

/** Full presign → PUT → confirm flow. Returns the confirmed attachment. */
export const uploadTicketAttachment = async (
  ticketId: string,
  file: File,
): Promise<TicketAttachmentOut> => {
  const contentType = file.type || "application/octet-stream";
  const presign = await presignTicketAttachment(ticketId, {
    filename: file.name,
    content_type: contentType,
  });
  await uploadTicketAttachmentBytes(
    presign.upload_url,
    file,
    presign.content_type || contentType,
  );
  return confirmTicketAttachment(ticketId, {
    attachment_id: presign.attachment_id,
    filename: file.name,
    content_type: presign.content_type || contentType,
    size_bytes: file.size,
  });
};
