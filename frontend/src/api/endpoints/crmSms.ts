import { api } from "@/api/client";

// ─── EVT-014: CRM Contact SMS ────────────────────────────────────
// LIVE backend: app/routers/crm_contact_sms.py
//   prefix = /ui/crm/contacts
//   POST /{contact_id}/sms            (require_ui_session, 201) -> CrmContactSmsOut
//   GET  /{contact_id}/sms            (require_ui_session)      -> CrmContactSmsLogListOut
//     NOTE: the GET lists ALL sends by the authenticated sender (the
//           contact_id path param is currently ignored by the live service).
// Feature flag CRM_CONTACT_SMS_ENABLED defaults OFF -> all endpoints 404.

export interface CrmContactSmsOut {
  sms_id: string;
  contact_id: string;
  contact_phone: string; // masked, e.g. +*******4567
  status: string; // sent | dev_logged | suppressed | rate_limited | failed | disabled
  message_id: string;
  sent_at_ts: number;
}

export interface CrmContactSmsLogListOut {
  items: CrmContactSmsOut[];
  cursor: string | null;
}

export interface SendContactSmsReq {
  body: string; // 1..1600 chars
}

const BASE = "/ui/crm/contacts";

export const sendContactSms = (contactId: string, req: SendContactSmsReq) =>
  api.post<CrmContactSmsOut>(
    `${BASE}/${encodeURIComponent(contactId)}/sms`,
    req,
  );

export const listContactSmsLog = (
  contactId: string,
  opts?: { limit?: number; cursor?: string },
) => {
  const params: Record<string, string> = {};
  if (opts?.limit) params["limit"] = String(opts.limit);
  if (opts?.cursor) params["cursor"] = opts.cursor;
  return api.get<CrmContactSmsLogListOut>(
    `${BASE}/${encodeURIComponent(contactId)}/sms`,
    params,
  );
};
