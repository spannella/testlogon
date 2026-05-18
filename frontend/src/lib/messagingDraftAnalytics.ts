export type MessagingDraftEventName =
  | "draft_save"
  | "draft_load"
  | "draft_remove"
  | "draft_refresh"
  | "draft_update"
  | "draft_fallback";

export interface MessagingDraftEvent {
  event: MessagingDraftEventName;
  outcome: "success" | "failure";
  source: "server" | "local";
  reason?: string;
  conversation_id_present: boolean;
  at_ms: number;
}

const ALLOWED_KEYS: Array<keyof MessagingDraftEvent> = [
  "event",
  "outcome",
  "source",
  "reason",
  "conversation_id_present",
  "at_ms",
];

export function sanitizeMessagingDraftEvent(payload: MessagingDraftEvent): MessagingDraftEvent {
  const safe: Partial<MessagingDraftEvent> = {};
  for (const key of ALLOWED_KEYS) {
    if (payload[key] !== undefined) {
      safe[key] = payload[key];
    }
  }
  return safe as MessagingDraftEvent;
}

export function emitMessagingDraftEvent(payload: MessagingDraftEvent): void {
  if (typeof window === "undefined") return;
  const safe = sanitizeMessagingDraftEvent(payload);
  window.dispatchEvent(new CustomEvent<MessagingDraftEvent>("messaging:draft-analytics", { detail: safe }));
}
