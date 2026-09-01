// Pure, side-effect-free helpers for conversation-lifecycle UI decisions.
//
// The backend (app/routers/messaging.py) exposes:
//   POST   /messaging/conversations/{id}/accept                    — accept a pending invite
//   POST   /messaging/conversations/{id}/leave                     — leave (active) OR decline (pending)
//   DELETE /messaging/conversations/{id}                           — delete when last active participant
//   DELETE /messaging/conversations/{id}/participants/{pid}        — admin removes a participant
//   PATCH  /messaging/conversations/{id}/participants/{pid}        — admin changes a role
//
// The viewer's own membership status is projected onto Conversation.status by the
// backend (`participant.get("status", ...)` in _conversation_out_from_items), so we
// key the guards off that plus the viewer's role.

export type ParticipantRole = "admin" | "member";
export type MembershipStatus = "pending" | "active" | "left" | string;

/** Minimal shape needed for lifecycle decisions (a Conversation satisfies this). */
export interface ConversationLifecycleView {
  /** The VIEWER's membership status, as projected onto Conversation.status. */
  status?: MembershipStatus;
  type?: "dm" | "group" | string;
  /** Count of participants the client knows about (may include left members). */
  participants?: Array<{ user_id: string; status?: string; role?: ParticipantRole | string }>;
}

/** True when the viewer has a pending (not-yet-accepted) invite to this conversation. */
export function isPendingInvite(convo: ConversationLifecycleView | null | undefined): boolean {
  return (convo?.status ?? "") === "pending";
}

/** True when the viewer is an active participant. */
export function isActiveMember(convo: ConversationLifecycleView | null | undefined): boolean {
  return (convo?.status ?? "") === "active";
}

/** Number of participants currently in the "active" state. */
export function activeParticipantCount(convo: ConversationLifecycleView | null | undefined): number {
  const parts = convo?.participants ?? [];
  return parts.filter((p) => (p.status ?? "active") === "active").length;
}

/**
 * The viewer can leave when they are an active member. Leaving a conversation you
 * only have a pending invite to is expressed as "decline" (also POST /leave), so
 * canLeave is specifically about the active case.
 */
export function canLeave(convo: ConversationLifecycleView | null | undefined): boolean {
  return isActiveMember(convo);
}

/**
 * A pending invite can be accepted or declined. Decline maps to the same /leave
 * endpoint on the backend, but we surface it separately in the UI.
 */
export function canRespondToInvite(convo: ConversationLifecycleView | null | undefined): boolean {
  return isPendingInvite(convo);
}

/**
 * Delete is only allowed for the last remaining active participant — the backend
 * rejects deletion while other active participants exist. We optimistically allow
 * the action when the viewer is active and is the only known active participant;
 * the backend remains the source of truth (a stale client count degrades to a 400
 * -> error toast).
 */
export function canDelete(convo: ConversationLifecycleView | null | undefined): boolean {
  if (!isActiveMember(convo)) return false;
  const active = activeParticipantCount(convo);
  // If we have participant data, require the viewer to be the only active one.
  // With no participant data we still permit the attempt (backend will gate it).
  return active <= 1;
}

/**
 * Participant management (remove member / change role) is admin-only. Determined
 * from the viewer's own participant record.
 */
export function canManageParticipants(
  convo: ConversationLifecycleView | null | undefined,
  viewerUserId: string | null | undefined,
): boolean {
  if (!isActiveMember(convo)) return false;
  if ((convo?.type ?? "dm") !== "group") return false;
  if (!viewerUserId) return false;
  const me = (convo?.participants ?? []).find((p) => p.user_id === viewerUserId);
  return (me?.role ?? "member") === "admin";
}

/**
 * An admin may remove any OTHER active participant — never themselves (the backend
 * returns 400 "Use /leave to remove yourself").
 */
export function canRemoveParticipant(
  convo: ConversationLifecycleView | null | undefined,
  viewerUserId: string | null | undefined,
  targetUserId: string,
): boolean {
  if (!canManageParticipants(convo, viewerUserId)) return false;
  return targetUserId !== viewerUserId;
}

/** Human label for the primary lifecycle action available to the viewer. */
export function leaveActionLabel(convo: ConversationLifecycleView | null | undefined): string {
  if (isPendingInvite(convo)) return "Decline invite";
  return "Leave conversation";
}

/** Human label for the destructive delete action. */
export function deleteActionLabel(convo: ConversationLifecycleView | null | undefined): string {
  return (convo?.type ?? "dm") === "group" ? "Delete group" : "Delete conversation";
}

/** Label for the role toggle on a given participant. */
export function roleToggleLabel(currentRole: ParticipantRole | string | undefined): string {
  return (currentRole ?? "member") === "admin" ? "Demote to member" : "Promote to admin";
}

/** The role a toggle would move a participant to. */
export function nextRole(currentRole: ParticipantRole | string | undefined): ParticipantRole {
  return (currentRole ?? "member") === "admin" ? "member" : "admin";
}
