import { api } from "@/api/client";
import type {
  BroadcastInputList,
  BroadcastInputCreated,
  BroadcastLayout,
  BroadcastGuestInvite,
  BroadcastGuestInviteList,
  BroadcastGuestAcceptResult,
  BroadcastWebRTCAnswer,
} from "@/api/types";

const BASE = "/broadcast/sessions";

// ─── Inputs ──────────────────────────────────────────────────────

export async function listInputs(sessionId: string): Promise<BroadcastInputList> {
  return api.get<BroadcastInputList>(`${BASE}/${sessionId}/inputs`);
}

export async function addInput(
  sessionId: string,
  body: { input_type?: string; label?: string },
): Promise<BroadcastInputCreated> {
  return api.post<BroadcastInputCreated>(`${BASE}/${sessionId}/inputs`, body);
}

export async function removeInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  return api.del<{ ok: boolean }>(`${BASE}/${sessionId}/inputs/${inputId}`);
}

export async function activateInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/inputs/${inputId}/activate`);
}

export async function deactivateInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/inputs/${inputId}/deactivate`);
}

// ─── Layout ──────────────────────────────────────────────────────

export async function switchLayout(
  sessionId: string,
  body: { mode: string; primary_input_id?: string | null; input_ids?: string[] | null },
): Promise<BroadcastLayout> {
  return api.post<BroadcastLayout>(`${BASE}/${sessionId}/layout`, body);
}

export async function getLayout(sessionId: string): Promise<BroadcastLayout> {
  return api.get<BroadcastLayout>(`${BASE}/${sessionId}/layout`);
}

// ─── Guest Invites ──────────────────────────────────────────────

export async function createGuestInvite(
  sessionId: string,
  body: { join_mode?: string; label?: string; expiry_minutes?: number },
): Promise<BroadcastGuestInvite> {
  return api.post<BroadcastGuestInvite>(`${BASE}/${sessionId}/guest-invites`, body);
}

export async function listGuestInvites(sessionId: string): Promise<BroadcastGuestInviteList> {
  return api.get<BroadcastGuestInviteList>(`${BASE}/${sessionId}/guest-invites`);
}

export async function acceptGuestInvite(
  sessionId: string,
  inviteId: string,
  body: { display_name: string },
): Promise<BroadcastGuestAcceptResult> {
  return api.post<BroadcastGuestAcceptResult>(
    `${BASE}/${sessionId}/guest-invites/${inviteId}/accept`,
    body,
  );
}

export async function revokeGuestInvite(
  sessionId: string,
  inviteId: string,
): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/guest-invites/${inviteId}/revoke`);
}

// ─── Guest Management ───────────────────────────────────────────

export async function removeGuest(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/guests/${inputId}/remove`);
}

export async function muteGuest(
  sessionId: string,
  inputId: string,
  body: { muted: boolean },
): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/guests/${inputId}/mute`, body);
}

export async function promoteGuest(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  return api.post<{ ok: boolean }>(`${BASE}/${sessionId}/guests/${inputId}/promote`);
}

// ─── WebRTC ─────────────────────────────────────────────────────

export async function sendWebRTCOffer(
  sessionId: string,
  inputId: string,
  body: { sdp_offer: string },
): Promise<BroadcastWebRTCAnswer> {
  return api.post<BroadcastWebRTCAnswer>(
    `${BASE}/${sessionId}/inputs/${inputId}/webrtc-offer`,
    body,
  );
}
