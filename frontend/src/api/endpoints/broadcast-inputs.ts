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
  const { data } = await api.get(`${BASE}/${sessionId}/inputs`);
  return data;
}

export async function addInput(
  sessionId: string,
  body: { input_type?: string; label?: string },
): Promise<BroadcastInputCreated> {
  const { data } = await api.post(`${BASE}/${sessionId}/inputs`, body);
  return data;
}

export async function removeInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  const { data } = await api.delete(`${BASE}/${sessionId}/inputs/${inputId}`);
  return data;
}

export async function activateInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/inputs/${inputId}/activate`);
  return data;
}

export async function deactivateInput(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/inputs/${inputId}/deactivate`);
  return data;
}

// ─── Layout ──────────────────────────────────────────────────────

export async function switchLayout(
  sessionId: string,
  body: { mode: string; primary_input_id?: string | null; input_ids?: string[] | null },
): Promise<BroadcastLayout> {
  const { data } = await api.post(`${BASE}/${sessionId}/layout`, body);
  return data;
}

export async function getLayout(sessionId: string): Promise<BroadcastLayout> {
  const { data } = await api.get(`${BASE}/${sessionId}/layout`);
  return data;
}

// ─── Guest Invites ──────────────────────────────────────────────

export async function createGuestInvite(
  sessionId: string,
  body: { join_mode?: string; label?: string; expiry_minutes?: number },
): Promise<BroadcastGuestInvite> {
  const { data } = await api.post(`${BASE}/${sessionId}/guest-invites`, body);
  return data;
}

export async function listGuestInvites(sessionId: string): Promise<BroadcastGuestInviteList> {
  const { data } = await api.get(`${BASE}/${sessionId}/guest-invites`);
  return data;
}

export async function acceptGuestInvite(
  sessionId: string,
  inviteId: string,
  body: { display_name: string },
): Promise<BroadcastGuestAcceptResult> {
  const { data } = await api.post(`${BASE}/${sessionId}/guest-invites/${inviteId}/accept`, body);
  return data;
}

export async function revokeGuestInvite(
  sessionId: string,
  inviteId: string,
): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/guest-invites/${inviteId}/revoke`);
  return data;
}

// ─── Guest Management ───────────────────────────────────────────

export async function removeGuest(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/guests/${inputId}/remove`);
  return data;
}

export async function muteGuest(
  sessionId: string,
  inputId: string,
  body: { muted: boolean },
): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/guests/${inputId}/mute`, body);
  return data;
}

export async function promoteGuest(sessionId: string, inputId: string): Promise<{ ok: boolean }> {
  const { data } = await api.post(`${BASE}/${sessionId}/guests/${inputId}/promote`);
  return data;
}

// ─── WebRTC ─────────────────────────────────────────────────────

export async function sendWebRTCOffer(
  sessionId: string,
  inputId: string,
  body: { sdp_offer: string },
): Promise<BroadcastWebRTCAnswer> {
  const { data } = await api.post(`${BASE}/${sessionId}/inputs/${inputId}/webrtc-offer`, body);
  return data;
}
