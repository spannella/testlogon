import { api } from "@/api/client";
import type {
  WatchParty,
  WatchPartyParticipant,
  CreatePartyReq,
  PlaybackControlReq,
  InviteResolveResp,
} from "@/api/types";

export const createParty = (data: CreatePartyReq) =>
  api.post<WatchParty>("/ui/watch-parties/", data);

export const listParties = () =>
  api.get<WatchParty[]>("/ui/watch-parties/");

export const getParty = (partyId: string) =>
  api.get<WatchParty>(`/ui/watch-parties/${partyId}`);

export const resolveInvite = (inviteCode: string) =>
  api.get<InviteResolveResp>(`/ui/watch-parties/join/${inviteCode}`);

export const joinParty = (partyId: string) =>
  api.post<WatchPartyParticipant>(`/ui/watch-parties/${partyId}/join`);

export const leaveParty = (partyId: string) =>
  api.post(`/ui/watch-parties/${partyId}/leave`);

export const endParty = (partyId: string) =>
  api.post<WatchParty>(`/ui/watch-parties/${partyId}/end`);

export const controlPlayback = (partyId: string, data: PlaybackControlReq) =>
  api.post<WatchParty>(`/ui/watch-parties/${partyId}/control`, data);

export const listParticipants = (partyId: string) =>
  api.get<WatchPartyParticipant[]>(`/ui/watch-parties/${partyId}/participants`);

export const grantCoHost = (partyId: string, userSub: string) =>
  api.post(`/ui/watch-parties/${partyId}/co-host`, { user_sub: userSub });

export const kickParticipant = (partyId: string, userSub: string) =>
  api.post(`/ui/watch-parties/${partyId}/kick/${userSub}`);

export const sendHeartbeat = (partyId: string) =>
  api.post(`/ui/watch-parties/${partyId}/heartbeat`);

export const getPlaybackUrl = (partyId: string) =>
  api.get<{ url: string; video_id: string }>(`/ui/watch-parties/${partyId}/playback-url`);
