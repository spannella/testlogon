import { api } from "@/api/client";
import type {
  DelegateAddReq,
  DelegateAuditOut,
  DelegateInviteRespondReq,
  DelegateOut,
  DelegateSettingsOut,
  DelegateSettingsReq,
  DelegateUpdatePermissionsReq,
  ManagedCreatorOut,
  PermissionPresetOut,
  DelegatedConversation,
  DelegatedMessage,
  DelegatedSendMessageReq,
  ChatDelegateAuditEntry,
} from "@/api/types";

const BASE = "/ui/delegates";

export async function listDelegates(): Promise<DelegateOut[]> {
  return api.get<DelegateOut[]>(BASE);
}

export async function addDelegate(req: DelegateAddReq): Promise<DelegateOut> {
  return api.post<DelegateOut>(BASE, req);
}

export async function getDelegate(delegateId: string): Promise<DelegateOut> {
  return api.get<DelegateOut>(`${BASE}/${delegateId}`);
}

export async function updateDelegatePermissions(
  delegateId: string,
  req: DelegateUpdatePermissionsReq,
): Promise<DelegateOut> {
  return api.put<DelegateOut>(`${BASE}/${delegateId}/permissions`, req);
}

export async function revokeDelegate(delegateId: string): Promise<void> {
  return api.del<void>(`${BASE}/${delegateId}`);
}

export async function listManagedCreators(): Promise<ManagedCreatorOut[]> {
  return api.get<ManagedCreatorOut[]>(`${BASE}/managed`);
}

export async function listInvites(): Promise<DelegateOut[]> {
  return api.get<DelegateOut[]>(`${BASE}/invites`);
}

export async function respondToInvite(
  creatorId: string,
  req: DelegateInviteRespondReq,
): Promise<{ ok: boolean; status: string }> {
  return api.post<{ ok: boolean; status: string }>(
    `${BASE}/invites/${creatorId}/respond`,
    req,
  );
}

export async function getDelegateSettings(): Promise<DelegateSettingsOut> {
  return api.get<DelegateSettingsOut>(`${BASE}/settings`);
}

export async function updateDelegateSettings(
  req: DelegateSettingsReq,
): Promise<DelegateSettingsOut> {
  return api.put<DelegateSettingsOut>(`${BASE}/settings`, req);
}

export async function getDelegateAudit(): Promise<DelegateAuditOut[]> {
  return api.get<DelegateAuditOut[]>(`${BASE}/audit`);
}

export async function listPresets(): Promise<PermissionPresetOut[]> {
  return api.get<PermissionPresetOut[]>(`${BASE}/presets`);
}

// ─── Chat Delegation (DELEGATE-002) ─────────────────────────────────

const MSG_BASE = "/messaging/delegate";

export async function listDelegatedConversations(
  creatorId: string,
): Promise<DelegatedConversation[]> {
  return api.get<DelegatedConversation[]>(
    `${MSG_BASE}/${creatorId}/conversations`,
  );
}

export async function listDelegatedMessages(
  creatorId: string,
  conversationId: string,
  params?: { limit?: number; before?: string },
): Promise<DelegatedMessage[]> {
  return api.get<DelegatedMessage[]>(
    `${MSG_BASE}/${creatorId}/conversations/${conversationId}/messages`,
    params,
  );
}

export async function sendDelegatedMessage(
  creatorId: string,
  conversationId: string,
  req: DelegatedSendMessageReq,
): Promise<DelegatedMessage> {
  return api.post<DelegatedMessage>(
    `${MSG_BASE}/${creatorId}/conversations/${conversationId}/messages`,
    req,
  );
}

export async function listChatDelegateAudit(
  creatorId: string,
  params?: { conversation_id?: string; limit?: number },
): Promise<ChatDelegateAuditEntry[]> {
  return api.get<ChatDelegateAuditEntry[]>(
    `${MSG_BASE}/${creatorId}/audit`,
    params,
  );
}
