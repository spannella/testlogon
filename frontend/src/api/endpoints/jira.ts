import { api } from "@/api/client";

export interface JiraConnection {
  connection_id: string;
  workspace_id: string;
  cloud_id: string;
  site_url: string;
  status: string;
  scopes: string[];
  updated_at?: number | null;
}

export interface JiraStatusResp {
  connected: boolean;
  items: JiraConnection[];
}

export interface JiraConnectResp {
  connect_url: string;
  state: string;
}

export interface JiraCallbackResp {
  status: "connected" | "failed";
  connection_id?: string | null;
  error_code?: string | null;
}

export interface JiraProject {
  cloud_id: string;
  project_id: string;
  project_key: string;
  name: string;
  is_private: boolean;
}

export interface JiraProjectsResp {
  items: JiraProject[];
  next_cursor?: string | null;
}

export interface JiraProjectPreferencesResp {
  workspace_id: string;
  cloud_id: string;
  project_keys: string[];
  updated_at?: number | null;
}

export interface TicketJiraSyncStatus {
  ticket_id: string;
  linked: boolean;
  provider?: "jira" | null;
  sync_state: "not_linked" | "queued" | "in_sync" | "conflict" | "failed";
  link_id?: string | null;
  external_issue_id?: string | null;
  external_issue_key?: string | null;
  jira_status?: string | null;
  last_synced_at?: number | null;
  conflict_fields: string[];
  conflict_local_values: Record<string, unknown>;
  conflict_remote_values: Record<string, unknown>;
}

export function getJiraStatus(workspaceId: string) {
  return api<JiraStatusResp>("/integrations/jira/status", { params: { workspace_id: workspaceId } });
}

export function beginJiraConnect(workspaceId: string, redirectUri: string) {
  return api<JiraConnectResp>("/integrations/jira/connect", {
    method: "POST",
    body: JSON.stringify({ workspace_id: workspaceId, redirect_uri: redirectUri }),
  });
}

export function completeJiraCallback(code: string, state: string) {
  return api<JiraCallbackResp>("/integrations/jira/callback", { params: { code, state } });
}

export function disconnectJira(workspaceId: string, connectionId: string) {
  return api<{ ok: boolean }>("/integrations/jira/disconnect", {
    method: "POST",
    body: JSON.stringify({ workspace_id: workspaceId, connection_id: connectionId }),
  });
}

export function listJiraProjects(workspaceId: string, cloudId: string) {
  return api<JiraProjectsResp>("/integrations/jira/projects", {
    params: { workspace_id: workspaceId, cloud_id: cloudId, limit: "100" },
  });
}

export function getJiraPreferences(workspaceId: string, cloudId: string) {
  return api<JiraProjectPreferencesResp>("/integrations/jira/preferences", {
    params: { workspace_id: workspaceId, cloud_id: cloudId },
  });
}

export function putJiraPreferences(workspaceId: string, cloudId: string, projectKeys: string[]) {
  return api<JiraProjectPreferencesResp>("/integrations/jira/preferences", {
    method: "PUT",
    body: JSON.stringify({
      workspace_id: workspaceId,
      cloud_id: cloudId,
      project_keys: projectKeys,
    }),
  });
}

export function getTicketJiraSyncStatus(ticketId: string) {
  return api<TicketJiraSyncStatus>(`/tickets/${ticketId}/sync-status`, { method: "GET" });
}

export function linkExistingJiraIssueToTicket(opts: {
  ticketId: string;
  workspaceId: string;
  externalIssueKey: string;
  linkMode?: "push_only" | "pull_only" | "bidirectional";
}) {
  return api<{ ticket_id: string; link_id: string; external_issue_key: string; sync_state: string }>(
    `/tickets/${opts.ticketId}/external-links/jira/link-existing`,
    {
      method: "POST",
      headers: { "Idempotency-Key": `ui-link-${Date.now()}-${Math.random().toString(36).slice(2, 10)}` },
      body: JSON.stringify({
        workspace_id: opts.workspaceId,
        external_issue_key: opts.externalIssueKey,
        link_mode: opts.linkMode ?? "bidirectional",
      }),
    },
  );
}

export function unlinkJiraIssueFromTicket(ticketId: string, linkId: string) {
  return api<{ ticket_id: string; link_id: string; sync_state: string }>(
    `/tickets/${ticketId}/external-links/${linkId}`,
    { method: "DELETE" },
  );
}

export function resolveJiraConflict(opts: {
  ticketId: string;
  linkId: string;
  workspaceId: string;
  action: "keep_internal" | "keep_jira";
  currentTicket: Record<string, unknown>;
}) {
  return api<{ ticket_id: string; link_id: string; action: string; sync_state: "in_sync"; follow_up_tasks: number }>(
    `/tickets/${opts.ticketId}/external-links/${opts.linkId}/resolve-conflict`,
    {
      method: "POST",
      body: JSON.stringify({
        workspace_id: opts.workspaceId,
        action: opts.action,
        current_ticket: opts.currentTicket,
      }),
    },
  );
}
