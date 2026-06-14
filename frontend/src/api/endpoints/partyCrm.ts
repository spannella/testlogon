import { api } from "@/api/client";

// ─────────────────────────────────────────────────────────────────────────────
// SuiteCRM CONTACTS-EXTRA (CCT-001..006) — Party-CRM endpoint wrappers.
//
// LIVE backend: app/routers/party_cct.py
//   org_router    prefix /ui/party/orgs       (flag: party_crm_org_accounts_enabled)
//   party_router  prefix /ui/party/parties    (flag: party_crm_enabled)
//   vcard_router  prefix /ui/party            (flag: party_crm_enabled)
//   admin_router  prefix /ui/admin/party      (flag: party_crm_enabled, admin/root)
//
// All flags default OFF → endpoints return 503 ("not enabled"). The UI handles
// that with ApiError.status === 503 and a clear "not enabled" state.
//
// Types are defined INLINE here (mirror app/models.py Cct* models) — they are NOT
// added to the shared api/types.ts.
// ─────────────────────────────────────────────────────────────────────────────

export type CctPartyStatus = "ACTIVE" | "INACTIVE" | "MERGED" | "ARCHIVED";
export type CctPartyType = "PERSON" | "PARTY_GROUP";

export interface CctPartyRoleOut {
  role_type: string;
  org_party_id?: string | null;
  granted_at: number;
}

export interface CctRelationshipOut {
  rel_id: string;
  from_party_id: string;
  to_party_id: string;
  relationship_type: string;
  created_at: number;
  meta?: Record<string, unknown> | null;
}

export interface CctPartyOut {
  party_id: string;
  party_type: CctPartyType;
  status: CctPartyStatus;
  name: string;
  display_name?: string | null;
  owner_user_sub: string;
  created_at: number;
  updated_at: number;
  merged_into_party_id?: string | null;
  manager_party_id?: string | null;
  direct_report_count: number;
}

export interface CctOrgAccountOut {
  party_id: string;
  name: string;
  status: CctPartyStatus;
  roles: CctPartyRoleOut[];
  member_count: number;
  created_at: number;
  updated_at: number;
  // CCT-001 business metadata
  industry?: string | null;
  website?: string | null;
  phone?: string | null;
  employee_count?: number | null;
  annual_revenue_cents?: number | null;
  // CCT-002 hierarchy
  parent_org_party_id?: string | null;
  child_org_count: number;
}

export interface CctOrgAccountUpdateIn {
  name?: string | null;
  industry?: string | null;
  website?: string | null;
  phone?: string | null;
  employee_count?: number | null;
  annual_revenue_cents?: number | null;
}

export interface CctHierarchyOut {
  ancestors: CctRelationshipOut[];
  children: CctRelationshipOut[];
}

export interface CctReportsToOut {
  direction: string;
  chain: CctRelationshipOut[];
}

export interface CctDuplicateCandidateOut {
  party_a_id: string;
  party_b_id: string;
  score: number;
  match_signals: string[];
}

export interface CctDuplicateCandidateListOut {
  items: CctDuplicateCandidateOut[];
  cursor?: string | null;
}

// ─── CCT-001: org account business metadata ──────────────────────────────────

export const patchOrgAccount = (orgPartyId: string, body: CctOrgAccountUpdateIn) =>
  api.patch<CctOrgAccountOut>(`/ui/party/orgs/${encodeURIComponent(orgPartyId)}`, body);

// ─── CCT-002: org hierarchy (parent_org) ─────────────────────────────────────

export const getOrgHierarchy = (
  orgPartyId: string,
  direction: "ancestors" | "children" | "both" = "both",
) =>
  api.get<CctHierarchyOut>(
    `/ui/party/orgs/${encodeURIComponent(orgPartyId)}/hierarchy`,
    { direction },
  );

export const setParentOrg = (orgPartyId: string, parentOrgPartyId: string) =>
  api.put<CctRelationshipOut>(`/ui/party/orgs/${encodeURIComponent(orgPartyId)}/parent`, {
    parent_org_party_id: parentOrgPartyId,
  });

export const removeParentOrg = (orgPartyId: string) =>
  api.del<{ ok: boolean }>(`/ui/party/orgs/${encodeURIComponent(orgPartyId)}/parent`);

// ─── CCT-003: manager chain (REPORTS_TO) ─────────────────────────────────────

export const getReportsTo = (
  partyId: string,
  direction: "manager_chain" | "reports" = "manager_chain",
) =>
  api.get<CctReportsToOut>(
    `/ui/party/parties/${encodeURIComponent(partyId)}/reports-to`,
    { direction },
  );

export const setManager = (partyId: string, managerPartyId: string) =>
  api.put<CctRelationshipOut>(`/ui/party/parties/${encodeURIComponent(partyId)}/manager`, {
    manager_party_id: managerPartyId,
  });

export const removeManager = (partyId: string) =>
  api.del<{ ok: boolean }>(`/ui/party/parties/${encodeURIComponent(partyId)}/manager`);

// ─── CCT-004: duplicate detection ────────────────────────────────────────────

export const getDuplicatesForParty = (partyId: string) =>
  api.get<CctDuplicateCandidateOut[]>(
    `/ui/party/parties/${encodeURIComponent(partyId)}/duplicates`,
  );

export const listDuplicateCandidates = (cursor?: string) => {
  const params: Record<string, string> = {};
  if (cursor) params["cursor"] = cursor;
  return api.get<CctDuplicateCandidateListOut>(
    "/ui/admin/party/duplicate-candidates",
    params,
  );
};

// ─── CCT-005: party merge (admin/root) ───────────────────────────────────────

export const mergeParties = (winnerPartyId: string, loserPartyId: string) =>
  api.post<CctPartyOut>("/ui/party/parties/merge", {
    winner_party_id: winnerPartyId,
    loser_party_id: loserPartyId,
  });

// ─── CCT-006: vCard import ───────────────────────────────────────────────────

export const importVcard = (file: File) => {
  const fd = new FormData();
  fd.append("file", file);
  return api.upload<CctPartyOut[]>("/ui/party/vcard-import", fd);
};

// vCard export (per-party download URL — opened directly in browser, not fetched)
export const vcardExportUrl = (partyId: string) =>
  `/ui/party/parties/${encodeURIComponent(partyId)}/vcard`;
