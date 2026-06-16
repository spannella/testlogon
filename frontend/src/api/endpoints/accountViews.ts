/**
 * VEW-001..005 — Account Views API
 *
 * Field-level access delegation for financial resources:
 *   wallet / ledger_account / payout_destination
 *
 * Backend router: app/routers/account_views.py
 * Paths: /ui/views/* (auth) + /ui/views/public/* (unauthenticated)
 * Feature flags: OPEN_BANK_PROJECT_ENABLED + ACCOUNT_VIEWS_ENABLED
 *   → 404 when either flag is off; handle with ApiError.status === 404.
 */

import { api } from "@/api/client";

// ─── Resource types ────────────────────────────────────────────────────────────

export type ResourceType = "wallet" | "ledger_account" | "payout_destination";

// ─── Grant field catalog ───────────────────────────────────────────────────────

export type GrantField =
  | "can_see_balance"
  | "can_see_available_balance"
  | "can_see_transaction_list"
  | "can_see_transaction_amount"
  | "can_see_transaction_description"
  | "can_see_counterparty"
  | "can_see_counterparty_name"
  | "can_see_owners"
  | "can_see_account_label"
  | "can_see_payout_destination_masked"
  | "can_add_comment"
  | "can_add_tag"
  | "can_add_narrative"
  | "can_delete_comment";

export type GrantsMatrix = Partial<Record<GrantField, boolean>>;

// ─── Preset ───────────────────────────────────────────────────────────────────

export interface PresetOut {
  key: string;
  label: string;
  grants: GrantsMatrix;
}

export interface GrantCatalogOut {
  fields: GrantField[];
  presets: PresetOut[];
}

// ─── View (VEW-001) ───────────────────────────────────────────────────────────

export interface ViewOut {
  view_id: string;
  resource_type: ResourceType;
  resource_id: string;
  owner_sub: string;
  name: string;
  description: string;
  is_system_alias: boolean;
  grants: GrantsMatrix;
  preset: string | null;
  metadata_visibility: string;
  created_at: number;
  updated_at: number;
}

export interface ViewCreateIn {
  name: string;
  grants: GrantsMatrix;
  preset?: string;
  description?: string;
  metadata_visibility?: string;
}

export interface ViewUpdateIn {
  name?: string;
  grants?: GrantsMatrix;
  description?: string;
  metadata_visibility?: string;
}

// ─── Grant (VEW-002) ──────────────────────────────────────────────────────────

export interface ViewGrantOut {
  grant_id: string;
  view_id: string;
  grantee_sub: string;
  owner_sub: string;
  resource_type: ResourceType;
  resource_id: string;
  status: "pending" | "active" | "revoked";
  invited_at: number;
  accepted_at: number;
  updated_at: number;
}

export interface ViewGrantListOut {
  grants: ViewGrantOut[];
  next_cursor: string | null;
}

export interface SharedWithMeOut {
  grants: ViewGrantOut[];
  next_cursor: string | null;
}

// ─── Public link (VEW-002) ────────────────────────────────────────────────────

export interface PublicViewLinkOut {
  url: string;
  token: string;
  expires_at: number;
}

// ─── Resource projection (VEW-003) ───────────────────────────────────────────

export interface ViewProvenanceOut {
  view_id: string;
  view_name: string;
  preset: string | null;
  granted_fields: string[];
}

export interface ViewedResourceOut {
  resource_type: ResourceType;
  resource_id: string;
  data: Record<string, unknown>;
  _view: ViewProvenanceOut;
  expires_at?: number;
}

// ─── Grant catalog ────────────────────────────────────────────────────────────

/** GET /ui/views/grant-catalog */
export const getGrantCatalog = () =>
  api.get<GrantCatalogOut>("/ui/views/grant-catalog");

// ─── Shared-with-me (VEW-002) ─────────────────────────────────────────────────

/** GET /ui/views/shared-with-me */
export const listSharedWithMe = (params?: { cursor?: string; limit?: number }) => {
  const p: Record<string, string> = {};
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<SharedWithMeOut>("/ui/views/shared-with-me", p);
};

// ─── VEW-001 — View CRUD ─────────────────────────────────────────────────────

/** POST /ui/views/{resource_type}/{resource_id} */
export const createView = (
  resourceType: ResourceType,
  resourceId: string,
  body: ViewCreateIn,
) =>
  api.post<ViewOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}`,
    body,
  );

/** GET /ui/views/{resource_type}/{resource_id} */
export const listViews = (resourceType: ResourceType, resourceId: string) =>
  api.get<ViewOut[]>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}`,
  );

/** GET /ui/views/{resource_type}/{resource_id}/{view_id} */
export const getView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
) =>
  api.get<ViewOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}`,
  );

/** PATCH /ui/views/{resource_type}/{resource_id}/{view_id} */
export const updateView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  body: ViewUpdateIn,
) =>
  api.patch<ViewOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}`,
    body,
  );

/** DELETE /ui/views/{resource_type}/{resource_id}/{view_id} */
export const deleteView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
) =>
  api.del<void>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}`,
  );

// ─── VEW-002 — Grant management ──────────────────────────────────────────────

/** POST /ui/views/{resource_type}/{resource_id}/{view_id}/grants */
export const grantView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  granteeSub: string,
) =>
  api.post<ViewGrantOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/grants`,
    { grantee_sub: granteeSub },
  );

/** GET /ui/views/{resource_type}/{resource_id}/{view_id}/grants */
export const listGrantsForView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  params?: { cursor?: string; limit?: number },
) => {
  const p: Record<string, string> = {};
  if (params?.cursor) p["cursor"] = params.cursor;
  if (params?.limit) p["limit"] = String(params.limit);
  return api.get<ViewGrantListOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/grants`,
    p,
  );
};

/** DELETE /ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee_sub} */
export const revokeGrant = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  granteeSub: string,
) =>
  api.del<void>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/grants/${encodeURIComponent(granteeSub)}`,
  );

/** POST /ui/views/{resource_type}/{resource_id}/{view_id}/grants/{grantee_sub}/respond */
export const respondToGrant = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  granteeSub: string,
  accept: boolean,
) =>
  api.post<ViewGrantOut | null>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/grants/${encodeURIComponent(granteeSub)}/respond`,
    { accept },
  );

// ─── VEW-002 — Public link ───────────────────────────────────────────────────

/** POST /ui/views/{resource_type}/{resource_id}/{view_id}/public-link */
export const createPublicLink = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
  ttlDays?: number,
) =>
  api.post<PublicViewLinkOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/public-link`,
    { ttl_days: ttlDays ?? null },
  );

/** DELETE /ui/views/public/{token} — revoke a public link */
export const revokePublicLink = (token: string) =>
  api.del<void>(`/ui/views/public/${encodeURIComponent(token)}`);

// ─── VEW-003 — Read resource through view (authenticated) ────────────────────

/** GET /ui/views/{resource_type}/{resource_id}/{view_id}/data */
export const readResourceThroughView = (
  resourceType: ResourceType,
  resourceId: string,
  viewId: string,
) =>
  api.get<ViewedResourceOut>(
    `/ui/views/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}/${encodeURIComponent(viewId)}/data`,
  );

// ─── VEW-003 — Public (unauthenticated) read ─────────────────────────────────

/** GET /ui/views/public/{token} — unauthenticated read through public link */
export const readPublicView = (token: string) =>
  api.get<ViewedResourceOut>(`/ui/views/public/${encodeURIComponent(token)}`);
