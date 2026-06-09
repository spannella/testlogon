import { api } from "@/api/client";
import type {
  HoneytokenMintIn,
  HoneytokenMintOut,
  HoneytokenOut,
  HoneytokenHitsOut,
  HoneytokenRetireOut,
  SecurityEventOut,
  SecurityEventListOut,
  SecurityOverviewOut,
} from "@/api/types";

// Defensive-only security tooling (HNY workstream).
//
// Honeytoken CRUD/hits (HNY-007) is live on the committed backend at
// /v1/admin/security/honeytokens (root-gated). The unified dashboard
// aggregation endpoints (HNY-013/014 — /overview, /events) may not yet be
// mounted in every environment; callers should tolerate a 404 and render
// zeroed sections (the security_dashboard_enabled flag also defaults OFF).

const HONEYTOKENS = "/v1/admin/security/honeytokens";
const DASHBOARD = "/v1/admin/security";

// ── Honeytoken CRUD (HNY-007, root-gated, live) ──────────────────────────────

export const listHoneytokens = () => api.get<HoneytokenOut[]>(HONEYTOKENS);

export const mintHoneytoken = (body: HoneytokenMintIn) =>
  api.post<HoneytokenMintOut>(HONEYTOKENS, body);

export const retireHoneytoken = (tokenId: string) =>
  api.del<HoneytokenRetireOut>(`${HONEYTOKENS}/${encodeURIComponent(tokenId)}`);

export const getHoneytokenHits = (tokenId: string) =>
  api.get<HoneytokenHitsOut>(`${HONEYTOKENS}/${encodeURIComponent(tokenId)}/hits`);

// ── Unified security dashboard (HNY-013/014, admin-gated) ────────────────────

export const getSecurityOverview = (window?: string) =>
  api.get<SecurityOverviewOut>(
    `${DASHBOARD}/overview`,
    window ? { window } : undefined,
  );

export const listSecurityEvents = (params?: {
  kind?: string;
  severity?: string;
  ip?: string;
  limit?: number;
  cursor?: string;
}) => {
  const q: Record<string, string> = {};
  if (params?.kind) q.kind = params.kind;
  if (params?.severity) q.severity = params.severity;
  if (params?.ip) q.ip = params.ip;
  if (params?.limit != null) q.limit = String(params.limit);
  if (params?.cursor) q.cursor = params.cursor;
  return api.get<SecurityEventListOut>(`${DASHBOARD}/events`, q);
};

export const getSecurityEvent = (eventId: string) =>
  api.get<SecurityEventOut>(`${DASHBOARD}/events/${encodeURIComponent(eventId)}`);

export const getActiveThreats = () =>
  api.get<{ threats: SecurityEventOut[] }>(`${DASHBOARD}/threats/active`);
