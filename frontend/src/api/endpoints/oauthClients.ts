/**
 * OAU-001..OAU-006: OAuth2/OIDC consumer-app registry API wrappers.
 *
 * All endpoints are under /ui/oauth/consumers (cookie-auth + CSRF).
 * Gated on OPEN_BANK_PROJECT_ENABLED AND OAUTH_PROVIDER_ENABLED — backend
 * returns 404/503 when either flag is off.
 */

import { api } from "@/api/client";

// ─── Inline TypeScript interfaces (do NOT add to api/types.ts) ───────────────

/** A registered OAuth2/OIDC consumer app (safe — no secret hash). */
export interface OAuthConsumer {
  client_id: string;
  client_secret_prefix: string;
  owner_sub: string;
  name: string;
  description: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  is_confidential: boolean;
  enabled: boolean;
  created_at: number;
  updated_at: number;
  secret_rotated_at: number;
}

/** Returned after creating a consumer — includes one-time plaintext secret. */
export interface OAuthConsumerCreated {
  client_id: string;
  client_secret: string;
  client_secret_prefix: string;
  name: string;
  created_at: number;
}

/** Returned after rotating the client secret — includes new one-time plaintext. */
export interface OAuthSecretRotated {
  client_id: string;
  client_secret: string;
  client_secret_prefix: string;
  secret_rotated_at: number;
}

export interface CreateConsumerInput {
  name: string;
  description?: string;
  redirect_uris: string[];
  allowed_scopes: string[];
  is_confidential?: boolean;
}

export interface UpdateConsumerInput {
  name?: string;
  description?: string;
  redirect_uris?: string[];
  allowed_scopes?: string[];
}

// ─── Consumer CRUD ────────────────────────────────────────────────────────────

/** List all OAuth consumer apps owned by the authenticated user. */
export const listOAuthConsumers = (): Promise<OAuthConsumer[]> =>
  api.get<OAuthConsumer[]>("/ui/oauth/consumers");

/** Get a single consumer by client_id. */
export const getOAuthConsumer = (clientId: string): Promise<OAuthConsumer> =>
  api.get<OAuthConsumer>(`/ui/oauth/consumers/${clientId}`);

/** Register a new OAuth consumer app. Returns one-time client_secret. */
export const createOAuthConsumer = (
  input: CreateConsumerInput,
): Promise<OAuthConsumerCreated> =>
  api.post<OAuthConsumerCreated>("/ui/oauth/consumers", input);

/** Update mutable fields on a consumer. */
export const updateOAuthConsumer = (
  clientId: string,
  input: UpdateConsumerInput,
): Promise<OAuthConsumer> =>
  api.patch<OAuthConsumer>(`/ui/oauth/consumers/${clientId}`, input);

/** Delete a consumer app (irreversible). */
export const deleteOAuthConsumer = (
  clientId: string,
): Promise<{ ok: boolean }> =>
  api.del<{ ok: boolean }>(`/ui/oauth/consumers/${clientId}`);

// ─── Enable / Disable ────────────────────────────────────────────────────────

/** Re-enable a previously disabled consumer app. */
export const enableOAuthConsumer = (
  clientId: string,
): Promise<OAuthConsumer> =>
  api.post<OAuthConsumer>(`/ui/oauth/consumers/${clientId}/enable`);

/** Disable a consumer app (all existing tokens immediately rejected). */
export const disableOAuthConsumer = (
  clientId: string,
): Promise<OAuthConsumer> =>
  api.post<OAuthConsumer>(`/ui/oauth/consumers/${clientId}/disable`);

// ─── Secret rotation ─────────────────────────────────────────────────────────

/** Rotate the client_secret. Returns new plaintext once; old secret immediately invalid. */
export const rotateOAuthConsumerSecret = (
  clientId: string,
): Promise<OAuthSecretRotated> =>
  api.post<OAuthSecretRotated>(`/ui/oauth/consumers/${clientId}/rotate-secret`);
