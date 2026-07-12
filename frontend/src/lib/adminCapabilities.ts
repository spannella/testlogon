import type { AdminProfileType, AdminScope } from "@/api/endpoints/adminRoles";
import { useAuthStore } from "@/stores/authStore";

interface JwtAdminProfile {
  type?: AdminProfileType | string;
  scopes?: string[];
}

interface JwtClaims {
  role?: string;
  admin_profile?: JwtAdminProfile;
}

function parseJwtClaims(token: string | null): JwtClaims | null {
  if (!token || token.split(".").length < 2) return null;
  try {
    return JSON.parse(atob(token.split(".")[1]!));
  } catch {
    return null;
  }
}

export function getRoleFromAccessToken(token: string | null): string | null {
  const claims = parseJwtClaims(token);
  if (typeof claims?.role === "string") return claims.role;
  // Cookie login stores an empty access token, so fall back to the role
  // fetched from /ui/me (role/is_admin) and cached in the auth store.
  const stored = useAuthStore.getState().role;
  return typeof stored === "string" ? stored : null;
}

export function getAdminProfileFromAccessToken(token: string | null): { type: AdminProfileType; scopes: AdminScope[] } | null {
  const claims = parseJwtClaims(token);
  if (!claims || claims.role !== "admin") {
    // No role-bearing JWT (cookie login) -> fall back to /ui/me identity.
    if (useAuthStore.getState().role !== "admin") return null;
    const storedProfile = useAuthStore.getState().adminProfile;
    if (storedProfile) return { type: storedProfile.type as AdminProfileType, scopes: storedProfile.scopes as AdminScope[] };
    return { type: "general", scopes: [] };
  }

  const raw = claims.admin_profile;
  if (!raw || raw.type !== "scoped") {
    return { type: "general", scopes: [] };
  }

  const scopes = Array.isArray(raw.scopes)
    ? (raw.scopes.filter((s): s is AdminScope => s === "auth_support" || s === "billing_support" || s === "content_moderation"))
    : [];

  if (scopes.length === 0) {
    return { type: "general", scopes: [] };
  }

  return { type: "scoped", scopes: Array.from(new Set(scopes)) };
}

export function canAccessGeneralAdminControls(token: string | null): boolean {
  const role = getRoleFromAccessToken(token);
  if (role === "root") return true;
  if (role !== "admin") return false;
  return getAdminProfileFromAccessToken(token)?.type === "general";
}

export function canSeeRootRoleManagement(token: string | null): boolean {
  return getRoleFromAccessToken(token) === "root";
}


export function canAccessModerationBoard(token: string | null): boolean {
  const role = getRoleFromAccessToken(token);
  if (role === "root") return true;
  if (role !== "admin") return false;
  const profile = getAdminProfileFromAccessToken(token);
  if (!profile) return false;
  return profile.type === "general" || profile.scopes.includes("content_moderation");
}

export function canAccessPaymentIncidentQueue(token: string | null): boolean {
  const role = getRoleFromAccessToken(token);
  if (role === "root") return true;
  if (role !== "admin") return false;
  const profile = getAdminProfileFromAccessToken(token);
  if (!profile) return false;
  return profile.type === "general" || profile.scopes.includes("billing_support");
}
