import type { ReactNode } from "react";
import { Link } from "react-router-dom";

import { isCanonicalProfileNavigationEnabled } from "@/lib/featureFlags";
import { cn } from "@/lib/utils";

export interface UserProfileIdentity {
  userId?: string | null;
  username?: string | null;
  displayName?: string | null;
}

export interface UserProfileLinkProps extends UserProfileIdentity {
  fallbackLabel?: string;
  className?: string;
  ariaLabel?: string;
  title?: string;
  children?: ReactNode;
}

function normalizeIdentifier(raw?: string | null): string {
  return (raw ?? "").trim();
}

export function resolveCanonicalProfilePath(identity: UserProfileIdentity): string | null {
  const username = normalizeIdentifier(identity.username);
  if (username) return `/u/${encodeURIComponent(username)}`;

  const userId = normalizeIdentifier(identity.userId);
  if (userId) return `/u/${encodeURIComponent(userId)}`;

  return null;
}

export function resolveUserProfileLabel(
  identity: UserProfileIdentity,
  fallbackLabel = "Unknown user",
): string {
  const displayName = normalizeIdentifier(identity.displayName);
  if (displayName) return displayName;

  const username = normalizeIdentifier(identity.username);
  if (username) return username;

  const userId = normalizeIdentifier(identity.userId);
  if (userId) return userId;

  return fallbackLabel;
}

export function UserProfileLink({
  userId,
  username,
  displayName,
  fallbackLabel = "Unknown user",
  className,
  ariaLabel,
  title,
  children,
}: UserProfileLinkProps) {
  const identity: UserProfileIdentity = { userId, username, displayName };
  const label = resolveUserProfileLabel(identity, fallbackLabel);
  const path = isCanonicalProfileNavigationEnabled() ? resolveCanonicalProfilePath(identity) : null;
  const accessibleName = ariaLabel ?? `View ${label} profile`;

  if (!path) {
    return (
      <span className={className} aria-label={accessibleName} title={title ?? label}>
        {children ?? label}
      </span>
    );
  }

  return (
    <Link
      to={path}
      aria-label={accessibleName}
      title={title ?? label}
      className={cn("hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-sm", className)}
    >
      {children ?? label}
    </Link>
  );
}

export default UserProfileLink;
