import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ShieldAlert } from "lucide-react";

/**
 * Rendered when a CRM cluster router is not registered (flag OFF) or the
 * backend returns 404/503 for the feature. Distinguishes "not enabled" from a
 * permission error so admins get an actionable message.
 */
export function NotEnabledState({
  status,
  feature,
}: {
  status?: number;
  feature: string;
}) {
  const isPerm = status === 403;
  const isAuth = status === 401;
  return (
    <Card className="border-dashed">
      <CardHeader>
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-muted-foreground" />
          <CardTitle className="text-base">
            {isPerm
              ? "Insufficient permissions"
              : isAuth
                ? "Authentication required"
                : `${feature} is not enabled`}
          </CardTitle>
        </div>
        <CardDescription>
          {isPerm
            ? "You need admin or root access to view this area."
            : isAuth
              ? "Sign in with an admin or root account to continue."
              : `This feature is gated behind a server flag and is currently disabled. Ask an operator to enable it.`}
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        {!isPerm && !isAuth && (
          <p>
            Once the feature flag is enabled on the backend, this page will load
            automatically.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

/** True when an error indicates the feature/route is unavailable (not loaded). */
export function isNotEnabled(err: unknown): boolean {
  const status = (err as { status?: number } | null)?.status;
  return status === 404 || status === 503;
}
