/**
 * VEW-003 — Public (unauthenticated) view of a shared resource.
 *
 * Route: /bank/views/public/:token
 *
 * Reads resource data through a public share link. No auth required.
 * Token is HMAC-signed + time-limited; backend validates and projects
 * only the permitted fields.
 */

import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Eye, AlertCircle, ArrowLeft } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import { readPublicView } from "@/api/endpoints/accountViews";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtCents(cents: unknown): string {
  const num = Number(cents);
  if (isNaN(num)) return String(cents ?? "—");
  return (num / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });
}

function fmtTs(ts: unknown): string {
  if (!ts) return "—";
  const num = Number(ts);
  if (isNaN(num)) return String(ts);
  return new Date(num * 1000).toLocaleString();
}

function humanizeKey(key: string): string {
  return key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// ─── Data display ─────────────────────────────────────────────────────────────

function DataDisplay({ data, resourceType }: { data: Record<string, unknown>; resourceType: string }) {
  const skip = new Set(["resource_type", "resource_id", "payout_id", "user_id"]);

  if (resourceType === "wallet") {
    return (
      <div className="grid grid-cols-2 gap-4">
        {data["wallet_balance_cents"] != null && (
          <div>
            <p className="text-xs text-muted-foreground">Balance</p>
            <p className="text-2xl font-bold">{fmtCents(data["wallet_balance_cents"])}</p>
          </div>
        )}
        {data["available_balance_cents"] != null && (
          <div>
            <p className="text-xs text-muted-foreground">Available</p>
            <p className="text-xl font-semibold">{fmtCents(data["available_balance_cents"])}</p>
          </div>
        )}
        {data["label"] != null && (
          <div>
            <p className="text-xs text-muted-foreground">Label</p>
            <p className="text-sm">{String(data["label"])}</p>
          </div>
        )}
        {data["currency"] != null && (
          <div>
            <p className="text-xs text-muted-foreground">Currency</p>
            <p className="text-sm uppercase">{String(data["currency"])}</p>
          </div>
        )}
      </div>
    );
  }

  // Generic fallback
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
      {Object.entries(data)
        .filter(([k]) => !skip.has(k) && !Array.isArray(data[k]))
        .map(([k, v]) => (
          <div key={k} className="space-y-0.5">
            <dt className="text-xs text-muted-foreground">{humanizeKey(k)}</dt>
            <dd className="text-sm font-medium">
              {v == null
                ? "—"
                : k.includes("cents")
                ? fmtCents(v)
                : k.endsWith("_at") || k === "ts"
                ? fmtTs(v)
                : typeof v === "object"
                ? JSON.stringify(v)
                : String(v)}
            </dd>
          </div>
        ))}
    </dl>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function PublicViewPage() {
  const { token } = useParams<{ token: string }>();

  const dataQ = useQuery({
    queryKey: ["account-views", "public", token],
    queryFn: () => readPublicView(token!),
    enabled: !!token,
    retry: false,
  });

  const isInvalid =
    dataQ.isError &&
    dataQ.error instanceof ApiError &&
    (dataQ.error.status === 403 || dataQ.error.status === 400);

  const featureOff =
    dataQ.isError &&
    dataQ.error instanceof ApiError &&
    dataQ.error.status === 404;

  return (
    <div className="min-h-screen bg-muted/30 flex items-start justify-center p-6">
      <div className="w-full max-w-2xl space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <Eye className="h-7 w-7 text-primary" />
          <div>
            <h1 className="text-xl font-bold">Shared Resource View</h1>
            <p className="text-sm text-muted-foreground">
              This resource has been shared with you via a public link.
            </p>
          </div>
        </div>

        {dataQ.isLoading && (
          <div className="space-y-4">
            <Skeleton className="h-8 w-40" />
            <Skeleton className="h-48 w-full rounded-lg" />
          </div>
        )}

        {featureOff && (
          <Card>
            <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
              <AlertCircle className="h-10 w-10 text-muted-foreground" />
              <p className="font-semibold">Feature not available</p>
              <p className="text-sm text-muted-foreground">
                Account Views are not enabled on this server.
              </p>
            </CardContent>
          </Card>
        )}

        {isInvalid && (
          <Card>
            <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
              <AlertCircle className="h-10 w-10 text-destructive" />
              <p className="font-semibold">Link invalid or expired</p>
              <p className="text-sm text-muted-foreground">
                {dataQ.error instanceof Error
                  ? dataQ.error.message
                  : "This public view link is invalid, expired, or has been revoked."}
              </p>
            </CardContent>
          </Card>
        )}

        {dataQ.isError && !isInvalid && !featureOff && (
          <Card>
            <CardContent className="py-8 text-center text-sm text-destructive">
              {dataQ.error instanceof Error ? dataQ.error.message : "Failed to load shared resource"}
            </CardContent>
          </Card>
        )}

        {dataQ.data && (
          <>
            {/* View metadata */}
            <Card className="border-primary/20 bg-primary/5">
              <CardContent className="pt-4 pb-3">
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-medium">
                    {dataQ.data._view.view_name || "Shared View"}
                  </span>
                  {dataQ.data._view.preset && (
                    <Badge variant="outline" className="text-xs capitalize">
                      {dataQ.data._view.preset}
                    </Badge>
                  )}
                  {dataQ.data.expires_at && (
                    <span className="text-xs text-muted-foreground">
                      Expires {fmtTs(dataQ.data.expires_at)}
                    </span>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Visible fields:{" "}
                  {dataQ.data._view.granted_fields.length === 0
                    ? "none"
                    : dataQ.data._view.granted_fields.join(", ")}
                </p>
              </CardContent>
            </Card>

            {/* Resource data */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base capitalize">
                  {dataQ.data.resource_type.replace(/_/g, " ")}
                </CardTitle>
                <CardDescription className="font-mono text-xs">
                  {dataQ.data.resource_id}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <DataDisplay
                  data={dataQ.data.data}
                  resourceType={dataQ.data.resource_type}
                />
              </CardContent>
            </Card>

            {/* Footer */}
            <p className="text-center text-xs text-muted-foreground">
              This view shows only the fields the resource owner has chosen to share.
            </p>
          </>
        )}

        <div className="text-center">
          <Button variant="ghost" size="sm" asChild>
            <Link to="/bank/views">
              <ArrowLeft className="h-4 w-4 mr-1" /> Manage my views
            </Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
