/**
 * Hotel Guest Folio List (HTL-029..031).
 *
 * Route: hotels/folios
 *
 * Shows a search/filter form to look up a folio by hotel + reservation ID,
 * and lists recent folios accessed (stored in local session state).
 *
 * Feature-gated: HOTEL_PMS_ENABLED (default OFF) → backend returns 404.
 * Renders a clear "not enabled" state when 404/503 is received.
 *
 * Admin-only write actions (post charges, settle, close) are accessible from
 * the detail page. This page is a navigation hub.
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search, AlertCircle, Building2, Loader2 } from "lucide-react";

import { ApiError } from "@/api/client";
import { getFolio } from "@/api/endpoints/hotelFolios";
import { PageHeader } from "@/components/shared/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function centsToCurrency(cents: number, currency = "usd"): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
    minimumFractionDigits: 2,
  }).format(cents / 100);
}

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  open:   "bg-green-100 text-green-800",
  closed: "bg-gray-100 text-gray-600",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status] ?? "bg-gray-100 text-gray-600";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

// ─── Lookup form ──────────────────────────────────────────────────────────────

function FolioLookupForm() {
  const [hotelId, setHotelId] = useState("");
  const [rid, setRid] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const navigate = useNavigate();

  const query = useQuery({
    queryKey: ["hotel-folio-lookup", hotelId, rid],
    queryFn: () => getFolio(hotelId, rid),
    enabled: submitted && hotelId.trim().length > 0 && rid.trim().length > 0,
    retry: false,
  });

  const handleLookup = () => {
    if (!hotelId.trim() || !rid.trim()) return;
    setSubmitted(true);
  };

  const isNotEnabled =
    query.isError &&
    query.error instanceof ApiError &&
    (query.error.status === 404 || query.error.status === 503);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="h-4 w-4" />
          Look up folio
        </CardTitle>
        <CardDescription>
          Enter a hotel ID and reservation ID to view or open a guest folio.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="folio-hotel-id">Hotel ID</Label>
            <Input
              id="folio-hotel-id"
              placeholder="e.g. hotel_abc123"
              value={hotelId}
              onChange={(e) => {
                setHotelId(e.target.value);
                setSubmitted(false);
              }}
              data-testid="folio-hotel-id-input"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="folio-rid">Reservation ID</Label>
            <Input
              id="folio-rid"
              placeholder="e.g. res_xyz789"
              value={rid}
              onChange={(e) => {
                setRid(e.target.value);
                setSubmitted(false);
              }}
              data-testid="folio-rid-input"
            />
          </div>
        </div>

        <div className="flex gap-2">
          <Button
            onClick={handleLookup}
            disabled={!hotelId.trim() || !rid.trim() || query.isFetching}
            data-testid="folio-lookup-btn"
          >
            {query.isFetching ? (
              <Loader2 className="h-4 w-4 animate-spin mr-1" />
            ) : (
              <Search className="h-4 w-4 mr-1" />
            )}
            Look up
          </Button>
          {query.data && (
            <Button
              variant="default"
              onClick={() => navigate(`/hotels/folios/${hotelId}/${rid}`)}
              data-testid="folio-open-detail-btn"
            >
              Open detail
            </Button>
          )}
        </div>

        {isNotEnabled && (
          <div className="flex items-center gap-2 rounded-md border border-yellow-200 bg-yellow-50 p-3 text-sm text-yellow-800">
            <AlertCircle className="h-4 w-4 shrink-0" />
            Hotel PMS is not enabled on this platform. Contact your administrator.
          </div>
        )}

        {query.isError && !isNotEnabled && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {query.error instanceof ApiError
              ? query.error.detail
              : "An error occurred."}
          </div>
        )}

        {query.data && (
          <div className="rounded-md border bg-muted/30 p-3 space-y-1 text-sm">
            <div className="font-semibold">
              Folio found: {query.data.folio_id}
            </div>
            <div className="flex gap-2 items-center">
              <StatusBadge status={query.data.status} />
              <span className="text-muted-foreground">
                Balance:{" "}
                <strong>
                  {centsToCurrency(
                    query.data.balance_due_cents,
                    query.data.currency,
                  )}
                </strong>
              </span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function FolioListPage() {
  return (
    <div className="space-y-6 p-4 md:p-6 lg:p-8">
      <PageHeader
        title="Guest Folios"
        description="View and manage hotel guest folios — charges, payments, and deposits."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <FolioLookupForm />

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Building2 className="h-4 w-4" />
              About guest folios
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              A guest folio is the master bill for a hotel reservation. It
              tracks all room-night charges, add-on services, taxes, fees,
              payments, and the deposit held in escrow.
            </p>
            <ul className="list-disc list-inside space-y-1">
              <li>Folios are automatically opened on the first read.</li>
              <li>Admins can post custom charges and catalog add-ons.</li>
              <li>Deposits are held from the guest wallet via escrow.</li>
              <li>Payments settle the balance (wallet or external methods).</li>
              <li>A folio can be downloaded as a PDF for the guest.</li>
            </ul>
            <Badge variant="outline" className="text-xs">
              Requires HOTEL_PMS_ENABLED
            </Badge>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
